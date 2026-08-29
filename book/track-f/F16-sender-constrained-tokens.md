# F16 — Sender-constrained tokens: mTLS and DPoP

**Part F · Delegated authorization — OAuth 2** · *Builds on [F07](F07-access-refresh-scopes.md), [B15](../track-b/B15-certificates-and-pki.md)*
---

## Why it matters

A **bearer** token means possession is sufficient ([C03](../track-c/C03-the-vocabulary.md)).
Steal the string, use the string. That is the entire security model, and its entire weakness.

```
   Attacker gets your access token (from a log, an XSS, a proxy, a leaked backup)
                              │
                              ▼
   Uses it from their own machine. The API cannot tell the difference,
   because there IS no difference — the token is all that's required.
```

Short lifetimes shrink the window ([E10](../track-e/E10-token-lifetimes-and-rotation.md))
but do not close it. **Sender-constrained tokens** close it differently: they bind the token
to a **key** the client holds, so a stolen token is useless without also stealing the key —
and the key never travels.

This chapter can be short. Bearer tokens over TLS are still fine for most contexts. But
sender-constrained tokens are part of the 2026 landscape — mandatory in banking (FAPI),
increasingly used for high-value APIs — and you should not meet DPoP for the first time in a
production incident.

---

## The idea: proof of possession

> **A sender-constrained token can only be used by the client that holds a specific private
> key, and the client proves possession of that key on every request.**

The token carries a **confirmation claim** (`cnf`) binding it to a key:

```json
{
  "sub": "user-4471",
  "aud": "https://api.example.com",
  "cnf": { "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" }
}
```

`jkt` is the thumbprint of the client's public key. On each request, the client proves it
holds the matching **private** key. A thief who copies the token cannot produce the proof,
because the private key never left the client ([B11](../track-b/B11-asymmetric-encryption.md)).

Two standards do this. They bind to different keys and suit different deployments.

---

## mTLS-constrained tokens (RFC 8705)

Bind the token to the client's **TLS client certificate** ([J04](../track-j/J04-mtls.md)).

```
   1. Client connects with a TLS client certificate (mutual TLS). B15.
   2. AS issues a token whose cnf.x5t#S256 = hash of that certificate.
   3. Resource server: the request arrives over an mTLS connection.
      Does the presented cert's hash match the token's cnf? No → reject.
```

The key here is the certificate's private key, used in the TLS handshake itself. The proof
of possession is *the TLS connection existing* — you cannot complete an mTLS handshake
without the private key ([B12](../track-b/B12-key-exchange.md)).

| | mTLS-constrained |
|---|---|
| Bound to | The TLS client certificate |
| Proof per request | The mTLS handshake |
| Infrastructure | Requires client certs everywhere; TLS termination that preserves the cert |
| Best for | **Service-to-service**, banking/FAPI, controlled environments |
| Weakness | Awkward through load balancers and CDNs that terminate TLS; hard for browsers |

mTLS is excellent where you control both ends and the network path
([J04](../track-j/J04-mtls.md)). It is painful in front of a CDN, and impractical for a
browser (managing client certs in browsers is a poor experience). That gap is what DPoP
fills.

---

## DPoP (RFC 9449)

**Demonstrating Proof of Possession** binds the token to a key the client generates itself —
**at the application layer**, so it works over ordinary TLS, through CDNs, and in browsers.

On each request, the client sends a `DPoP` header: a short-lived JWT signed with its private
key ([B14](../track-b/B14-digital-signatures.md)), proving possession *and* binding the proof
to this specific request.

```http
GET /v1/photos HTTP/1.1
Authorization: DPoP eyJhbGciOiJFUzI1Ni...        ← the access token (note: DPoP scheme)
DPoP: eyJ0eXAiOiJkcG9wK2p3dC...                   ← a fresh proof JWT, per request
```

The DPoP proof JWT contains:

```json
{
  "htm": "GET",                                   // the HTTP method
  "htu": "https://api.example.com/v1/photos",     // the HTTP URI
  "iat": 1756345200,
  "jti": "a-unique-id",                           // replay prevention
  "ath": "hash-of-the-access-token"               // binds proof to THIS token
}
```

signed with the client's key, whose public part is in the JWT header and whose thumbprint is
in the token's `cnf.jkt`.

The resource server checks:

1. The **access token's signature** and claims ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)).
2. The **DPoP proof's signature**, using the public key in its header.
3. That the proof's key **thumbprint matches `cnf.jkt`** in the access token.
4. That **`htm`/`htu` match this actual request** — so a proof for `GET /photos` cannot be
   replayed against `DELETE /photos`.
5. That **`jti` has not been seen** (within a time window) — replay prevention
   ([J06](../track-j/J06-signing-webhooks.md)).
6. That **`iat`** is recent.

A stolen access token now needs the private key *and* a fresh, correctly-bound proof — which
the thief cannot produce.

| | DPoP |
|---|---|
| Bound to | An application-layer key the client generates |
| Proof per request | A signed JWT in the `DPoP` header |
| Infrastructure | Works over plain TLS, through CDNs, in browsers |
| Best for | **SPAs, mobile, public clients**, anywhere mTLS is impractical |
| Weakness | The proof key must be stored safely — see below |

---

## The catch DPoP does not remove

DPoP binds the token to a key. But **where does the key live?** In a browser, if the key is
readable by script, an XSS can steal *both* the token and the key and forge proofs
([E16](../track-e/E16-xss-is-an-auth-vulnerability.md)).

The mitigation is a **non-extractable `CryptoKey`** in the Web Crypto API, stored in
IndexedDB. Script can *use* it to sign but cannot *export* it. An XSS can then forge proofs
only *while the page is open* — it cannot exfiltrate the key for offline use, which is a real
improvement over a plain bearer token in `localStorage`
([E12](../track-e/E12-where-to-store-a-token.md)), but not a cure.

This is the same lesson as passkeys and secure enclaves
([D16](../track-d/D16-biometrics.md), [A10](../track-a/A10-where-secrets-live.md)): a key
that can be *used* under compromise but not *taken* bounds the damage. It does not eliminate
it.

---

## When to use which

```
Do you need proof-of-possession at all?
│
├── Most first-party web apps ──> NO. Bearer tokens + short lifetimes + HttpOnly
│                                 cookies are fine. Don't add complexity.  E12
│
└── High-value API, or regulated, or the token crosses hostile ground?
    │
    ├── Service-to-service, you control the network ──> mTLS  (RFC 8705)  J04
    │
    ├── Banking / FAPI ──> mTLS (usually mandated)
    │
    └── Browser / mobile / public client, CDN in the path ──> DPoP  (RFC 9449)
```

The honest default: **bearer tokens are acceptable in most contexts.** Do not reach for
sender-constrained tokens reflexively — they add real operational complexity (key
management, proof validation, clock-skew tolerance, `jti` replay caches). Use them where the
value of the tokens, or a regulator, justifies it.

Where they *are* justified, the payoff is large: a leaked token — from a log, a breach, a
misconfigured proxy — becomes worthless, which removes an entire category of incident.

---

## Terms defined in this chapter

`sender-constrained token`, `mTLS`, `DPoP`, `proof of possession`

---

## What to remember

1. **A bearer token is stolen-string-is-access.** Sender-constrained tokens bind the token
   to a **key** that never travels.
2. The token carries a **`cnf`** claim; the client **proves possession** of the matching
   private key on every request.
3. **mTLS (RFC 8705)** binds to a TLS client certificate — great for service-to-service and
   FAPI, awkward through CDNs and browsers.
4. **DPoP (RFC 9449)** binds to an app-layer key via a per-request signed JWT — works over
   plain TLS, in browsers, through CDNs.
5. DPoP's proof binds to the **method and URI** (`htm`/`htu`) and the token (`ath`), and uses
   `jti` for replay prevention.
6. **DPoP does not fix XSS** unless the key is non-extractable — but it turns permanent theft
   into use-while-present.
7. **Bearer tokens are fine for most apps.** Add sender-constraint where value or regulation
   demands it.

---

## Sources

- [RFC 9449 — OAuth 2.0 Demonstrating Proof of Possession (DPoP)](https://www.rfc-editor.org/rfc/rfc9449)
- [RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://www.rfc-editor.org/rfc/rfc8705)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §4.10
- [FAPI 2.0 Security Profile](https://openid.net/specs/fapi-2_0-security-profile.html)

---

**Next:** [F17 — OAuth for SPAs, and the backend-for-frontend pattern](F17-oauth-for-spas-and-bff.md)
