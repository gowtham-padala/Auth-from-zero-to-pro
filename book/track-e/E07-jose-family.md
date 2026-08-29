# E07 — JOSE, JWK, JWKS, JWA: the acronym family, untangled

**Part E · Sessions & tokens** · *Builds on [E06](E06-jwt-part-2-signature-jws-jwe.md)*
---

## The family, in one table

| Acronym | Expands to | It is | RFC |
|---|---|---|---|
| **JOSE** | JSON Object Signing and Encryption | The **umbrella** — the working group and the family | — |
| **JWS** | JSON Web **Signature** | A *signed* thing. 3 parts. | [7515](https://www.rfc-editor.org/rfc/rfc7515) |
| **JWE** | JSON Web **Encryption** | An *encrypted* thing. 5 parts. | [7516](https://www.rfc-editor.org/rfc/rfc7516) |
| **JWK** | JSON Web **Key** | **One key**, as JSON | [7517](https://www.rfc-editor.org/rfc/rfc7517) |
| **JWKS** | JSON Web Key **Set** | **Many keys**, as JSON | 7517 §5 |
| **JWA** | JSON Web **Algorithms** | The registry of `alg` and `enc` values | [7518](https://www.rfc-editor.org/rfc/rfc7518) |
| **JWT** | JSON Web **Token** | Claims *carried in* a JWS (usually) or JWE | [7519](https://www.rfc-editor.org/rfc/rfc7519) |

The relationship that makes it click:

```
   JOSE  ─────────────── the family
     │
     ├── JWS   how to sign      ──┐
     ├── JWE   how to encrypt   ──┤ these are CONTAINERS
     ├── JWK   how to write a key │
     └── JWA   which algorithms   │
                                  │
   JWT  ── a set of claims ───────┘  put INSIDE a container
```

> **A JWT is not a format. It is *content*.** The format is JWS or JWE.
>
> "A JWT" in ordinary speech means "claims inside a JWS." Which is why a JWT has three parts
> — it is a JWS — and why the rare encrypted one has five.

---

## JWK — one key, as JSON

A public key, written as a JSON object instead of PEM.

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "use": "sig",
  "alg": "ES256",
  "kid": "2026-08-key-1"
}
```

| Field | Meaning |
|---|---|
| `kty` | Key type: `EC`, `RSA`, `oct` (symmetric), `OKP` (Ed25519) |
| `use` | `sig` (signature) or `enc` (encryption) |
| `alg` | The intended algorithm |
| **`kid`** | **Key ID — the whole reason rotation works** |
| `n`, `e` | RSA modulus and exponent |
| `crv`, `x`, `y` | Elliptic curve parameters |
| `d` | **The private key.** Must never appear in a published JWKS. |

**Check for `d`.** A JWK containing `d` is a private key. Publishing one is a catastrophic
and entirely preventable mistake — and it has happened, because a library serialised the
whole key object rather than `public_key().to_jwk()`.

---

## JWKS — the key set

An array of JWKs, served at a URL:

```json
{
  "keys": [
    { "kid": "2026-08-key-1", "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "use": "sig", "alg": "ES256" },
    { "kid": "2026-05-key-9", "kty": "EC", "crv": "P-256", "x": "...", "y": "...", "use": "sig", "alg": "ES256" }
  ]
}
```

```
https://auth.example.com/.well-known/jwks.json
```

**Two keys is normal and correct.** During rotation, both the previous and current keys must
be published, so tokens signed by either verify ([I06](../track-i/I06-key-rotation.md)).

This solves the key distribution problem for signature verification
([B10](../track-b/B10-key-distribution-problem.md)): the issuer publishes public keys over
HTTPS; verifiers fetch them; nothing secret is transmitted; rotation happens without
coordination.

### How verification uses it

```
1. Read `kid` from the token's header
2. Fetch the JWKS (from cache, if fresh)
3. Find the JWK whose kid matches
4. Verify the signature with that key, using YOUR pinned algorithm  (E06)
```

Step 3 is where an unhandled miss becomes an outage.

---

## Fetching it correctly

Four things go wrong. All four are avoidable.

```python
import jwt
from jwt import PyJWKClient

# ① CACHE. Without this you make an HTTPS request per token verification —
#    latency on every call and a self-inflicted DoS on your provider.
jwks_client = PyJWKClient(
    "https://auth.example.com/.well-known/jwks.json",
    cache_keys=True,
    lifespan=3600,          # respect the endpoint's Cache-Control
    max_cached_keys=16,
)

def verify(token: str) -> dict:
    try:
        # ② On a `kid` MISS, refetch ONCE — a key may have just rotated.
        signing_key = jwks_client.get_signing_key_from_jwt(token)
    except jwt.PyJWKClientError:
        jwks_client.fetch_data()                       # force refresh
        signing_key = jwks_client.get_signing_key_from_jwt(token)

    return jwt.decode(
        token, signing_key.key,
        algorithms=["ES256"],                          # ③ pinned — E06
        issuer="https://auth.example.com",
        audience="https://api.example.com",
    )
```

| # | Rule | Missing it means |
|---|---|---|
| ① | **Cache the JWKS** | An HTTPS round trip per request; you DoS your own IdP |
| ② | **Refetch once on a `kid` miss** | Every token fails the instant the provider rotates |
| ③ | **Pin the algorithm** | `alg: none`, algorithm confusion ([E06](E06-jwt-part-2-signature-jws-jwe.md)) |
| ④ | **Rate-limit the refetch** | A flood of bad `kid`s becomes a request storm at your provider |

Rule ④ deserves a sentence. An attacker sending tokens with random `kid` values triggers a
refetch per request if you are naive. Cap refetches to, say, one per minute; between
refetches, an unknown `kid` is simply a verification failure.

**Also:** fetch over **HTTPS**, from a URL derived from the **configured issuer**, and never
from a URL found inside a token ([E06](E06-jwt-part-2-signature-jws-jwe.md)). The JWKS URL
is a trust anchor. If an attacker controls it, they control your authentication entirely.

---

## JWA — the algorithm registry

Names for algorithms, so `"ES256"` means one specific thing everywhere.

### Signing (`alg` in a JWS)

| Value | Algorithm | Verdict |
|---|---|---|
| `HS256` / `384` / `512` | HMAC | ✅ **single party only** ([E06](E06-jwt-part-2-signature-jws-jwe.md)) |
| `RS256` / `384` / `512` | RSA PKCS#1 v1.5 | ✅ Common; legacy padding |
| `PS256` / `384` / `512` | RSA-PSS | ✅ Better RSA |
| **`ES256`** / `384` / `512` | ECDSA | ✅ **Preferred default** |
| `EdDSA` | Ed25519 | ✅ Best where supported ([B14](../track-b/B14-digital-signatures.md)) |
| `none` | — | ❌ **Never accept** |

### Encryption (`enc` in a JWE)

`A128GCM`, `A256GCM` — AEAD ([B09](../track-b/B09-symmetric-encryption.md)). Prefer these.
`A128CBC-HS256` is the older composite construction.

Key management (`alg` in a JWE): `RSA-OAEP`, `ECDH-ES`, `A256KW`, `dir`. Note that in a JWE,
`alg` names how the *content key* is wrapped — a different meaning from JWS. That collision
is one of the genuinely confusing parts of the family.

**Avoid `RSA1_5`** — vulnerable to Bleichenbacher-style oracle attacks
([B11](../track-b/B11-asymmetric-encryption.md)).

---

## Compact vs JSON serialisation

Everything so far is **compact serialisation** — dot-separated, URL-safe, one signature.

There is also **JSON serialisation**, which is verbose and supports **multiple signatures**
over the same payload:

```json
{
  "payload": "eyJzdWIiOiI0NDcxIn0",
  "signatures": [
    { "protected": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImsxIn0", "signature": "..." },
    { "protected": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImsyIn0", "signature": "..." }
  ]
}
```

Useful for multi-party attestation and for migration periods where different recipients
trust different keys. You will rarely see it. Recognising the shape is enough.

---

## Related specifications you will meet

| Spec | What it is | Where |
|---|---|---|
| [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) | **JWT Best Current Practices** | **Read this one** |
| [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638) | JWK Thumbprint — a canonical key fingerprint | DPoP ([F16](../track-f/F16-sender-constrained-tokens.md)) |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) | JWT profile for OAuth access tokens (`typ: at+jwt`) | [F12](../track-f/F12-introspection-vs-local-validation.md) |
| [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) | JWT client authentication and grants | [F09](../track-f/F09-public-vs-confidential-clients.md) |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) | DPoP — proof-of-possession JWTs | [F16](../track-f/F16-sender-constrained-tokens.md) |

RFC 8725 is the short, dense document that would have prevented most JWT vulnerabilities
ever shipped. If you implement anything in this track, read it.

---

## Terms defined in this chapter

`JOSE`, `JWA`, `JWK`, `JWKS`, `kid`

---

## What to remember

1. **JOSE** is the family. **JWS** signs, **JWE** encrypts, **JWK** is a key, **JWKS** is a
   key set, **JWA** names algorithms, **JWT** is the claims inside.
2. **A JWT is content, not a format.** Three parts because it is a JWS.
3. **`kid` is what makes rotation possible.** Two keys in a JWKS is normal.
4. **Cache the JWKS**, refetch **once** on a `kid` miss, and **rate-limit the refetch**.
5. **Fetch over HTTPS from a URL derived from the configured issuer.** Never from the token.
6. A JWK containing **`d`** is a private key. Never publish it.
7. **`ES256` as the default.** `EdDSA` where supported. `HS256` only single-party.
8. **Read RFC 8725.**

---

## Sources

- [RFC 7517 — JSON Web Key](https://www.rfc-editor.org/rfc/rfc7517)
- [RFC 7518 — JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)
- [RFC 8725 — JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [IETF JOSE Working Group](https://datatracker.ietf.org/wg/jose/documents/)

---

**Next:** [E08 — Signed cookies vs JWTs vs opaque tokens: pick one](E08-signed-cookies-vs-jwt-vs-opaque.md)
