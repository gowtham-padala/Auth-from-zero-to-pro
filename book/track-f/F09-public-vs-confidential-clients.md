# F09 — Public vs confidential clients, and why it changes everything

**Part F · Delegated authorization — OAuth 2** · *Builds on [F04](F04-build-oauth-client-raw-http.md)*
---

## Why it matters

A team ships a React SPA with OAuth. The provider's dashboard gave them a `client_id` and a
`client_secret`, so they use both — the secret goes into the SPA's config.

```js
const CLIENT_SECRET = "cs_live_8f14e45fceea167a";   // in the bundle
```

Anyone opens dev tools, reads the bundle ([A07](../track-a/A07-client-vs-server.md)), and
has the client secret. They can now impersonate the application: mint tokens, phish users
with a legitimate-looking consent screen, and abuse any trust the AS places in "the client."

The mistake is treating a SPA as a **confidential client** when it is structurally a
**public** one. A public client *cannot hold a secret*, and pretending otherwise does not
create security — it creates a leaked secret.

---

## The one question

> **Can this client keep a secret from its own user?**

That is the entire distinction, and everything downstream flows from it.

```
   CONFIDENTIAL CLIENT                    PUBLIC CLIENT
   ──────────────────                    ─────────────
   Runs where the user CANNOT reach      Runs where the user CAN reach
   its code or storage.                  its code or storage.

   • Server-side web app backend         • Single-page app (browser)
   • A backend service                   • Mobile app (on-device binary)
   • A CLI daemon with a vault           • Desktop app
                                         • CLI without secure storage
   CAN hold a client_secret.  ✅          CANNOT hold a secret.  ❌
```

It has nothing to do with the language, the framework, or whether the word "server" appears.
It is one question: **is the code and its storage on a machine the user controls?**
([A07](../track-a/A07-client-vs-server.md).)

- A React app rendered in a browser: **public**, even though a Node server delivered it.
- A Next.js *route handler* running on the server: **confidential**.
- The same Next.js app's *client component*: **public**.

The boundary can run *through* one codebase. The backend-for-frontend pattern exists exactly
to keep the confidential part confidential ([F17](F17-oauth-for-spas-and-bff.md)).

---

## Why it changes everything

The client type determines how the client authenticates at the token endpoint, which
determines which protections apply.

| | Confidential | Public |
|---|---|---|
| Client secret | ✅ Yes | ❌ **None usable** |
| Proves identity at `/token` | Secret or `private_key_jwt` | **Nothing** — anyone can claim the `client_id` |
| Protects the code exchange with | Secret **+** PKCE | **PKCE alone** |
| `client_id` is | Public | Public |
| Can be impersonated? | Only with the stolen secret | **Yes, trivially** — the `client_id` is public |

The consequence in the last row is the one people underestimate. A public client's
`client_id` is visible to everyone, and there is no secret behind it. So **any attacker can
start a flow claiming to be your app.** The protections that remain are:

1. **Registered redirect URIs** ([F03](F03-authorization-code-flow.md)) — the AS only sends
   codes to URIs *you* registered, so an impersonator cannot redirect the code to
   themselves.
2. **PKCE** ([F06](F06-pkce.md)) — even if a code is intercepted, only the client instance
   that started the flow can exchange it.

For a public client, those two are the *entire* security model of the code exchange. This is
why PKCE is non-negotiable for public clients — remove it and there is nothing left.

---

## How confidential clients authenticate

Three methods, weakest to strongest:

### `client_secret` — a shared password for the app

```http
POST /token
Authorization: Basic base64(client_id:client_secret)
```

Simple, and it is a shared secret with all the shared-secret problems
([B10](../track-b/B10-key-distribution-problem.md)): it can leak, it must be distributed,
and both you and the AS hold it (so an AS breach exposes it). Fine for many cases, and it
must live in a secret manager, never in code ([A10](../track-a/A10-where-secrets-live.md),
[I05](../track-i/I05-secrets-management.md)).

### `private_key_jwt` — the client signs a JWT with its own key

```http
POST /token
grant_type=authorization_code&code=...
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<a JWT signed with the client's PRIVATE key>
```

The client proves identity with a **signature**, not a shared secret
([B14](../track-b/B14-digital-signatures.md)). The AS holds only the client's *public* key.

Better on every axis: nothing shared to leak, an AS breach does not expose the credential,
and it is easy to rotate ([RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)). **Prefer it
for new high-value integrations**, and it is the direction OAuth 2.1 and FAPI push.

### mTLS — the client presents a certificate

The client authenticates with a TLS client certificate
([J04](../track-j/J04-mtls.md), [F16](F16-sender-constrained-tokens.md)). Strongest, and it
additionally enables sender-constrained tokens. Common in banking/FAPI and
service-to-service.

---

## The rules, by client type

### Public clients

```
✅  Authorization code flow + PKCE (S256), always      F06
✅  Registered, exactly-matched redirect URIs          F03
✅  No client secret (any "secret" is public)
❌  Never the implicit grant                           F15
❌  Never the password grant                           F15
✅  Short-lived access tokens; rotating refresh tokens  E10
✅  Tokens in memory / secure OS storage — never localStorage   E12
✅  Strongly consider a BFF, which makes it confidential  F17
```

### Confidential clients

```
✅  Authorization code flow + PKCE (defence in depth)   F06
✅  Client secret in a vault, or private_key_jwt         I05
✅  Registered, exactly-matched redirect URIs
✅  Can use client credentials grant for M2M            F10
✅  Rotate credentials on a schedule                    I06
```

Notice both lists include PKCE. It is mandatory for public clients and now recommended for
confidential ones too ([F06](F06-pkce.md)).

---

## The SPA question, resolved

A SPA is a public client. Given that, there are three architectures, and the trend is
decisive:

| Approach | Client type | Verdict |
|---|---|---|
| SPA holds tokens directly | Public | ⚠️ Works with PKCE; tokens exposed to XSS ([E12](../track-e/E12-where-to-store-a-token.md)) |
| **SPA + backend-for-frontend** | **The BFF is confidential** | ✅ **Recommended** ([F17](F17-oauth-for-spas-and-bff.md)) |
| SPA using implicit grant | Public | ❌ **Dead** ([F15](F15-implicit-and-password-grants.md)) |

The BFF turns the problem inside out: a small server component becomes the confidential
OAuth client, holds the tokens server-side, and hands the browser only a session cookie. The
SPA never touches a token. This is the current best-practice answer for browser apps, and it
is why "SPAs are public clients" does not mean "SPAs must hold tokens in the browser."

---

## Terms defined in this chapter

`public client`, `confidential client`, `client authentication`, `client secret`,
`private_key_jwt`

---

## What to remember

1. **One question: can the client keep a secret from its own user?** Yes → confidential.
   No → public.
2. It is about **where the code and storage run**, not the language or framework. The
   boundary can run through one codebase.
3. **A public client has no usable secret.** Its `client_id` is public, so anyone can claim
   it — registered redirect URIs and **PKCE** are its whole defence.
4. Putting a `client_secret` in a SPA or mobile binary **leaks the secret**. It does not make
   the client confidential.
5. Confidential clients: prefer **`private_key_jwt`** or **mTLS** over a shared secret for
   high-value integrations.
6. **A SPA is public — but a BFF makes the OAuth client confidential**, which is the
   recommended architecture.

---

## Sources

- [RFC 6749 §2.1](https://www.rfc-editor.org/rfc/rfc6749#section-2.1) — client types
- [RFC 7523 — JWT client authentication](https://www.rfc-editor.org/rfc/rfc7523)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §2.1, §2.6
- [OAuth 2.0 for Browser-Based Apps](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/) — the BFF recommendation

---

**Next:** [F10 — Client credentials: machine-to-machine auth](F10-client-credentials.md)
