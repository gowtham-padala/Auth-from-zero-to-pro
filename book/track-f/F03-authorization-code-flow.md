# F03 — The authorization code flow, drawn slowly

**Part F · Delegated authorization — OAuth 2** · *Builds on [F02](F02-four-roles-two-channels.md), [A09](../track-a/A09-redirects.md)*
---

## The flow, step by step

```
 USER         BROWSER              CLIENT (server)         AUTH SERVER      RESOURCE SVR
  │              │                      │                      │               │
  │  clicks      │                      │                      │               │
  │ "connect" ──>│                      │                      │               │
  │              │─── GET /connect ────>│                      │               │
  │              │                      │ ① build authz URL:   │               │
  │              │                      │   client_id,         │               │
  │              │                      │   redirect_uri,      │               │
  │              │                      │   scope, state,      │               │
  │              │                      │   code_challenge     │               │
  │              │<── 302 to /authorize │                      │               │
  │              │───────── GET /authorize?... ───────────────>│               │
  │              │                      │                      │ ② who is this?│
  │  log in ────>│───────────────────────────────────────────>│  (session or  │
  │              │                      │                      │   login page) │
  │              │                      │                      │ ③ consent?    │
  │  "Allow" ───>│───────────────────────────────────────────>│               │
  │              │                      │                      │ ④ mint CODE   │
  │              │<───── 302 to redirect_uri?code=X&state ─────│               │
  │              │─── GET /callback?code=X&state ─────────────>│               │
  │              │                      │ ⑤ check state        │               │
  │              │                      │                      │               │
  │              │                      │═══ BACK CHANNEL ═════│               │
  │              │                      │ ⑥ POST /token:       │               │
  │              │                      │   code, client_id,   │               │
  │              │                      │   client_secret,     │               │
  │              │                      │   code_verifier ────>│               │
  │              │                      │<──── access_token ───│ ⑦ validate,   │
  │              │                      │   (+ refresh_token)  │   issue       │
  │              │                      │                      │               │
  │              │                      │─── GET /data (Bearer token) ────────>│
  │              │                      │<──────────── data ──────────────────│
  │  page ◄──────│◄─────────────────────│                      │               │
```

Ten steps. Front channel for 1–5, back channel for 6–7, then the resource request. Let me
walk each one.

---

## ① The authorization request

The client builds a URL and redirects the browser to the AS:

```
GET https://auth.example.com/authorize?
    response_type=code
    &client_id=printco-12345
    &redirect_uri=https://printco.example/callback
    &scope=photos:read
    &state=xyz789
    &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
    &code_challenge_method=S256
```

| Parameter | Meaning | Chapter |
|---|---|---|
| `response_type=code` | "Give me a **code**, not a token." The safe choice. | here |
| `client_id` | Which app is asking. Public, not a secret. | [F09](F09-public-vs-confidential-clients.md) |
| `redirect_uri` | Where to send the browser back. **Must be pre-registered.** | below |
| `scope` | What access is requested. | [F07](F07-access-refresh-scopes.md) |
| `state` | CSRF protection. Unguessable, tied to this session. | [F05](F05-the-state-parameter.md) |
| `code_challenge` | PKCE. Binds the flow to this client. | [F06](F06-pkce.md) |

The client keeps two secrets on its own side for later: the value behind `state`, and the
`code_verifier` behind `code_challenge`.

## ② The user authenticates

The browser is now on the **AS's own domain**. This is the entire security foundation of
OAuth, and it is why redirects matter ([A09](../track-a/A09-redirects.md)):

- The user types their password (or uses a passkey) **on the AS, in the address bar they can
  verify** — never on the client.
- The client **never sees the credential**. That is the whole point
  ([F01](F01-the-problem-oauth-solves.md)).
- The AS handles MFA, its own session, everything.

If the user already has a session with the AS, this step is invisible — which is why "Sign
in with Google" often feels instant.

## ③ Consent

The AS shows what the client is asking for ([F13](F13-consent-screens.md)):

```
   PrintCo wants to:
     ✓ View your photos
   [ Deny ]  [ Allow ]
```

## ④ The AS mints a code and redirects back

```
302 Location: https://printco.example/callback?code=SplxlOBeZQQYbYS6WxSbIA&state=xyz789
```

The **authorization code** is deliberately weak-by-design:

- **Single-use.** Redeemed once, then dead ([F14](F14-build-an-authorization-server.md)).
- **Short-lived.** 30–60 seconds. RFC recommends ≤ 10 minutes; less is better.
- **Bound to the client, `redirect_uri`, and (with PKCE) the `code_verifier`.**

It is safe to expose on the front channel *precisely because* it is worthless without the
back-channel exchange.

## ⑤ The client checks `state`

Before doing anything with the code, the client verifies the returned `state` matches what
it stored. A mismatch means this is not a response to a flow this user started — reject it
([F05](F05-the-state-parameter.md)).

## ⑥ The code exchange — on the back channel

Now the client, server-to-server, trades the code for tokens:

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <base64(client_id:client_secret)>     ← confidential clients only

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://printco.example/callback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

This never touches the browser. Here the client proves three things: it holds the code, it
is the registered client (via `client_secret` or, for public clients, PKCE), and it started
*this* flow (via `code_verifier`).

## ⑦ The AS validates and issues tokens

The AS checks: the code exists, is unexpired, is unredeemed, was issued to this client, the
`redirect_uri` matches the one in step ①, the client authentication is valid, and
`SHA256(code_verifier) == code_challenge`. All pass → tokens:

```json
{
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "scope": "photos:read"
}
```

And it marks the code redeemed. A second attempt to use it fails — and, per RFC 9700, a
*reused* code should invalidate the tokens already issued from it, because reuse means
someone may have intercepted it.

## The resource request

Finally, the client calls the resource server with the token
([F07](F07-access-refresh-scopes.md)):

```http
GET /v1/photos HTTP/1.1
Host: api.example.com
Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA
```

The RS validates the token ([F12](F12-introspection-vs-local-validation.md)), checks the
`aud` and `scope` ([F08](F08-audience-and-resource-indicators.md)), and returns the data.

---

## Why the code, and not just the token?

The question the whole chapter answers. Compare the two designs:

```
   IMPLICIT (dead)                      AUTHORIZATION CODE (correct)
   ──────────────                       ───────────────────────────
   AS ──token──> browser ──> client     AS ──code──> browser ──> client
              👁 in the URL                        👁 in the URL
              👁 in logs                           👁 in logs
              👁 in Referer                        👁 in Referer
              💀 it's the real token               🛡 useless without the
                                                    back-channel exchange
                                          client ──code+proof──> AS ──token──> client
                                                    🔒 back channel only
```

The code is the thing you can afford to expose. The token is not. The extra step moves the
valuable thing onto the channel where it cannot leak. That is not overhead — it is the
entire reason the flow exists.

The remaining risk: what if an attacker *does* intercept the code on the front channel? For
a confidential client, they still lack the `client_secret`. For a **public** client, there
is no secret — so PKCE ([F06](F06-pkce.md)) is what makes the intercepted code useless. That
is why PKCE is now mandatory for everyone.

---

## Terms defined in this chapter

`grant type`, `authorization code`, `authorization endpoint`, `token endpoint`,
`redirect_uri`, `authorization request`

---

## What to remember

1. **Ten steps: front channel (1–5), back channel (6–7), then the resource request.**
2. The user authenticates **on the AS's domain**, in the address bar they can verify. The
   client never sees the credential.
3. The **code** crosses the front channel; it is single-use, short-lived, and bound to the
   client. The **token** is obtained on the back channel and never touches the browser.
4. **`redirect_uri` must be pre-registered and exactly matched.** ([F20](F20-attack-your-own-oauth.md).)
5. Check `state` before using the code ([F05](F05-the-state-parameter.md)).
6. The extra exchange step exists to keep the token off the front channel. That is the whole
   design.
7. PKCE is what protects the code when there is no client secret.

---

## Sources

- [RFC 6749 — OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) §4.1 (authorization code grant)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §2.1 (code flow requirements)
- Aaron Parecki, [oauth.com — Authorization Code Grant](https://www.oauth.com/oauth2-servers/server-side-apps/authorization-code/)
- [The OAuth 2.1 draft §4.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)

---

**Next:** [F04 — Build an OAuth client with raw HTTP, no SDK](F04-build-oauth-client-raw-http.md)
