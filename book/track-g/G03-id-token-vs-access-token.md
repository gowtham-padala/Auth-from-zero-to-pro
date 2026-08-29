# G03 — ID token vs access token: stop sending the wrong one

**Part G · Federated identity & SSO** · *Builds on [G02](G02-oidc-on-top-of-oauth.md), [F08](../track-f/F08-audience-and-resource-indicators.md)*
---

## The two tokens

```
   ID TOKEN                               ACCESS TOKEN
   ────────                               ────────────
   "WHO logged in, and how, and when"     "This bearer MAY do X at API Y"
   FOR: the CLIENT (your app)             FOR: the RESOURCE SERVER (the API)
   aud = your client_id                   aud = the API's identifier
   Read by: your code                     Presented to: the API
   Format: always a JWT (OIDC)            Format: JWT or opaque — client doesn't care
   Answers: authentication                Answers: authorization
```

The one-line rule:

> **ID token → your own code, to learn who logged in. Access token → an API, to authorize an
> action. Never cross them.**

The `aud` claim ([F08](../track-f/F08-audience-and-resource-indicators.md)) is what makes this
concrete: the ID token's audience is *you*, so you consume it; the access token's audience is
the *API*, so you forward it there and nowhere else.

---

## The ID token, in detail

A signed JWT describing the **authentication event**:

```json
{
  "iss": "https://accounts.google.com",     // who issued it
  "sub": "110169484474386276334",           // stable user id, unique per issuer  C03
  "aud": "your-client-id.apps.google.com",  // YOU. Reject if not you.
  "exp": 1756348800,
  "iat": 1756345200,
  "auth_time": 1756345100,                  // when they actually authenticated  D18
  "nonce": "n-0S6_WzA2Mj",                  // binds to YOUR request  G02
  "acr": "urn:...:aal2",                    // assurance level reached  D18
  "amr": ["pwd", "otp"],                    // how they authenticated  D18
  "email": "alice@example.com",
  "email_verified": true,                   // check this before linking!  D02/G12
  "name": "Alice Smith",
  "picture": "https://.../photo.jpg"
}
```

Every claim answers something about *the login*: who (`sub`), for whom (`aud`), when
(`auth_time`), how strongly (`acr`, `amr`), and bound to which request (`nonce`). This is why
it is the authentication answer — and why validating it is validating the login
([G04](G04-validate-an-id-token-by-hand.md)).

**The ID token is consumed once, at login, by your code.** You validate it, extract the
identity, and create your own session ([E03](../track-e/E03-build-server-side-sessions.md)).
After that you do not need it again — it is not a session, and it is not a bearer credential
for anything.

---

## The access token, in detail

The credential for calling an API ([F07](../track-f/F07-access-refresh-scopes.md)):

```json
{
  "iss": "https://accounts.google.com",
  "sub": "110169484474386276334",
  "aud": "https://www.googleapis.com/calendar/v3",   // the API, not you
  "scope": "calendar.readonly",
  "exp": 1756348800
}
```

From the client's perspective it is **opaque** — you attach it to API requests and never look
inside ([F07](../track-f/F07-access-refresh-scopes.md)). Its `aud` is the *API*, and only that
API should validate and accept it ([F08](../track-f/F08-audience-and-resource-indicators.md)).

---

## Why building an API that accepts ID tokens is wrong

It is tempting: the ID token has the user's identity right there, so why not send it to your
API and skip the access token?

Because it inverts the audience model and creates a fragile, insecure coupling:

- **The `aud` is wrong.** The ID token's audience is the *client*. An API validating it
  correctly must check `aud == its own id` — which the ID token fails, because it names the
  client. An API that accepts it has *disabled* the audience check that protects it
  ([F08](../track-f/F08-audience-and-resource-indicators.md)).
- **No scopes.** The ID token has no `scope`; it is not a *permission* to do anything. You
  lose delegated authorization entirely ([F07](../track-f/F07-access-refresh-scopes.md)).
- **Wrong lifetime and refresh model.** ID tokens are consumed once at login; access tokens
  are refreshed ([E10](../track-e/E10-token-lifetimes-and-rotation.md)).
- **It leaks identity to every API.** The ID token carries `email`, `name`, `picture` —
  broadcasting PII to services that only needed authorization
  ([I11](../track-i/I11-compliance.md)).

If your API and your login are the same system (first-party), you do not need either token as
a bearer credential — you validate the ID token once and use **your own session**
([E09](../track-e/E09-should-you-use-jwts-for-sessions.md),
[F17](../track-f/F17-oauth-for-spas-and-bff.md)). If they are separate, the API takes an
**access token**, obtained for *its* audience.

---

## The `at_hash` binding

A subtle OIDC feature that ties the two tokens together. When both are issued, the ID token
may carry `at_hash` — a hash of the access token
([B04](../track-b/B04-what-a-hash-function-is.md)):

```json
{ "sub": "...", "at_hash": "77QmUPtjPfzWtF2AnpK9RQ" }
```

It lets the client verify that the access token it received was the one issued *with* this ID
token — a defence against an attacker substituting a different access token into the flow
([G04](G04-validate-an-id-token-by-hand.md)). Check it when present.

---

## The hybrid flow

Most flows return the ID token only from the token endpoint (back channel). The **hybrid
flow** (`response_type=code id_token`) returns *some* artifacts on the front channel and some
on the back:

```
response_type=code id_token   →  ID token in the redirect (front channel)
                                 + code for the back-channel exchange
```

It exists for cases where the RP wants to see identity immediately, before the code exchange
completes. It is niche and carries front-channel exposure risk for the ID token (which is why
`nonce` and careful validation matter even more). **Prefer the plain code flow**
([F03](../track-f/F03-authorization-code-flow.md)) unless a specific integration requires
hybrid.

---

## The decision table

| You have... | You want to... | Use |
|---|---|---|
| Just logged the user in | Know who they are | **ID token**, validated |
| An ID token | Create a session | Validate it, then **your own session** ([E03](../track-e/E03-build-server-side-sessions.md)) |
| A validated identity | Call your own API (same system) | **Your session cookie** — neither token |
| A validated identity | Call a *separate* API | **Access token** for that API's audience |
| An access token | Learn who the user is | ❌ **Don't.** Use the ID token, or `/userinfo` ([G06](G06-claims-vs-scopes-userinfo.md)) |
| An access token | Call the API it's for | ✅ Attach it as `Bearer` |

---

## Terms defined in this chapter

`ID token`, `at_hash`, `hybrid flow`

---

## What to remember

1. **ID token → your code (authentication). Access token → an API (authorization).** Never
   cross them.
2. The ID token's **`aud` is your client**; the access token's **`aud` is the API**. That is
   the whole distinction, made concrete.
3. The ID token describes the **login** — `sub`, `aud`, `auth_time`, `nonce`, `acr`, `amr`.
   Consumed once, at login, by your code.
4. **Do not build an API that accepts ID tokens.** It disables the audience check and leaks
   PII to every service.
5. First-party: validate the ID token once, then use **your own session** — not either token
   as a bearer credential.
6. Check **`at_hash`** when present; **prefer the plain code flow** over hybrid.

---

## Sources

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) §2 (ID token), §3.1.3.6 (`at_hash`), §3.3 (hybrid flow)
- [RFC 9068 — JWT Profile for OAuth Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 8725 — JWT BCP](https://www.rfc-editor.org/rfc/rfc8725)

---

**Next:** [G04 — Validate an ID token by hand: JWKS, iss, aud, nonce, exp](G04-validate-an-id-token-by-hand.md)
