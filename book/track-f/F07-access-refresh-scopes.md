# F07 — Access tokens, refresh tokens, and scopes

**Part F · Delegated authorization — OAuth 2** · *Builds on [F04](F04-build-oauth-client-raw-http.md), [E10](../track-e/E10-token-lifetimes-and-rotation.md)*
---

## Three tokens, three jobs

| Token | Presented to | Lifetime | Job |
|---|---|---|---|
| **Access token** | The resource server (API) | **Minutes** | The credential for *this request* |
| **Refresh token** | The authorization server only | Days–months | Obtain new access tokens |
| **ID token** | Nobody — read by the *client* | Minutes | Says *who logged in* (OIDC — [G03](../track-g/G03-id-token-vs-access-token.md)) |

The most common and most dangerous confusion is between the access token and the ID token.
They go to different places and answer different questions ([G03](../track-g/G03-id-token-vs-access-token.md)):

> **Access token → an API, to authorize an action. ID token → your own code, to learn who
> the user is. Sending an ID token to an API, or trusting an access token as identity, are
> both bugs.**

---

## Access tokens

The credential the client presents to the resource server, in the `Authorization` header
([A04](../track-a/A04-headers.md)):

```http
GET /v1/photos HTTP/1.1
Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA
```

Three defining properties:

**Short-lived.** 5–15 minutes typically. Because it travels widely — every API call carries
it — and it is hard to revoke ([E11](../track-e/E11-revocation.md)), its power comes from
its brevity. A leaked access token is a small window.

**Bearer, by default.** Possession is sufficient ([C03](../track-c/C03-the-vocabulary.md)).
Steal the string, use the string. This is the weakness that sender-constrained tokens fix
([F16](F16-sender-constrained-tokens.md)) — but plain bearer tokens are still the norm and
are acceptable given short lifetimes and TLS.

**Opaque *to the client*.** The client should treat the access token as a meaningless string
and never parse it. It may be a JWT the *resource server* validates
([F12](F12-introspection-vs-local-validation.md)), or truly opaque — but that is the RS's
business, not the client's. A client that cracks open an access token to read claims has
coupled itself to a format it does not own, and RFC 9700 explicitly warns against it.

---

## Refresh tokens

The long-lived credential used *only* to get new access tokens, and *only* at the token
endpoint — never at an API.

```http
POST /token
grant_type=refresh_token&refresh_token=tGzv3JOkF0XG5Qx2TlKWIA
```

The design is the resolution of the revocation tension from Track E
([E09](../track-e/E09-should-you-use-jwts-for-sessions.md)):

- **The access token is short and unrevocable** — small leak window, no lookup needed.
- **The refresh token is long and revocable** — held in one place, deleteable, and the thing
  that actually grants continued access.

Everything about refresh tokens — rotation, reuse detection, family invalidation, where they
live per client — is [E10](../track-e/E10-token-lifetimes-and-rotation.md). The one-line
summary: **rotate on every use, and treat reuse as a compromise.**

Note: a client does not always get a refresh token. It must request `offline_access` scope
(in OIDC), the AS must be willing, and public clients get them only under strict conditions.
Never assume one was issued ([J08](../track-j/J08-mcp-and-oauth-21.md) makes this a `MUST
NOT assume`).

---

## Scopes

> **A scope is a coarse label bounding what the *client* may do on the user's behalf.**

```
scope=photos:read photos:write contacts:read
```

Two properties that define what scopes are — and, crucially, what they are not.

### Scopes are about the client, not the user

A scope grants the *application* permission to *attempt* something on the user's behalf. It
**can only narrow**, never expand:

```
   User's actual permissions:  can read and write their OWN photos
   Token scope:                photos:write
   ─────────────────────────────────────────────────────────────
   Result: the app may attempt writes — but ONLY to the user's own
           photos, because the user's permissions still apply on top.
```

A `photos:write` scope on a token for a user who can only read grants nothing. The scope
says "this app is *allowed to try* writes," and the resource server still enforces what the
*user* may actually do ([H05](../track-h/H05-roles-permissions-scopes-groups.md)).

### Scopes are coarse. They are not an authorization model

```
   scope=documents:read   →   "may read documents"
   NOT                    →   "may read THIS document"
```

This is the boundary people cross and regret. A scope says *category*; it never says *which
object*. `documents:read` does not answer "may this user read document 9182?" — that is
per-object authorization, and it is Track H
([H14](../track-h/H14-attack-your-own-authorization.md)).

> **Scope is a filter on delegation. Every scope-based system still needs a real
> authorization layer underneath.** Treating a scope check as sufficient authorization is one
> of the most common serious API vulnerabilities (BOLA/IDOR —
> [H14](../track-h/H14-attack-your-own-authorization.md)).

Concretely, on the resource server:

```python
def get_photo(photo_id, token):
    require_scope(token, "photos:read")        # ① the app MAY read photos
    photo = db.get_photo(photo_id)
    if photo.owner_id != token.subject:        # ② but only THIS user's photos
        abort(403)                             #    ← the check scopes cannot make
    return photo
```

Check ① is the scope. Check ② is authorization. Both are required. Ship only ① and you have
an IDOR.

---

## Designing scopes

Good scopes are **granular, readable, and resource-oriented**:

```
   ✅  photos:read        contacts:read       calendar:write
   ✅  repo:status        user:email          gist:read
```

Bad scopes are **coarse and vague**:

```
   ❌  admin              full_access         all
   ❌  read (read what?)  api                 default
```

Principles:

**Least privilege.** Offer scopes fine enough that a client can request exactly what it
needs. GitHub's `user:email` vs `user` is the model — a client wanting only the email should
not have to request the whole profile.

**Human-readable on the consent screen.** The user sees these ([F13](F13-consent-screens.md)).
`photos:read` renders as "View your photos." `scope_47` renders as nothing meaningful, and a
user who cannot understand the request cannot meaningfully consent.

**Incremental authorization.** Request the minimum at first; ask for more *when you actually
need it*. A photo app should not request `photos:delete` until the user clicks delete. This
raises consent rates (the first ask is small) and reduces blast radius. Google's APIs are
built around this.

```
   First run:        scope=photos:read              → user sees "view photos", allows
   User clicks edit: scope=photos:read photos:write → a second, targeted consent
```

**Never over-request.** Over-requesting reads as untrustworthy, lowers
consent rates, and enlarges the damage of a compromise.

---

## What the token response looks like

```json
{
  "access_token":  "2YotnFZFEjr1zCsicMWpAA",
  "token_type":    "Bearer",
  "expires_in":    900,
  "refresh_token": "tGzv3JOkF0XG5Qx2TlKWIA",
  "scope":         "photos:read"
}
```

Two things clients get wrong:

**The `scope` in the response may be *less* than you asked for.** The AS or user can grant a
subset. **Always read the granted scope from the response** and adapt — do not assume you
got what you requested. Requesting `read write` and receiving `read` means the write button
should be disabled, not clicked into a `403`.

**`expires_in` is *seconds*, relative.** Not a timestamp, not milliseconds. Refresh before
it elapses ([E10](../track-e/E10-token-lifetimes-and-rotation.md)).

---

## Where the tokens live

Per client type ([E12](../track-e/E12-where-to-store-a-token.md),
[E10](../track-e/E10-token-lifetimes-and-rotation.md)):

| Client | Access token | Refresh token |
|---|---|---|
| Server-side web (confidential) | Server memory / cache | **Server-side, encrypted** ([I05](../track-i/I05-secrets-management.md)) |
| SPA with a BFF | Never in the browser | **BFF, server-side** ([F17](F17-oauth-for-spas-and-bff.md)) |
| SPA without a BFF | In memory only | `HttpOnly` cookie, path-scoped |
| Mobile | Memory | Keychain / Keystore ([D16](../track-d/D16-biometrics.md)) |
| M2M | Memory; re-fetch on expiry | Usually none — just re-request ([F10](F10-client-credentials.md)) |

Refresh tokens are long-lived credentials. Encrypt them at rest and treat them like
passwords ([A10](../track-a/A10-where-secrets-live.md)).

---

## Terms defined in this chapter

`access token`, `refresh token`, `scope (OAuth)`, `incremental authorization`

---

## What to remember

1. **Three tokens:** access (to the API, short), refresh (to the AS, long, revocable), ID
   (to your code, identity — OIDC).
2. **Access token → API. ID token → your code.** Confusing them is the classic OAuth bug.
3. The client treats the **access token as opaque** and never parses it.
4. **Scopes bound the client and can only narrow.** The user's own permissions still apply.
5. **Scopes are coarse — never per-object.** Every scope check needs an authorization check
   behind it, or you have an IDOR.
6. **Least privilege + incremental authorization.** Request the minimum, ask for more when
   needed.
7. **Read the *granted* scope from the response.** You may get less than you asked for.
8. Refresh tokens are passwords. Store them accordingly.

---

## Sources

- [RFC 6749 §3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3) (scope), §4–6 (tokens)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §2.3 (don't parse access tokens)
- [RFC 6750 — Bearer Token Usage](https://www.rfc-editor.org/rfc/rfc6750)
- Aaron Parecki, [oauth.com — Scopes](https://www.oauth.com/oauth2-servers/scope/)

---

**Next:** [F08 — Audience and resource indicators: the part everyone gets wrong](F08-audience-and-resource-indicators.md)
