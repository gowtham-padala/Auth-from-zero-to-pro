# G06 — Claims vs scopes, and the UserInfo endpoint

**Part G · Federated identity & SSO** · *Builds on [G02](G02-oidc-on-top-of-oauth.md)*
---

## Scopes request; claims deliver

```
   SCOPE                                   CLAIM
   ─────                                   ─────
   A REQUEST for a bundle of claims        A single piece of data about the user
   scope=email                       →     email, email_verified
   scope=profile                     →     name, family_name, picture, locale, ...
   Sent in the authorization request       Returned in the ID token or from /userinfo
   The user consents to it                 The value the consent unlocked
```

The OIDC standard scopes and what each unlocks:

| Scope | Claims it authorizes |
|---|---|
| **`openid`** | `sub` — required; it is what makes the request OIDC ([G02](G02-oidc-on-top-of-oauth.md)) |
| **`profile`** | `name`, `family_name`, `given_name`, `picture`, `locale`, `updated_at`, ... |
| **`email`** | `email`, `email_verified` |
| **`address`** | `address` (a structured object) |
| **`phone`** | `phone_number`, `phone_number_verified` |

So `scope=openid email profile` is the common login request: identity, email, and basic
profile. Request only what you need ([F07](../track-f/F07-access-refresh-scopes.md)) — asking
for `phone` when you will never use it is over-collection the user sees on the consent screen
([F13](../track-f/F13-consent-screens.md)) and a compliance liability
([I11](../track-i/I11-compliance.md)).

---

## Two places to get claims

Claims arrive by one of two routes, and knowing which — and why — matters.

### 1. In the ID token

The IdP puts (some) claims directly in the ID token ([G03](G03-id-token-vs-access-token.md)):

```json
{ "sub": "...", "aud": "...", "email": "alice@example.com", "name": "Alice" }
```

**Pro:** no extra request; you have them the moment you validate the token
([G04](G04-validate-an-id-token-by-hand.md)).
**Con:** the token grows. A token stuffed with claims can exceed header size limits
([E05](../track-e/E05-jwt-part-1-three-parts.md)) and carries PII in a widely-copied artifact.

### 2. From the UserInfo endpoint

A standard OIDC API that returns claims about the user, called with the **access token**
([G03](G03-id-token-vs-access-token.md)):

```http
GET /userinfo HTTP/1.1
Host: openidconnect.googleapis.com
Authorization: Bearer <ACCESS token, not the ID token>
```

```json
{
  "sub": "110169484474386276334",
  "email": "alice@example.com",
  "email_verified": true,
  "name": "Alice Smith",
  "picture": "https://.../photo.jpg"
}
```

**Pro:** keeps the ID token small; fetch claims fresh, when you need them.
**Con:** an extra network round trip.

Providers differ on which route they use — Google returns core claims in the ID token *and*
offers UserInfo; some minimise the ID token and expect you to call UserInfo. Discovery tells
you what is available ([G05](G05-discovery-and-well-known.md)).

---

## The UserInfo trap: verify `sub`

The critical, easily-missed rule:

> **The `sub` returned by UserInfo MUST match the `sub` in the ID token. If it does not,
> reject the response.**

Why: the access token you sent to UserInfo and the ID token you validated are separate
artifacts. Without checking that they describe the *same subject*, an attacker who can
influence which access token you use could get you to fetch claims for a *different* user and
attach them to this login — a token-substitution attack
([F08](../track-f/F08-audience-and-resource-indicators.md)).

```python
def get_userinfo(access_token, id_token_sub):
    resp = requests.get(USERINFO_ENDPOINT,
                        headers={"Authorization": f"Bearer {access_token}"}).json()
    if resp["sub"] != id_token_sub:                 # ← the check everyone forgets
        raise SecurityError("userinfo sub mismatch")
    return resp
```

This is the UserInfo equivalent of validating `aud` on a token: "is this data actually about
the user I think logged in?"

---

## Claims are only as trustworthy as their issuer

A claim is an *assertion* by the IdP ([C03](../track-c/C03-the-vocabulary.md)), and the trust
you place in it should match how the IdP obtained it.

- **`sub`** — always trust it *as an identifier within that issuer*. It is the IdP's own
  primary key for the user, and it is stable ([G12](G12-account-linking.md)).
- **`email_verified`** — trust `email` for *linking* only when this is `true`. `false` or
  absent means the IdP has not confirmed the email, and linking on it is account takeover
  ([D02](../track-d/D02-email-as-identity.md), [G12](G12-account-linking.md)).
- **`name`, `picture`, `locale`** — user-supplied, unverified. Fine to *display*; never to
  make a security decision on.
- **Custom claims** (`roles`, `groups`, `department`) — trust them only as far as you trust
  the IdP to set them correctly, and only after signature validation
  ([G04](G04-validate-an-id-token-by-hand.md)). Do **not** treat an IdP's `roles` claim as
  *your* authorization model — map it into your own ([H05](../track-h/H05-roles-permissions-scopes-groups.md)).

The through-line: **verify the token, then decide how much to trust each claim based on how
the IdP got it.** Signature validation makes the claims *authentic* (they really came from the
IdP); it does not make them *true* (the IdP might be asserting an unverified email).

---

## Requesting specific claims

Beyond scopes, OIDC lets you request individual claims with the `claims` parameter, and target
where they land:

```json
{
  "id_token":  { "email": {"essential": true} },
  "userinfo":  { "picture": null }
}
```

Rarely needed — scopes cover most cases — but useful when you need one specific claim in the
ID token (so you have it without a UserInfo call) and can leave the rest to UserInfo. Support
varies by provider; check discovery's `claims_parameter_supported`.

---

## Terms defined in this chapter

`UserInfo endpoint`, `standard claims`

---

## What to remember

1. **A scope requests a bundle of claims; the claims are the data.** `openid` alone gives you
   only `sub` — that is why your email was "missing."
2. Standard scopes: **`openid` → `sub`**, **`email` → email**, **`profile` → name/picture/…**.
   Request only what you need.
3. Claims arrive **in the ID token** (no extra call, bigger token) or **from UserInfo** (a
   round trip, smaller token). Providers differ; discovery tells you.
4. **UserInfo is called with the *access* token** — and you **MUST verify its `sub` matches
   the ID token's `sub`.** The most-missed UserInfo check.
5. **A claim is only as trustworthy as its issuer.** Trust `sub` as an identifier; trust
   `email` for linking only when `email_verified`; treat `name`/`picture` as display-only.
6. **Do not adopt the IdP's `roles` as your authorization model** — map it into your own.

---

## Sources

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) §5.1 (standard claims), §5.3 (UserInfo), §5.5 (requesting claims)
- [OpenID Connect Core §5.3.2](https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse) — the `sub` match requirement
- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed.

---

**Next:** [G07 — SAML survival guide](G07-saml-survival-guide.md)
