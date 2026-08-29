# G02 — OIDC on top of OAuth: what the openid scope changes

**Part G · Federated identity & SSO** · *Builds on [G01](G01-sign-in-with-google.md), [F07](../track-f/F07-access-refresh-scopes.md)*
---

## The distinction, once

> **OAuth 2.0 is authorization: "may this app do X?"**
> **OpenID Connect is authentication: "who is this user, and did they just log in to my
> app?"**

OIDC is a thin, standardised **identity layer on top of OAuth 2.0**. It does not replace
OAuth; it adds three things OAuth lacks:

1. **An ID token** — a signed JWT about the *authentication event*, for the *client*
   ([G03](G03-id-token-vs-access-token.md)).
2. **A standard `/userinfo` endpoint** and a set of **standard claims**
   ([G06](G06-claims-vs-scopes-userinfo.md)).
3. **Discovery and standard behaviour** — every OIDC provider works the same way
   ([G05](G05-discovery-and-well-known.md)), so one client library talks to all of them.

That standardisation is the underrated part. Plain OAuth providers each expose identity
differently — Google's userinfo, GitHub's `/user`, Facebook's Graph API, all different shapes
([G01](G01-sign-in-with-google.md)). OIDC makes "log in with anyone" a single code path.

---

## What `openid` changes

Add one scope to the authorization request ([F03](../track-f/F03-authorization-code-flow.md)):

```
   OAuth:   scope=email profile          →  access token. No identity guarantee.
   OIDC:    scope=OPENID email profile    →  access token + ID TOKEN.
```

The presence of `openid` is the switch. It tells the authorization server: *this is a login,
issue an ID token.* Everything else about the flow is identical — same code exchange, same
`state`, same PKCE ([F06](../track-f/F06-pkce.md)). You are running OAuth's authorization
code flow and receiving one extra artifact.

```
   POST /token response WITHOUT openid:        WITH openid:
   {                                           {
     "access_token": "...",                      "access_token": "...",
     "token_type": "Bearer",                     "token_type": "Bearer",
     "expires_in": 3600,                         "expires_in": 3600,
     "refresh_token": "..."                      "refresh_token": "...",
   }                                             "id_token": "eyJ..."   ← the identity
                                               }
```

The `id_token` is the whole difference, and it is what you validate to know who logged in
([G04](G04-validate-an-id-token-by-hand.md)).

---

## The parameters OIDC adds to the request

Beyond `state` and PKCE, an OIDC login typically sends:

```
GET /authorize?
    response_type=code
    &scope=openid email profile
    &client_id=...
    &redirect_uri=...
    &state=...                    ← CSRF (OAuth)                F05
    &nonce=n-0S6_WzA2Mj           ← replay protection (OIDC)    G04
    &code_challenge=...           ← PKCE (OAuth)                F06
    &prompt=...                   ← control the login UX        below
    &max_age=300                  ← require recent auth         D18
    &acr_values=...               ← require an assurance level  D18
```

Three OIDC-specific ones:

**`nonce`** — a value you generate and store, which the IdP embeds *inside the ID token*. You
verify it matches on return. It binds the token to *this* authentication request, preventing
a token from being replayed into a different login. It is to the *ID token* what `state` is to
the *callback* ([F05](../track-f/F05-the-state-parameter.md)) — different jobs, both needed
([G04](G04-validate-an-id-token-by-hand.md)).

**`prompt`** — controls the login UX:

| Value | Effect |
|---|---|
| `none` | No UI; fail if the user is not already authenticated. For silent SSO checks. |
| `login` | Force re-authentication even if a session exists. Step-up ([D18](../track-d/D18-step-up-auth-and-aal.md)). |
| `consent` | Force the consent screen again. |
| `select_account` | Let the user pick which account. |

**`max_age`** / **`acr_values`** — require the authentication to be recent, or to meet an
assurance level. The IdP returns `auth_time` and `acr` in the ID token, and **you must verify
them** — a provider may ignore a request it cannot satisfy ([D18](../track-d/D18-step-up-auth-and-aal.md),
[G04](G04-validate-an-id-token-by-hand.md)).

---

## The assurance levels, briefly

NIST's three-dimensional model ([D18](../track-d/D18-step-up-auth-and-aal.md)) — federation
adds the third:

| Level | Governs | Spec |
|---|---|---|
| **IAL** | Identity proofing — how well was the real-world identity verified? | SP 800-63A |
| **AAL** | Authentication — how strongly did they authenticate? | SP 800-63B |
| **FAL** | **Federation** — how strongly is the assertion protected and bound? | **SP 800-63C** |

**FAL** is the OIDC-specific one. It rises with protections like signed *and encrypted*
assertions, holder-of-key binding (the assertion is bound to a key the RP must prove it
holds), and stronger issuer authentication. Most consumer OIDC is FAL1 (a signed bearer
assertion — the ID token). Higher-assurance federation (government, high-value enterprise)
requires FAL2+.

You will rarely tune FAL directly, but knowing it exists explains why some enterprise
integrations demand encrypted assertions and key binding rather than a plain signed ID token.

---

## The layered picture

```
   ┌─────────────────────────────────────────────────────────┐
   │  OpenID Connect (OIDC)          ← IDENTITY               │
   │   • ID token (who + when + how)                          │
   │   • /userinfo, standard claims                           │
   │   • discovery, nonce, prompt, acr                        │
   ├─────────────────────────────────────────────────────────┤
   │  OAuth 2.0                      ← AUTHORIZATION           │
   │   • authorization code flow                              │
   │   • access tokens, scopes, refresh                       │
   │   • the two channels, PKCE, state                        │
   ├─────────────────────────────────────────────────────────┤
   │  HTTP + TLS + JOSE              ← the substrate           │
   │   Tracks A, B, E                                          │
   └─────────────────────────────────────────────────────────┘
```

You do not choose "OAuth or OIDC." You use OAuth's machinery, and OIDC is the identity
semantics layered on top. When you need *authorization* (call an API on the user's behalf),
you are using the OAuth layer. When you need *authentication* (who logged in), you are using
the OIDC layer. A single "Sign in with Google" flow uses both at once.

---

## When to use which

| You want to... | Use |
|---|---|
| Let the user log in ("who are you?") | **OIDC** — the ID token is the answer |
| Call an API on the user's behalf | **OAuth** — the access token |
| Both (log in *and* read their calendar) | Both — one flow, `scope=openid calendar:read` |
| Machine-to-machine, no user | **OAuth** client credentials ([F10](../track-f/F10-client-credentials.md)) — no OIDC |

The reflex to build: **if there is a human logging in, you want OIDC.** Raw OAuth for login
is the exploitable shortcut ([G01](G01-sign-in-with-google.md)).

---

## Terms defined in this chapter

`OIDC`, `openid scope`

---

## What to remember

1. **OAuth is authorization; OIDC is authentication.** OIDC is a thin identity layer *on top
   of* OAuth, not a replacement.
2. **The `openid` scope is the switch** — it adds an **ID token** to an otherwise-identical
   code flow.
3. OIDC also standardises **`/userinfo`, claims, and discovery**, so one client library talks
   to every provider.
4. OIDC adds **`nonce`** (binds the ID token to this request), **`prompt`**, **`max_age`**,
   and **`acr_values`** — and you must *verify* what comes back.
5. Federation has its own assurance level — **FAL** (SP 800-63C) — governing how the assertion
   is protected and bound.
6. You do not pick one: a login flow uses the OAuth machinery *and* the OIDC identity layer.
7. **A human logging in → OIDC.** Raw OAuth for login is the exploitable shortcut.

---

## Sources

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) §2 (ID token), §3.1.2 (authentication request)
- [NIST SP 800-63C-4 — Federation and Assertions](https://csrc.nist.gov/pubs/sp/800/63/c/4/final)
- [oauth.net — OpenID Connect](https://oauth.net/openid-connect/)
- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed., Ch. 5

---

**Next:** [G03 — ID token vs access token: stop sending the wrong one](G03-id-token-vs-access-token.md)
