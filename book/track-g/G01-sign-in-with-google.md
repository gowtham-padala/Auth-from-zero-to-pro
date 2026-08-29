# G01 — What actually happens when you click "Sign in with Google"

**Part G · Federated identity & SSO** · *Builds on [F03](../track-f/F03-authorization-code-flow.md)*
---

## The three parties

"Sign in with Google" is **federated identity** ([C01](../track-c/C01-auth-is-five-different-problems.md)):
you outsource authentication to a system the user already has an account with.

```
   YOU (the user)              YOUR APP                        GOOGLE
   the person                  the Relying Party (RP)          the Identity Provider (IdP)
                               wants to know who you are        already knows who you are
```

- **Identity provider (IdP)** — Google. Authenticates the user and *vouches* for them.
- **Relying party (RP)** — your app. *Relies* on the IdP's word instead of storing passwords.
  (In OAuth terms it is the client; in SAML terms it is the service provider — same role,
  three names.)

The bargain: **you stop being a password custodian; you start being a trust delegator.** You
no longer store or verify passwords ([D03](../track-d/D03-how-to-store-passwords.md)); you
verify that *Google says* this is the user. What you gain — no passwords, Google's MFA and
risk engine, enterprise-readiness — you pay for in a hard dependency and the job of
validating Google's statement *correctly* ([G04](G04-validate-an-id-token-by-hand.md)).

---

## What the click does

It is the authorization code flow from [F03](../track-f/F03-authorization-code-flow.md), with
one magic word added — `openid` — that turns it into an OIDC flow and produces an **ID
token** ([G02](G02-oidc-on-top-of-oauth.md)).

```
 USER          BROWSER              YOUR APP (RP)              GOOGLE (IdP)
  │              │                     │                          │
  │ clicks ─────>│                     │                          │
  │ "Sign in     │─── GET /auth/google ──>│                       │
  │  with Google"│                     │ build authz URL:         │
  │              │                     │  scope=OPENID email profile  ← the magic word
  │              │                     │  state, nonce, PKCE       │
  │              │<── 302 to accounts.google.com/o/oauth2/... ────│
  │              │─────────── GET /o/oauth2/auth?... ────────────>│
  │              │                     │                    ① authenticates YOU
  │ already ─────│─────────────────────────────────────────────> │   (password? passkey?
  │ logged in?   │                     │                    already-live session?)
  │  → instant   │                     │                    ② consent (first time only)
  │              │<──── 302 to your redirect_uri?code=X&state ────│
  │              │─── GET /callback?code=X&state ──>│             │
  │              │                     │ ③ check state             │
  │              │                     │═══ BACK CHANNEL ══════════│
  │              │                     │ ④ POST /token (code, PKCE)>│
  │              │                     │<── ID TOKEN + access token │
  │              │                     │ ⑤ VALIDATE THE ID TOKEN    │  ← the whole game
  │              │                     │    (sig, iss, aud, nonce, exp)  G04
  │              │                     │ ⑥ find-or-create user      │  G12
  │              │                     │ ⑦ create YOUR session      │  E03
  │  logged in ◄─│◄────────────────────│                            │
```

The steps that are *new* versus plain OAuth:

- **`scope=openid`** — asks for an ID token. Without it, you get plain OAuth and no identity
  ([G02](G02-oidc-on-top-of-oauth.md)).
- **`nonce`** — a value you generate, that Google echoes *inside the ID token*, binding the
  token to *this* login request ([G04](G04-validate-an-id-token-by-hand.md)).
- **The ID token itself** — a signed JWT ([E05](../track-e/E05-jwt-part-1-three-parts.md))
  about the *authentication event*, for *your app* ([G03](G03-id-token-vs-access-token.md)).
- **Step ⑤, validation** — the entire security of the login. Skipping it is the
  classic "Sign in with Google" vulnerability.

Everything else is the code flow you already know
([F03](../track-f/F03-authorization-code-flow.md)): front channel for the redirect and code,
back channel for the exchange, `state` and PKCE throughout.

---

## Why "instant" login feels like magic

If you are already logged in to Google, the click seems to skip straight to consent — or past
it. That is because step ① reuses **Google's own session** with your browser
([E01](../track-e/E01-why-http-needs-sessions.md)). You authenticated to Google earlier;
Google remembers; your app benefits.

This is the "single" in single sign-on ([G11](G11-federated-sessions-single-logout.md)): one
authentication to the IdP, reused across many RPs. It is a real convenience and a real
concentration of risk — compromise the Google account and every RP that trusts it is exposed.

---

## The step everyone gets wrong: after the ID token

Two mistakes, both about what to do *after* you have a
verified identity.

### Mistake 1: skipping validation

An ID token you have not fully validated is worthless. The nine-check list
([E06](../track-f/../track-e/E06-jwt-part-2-signature-jws-jwe.md)) plus OIDC's `nonce` is
[G04](G04-validate-an-id-token-by-hand.md), and the two checks that stop it
are:

- **`aud`** — was this token issued for *my* client? A token for a different app must be
  rejected ([F08](../track-f/F08-audience-and-resource-indicators.md)).
- **`iss`** — did it really come from Google?

### Mistake 2: trusting an unverified email to link accounts

Google's ID token may contain `email` and `email_verified`. If you find an existing local
account with that email and log the user into it:

- **You must check `email_verified: true`.** An IdP that has not verified the email is telling
  you not to trust it. Linking on an unverified email is a documented account-takeover path
  ([D02](../track-d/D02-email-as-identity.md)).
- **You should key on `(iss, sub)`, not email** — emails change and get reassigned; `sub` is
  the stable identifier within the issuer ([C03](../track-c/C03-the-vocabulary.md)). This is
  the whole of [G12](G12-account-linking.md).

### The right ending

```
④ get + VALIDATE the ID token          ← G04 — sig, iss, aud, nonce, exp
⑤ identity = (iss, sub) from the token ← C03 — stable, unique-per-issuer
⑥ find-or-create YOUR user, checking email_verified before any linking  ← G12
⑦ create YOUR OWN session              ← E03 — do NOT use Google's tokens as your session
```

Step ⑦ is the same lesson as [F04](../track-f/F04-build-oauth-client-raw-http.md): OAuth/OIDC
ends, *your* session begins. The ID token proved who logged in, once; your session
([E03](../track-e/E03-build-server-side-sessions.md)) carries it thereafter. Do not use
Google's access or ID token as your web session
([E09](../track-e/E09-should-you-use-jwts-for-sessions.md)).

---

## The consumer IdPs, briefly

| IdP | Notes |
|---|---|
| **Google** | The reference OIDC implementation. `email_verified` reliable. |
| **Microsoft (Entra)** | OIDC; also the enterprise path ([G09](G09-multi-tenant-sso.md)). |
| **Apple** | OIDC, privacy-focused. Offers **private relay emails** — a random forwarding address, so `email` is not the user's real one. Handle accordingly. |
| **GitHub** | OAuth, **not** full OIDC — no ID token. You call the API for identity, so validate carefully. |
| **Facebook** | OAuth-based; its own quirks. |

Two traps worth flagging: **GitHub is not OIDC** (no ID token, so you must be extra careful
reading identity from an API), and **Apple gives relay emails** that are not the user's real
address and can be disabled by the user later, breaking email-keyed accounts. Both reinforce
keying on `(iss, sub)`.

---

## Terms defined in this chapter

`SSO`, `social login`, `identity provider` (IdP — from C05), `relying party` (from D14,
applied here)

---

## What to remember

1. "Sign in with Google" is **federated identity** — you outsource authentication to an IdP
   and become a trust delegator instead of a password custodian.
2. It is the **authorization code flow plus `openid`**, which produces an **ID token** — a
   signed statement about *who logged in, for your app*.
3. **The ID token, fully validated, is the login.** Reading an email from an access token is
   the exploitable mistake.
4. **Validate `iss`, `aud`, `nonce`, `exp`, and the signature** — [G04](G04-validate-an-id-token-by-hand.md).
5. **Key on `(iss, sub)`, and check `email_verified` before linking.** Linking on an
   unverified email is account takeover.
6. **OIDC/OAuth ends; your own session begins.** Never use the IdP's tokens as your web
   session.
7. GitHub is not OIDC; Apple hands out relay emails. Both argue for `(iss, sub)`.

---

## Sources

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html) §3.1 (authorization code flow)
- [Google Identity: OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect)
- [OWASP: OAuth/OIDC login vulnerabilities](https://cheatsheetseries.owasp.org/cheatsheets/OAuth2_Cheat_Sheet.html)
- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed.

---

**Next:** [G02 — OIDC on top of OAuth: what the openid scope changes](G02-oidc-on-top-of-oauth.md)
