# F15 — Implicit and password grants: why they're dead

**Part F · Delegated authorization — OAuth 2** · *Builds on [F06](F06-pkce.md)*
---

## Why this chapter exists

Most OAuth tutorials on the internet still teach the implicit grant. A great deal of code
still uses the password grant. Both are **removed from OAuth 2.1** and both are recommended
against by [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700).

You need the vocabulary to recognise stale advice **on sight**, because you will find it,
and it looks authoritative. This chapter is that vocabulary.

> **If a tutorial tells you to put the access token in the URL fragment, or to send a
> username and password to the token endpoint, it is teaching a dead grant. Close the tab.**

---

## The implicit grant — dead

### What it was

The access token returned **directly to the browser** in the URL fragment, skipping the code
exchange:

```
https://app.example/callback#access_token=2YotnFZFEjr1zCsicMWpAA&token_type=Bearer
```

`response_type=token` instead of `response_type=code`. One round trip, no back channel.

### Why it existed

In ~2012, browsers could not make cross-origin requests — no CORS
([A11](../track-a/A11-same-origin-and-cors.md)) — so a SPA could not reach a token endpoint
on a different origin to do the code exchange ([F03](F03-authorization-code-flow.md)).
Implicit was the workaround: get the token straight from the redirect.

### Why it died

CORS shipped, so the reason for it evaporated — and its costs became unignorable:

**The token is on the front channel.** In the URL. Which means
([A01](../track-a/A01-what-happens-when-you-type-a-url.md),
[A04](../track-a/A04-headers.md)):

- **Browser history** — the token is in it.
- **Server access logs** — the fragment is not sent to the server, but the token still lands
  in the page, and any navigation or script can leak it.
- **`Referer` headers** — leaked to third-party scripts on the page.
- **No code exchange** means **no PKCE** — nothing binds the token to the client that started
  the flow ([F06](F06-pkce.md)).
- **Token injection** — an attacker can inject a token obtained elsewhere, because there is no
  code-to-client binding to verify.

This is the exact failure the two-channel design exists to prevent
([F02](F02-four-roles-two-channels.md)), and implicit threw the design away. The token — the
thing you must never expose — was placed on the channel that exposes everything.

### What replaces it

**Authorization code flow + PKCE**, for everyone, public clients included
([F06](F06-pkce.md)). A SPA does the code flow with PKCE, or — better — uses a
backend-for-frontend so it never holds a token at all
([F17](F17-oauth-for-spas-and-bff.md)).

The migration is not optional maintenance; implicit is a live vulnerability.

---

## The password grant (ROPC) — dead

### What it was

**Resource Owner Password Credentials.** The client collects the username and password and
sends them to the token endpoint:

```http
POST /token
grant_type=password&username=alice&password=hunter2&client_id=app
```

### Why it existed

For "trusted first-party apps" during the migration from custom login schemes to OAuth. The
idea: your own mobile app collects the password and trades it for tokens.

### Why it died

**It is the password anti-pattern with OAuth branding.** Everything OAuth exists to prevent
([F01](F01-the-problem-oauth-solves.md)), ROPC reintroduces:

- **The client sees the password.** The single thing the authorization code flow exists to
  avoid. Now every app has the plaintext password.
- **It cannot do MFA.** There is no interactive step, so no place for a second factor, a
  passkey, or a risk challenge. It breaks the instant you enable MFA
  ([D11](../track-d/D11-sms-second-factor.md)) — which is the *whole point* of modern login.
- **It cannot do federated login.** No redirect to an IdP, so "Sign in with Google" is
  impossible ([G01](../track-g/G01-sign-in-with-google.md)).
- **It normalises password-into-app.** It trains users that typing their password into a
  third-party UI is fine — the exact habit that makes phishing work
  ([A09](../track-a/A09-redirects.md)).
- **It breaks the trust boundary.** Every app that touches the password is now in scope for
  every credential-theft threat.

### What replaces it

**The authorization code flow.** Even for your own first-party mobile app: open a browser
(or an in-app browser tab that shows the URL — [F18](F18-oauth-for-mobile.md)), authenticate
on the AS, come back with a code. The password never enters your app.

For genuinely non-interactive cases (a backend calling an API for itself), use **client
credentials** ([F10](F10-client-credentials.md)) — but that is a *machine* identity, not a
user's password.

---

## The full grant scorecard, 2026

| Grant | Status | Use for |
|---|---|---|
| **Authorization code + PKCE** | ✅ **The default** | Everything with a user |
| **Client credentials** | ✅ Alive | Machine-to-machine ([F10](F10-client-credentials.md)) |
| **Device authorization** | ✅ Alive | Input-constrained devices ([F11](F11-device-flow.md)) |
| **Refresh token** | ✅ Alive | Renewing access ([E10](../track-e/E10-token-lifetimes-and-rotation.md)) |
| **Token exchange** (RFC 8693) | ✅ Alive | Delegation, impersonation ([F19](F19-token-exchange.md)) |
| **Implicit** | ❌ **Dead** | Nothing. Use code + PKCE. |
| **Password (ROPC)** | ❌ **Dead** | Nothing. Use code flow. |
| **Hybrid** (`code id_token`) | ⚠️ Niche | Specific OIDC cases ([G03](../track-g/G03-id-token-vs-access-token.md)) |

Memorise the top block and the two ❌ rows. That is enough to sort any tutorial into
"current" or "stale" in five seconds.

---

## How to recognise stale OAuth advice

A field guide, because you *will* encounter this:

| Red flag | What it means |
|---|---|
| `response_type=token` | Implicit grant. Dead. |
| Access token in the URL `#fragment` | Implicit grant. Dead. |
| "no PKCE needed for confidential clients" | Pre-2020 advice ([F06](F06-pkce.md)) |
| `grant_type=password` with a real user's password | ROPC. Dead. |
| "store the client secret in your SPA" | Public/confidential confusion ([F09](F09-public-vs-confidential-clients.md)) |
| No `state` parameter | Pre-CSRF-awareness ([F05](F05-the-state-parameter.md)) |
| "OAuth for login" with no mention of OIDC | Conflates authz and authn ([G02](../track-g/G02-oidc-on-top-of-oauth.md)) |
| No `aud` validation on the resource server | Confused-deputy-prone ([F08](F08-audience-and-resource-indicators.md)) |

The through-line: **OAuth got more restrictive over time.** The grants were narrowed, PKCE
was universalised, and the token was kept off the front channel. Advice that predates those
changes is not merely old — it teaches designs that are now known-vulnerable.

---

## Terms defined in this chapter

`implicit grant`, `ROPC`, `fragment` (revisited from A01)

---

## What to remember

1. **Implicit and ROPC are removed from OAuth 2.1** and recommended against by RFC 9700.
2. **Implicit put the token in the URL fragment** — front channel, no PKCE, injectable. Dead.
3. **ROPC is the password anti-pattern rebranded** — the app sees the password, no MFA, no
   federation. Dead.
4. Both are replaced by **authorization code + PKCE**, public clients included.
5. **Recognise stale advice on sight:** `response_type=token`, token in the fragment,
   `grant_type=password`, secrets in a SPA, no `state`.
6. OAuth trended *more* restrictive. Old tutorials teach vulnerable designs.

---

## Sources

- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §2.1.2 (implicit), §2.4 (ROPC)
- [The OAuth 2.1 draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — §2.1.2 removes both
- Aaron Parecki, [Is the OAuth 2.0 Implicit Flow Dead?](https://developer.okta.com/blog/2019/05/01/is-the-oauth-implicit-flow-dead)

---

**Next:** [F16 — Sender-constrained tokens: mTLS and DPoP](F16-sender-constrained-tokens.md)
