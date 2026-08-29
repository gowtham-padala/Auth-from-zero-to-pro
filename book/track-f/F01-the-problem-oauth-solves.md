# F01 — The problem OAuth was invented to solve

**Part F · Delegated authorization — OAuth 2** · *Builds on [A08](../track-a/A08-what-an-api-is.md)*
---

## The five failures, and their fixes

Every part of OAuth exists to fix one row of this table. Read it once now; it will make the
whole track read as a solution rather than a ritual.

| The password anti-pattern fails because... | OAuth's fix | Chapter |
|---|---|---|
| The app gets **all** your permissions | **Scopes** — narrow, requested, consented | [F07](F07-access-refresh-scopes.md) |
| You cannot revoke **one** app | **Per-app tokens** you can revoke individually | [E11](../track-e/E11-revocation.md) |
| The app **stores your password** | The app **never sees it** — you log in at the service | [F03](F03-authorization-code-flow.md) |
| It breaks the instant you enable **2FA** | The **service** handles login, MFA and all | [F02](F02-four-roles-two-channels.md) |
| The service **cannot tell app from user** | **Client identity** + delegation claims | [F19](F19-token-exchange.md) |

That is the whole motivation. Five problems, five mechanisms.

---

## What OAuth is — and is not

> **OAuth 2.0 is a delegated *authorization* framework. It lets application A do specific,
> bounded things to service B's resources on a user's behalf, without becoming the user.**

Read the emphasis. OAuth is about **authorization** (may this app do this?), not
**authentication** (who is this person?). That distinction is not pedantry — it is the
single most consequential misunderstanding in the entire field.

### The mistake everyone makes

"I'll add OAuth so users can log in."

Plain OAuth 2.0 does **not** tell you who logged in. It gives your application a token to
call an API. That token says *what the app may do*; it says nothing verifiable about *who
the user is*.

Build "login with OAuth" on raw OAuth 2.0 and you get a system that appears to work and has
no defined, secure way to answer "who is this?" — which is exactly how the classic
OAuth-login vulnerabilities happen (accepting a token issued for a *different* application,
for instance).

**The layer that adds identity is OpenID Connect**, and it is
[Track G](../track-g/G01-sign-in-with-google.md). OAuth for *authorization*, OIDC for
*authentication*. Keep them separate in your head and most of the confusion in this space
evaporates ([C01](../track-c/C01-auth-is-five-different-problems.md)).

---

## When you actually need OAuth

Here is the part most tutorials skip, and it will save you weeks: **you often do not need
OAuth at all.**

| Situation | Do you need OAuth 2? |
|---|---|
| Your own web app, your own users, your own API | **No.** Sessions ([Track E](../track-e/E01-why-http-needs-sessions.md)). |
| Your SPA calling your own API | **No.** Session cookie, or a BFF ([F17](F17-oauth-for-spas-and-bff.md)). |
| Your mobile app calling your own API | **Usually no.** Your own tokens are fine. |
| "Let users log in with Google" | **OIDC**, not raw OAuth ([Track G](../track-g/G01-sign-in-with-google.md)). |
| A **third-party** app calling **your** API for your users | **Yes.** This is the case OAuth is for. |
| **Your** app calling a **third-party** API (Google, Slack, GitHub) | **Yes**, as a client. |
| Machine-to-machine, no user | **Yes** — client credentials ([F10](F10-client-credentials.md)). |
| An AI agent acting for a user | **Yes** — and this is the frontier ([J07](../track-j/J07-auth-for-ai-agents.md)). |

The pattern: **OAuth is for crossing a boundary between two parties.** If there is only one
party — your app, your users, your API — you are reaching for a delegation protocol to solve
a problem that has no delegation in it. That adds redirect dances, token lifetimes, and a
much larger attack surface, in exchange for nothing.

The people happiest with OAuth are the ones who use it exactly where the boundary is, and
sessions everywhere else.

---

## The shape, before the detail

The correct version of the photo-printing story, so you have the picture before the
mechanics:

```
1. Printing site: "I'd like to read your photos."
2. Album service: sends YOU to its OWN login page (in your browser)
3. You: log in — with 2FA, on the real domain, in the address bar you can check  (A09)
4. Album service: "PrintCo wants to READ YOUR PHOTOS. Allow?"   ← consent
5. You: Allow.
6. Album service: gives PrintCo a token that can ONLY read photos,
                  ONLY yours, and expires in an hour.
7. PrintCo: uses the token. Cannot delete. Cannot change your password.
8. You: revoke it next week from a settings page, breaking nothing else.
```

Every property missing in 2006 is present:

- **The app never sees the password** — step 3 is on the service's domain.
- **The permission is narrow** — step 6 is scoped.
- **You consented, knowingly** — step 4.
- **It expires** — step 6.
- **It is independently revocable** — step 8.

That is OAuth's *shape*. The rest of this track is making each of those eight steps
unforgeable, because the only channel between PrintCo and the album service is your browser,
and the browser cannot be trusted ([F03](F03-authorization-code-flow.md)).

---

## A one-minute history, so stale advice does not confuse you

You will find contradictory tutorials. This is why:

| Year | Event | What it means for you |
|---|---|---|
| 2007 | OAuth 1.0 — request signing, no TLS assumed | Complex; obsolete. Ignore. |
| 2012 | **OAuth 2.0** — [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749). TLS instead of signatures | The foundation, but permissive |
| 2012 | Eran Hammer resigns as editor, calls it "a bad protocol" | Real criticism; largely addressed since |
| 2015 | **PKCE** — [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) | Now mandatory for everyone ([F06](F06-pkce.md)) |
| ~2019 | Implicit and password grants declared harmful | Half the internet's tutorials are now wrong ([F15](F15-implicit-and-password-grants.md)) |
| 2025 | **[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)** — Security BCP, published as a full RFC | The current normative baseline |
| ongoing | **OAuth 2.1** — [draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) | Consolidates the good parts; **still a draft in 2026** |

**OAuth 2.1 is not an RFC yet.** As of 2026 it is a stable draft that gathers OAuth 2.0 plus
PKCE, minus implicit and password grants, into one document. Major providers already
implement its requirements. Treat it as "the good subset of OAuth 2.0," which is what this
track teaches.

The practical upshot: **if a tutorial teaches the implicit grant, or tells you to send a
password to a token endpoint, it is stale.** [F15](F15-implicit-and-password-grants.md)
gives you the vocabulary to recognise that on sight.

---

## Terms defined in this chapter

`OAuth 2.0`, `OAuth 2.1`, `password anti-pattern`

---

## What to remember

1. OAuth exists to kill the **password anti-pattern** — handing app A your password for
   service B.
2. **Five failures, five fixes:** scopes, per-app tokens, never-see-the-password, the
   service handles login, client identity. That table is the whole motivation.
3. **OAuth is authorization, not authentication.** "Log in with Google" needs **OIDC**
   (Track G), not raw OAuth.
4. **You often do not need OAuth.** One party — your app, your users, your API — means
   sessions, not delegation.
5. OAuth is for **crossing a boundary between two parties.**
6. **OAuth 2.1 is still a draft.** It is OAuth 2.0 + PKCE − implicit − password grant. If a
   tutorial teaches implicit, it is stale.

---

## Sources

- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://www.rfc-editor.org/rfc/rfc6749) §1
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700)
- Aaron Parecki, [oauth.com](https://www.oauth.com/) and [OAuth 2 Simplified](https://aaronparecki.com/oauth-2-simplified/)
- [The OAuth 2.1 draft](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1)

---

**Next:** [F02 — Four roles and two channels](F02-four-roles-two-channels.md)
