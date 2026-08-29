# K05 — What should you use? The decision tree

**Part K · Capstone** · *Builds on [K03](K03-capstone-part-2.md)*
> The page that gets more traffic than the rest of the book combined. Six questions about your
> architecture, and out comes your stack — the session type, the token format, the grant type, the
> authorization model, plus the RFCs you need and the ones you can ignore. Build this as an
> interactive tool on the site too.

---

## How to use this

Answer the six questions for *your* system. Each answer points at a concrete choice and the chapter
that argues it. This is deliberately opinionated — [E09](../track-e/E09-should-you-use-jwts-for-sessions.md)
established that fence-sitting is worse than a clear recommendation you can override with reason.

---

## Question 1 — Who is logging in?

```
   Humans (your product's users)?          → you need Layers 1–2 (D, E). Continue.
   Machines / services only?               → Track J. Client credentials (F10),
                                             API keys done right (J02), or workload
                                             identity (J05). SKIP the rest.
   AI agents acting for users?             → J07/J08. Delegated, task-scoped. Continue,
                                             AND add agent auth.
```

---

## Question 2 — Do you store passwords, or federate?

```
   Store passwords yourself?
     → Argon2id (m≥19MiB, t=2, p=1), breach blocklist, allow paste.  D03/D04
     → Offer passkeys (best) and TOTP (SMS only as fallback).        D12/D14
   Federate ("Sign in with Google" / enterprise SSO)?
     → OIDC. Validate the ID token — all 10 checks.                  G02/G04
     → Own a local user keyed on (iss, sub); issue YOUR session.     G12/C05
   Enterprise B2B customers?
     → SSO (OIDC + SAML) + SCIM, multi-tenant. Consider BUYING it.   G08/G09/I02/C05
   → Most products: all of the above. Passwords+passkeys for small
     customers, SSO for enterprise, your own session always.
```

---

## Question 3 — What is your session?

The most consequential choice, and the most opinionated ([E09](../track-e/E09-should-you-use-jwts-for-sessions.md)):

```
   First-party web app / SPA / mobile calling YOUR API?
     → OPAQUE server-side session, __Host- HttpOnly cookie.         E03/E09/E12
     → SPA on a different origin? Use a BFF.                        F17
     → This is the RIGHT DEFAULT. Do not reach for JWTs here.

   Does something OUTSIDE your app need to verify the credential
   without asking you?  (microservices, other orgs, edge)
     → JWT (ES256), short-lived (5–15 min) + opaque revocable
       refresh token. Validate aud/iss/exp.                        E06/E08/F08
     → Otherwise: still opaque.
```

> **If you're unsure, the answer is opaque server-side sessions.** Most applications are one party
> ([E09](../track-e/E09-should-you-use-jwts-for-sessions.md)).

---

## Question 4 — Do you call other APIs, or expose one?

```
   Your app calls a third-party API on a user's behalf?
     → OAuth 2.1 client: authorization code + PKCE, back-channel exchange.  F03/F06
     → Store the third-party tokens server-side, encrypted.                 E10/I05
   You expose an API to third-party apps?
     → OAuth 2.1 authorization server (BUY/host one — Keycloak, Ory, hosted). F14/C05
     → Exact redirect_uri, mandatory PKCE, aud-scoped tokens.               F08/F20
   Machine-to-machine only?
     → Client credentials (F10), or workload identity (J05). No user, no redirect.
   AI agents / tools?
     → MCP over OAuth 2.1: discovery, resource-scoped tokens, no passthrough. J08
```

---

## Question 5 — What is your authorization model?

The layer you can't buy ([C01](../track-c/C01-auth-is-five-different-problems.md),
[C05](../track-c/C05-build-vs-buy.md)) — match the model to the *kind* of rule
([H11](../track-h/H11-opa-cedar-or-sql.md)):

```
   "Admins/editors/viewers" — global functional roles?
     → RBAC. Code + a roles table.                                  H04
   "Share THIS thing with THIS person" / folders inherit?
     → ReBAC (OpenFGA/SpiceDB). RBAC BREAKS here.                   H04/H07/H08
   "Anyone in Legal reads confidential during business hours"?
     → ABAC / policy engine (OPA/Cedar).                            H06/H11
   Multi-tenant?
     → RLS in the database for isolation, on TOP of the above.      H09/H10
   → Most real apps: RBAC for admin + ReBAC for sharing + RLS for
     tenants. Enforce at the SERVICE LAYER, fail closed.            H02
```

> **If your product has "share," "invite to," or "grant access to a specific thing" — you need
> ReBAC, not RBAC.** That's [H04](../track-h/H04-rbac-and-when-it-breaks.md)'s breaking point.

---

## Question 6 — What's your operational posture?

```
   Enterprise customers / compliance (SOC 2, GDPR)?
     → SCIM provisioning + deprovisioning, audit logs, key rotation. I02/I03/H13/I06
     → Data minimisation in tokens (identity, not PII).             I11/E08
   High-value / regulated?
     → Sender-constrained tokens (mTLS/DPoP), step-up auth.         F16/D18
   Any production system?
     → KMS for keys, secrets manager (no secrets in git),           I05/A10
       rotation with overlap, tamper-evident audit, an incident
       runbook, and the failure-mode checks as a regression suite.  I06/I10/I07
```

---

## The output: a worked example

For a typical **B2B SaaS document/collaboration product** (like the capstone), the tree produces:

```
   Login:          Email+passkeys+TOTP (small customers) + OIDC/SAML SSO (enterprise)  D/G
   Passwords:      Argon2id + breach blocklist                                        D03/D04
   Session:        Opaque, server-side, __Host- HttpOnly cookie                       E03/E09
   SPA:            BFF (tokens off the browser)                                       F17
   3rd-party API:  OAuth 2.1 client (PKCE); AS if exposing an API                     F06/F14
   Enterprise:     OIDC+SAML+SCIM, multi-tenant — likely BOUGHT                       G09/C05
   Authorization:  ReBAC (sharing) + RBAC (admin) + RLS (tenants), service-layer      H04/H07/H10
   Machine/agent:  API keys (hashed/prefixed), mTLS internal, MCP for agents          J02/J04/J08
   Ops:            SCIM lifecycle, KMS, rotation, tamper-evident audit, IR runbook    I
```

That's the capstone ([K01](K01-architecture-review.md)–[K03](K03-capstone-part-2.md)) — the tree
reconstructs it. Different products get different answers: a static marketing site with a contact
form needs almost none of this; a consumer app with no sharing skips ReBAC; a pure API skips
sessions.

---

## The RFCs you need — and the ones you can ignore

The tree also tells you which specs matter *for your answers* ([K06](K06-where-to-go-next.md)):

**You almost certainly need:**
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) — OAuth Security BCP (if any OAuth)
- [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) — PKCE
- [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725) — JWT BCP (if any JWTs)
- [NIST SP 800-63B](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) — passwords/MFA
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) — if you federate

**You need if your answers hit them:**
- [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) (resource indicators — multi-API), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) (JWT access tokens)
- [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) (SCIM — enterprise), [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) (device flow — TVs/CLIs)
- [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) (DPoP), [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) (mTLS) — sender-constrained
- [MCP Authorization](https://modelcontextprotocol.io/specification/draft/basic/authorization) — agents

**You can probably ignore:**
- Implicit/password grants (dead — [F15](../track-f/F15-implicit-and-password-grants.md))
- SAML if you have no enterprise customers ([G07](../track-g/G07-saml-survival-guide.md))
- DIDs/verifiable credentials, post-quantum ([appendix/excluded.md](../../appendix/excluded.md))

---

## Build this as a tool

This page should exist as an **interactive tool** on the site as well as prose — six questions, a
generated stack, and the RFC list. It will get more traffic than everything else combined, because
"what should I actually use?" is the question everyone arrives with. The full interactive version is
in [appendix/decision-tree.md](../../appendix/decision-tree.md).

---

## What to remember

1. **Six questions → your stack:** who logs in, passwords-or-federate, session type, call/expose
   APIs, authorization model, operational posture.
2. **Session: if unsure, opaque server-side.** Most apps are one party
   ([E09](../track-e/E09-should-you-use-jwts-for-sessions.md)).
3. **Authorization: "share/invite/grant-specific-thing" → ReBAC, not RBAC**
   ([H04](../track-h/H04-rbac-and-when-it-breaks.md)). Most apps: RBAC + ReBAC + RLS.
4. **Enterprise → buy the SSO/SCIM layer; build the authorization layer** ([C05](../track-c/C05-build-vs-buy.md)).
5. **The tree tells you which RFCs matter** for *your* answers — and which you can ignore.
6. **Different products get different answers** — a marketing site needs almost none of this.
7. **Build it as an interactive tool** — it's the question everyone arrives with.

---

## Sources

- Every track's decision chapters, especially [C05](../track-c/C05-build-vs-buy.md), [E09](../track-e/E09-should-you-use-jwts-for-sessions.md), [H11](../track-h/H11-opa-cedar-or-sql.md), [G08](../track-g/G08-saml-vs-oidc.md)
- [appendix/decision-tree.md](../../appendix/decision-tree.md) — the interactive version
- [appendix/rfc-index.md](../../appendix/rfc-index.md) — every spec, what it's for

---

**Next:** [K06 — Where to go next: specs, papers, and staying current](K06-where-to-go-next.md)
