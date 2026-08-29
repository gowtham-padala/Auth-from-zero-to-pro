# The decision tree — six questions, one stack

The interactive companion to [K05](../book/track-k/K05-the-decision-tree.md). Answer the six
questions for your system and follow the arrows; the leaf tells you the stack and the chapters that
argue each choice. On the website this should be a **clickable tool** — six questions, a generated
stack, and the RFC list ([rfc-index.md](rfc-index.md)). Here it is as a followable flowchart.

> **This page will get more traffic than the rest of the book combined**, because "what should I
> actually use?" is the question everyone arrives with.

---

## Q1 — Who is logging in?

```
   ┌─ Humans (your product's users) ──────────────▶ continue to Q2
   ├─ Machines / services only ───────────────────▶ TRACK J:
   │                                                 client credentials (F10),
   │                                                 API keys done right (J02),
   │                                                 or workload identity (J05).
   │                                                 Skip Q2–Q4.  → Q5, Q6
   └─ AI agents acting for users ─────────────────▶ continue to Q2,
                                                     AND add J07/J08 (delegated,
                                                     task-scoped, MCP).
```

## Q2 — Passwords or federation?

```
   ┌─ Store passwords yourself ───────────────────▶ Argon2id (m≥19MiB) + breach
   │                                                 blocklist + allow paste. D03/D04
   │                                                 Offer passkeys (best) + TOTP. D12/D14
   ├─ "Sign in with Google" (consumer) ───────────▶ OIDC. Validate the ID token
   │                                                 (10 checks). Own a local user
   │                                                 keyed on (iss,sub). G02/G04/G12
   └─ Enterprise B2B customers ───────────────────▶ OIDC + SAML + SCIM, multi-tenant.
                                                     Strongly consider BUYING it. G08/G09/I02/C05
   → Most products: all three. Passwords+passkeys (small),
     SSO (enterprise), your OWN session always.
```

## Q3 — What is your session? (the big one)

```
   Does something OUTSIDE your app need to verify the credential
   without asking you?  (microservices / other orgs / edge functions)
   │
   ├─ NO (first-party web/SPA/mobile → YOUR API) ─▶ ★ OPAQUE server-side session,
   │                                                 __Host- HttpOnly cookie.  E03/E09/E12
   │                                                 SPA on a different origin? → BFF.  F17
   │                                                 ← THE RIGHT DEFAULT. Not JWTs.
   │
   └─ YES (microservices / cross-org) ────────────▶ JWT (ES256), short-lived (5–15 min)
                                                     + opaque revocable refresh token.
                                                     Validate aud/iss/exp.  E06/E08/F08

   → If unsure: OPAQUE. Most apps are one party.  E09
```

## Q4 — Do you call other APIs, or expose one?

```
   ┌─ Call a 3rd-party API for a user ────────────▶ OAuth 2.1 client: code + PKCE,
   │                                                 back-channel exchange, tokens
   │                                                 stored server-side encrypted.  F03/F06/E10
   ├─ Expose an API to 3rd-party apps ────────────▶ OAuth 2.1 AS (buy/host: Keycloak,
   │                                                 Ory, hosted). Exact redirect_uri,
   │                                                 PKCE, aud-scoped tokens.  F14/F08/F20
   ├─ Machine-to-machine only ────────────────────▶ Client credentials (F10) /
   │                                                 workload identity (J05).
   └─ AI agents / tools ──────────────────────────▶ MCP over OAuth 2.1: discovery,
                                                     resource-scoped tokens, no
                                                     passthrough.  J08
```

## Q5 — What is your authorization model? (the one you can't buy)

```
   What KIND of rule is your access control?
   │
   ├─ "Admins / editors / viewers" (global roles) ▶ RBAC. Code + a roles table.  H04
   ├─ "Share THIS with THIS person" / inheritance ▶ ★ ReBAC (OpenFGA/SpiceDB).
   │                                                 RBAC BREAKS here.  H04/H07/H08
   ├─ "Legal reads confidential in business hours"▶ ABAC / policy engine (OPA/Cedar). H06/H11
   └─ Multi-tenant ───────────────────────────────▶ + RLS in the DB for isolation,
                                                     on TOP of the above.  H09/H10

   → Most real apps: RBAC (admin) + ReBAC (sharing) + RLS (tenants).
     Enforce at the SERVICE LAYER. Fail closed.  H02
   → If your product has "share / invite / grant-a-specific-thing"
     → you need ReBAC, not RBAC.  H04
```

## Q6 — Operational posture?

```
   ┌─ Enterprise / compliance (SOC 2, GDPR) ──────▶ SCIM provision+deprovision,
   │                                                 audit logs, key rotation,
   │                                                 data-min in tokens.  I02/I03/H13/I06/I11
   ├─ High-value / regulated ─────────────────────▶ Sender-constrained tokens
   │                                                 (mTLS/DPoP), step-up.  F16/D18
   └─ ANY production system ──────────────────────▶ KMS + secrets manager (no secrets
                                                     in git), rotation w/ overlap,
                                                     tamper-evident audit, IR runbook,
                                                     K04 attack pass as a regression
                                                     suite.  I05/A10/I06/I10/I07
```

---

## Worked leaf: a B2B SaaS collaboration product

Following the tree for a document/collaboration product (the capstone):

```
   Q1 Humans + agents      → Tracks D/E/G/H + J07/J08
   Q2 Passwords + SSO       → Argon2id+passkeys (small) + OIDC/SAML+SCIM (enterprise)
   Q3 First-party           → OPAQUE server-side session, __Host- cookie; BFF for the SPA
   Q4 Both directions       → OAuth 2.1 client + AS; MCP for agents
   Q5 Sharing + admin       → ReBAC (OpenFGA) + RBAC + RLS, service-layer, fail closed
   Q6 Enterprise            → SCIM, KMS, rotation, tamper-evident audit, IR runbook
   ────────────────────────────────────────────────────────────────────
   = the capstone.  K01–K03
```

## Worked leaf: a simple consumer app (no sharing, no enterprise)

```
   Q1 Humans                → Tracks D/E
   Q2 Passwords + social    → Argon2id+passkeys + "Sign in with Google" (OIDC)
   Q3 First-party           → OPAQUE server-side session
   Q4 Neither               → (no OAuth needed at all — F01)
   Q5 Own-your-stuff        → RBAC-lite / ownership checks + code, no ReBAC needed
   Q6 Production            → secrets manager, rotation, audit, IR runbook
   ────────────────────────────────────────────────────────────────────
   = a fraction of the capstone. You don't need most of F/G/H/J.
```

The tree's honest message: **different products get different answers.** A marketing site with a
contact form needs almost none of this. Match the machinery to the actual requirement.

---

**The RFCs your leaf implies:** see [rfc-index.md](rfc-index.md) — it lists which specs each answer
requires, and which you can ignore.

**Back to:** [README](../README.md) · [K05](../book/track-k/K05-the-decision-tree.md) · [rfc-index.md](rfc-index.md)
