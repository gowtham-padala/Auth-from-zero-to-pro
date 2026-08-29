# K01 — One app, all five layers: architecture review

**Part K · Capstone** · *Builds on all tracks*
> The capstone. One application, every layer, assembled — and reviewed against OWASP ASVS before a
> line of it is built. This is where the whole book becomes one coherent system.

---

## The document-sharing app, complete

The running project ([README](../../README.md)) has accumulated every layer. Here it is, whole —
each piece a chapter, the assembly a system. This is the review you do *before* building
([K02](K02-capstone-part-1.md), [K03](K03-capstone-part-2.md)), because architecture mistakes are
the expensive ones ([C04](../track-c/C04-threat-modeling.md)).

```
   ┌─────────────────────────────────────────────────────────────────────┐
   │  THE FIVE LAYERS (C01)                                               │
   │                                                                     │
   │  1. AUTHENTICATION   passwords (Argon2id) + TOTP + passkeys    D     │
   │  2. SESSIONS         opaque server-side sessions, __Host- cookie  E  │
   │  3. DELEGATION       OAuth 2.1 for third-party API access     F     │
   │  4. FEDERATION       OIDC + SAML SSO, multi-tenant            G     │
   │  5. AUTHORIZATION    ReBAC for sharing + RBAC for admin       H     │
   │                                                                     │
   │  + LIFECYCLE/OPS     SCIM, secrets, rotation, audit, IR       I     │
   │  + MACHINE           API keys, mTLS, agent auth (MCP)         J     │
   └─────────────────────────────────────────────────────────────────────┘
```

---

## The request path, end to end

One request — *"Alice's document-sharing app, Bob deletes a shared document"* — traced through every
layer, so you can see how the tracks compose ([C01](../track-c/C01-auth-is-five-different-problems.md)):

```
   DELETE /api/documents/9182
   Cookie: __Host-session=8f14e45f...
      │
   ┌──▼── TRANSPORT ────────────────────────────────────────────┐
   │ HTTPS (TLS 1.3), HSTS.  B17                                 │
   └──┬─────────────────────────────────────────────────────────┘
   ┌──▼── SESSION (layer 2) ────────────────────────────────────┐
   │ Look up sha256(session) → user=bob, tenant=88.  E03/E04    │
   │ (auth happened days ago — layer 1.  amr/acr on session. D18)│
   │ Fail → 401.                                                │
   └──┬─────────────────────────────────────────────────────────┘
   ┌──▼── TENANT ISOLATION ─────────────────────────────────────┐
   │ SET app.current_tenant = 88 (RLS).  H09/H10                │
   │ Document 9182 must be in tenant 88 — or it doesn't exist.  │
   └──┬─────────────────────────────────────────────────────────┘
   ┌──▼── AUTHORIZATION (layer 5) ──────────────────────────────┐
   │ ReBAC check: may bob DELETE document:9182?  H07/H08        │
   │   → is he owner, or editor of it or its parent folder?     │
   │ Fail → 403 (or 404 to hide existence).  A03/H14           │
   └──┬─────────────────────────────────────────────────────────┘
   ┌──▼── ACT + PROVE ──────────────────────────────────────────┐
   │ Delete. Write a tamper-evident audit entry.  H13           │
   │ Cache-Control: no-store.  A04                              │
   └────────────────────────────────────────────────────────────┘
```

Every box is a layer, every layer a track. The [C01](../track-c/C01-auth-is-five-different-problems.md)
insight made concrete: authentication happened once, days ago; **sessions and authorization run on
every request**, which is where the bugs live ([H14](../track-h/H14-attack-your-own-authorization.md)).

---

## The security boundaries

Where trust changes, and a check is mandatory ([A07](../track-a/A07-client-vs-server.md),
[C04](../track-c/C04-threat-modeling.md)):

```
   Browser  ═══boundary═══  Your server  ═══boundary═══  Third-party API
   (untrusted:              (trusted, but              (their trust domain:
    A07)                     every input checked)       validate aud, F08)

   Agent  ═══boundary═══  MCP server  ═══boundary═══  Tool
   (semi-trusted: J07)     (resource server)          (audience-bound token)

   Service ═══boundary═══ Service     (mTLS, J04 — "internal" is not trust, H12)
```

Each boundary is a place [A07](../track-a/A07-client-vs-server.md)'s rule applies: everything
crossing it is untrusted until verified. The architecture review is largely *finding every boundary
and confirming there's a check on it.*

---

## The design decisions, and where each was made

The capstone is a series of choices from across the book. Stated as decisions, with the chapter:

| Decision | Choice | Why | Chapter |
|---|---|---|---|
| Login identifier | Email + passkeys | Universal + phishing-resistant | [D01](../track-d/D01-identifiers.md), [D14](../track-d/D14-webauthn-and-passkeys-concepts.md) |
| Password storage | Argon2id | The 2026 standard | [D03](../track-d/D03-how-to-store-passwords.md) |
| Second factor | Passkey > TOTP > (SMS fallback) | Phishing resistance | [D11](../track-d/D11-sms-second-factor.md), [D12](../track-d/D12-build-totp.md) |
| Session type | **Opaque, server-side** | First-party → revocable | [E09](../track-e/E09-should-you-use-jwts-for-sessions.md) |
| Token storage | `__Host-` `HttpOnly` cookie | Survives XSS | [E02](../track-e/E02-cookie-attributes.md), [E12](../track-e/E12-where-to-store-a-token.md) |
| SPA architecture | BFF | Tokens off the browser | [F17](../track-f/F17-oauth-for-spas-and-bff.md) |
| Third-party access | OAuth 2.1 + PKCE | Delegation done right | [F06](../track-f/F06-pkce.md) |
| Enterprise login | OIDC + SAML, multi-tenant | Customers require it | [G08](../track-g/G08-saml-vs-oidc.md), [G09](../track-g/G09-multi-tenant-sso.md) |
| Sharing authorization | **ReBAC (OpenFGA)** | RBAC breaks on sharing | [H04](../track-h/H04-rbac-and-when-it-breaks.md), [H08](../track-h/H08-model-drive-in-openfga.md) |
| Admin authorization | RBAC | Functional roles | [H04](../track-h/H04-rbac-and-when-it-breaks.md) |
| Tenant isolation | RLS | Unbypassable | [H10](../track-h/H10-row-level-security.md) |
| Enforcement point | Service layer + RLS | No path bypasses it | [H02](../track-h/H02-the-enforcement-point.md) |
| Provisioning | SCIM + JIT | Enterprise lifecycle | [I02](../track-i/I02-provisioning-and-scim.md) |
| Secrets | KMS + workload identity | Never hold the key | [I05](../track-i/I05-secrets-management.md) |
| Machine auth | mTLS internal, API keys external | Right tool per case | [J02](../track-j/J02-api-keys.md), [J04](../track-j/J04-mtls.md) |
| Agent auth | Delegated, task-scoped, MCP | Semi-trusted delegate | [J07](../track-j/J07-auth-for-ai-agents.md), [J08](../track-j/J08-mcp-and-oauth-21.md) |

The pattern across the table: **each choice is the one the relevant track argued for.** The capstone
isn't a new design — it's the book's recommendations, assembled and made mutually consistent.

---

## Review against OWASP ASVS

Before building, review the design against a standard — **OWASP ASVS** (Application Security
Verification Standard) gives testable requirements ([I07](../track-i/I07-testing-auth.md)). The three
chapters that matter here:

```
   ASVS V2 — Authentication
     ☐ Argon2id storage, breach-blocklist, MFA, no composition rules   D03/D04
     ☐ Rate limiting, enumeration resistance, secure recovery          D07/D08/D09
   ASVS V3 — Session Management
     ☐ High-entropy session IDs, __Host- cookie, rotation, timeouts    E02/E04
     ☐ Logout invalidates server session; "log out everywhere"         E14/E13
   ASVS V7 (or V4) — Access Control
     ☐ Deny by default, fail closed, enforced server-side              H01/H02
     ☐ Object-level authorization (no IDOR), tenant isolation          H14/H09
```

The review is a checklist walk: for each ASVS requirement, *where in the architecture is it
satisfied, and how is it tested* ([I07](../track-i/I07-testing-auth.md))? A requirement with no
answer is a gap to fix before building — the cheapest possible time to find it
([C04](../track-c/C04-threat-modeling.md)).

---

## The threat model, one more time

Who's attacking this app, and what stops them ([C04](../track-c/C04-threat-modeling.md))? The
review confirms a defence for each realistic attacker:

| Attacker | Defence | Chapter |
|---|---|---|
| Credential stuffer | Breach blocklist, rate limiting, MFA | [D04](../track-d/D04-password-policies.md), [D08](../track-d/D08-rate-limiting-and-stuffing.md) |
| Phisher | Passkeys (origin-bound) | [D14](../track-d/D14-webauthn-and-passkeys-concepts.md) |
| **Curious/malicious user (IDOR)** | Object-level ReBAC + RLS | [H14](../track-h/H14-attack-your-own-authorization.md) |
| Cross-tenant attacker | RLS + tenant-scoped everything | [H09](../track-h/H09-multi-tenancy-isolation.md) |
| XSS-capable attacker | `HttpOnly`, CSP, opaque session | [E16](../track-e/E16-xss-is-an-auth-vulnerability.md) |
| Token thief | Short lifetimes, revocation, sender-constraint | [E10](../track-e/E10-token-lifetimes-and-rotation.md), [F16](../track-f/F16-sender-constrained-tokens.md) |
| Departed employee | SCIM deprovision + session kill | [I03](../track-i/I03-deprovisioning.md) |
| Manipulated agent | Task-scoped delegation, human-in-loop | [J07](../track-j/J07-auth-for-ai-agents.md) |

The most dangerous is still the **curious/malicious user** ([C04](../track-c/C04-threat-modeling.md),
[H14](../track-h/H14-attack-your-own-authorization.md)) — inside every perimeter by design, defeated
only by per-object authorization. The architecture must make IDOR *impossible*, not merely
prevented on the paths someone remembered.

---

## Terms defined in this chapter

`ASVS`, `security boundary`

---

## What to remember

1. **The capstone is the whole book, assembled** — five layers ([C01](../track-c/C01-auth-is-five-different-problems.md))
   plus lifecycle and machine identity, made mutually consistent.
2. **Trace one request through every layer** — session, tenant isolation, authorization, act,
   audit — and see that **sessions and authorization run on every request.**
3. **Review the architecture before building** — architecture mistakes are the expensive ones
   ([C04](../track-c/C04-threat-modeling.md)).
4. **Every choice is the one its track argued for** — the capstone is the book's recommendations
   made coherent, not a new design.
5. **Find every security boundary and confirm a check on it** ([A07](../track-a/A07-client-vs-server.md)) —
   that *is* the review.
6. **Walk OWASP ASVS V2/V3/V7** — for each requirement, where is it satisfied and how is it tested
   ([I07](../track-i/I07-testing-auth.md))?
7. **The curious/malicious user is the top threat** — the architecture must make IDOR *impossible*
   ([H14](../track-h/H14-attack-your-own-authorization.md)).

---

## Sources

- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — V2, V3, V7 (or V4 by version)
- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed. — the five-layer structural spine
- *API Security in Action* (Neil Madden) — the technical reference for E, F, H

---

**Next:** [K02 — Build the capstone, part 1: authentication and sessions](K02-capstone-part-1.md)
