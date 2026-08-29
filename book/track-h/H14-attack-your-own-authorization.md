# H14 — Broken access control: IDOR, privilege escalation, mass assignment

**Part H · Authorization** · *Builds on [H09](H09-multi-tenancy-isolation.md), [H04](H04-rbac-and-when-it-breaks.md)*

> **IDOR is statistically the most common serious vulnerability in real applications.** Broken
> access control is #1 in the OWASP Top 10 ([H01](H01-where-does-authz-live.md)). This chapter is
> the failure modes of authorization: what they are, why they happen, and how they are prevented.

---

## Why it matters

An authenticated user requests their own document, then changes one number:

```
GET /api/documents/9182   →  200 OK   (their document)
GET /api/documents/9183   →  200 OK   (someone else's)
```

The user was authenticated. The endpoint even checked they had the `documents:read` *role*. What it
did not check is whether *this* document is *theirs* ([C02](../track-c/C02-authn-vs-authz-vs-session.md)).
That single missing check is the most common serious flaw in software, and this chapter is the small
family of failures it belongs to.

---

## IDOR — the object check that isn't there

**IDOR** — Insecure Direct Object Reference. Change an identifier in a request and receive an object
that isn't yours. In API terms the same flaw is called **BOLA** (Broken Object Level Authorization),
#1 in the OWASP API Top 10.

**Why it is so common.** The ID *looks* like it came from your UI, and your UI only ever shows a user
their own objects. But the request does not come from your UI — it comes from whoever holds the
session, typing any ID ([A07](../track-a/A07-client-vs-server.md)). Authentication and a *role* check
feel sufficient, so the *object* check is skipped.

**Where it hides:**

```
   Every GET/PUT/PATCH/DELETE that takes an object ID — path, query, body, or header
   Nested resources:  /documents/42/comments/99   (both IDs need checking)
   Bulk endpoints:    ?ids=1,2,3                    (each one checked?)
   GraphQL:           every field resolver, not just the endpoint
   The "other paths":  CSV export, search, background jobs, the legacy API
   Cross-tenant:      tenant A reading tenant B's object — the worst case  (H09)
```

**The mental test** ([C02](../track-c/C02-authn-vs-authz-vs-session.md)): take a valid session for
user A, request user B's resource. What stops it? If the answer is "our UI wouldn't show that ID,"
you have an IDOR.

**The prevention.** Object-level authorization at the service layer, on *every* object access
([H02](H02-the-enforcement-point.md)) — `if not can(actor, action, object): forbid` — with row-level
security as the unbypassable backstop for tenant isolation
([H10](H10-row-level-security.md)). **Unguessable IDs help but are not a fix** — IDs leak, in URLs,
`Referer` headers, logs, and shared links ([H09](H09-multi-tenancy-isolation.md)). And when the
*existence* of a resource is sensitive, return `404` rather than `403` so an attacker can't map your
ID space ([A03](../track-a/A03-methods-status-codes-401-vs-403.md)).

---

## Privilege escalation — gaining permissions you weren't granted

Two directions:

- **Vertical** — a regular user reaching admin functionality. Root causes: an endpoint that isn't
  behind a check (which is why **deny by default** matters — [H01](H01-where-does-authz-live.md)), a
  rule that guards `POST /admin/*` but not `PUT /admin/*` (**authorize the operation, not the
  verb-and-path** — [A03](../track-a/A03-methods-status-codes-401-vs-403.md)), or letting the client
  set its own role.
- **Horizontal** — acting as another peer user, which is IDOR by another name.

A subtle escalation lives in **sharing itself**: if a *viewer* can grant themselves *owner*, sharing
was not treated as an authorized action ([H03](H03-acls-and-direct-permissions.md)). "Who may share,
and to what level?" is a permission check like any other.

**The prevention.** Deny by default ([H01](H01-where-does-authz-live.md)); authorize the *operation*;
never let the client assign roles; and check that granting is itself permitted.

---

## Mass assignment — fields the form never showed

An update handler binds request fields straight to model attributes:

```
PATCH /api/users/me
{ "name": "Alice", "is_admin": true, "tenant_id": "...", "credits": 999999 }
```

The form only has a name field — but the request isn't the form
([A07](../track-a/A07-client-vs-server.md)). If the handler binds the whole body, `is_admin` lands,
and the user is now an administrator ([D05](../track-d/D05-build-login-part-1-registration.md)). It
also enables cross-tenant moves (`tenant_id`), verification bypass (`email_verified`), and
business-logic abuse (`credits`).

**The prevention.** An explicit **allowlist** of bindable fields — parse the request into a typed
object containing only the fields a user may set, so `is_admin` has nowhere to go
([D05](../track-d/D05-build-login-part-1-registration.md)). Never bind request bodies directly to
models, and apply the allowlist to *update* handlers, not just registration — update paths are
usually written less carefully.

---

## Forced browsing — "hidden" is not "protected"

An endpoint exists but isn't linked — a `/debug` route, an internal API, an old `/api/v1` with weaker
checks. Reaching it directly is **forced browsing**, and it works because *hiding* something is not
*protecting* it ([A07](../track-a/A07-client-vs-server.md)).

**The prevention.** Deny by default, so an unprotected route is *broken*, not *open*
([H01](H01-where-does-authz-live.md)); remove debug and internal endpoints from production; and apply
authorization uniformly across API versions — a `v2` check means nothing if `v1` still serves the
data.

---

## The pattern behind all of them

Every failure here is the same shape: **a path to the data that skips the object-level check.** The
controller checks; the export, the GraphQL resolver, the background job, and the legacy endpoint do
not ([H02](H02-the-enforcement-point.md)). So the fix is architectural, not per-handler:

```
   Enforce object-level authorization at the SERVICE LAYER — the one door every
   entry point passes through — and back it with ROW-LEVEL SECURITY in the database.
   Then no path can forget the check.                                   H02 / H10
```

Combined with **deny by default** and **fail closed** ([H01](H01-where-does-authz-live.md)), this
turns the most common class of vulnerability from "prevented on the paths someone remembered" into
"structurally hard to introduce."

---

## The verification checklist

For any system, confirm — in tests that assert access is *refused*, not just granted
([I07](../track-i/I07-testing-auth.md)):

```
☐ Every object-ID endpoint checks ownership/authorization       C02 / H02
☐ Cross-tenant access is blocked (the worst case)               H09
☐ Nested and bulk endpoints check EACH id
☐ Exports, search, GraphQL, jobs, and legacy APIs authorize too H02
☐ Deny by default: admin/debug/legacy routes are protected      H01
☐ Operation authorized, not verb+path (no method confusion)     A03
☐ Sharing/granting is itself authorized (no viewer→owner)       H03
☐ Explicit field allowlist on create AND update                 D05
☐ 404 (not 403) hides existence where it's sensitive            A03 / H09
```

---

## Terms defined in this chapter

`IDOR`, `BOLA`, `privilege escalation`, `mass assignment`, `forced browsing`

---

## What to remember

1. **IDOR/BOLA is the most common serious vulnerability** — a missing *object* check behind a passing
   *authentication* and *role* check.
2. **Cross-tenant IDOR is the worst case** — company A reads company B's data
   ([H09](H09-multi-tenancy-isolation.md)).
3. **Object-level authorization at the service layer + RLS** is the fix
   ([H02](H02-the-enforcement-point.md), [H10](H10-row-level-security.md)). Unguessable IDs are not.
4. **Privilege escalation:** deny by default, authorize the operation (not verb+path), gate sharing.
5. **Mass assignment:** an explicit field allowlist, on create *and* update.
6. **Forced browsing:** hidden ≠ protected — deny by default makes a forgotten route *broken*, not
   *open*.
7. Every failure is "a path that skips the check." Fix it **architecturally**, not per-handler.

---

## Sources

- [OWASP API Security Top 10 — API1:2023 BOLA](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/), [API3 Mass Assignment](https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/), [API5 BFLA](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
- [OWASP Top 10 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)

---

**Next:** [I01 — The identity lifecycle: joiner, mover, leaver](../track-i/I01-identity-lifecycle.md)
