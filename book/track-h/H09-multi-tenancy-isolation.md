# H09 — Multi-tenancy and the isolation problem

**Part H · Authorization** · *Builds on [H04](H04-rbac-and-when-it-breaks.md)*
---

## Why it matters

A B2B SaaS app serves hundreds of companies. The documents endpoint:

```python
@app.get("/api/documents/<doc_id>")
@login_required                              # ✅ authenticated
@require_permission("documents:read")        # ✅ has the role
def get_document(doc_id):
    return db.query("SELECT * FROM documents WHERE id = %s", doc_id)   # ❌
```

A user at Acme changes the ID to a document belonging to Globex — a *different customer* — and
reads it. Both checks passed: the user is authenticated, and they have the `documents:read`
role. Nobody checked whether the document belongs to **their tenant**.

This is a **cross-tenant IDOR** ([H14](H14-attack-your-own-authorization.md)), and it is the
worst kind of authorization bug in B2B software: not "user A saw user B's data," but "company
A saw company B's data" — a breach of the isolation you sell as a product guarantee. It ends
deals, triggers breach notifications, and destroys trust.

---

## What multi-tenancy is

> **A tenant is one customer's isolated slice of a shared system. Multi-tenancy means one
> deployment serves many tenants with *enforced* isolation between them.**

```
   ┌──────────────── ONE DEPLOYMENT ────────────────┐
   │  Tenant: Acme        Tenant: Globex             │
   │  ├─ users            ├─ users                    │
   │  ├─ documents        ├─ documents                │
   │  └─ settings         └─ settings                 │
   │                                                  │
   │  Acme MUST NEVER see anything of Globex's.       │
   └──────────────────────────────────────────────────┘
```

Multi-tenancy is efficient (one codebase, shared infrastructure) and it is the standard SaaS
model. The entire risk is one word: **isolation.** Everything else in this chapter serves it.

Isolation is a stronger guarantee than ordinary authorization. Within a tenant, a bug might
leak one user's data to another — bad. *Across* tenants, a bug leaks one customer's data to
another — catastrophic and often contractual. So tenant isolation must be enforced at a layer
that no code path can forget ([H02](H02-the-enforcement-point.md)).

---

## The isolation strategies

```
   1. SEPARATE DATABASES     each tenant = its own database
   2. SEPARATE SCHEMAS       one database, a schema per tenant
   3. SHARED SCHEMA          one set of tables, a tenant_id column   ← most common
```

| | Separate DB | Separate schema | **Shared schema (tenant_id)** |
|---|---|---|---|
| Isolation strength | Strongest | Strong | **Weakest — depends on code** |
| Cost per tenant | High | Medium | **Low** |
| Scales to N tenants | Hundreds | Thousands | **Millions** |
| Noisy neighbour risk | None | Some | Some |
| "Forgot the filter" = breach | ❌ impossible | ❌ impossible | ✅ **the risk** |
| Best for | Few large/regulated tenants | Medium | **Most SaaS** |

The trade is stark: **the cheapest, most scalable model (shared schema) has the weakest
isolation** — a single forgotten `WHERE tenant_id = ?` is a cross-tenant breach. The opening
failure is exactly this. So if you choose shared-schema (most SaaS does), you must make the
tenant filter **unforgettable.**

---

## Making the tenant filter unforgettable

The example at the top is "someone wrote a query without the tenant filter." The fix is
**structural**, not disciplinary — you cannot rely on every developer remembering on every
query ([H02](H02-the-enforcement-point.md)).

### Weak: remember it everywhere ❌

```python
db.query("SELECT * FROM documents WHERE id = %s AND tenant_id = %s", doc_id, tenant_id)
```

Correct, and doomed — one forgotten `AND tenant_id` anywhere (a new endpoint, a background job,
an export, a hotfix) is a breach. Relying on humans to never forget is not isolation.

### Better: a scoped data layer ⚠️

Every query goes through a layer that injects the tenant automatically:

```python
class TenantScopedRepo:
    def __init__(self, tenant_id):
        self.tenant_id = tenant_id
    def documents(self):
        # There is no way to query documents WITHOUT the tenant filter.
        return db.table("documents").where(tenant_id=self.tenant_id)

# The handler literally cannot reach unscoped data:
repo = TenantScopedRepo(current_tenant())
doc = repo.documents().get(doc_id)      # tenant filter applied, always
```

Good — but only if *nothing* bypasses the repo (the [H02](H02-the-enforcement-point.md)
problem: exports, jobs, raw SQL). One direct query and the guarantee is gone.

### Best: row-level security in the database ✅

Push the filter into the database itself ([H10](H10-row-level-security.md)):

```sql
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON documents
  USING (tenant_id = current_setting('app.current_tenant')::uuid);
```

Now **every query, from any code path, any tool, any forgotten job, sees only the current
tenant's rows** — enforced by the database, unbypassable by application bugs. The opening
failure becomes impossible: even the query with no `WHERE tenant_id` returns only Acme's rows,
because the database adds the filter.

RLS is the strongest answer for shared-schema multi-tenancy, and it is [H10](H10-row-level-security.md)'s
whole chapter. Its one dependency: the app must **set `app.current_tenant` correctly on every
connection** ([H10](H10-row-level-security.md)) — get *that* wrong and it fails open, so it
becomes the one thing you guard obsessively.

---

## Setting the tenant context

The tenant must be established early, from a trusted source, on every request:

```python
@app.before_request
def establish_tenant():
    session = load_session()                         # E03
    if session is None:
        abort(401)

    # The tenant comes from the SESSION, never from the request. ★
    g.tenant_id = session.tenant_id

    # Set it for RLS, on this request's DB connection. H10.
    db.execute("SET app.current_tenant = %s", g.tenant_id)
```

**The tenant comes from the authenticated session, never from a request parameter** (the ★).
This is the multi-tenant version of "never trust client input"
([A07](../track-a/A07-client-vs-server.md)):

```python
# ❌ NEVER — the attacker just sets tenant_id to the victim's
tenant_id = request.args.get("tenant_id")

# ✅ from the session, established at login
tenant_id = session.tenant_id
```

If the tenant were attacker-supplied, isolation would be one query parameter away from
collapse. It is derived from *who they authenticated as*, at login
([G09](../track-g/G09-multi-tenant-sso.md)), and carried in the session.

---

## Cross-tenant is also users, jobs, and shared resources

Isolation is not only about queries. The seams:

**Users in the wrong tenant.** From [G09](../track-g/G09-multi-tenant-sso.md): key users on
`(tenant_id, ...)`, not globally, and validate at login that the identity belongs to the
tenant it claims. One person may exist in two tenants as two users.

**Background jobs and admin tools.** A reindex job or an admin console runs *outside* a request
and often *outside* the tenant context ([H02](H02-the-enforcement-point.md)). These are the
classic RLS bypass — they connect as a superuser, or forget to set `app.current_tenant`. Give
them explicit, audited tenant scoping ([H10](H10-row-level-security.md), [I04](../track-i/I04-admin-impersonation.md)).

**Shared/global resources.** Some data is genuinely cross-tenant (a system template, a public
document). Model these explicitly (e.g. `tenant_id IS NULL` with a policy that allows it), so
"shared" is a deliberate decision, not a hole.

**Caches keyed without the tenant.** A cache key of `document:42` instead of
`acme:document:42` serves Acme's cached document to Globex. **Include the tenant in every cache
key** — a subtle, common, and serious leak.

**IDs that reveal cross-tenant existence.** Sequential IDs let an attacker probe whether other
tenants' documents exist even when reads are blocked ([H14](H14-attack-your-own-authorization.md)).
Use unguessable IDs, and return `404` (not `403`) for other tenants' resources so existence
stays hidden ([A03](../track-a/A03-methods-status-codes-401-vs-403.md)).

---

## Noisy neighbours (a different problem)

Multi-tenancy has a second, non-security concern: one tenant's load degrading others' — a
**noisy neighbour**. A tenant running a huge export starves everyone's queries.

This is an *availability* problem, not an isolation/authorization one, but it belongs to the
same shared-infrastructure trade-off. Mitigations: per-tenant rate limits
([D08](../track-d/D08-rate-limiting-and-stuffing.md)), query timeouts, resource quotas, and —
for the largest tenants — moving them to dedicated infrastructure (the separate-database model,
for a few tenants who justify it).

---

## Terms defined in this chapter

`tenant isolation`, `noisy neighbour`

---

## What to remember

1. **A cross-tenant leak is the worst B2B authorization bug** — company A sees company B's
   data, breaching the isolation you sell.
2. Isolation strategies trade cost for strength: **shared-schema (tenant_id) is cheapest and
   weakest** — one forgotten filter is a breach.
3. **Make the tenant filter structural, not disciplinary.** Scoped repo helps; **row-level
   security is unbypassable** ([H10](H10-row-level-security.md)).
4. **The tenant comes from the authenticated session, NEVER from a request parameter.**
5. RLS's one weak point: the app must **set the tenant context correctly on every connection**
   — guard that obsessively.
6. Watch the seams: **background jobs, admin tools, shared resources, and cache keys** — all
   classic cross-tenant leaks. Put the tenant in every cache key.
7. Return **`404` for other tenants' resources** so existence stays hidden.
8. **Noisy neighbours** are an availability problem — per-tenant quotas, not authorization.

---

## Sources

- [OWASP: Multi-tenancy / Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)
- [PostgreSQL: Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html) ([H10](H10-row-level-security.md))
- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed., Ch. 7

---

**Next:** [H10 — Row-level security: authorization in the database](H10-row-level-security.md)
