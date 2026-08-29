# H10 — Row-level security: authorization in the database

**Part H · Authorization** · *Builds on [H02](H02-the-enforcement-point.md)*
---

## What RLS is

> **Row-level security is a database feature that filters which *rows* a query can see or
> modify, based on a policy, automatically, on every query.**

You define a policy once; the database applies it to every `SELECT`, `UPDATE`, `DELETE`, and
`INSERT` against that table, transparently.

```sql
-- Turn on RLS for the table.
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;

-- A policy: rows are visible only if their tenant matches the current session's tenant.
CREATE POLICY tenant_isolation ON documents
  USING (tenant_id = current_setting('app.current_tenant')::uuid);
```

Now:

```sql
-- The application runs this — note: NO tenant filter in the query.
SELECT * FROM documents WHERE id = 42;

-- The database rewrites it to, effectively:
SELECT * FROM documents WHERE id = 42
  AND tenant_id = current_setting('app.current_tenant')::uuid;
```

**The forgotten filter is added by the database.** The classic multi-tenancy bug from
[H09](H09-multi-tenancy-isolation.md) — a query with no tenant filter — now returns only the
current tenant's rows regardless. That is the entire value: **it is unbypassable by
application bugs.**

---

## The session variable — where it gets its answer

RLS filters by `current_setting('app.current_tenant')`. That value must be set, correctly, on
every request's database connection:

```python
@app.before_request
def set_db_context():
    session = load_session()                         # E03
    if session is None:
        abort(401)
    # Set the tenant (and user) for RLS. From the SESSION, never the request. H09.
    db.execute("SET app.current_tenant = %s", session.tenant_id)
    db.execute("SET app.current_user = %s", session.user_id)
```

More expressive policies can filter per-user, using both direct grants and relationships:

```sql
CREATE POLICY document_access ON documents
  USING (
    tenant_id = current_setting('app.current_tenant')::uuid          -- tenant isolation
    AND (
      owner_id = current_setting('app.current_user')::uuid           -- own documents
      OR id IN (                                                     -- shared documents
        SELECT resource_id FROM acl_entries
        WHERE subject_id = current_setting('app.current_user')::uuid
          AND resource_type = 'document'
      )
    )
  );
```

Now the ACL from [H03](H03-acls-and-direct-permissions.md) is enforced *in the database*, on
every query, unbypassable.

---

## The one thing that makes RLS fail open

RLS's guarantee has exactly one dependency, and it is where all the risk concentrates:

> **The session variable must be set correctly on every connection — and connection pools do
> not reset it between requests.**

This is the RLS footgun. With a connection pool ([E03](../track-e/E03-build-server-side-sessions.md)),
a connection is reused across requests and *tenants*. If request A sets
`app.current_tenant = acme` and request B reuses that connection **without** setting it,
request B runs as Acme — a cross-tenant leak, exactly what RLS was supposed to prevent.

Two robust patterns:

**1. `SET LOCAL` inside a transaction.** `SET LOCAL` scopes the setting to the current
transaction, so it is discarded automatically at commit/rollback — it cannot leak to the next
request on that connection:

```python
with db.transaction():
    db.execute("SET LOCAL app.current_tenant = %s", session.tenant_id)
    # ...all queries for this request, inside this transaction...
# setting is gone when the transaction ends
```

**2. Reset on connection checkout/return.** Configure the pool to `RESET ALL` (or re-set the
context) whenever a connection is handed out.

**Test this deliberately** ([H14](H14-attack-your-own-authorization.md)): hammer the app with
interleaved requests from two tenants over a small pool, and assert no cross-tenant row ever
appears. This is the test that catches the failure that matters most.

Also: the table **owner** and **superusers** bypass RLS by default. Your application must
connect as a *non-owner, non-superuser* role, or the policy does nothing.
`FORCE ROW LEVEL SECURITY` makes even the owner subject to policies — use it.

---

## RLS vs application-layer authorization

Not either/or — they cover different things ([H02](H02-the-enforcement-point.md)):

| | Application layer | **RLS (database)** |
|---|---|---|
| Enforces on | The paths that call it | **Every query, every path** |
| Bypassable by | A forgotten check, a new entry point | **Almost nothing** (barring the pool footgun) |
| Business nuance | ✅ Rich ("locked unless owner unless...") | ⚠️ Awkward in SQL |
| Performance | App-controlled | Adds to every query; watch indexes |
| Error messages | Precise (403 with reason) | Rows just vanish (harder to explain "why can't I see it?") |
| Debuggability | Clear | "The row exists but the query returns nothing" |

**Use both** ([H02](H02-the-enforcement-point.md)):

- **RLS as the unbypassable backstop** for the guarantees that must never break — tenant
  isolation above all ([H09](H09-multi-tenancy-isolation.md)).
- **Application-layer authorization for the rich business logic** and for good error messages —
  a user who is denied should get a clear `403` ([A03](../track-a/A03-methods-status-codes-401-vs-403.md)),
  not a mysteriously empty result.

Defence in depth: the app layer gives you expressiveness and clarity; RLS guarantees that even
if the app layer has a bug, the data does not leak.

---

## Costs and caveats

**Performance.** RLS predicates run on every query. Ensure the policy's columns
(`tenant_id`, `owner_id`) are **indexed**, and check query plans — a subquery in a policy can
turn a fast lookup into a slow one at scale.

**Debuggability.** "The row is there but I get nothing back" is confusing until you remember
RLS. Log the current session context, and provide an admin/support path that runs with explicit
scoping ([I04](../track-i/I04-admin-impersonation.md)) rather than silently seeing nothing.

**Not every database has it.** PostgreSQL and SQL Server have strong RLS; MySQL does not (you
emulate it with views or discipline); many NoSQL stores have nothing comparable. On stores
without RLS, the scoped-data-layer pattern ([H09](H09-multi-tenancy-isolation.md)) is your
fallback — weaker, but structural.

**Migrations and background jobs** must set the context too, or they either fail (can't see
rows) or, if they run as owner/superuser, bypass RLS entirely. Give jobs explicit, audited
tenant scoping ([H09](H09-multi-tenancy-isolation.md)).

---

## When to use RLS

✅ **Multi-tenant SaaS on a shared schema** — the canonical case; RLS is the strongest tenant
isolation ([H09](H09-multi-tenancy-isolation.md)).
✅ **When many code paths reach the same data** and you cannot guarantee they all check
([H02](H02-the-enforcement-point.md)).
✅ **Regulated data** where "the database enforces it" is an audit-friendly control
([I11](../track-i/I11-compliance.md)).

⚠️ **Complex, relationship-based authorization** ([H07](H07-rebac-and-zanzibar.md)) — expressible
in RLS via subqueries, but a dedicated engine ([H08](H08-model-drive-in-openfga.md)) may fit
better.

❌ **When you don't control the database**, or it lacks RLS.

---

## Terms defined in this chapter

`RLS`, `session variable`

---

## What to remember

1. **RLS moves the filter into the database**, so *every* query on *every* path is filtered —
   unbypassable by application bugs.
2. It gets its answer from a **session variable** you set per request, **from the session,
   never the request** ([H09](H09-multi-tenancy-isolation.md)).
3. **The one way it fails open: connection pools reusing a connection without resetting the
   variable.** Use `SET LOCAL` in a transaction, or reset on checkout. **Test it.**
4. Your app must connect as a **non-owner, non-superuser** role, or RLS is bypassed. Consider
   `FORCE ROW LEVEL SECURITY`.
5. **Use RLS *and* application authorization:** RLS as the unbypassable backstop, the app layer
   for business nuance and clear `403`s.
6. Index the policy columns; remember background jobs and migrations need the context too.
7. It is the **strongest tenant-isolation control** for shared-schema SaaS.

---

## Sources

- [PostgreSQL: Row Security Policies](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
- [Supabase: Row Level Security](https://supabase.com/docs/guides/database/postgres/row-level-security) — a practical treatment, including the JWT-claims-to-RLS pattern
- *API Security in Action* (Neil Madden), Ch. 8

---

**Next:** [H11 — OPA, Cedar, or just SQL?](H11-opa-cedar-or-sql.md)
