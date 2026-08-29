# H02 — The enforcement point: middleware, service layer, or database?

**Part H · Authorization** · *Builds on [H01](H01-where-does-authz-live.md)*
---

## Why it matters

An app checks authorization in its HTTP controllers. Every route handler verifies the user
owns the document before returning it. Thorough.

Then, over time, other paths to the same data appear:

```
   ✅ GET /api/documents/42     → controller checks ownership
   ❌ the nightly CSV export    → queries the documents table directly
   ❌ the GraphQL resolver      → different entry point, no check
   ❌ the admin dashboard       → "it's internal", no check
   ❌ a background reindex job   → reads everything, emits it to search
   ❌ the /debug endpoint        → someone added it, forgot it
```

Every one of these reaches the documents table by a path that bypasses the controller. The
authorization was real, and it was in **the wrong place** — high enough that new paths
routinely go around it.

The question "which layer enforces authorization?" is not academic. It decides how many paths
can forget the check.

---

## The layers

```
   ┌────────────────────────────────────────────────────────────┐
   │  UI                    ← NOT a control. UX only.  A07        │
   ├────────────────────────────────────────────────────────────┤
   │  EDGE / GATEWAY        ← coarse: is there a valid token?     │
   ├────────────────────────────────────────────────────────────┤
   │  MIDDLEWARE (per route)← route-level: may this role hit /admin?│
   ├────────────────────────────────────────────────────────────┤
   │  SERVICE LAYER         ← object-level: may they act on THIS? │  ← the workhorse
   ├────────────────────────────────────────────────────────────┤
   │  DATABASE (RLS)        ← data-level: filter rows to them     │  H10
   └────────────────────────────────────────────────────────────┘
```

The trade-off that governs the whole chapter:

> **The higher you enforce, the easier it is to forget a path. The lower you enforce, the
> harder it is to bypass — but the further from the business logic, and the coarser.**

Each layer catches something the others miss, and misses something the others catch. The
answer is not "pick one" — it is **defence in depth** ([C04](../track-c/C04-threat-modeling.md)),
with the *primary* enforcement at the layer that no path can go around.

---

## Layer by layer

### Middleware / per-route — necessary, insufficient

```python
@app.get("/admin/users")
@require_permission("users:list")     # ✅ route-level: is this the right kind of user?
def list_users(): ...
```

**Good at:** coarse, route-level rules. "Only admins reach `/admin/*`." "This endpoint needs
the `billing:write` scope."

**Blind to:** *which object*. `@require_permission("documents:read")` says the user may read
documents — not *this* document ([H01](H01-where-does-authz-live.md)). Middleware cannot do
object-level authorization because it runs before you have loaded the object.

**The classic bypass** ([A03](../track-a/A03-methods-status-codes-401-vs-403.md)): a rule on
`POST /admin/*` that forgets `PUT /admin/*`. Authorize the *operation*, not the verb-and-path
string.

Middleware is the first line, not the line.

### Service layer — where object authorization belongs

```python
class DocumentService:
    def get(self, actor: User, doc_id: str) -> Document:
        doc = self.repo.get(doc_id)          # load the object first...
        if not self.authz.can(actor, "read", doc):   # ...THEN authorize it
            raise Forbidden()                # object-level check — H14
        return doc

    def delete(self, actor: User, doc_id: str) -> None:
        doc = self.repo.get(doc_id)
        if not self.authz.can(actor, "delete", doc):
            raise Forbidden()
        self.repo.delete(doc)
        self.audit.record(actor, "delete", doc)   # H13
```

**This is the workhorse.** Object-level authorization has to happen *after* the object is
loaded (you cannot check "do they own doc 42?" without doc 42), and the service layer is where
that happens.

**The key property: every entry point funnels through the service.** The controller, the
GraphQL resolver, the CLI command, the background job, and the CSV export all call
`DocumentService.get()` — so they all get the check, for free, exactly once.

The example at the top of this chapter is what happens when they *don't* — when each entry
point reaches the repository or the database directly. **Make the service the only door to the
data**, and the "forgot a path" class of bug largely disappears.

### Database — the layer nothing bypasses

Row-level security ([H10](H10-row-level-security.md)) pushes the filter into the database:

```sql
CREATE POLICY tenant_isolation ON documents
  USING (tenant_id = current_setting('app.current_tenant')::uuid);
```

Now *every* query — from any code path, any tool, any forgotten job — sees only permitted
rows. The CSV export, the reindex job, the `/debug` endpoint: all filtered, because they all
go through the database.

**Good at:** being unbypassable, and at data-level filtering (multi-tenancy —
[H09](H09-multi-tenancy-isolation.md)).

**Blind to:** business nuance. "Editors can edit unless the document is locked, unless they're
the owner, unless it's after the deadline" is awkward to express in SQL policies and belongs
in the service layer. And RLS depends on the app setting the session variable correctly on
every connection ([H10](H10-row-level-security.md)) — get that wrong and it fails open.

---

## The rule: authorize where you cannot be bypassed

Combining the layers:

```
   Edge      → is there a valid credential?          (authn — cheap early reject)
   Middleware→ coarse route/role rules               (defence in depth)
   SERVICE   → OBJECT-LEVEL authorization            ← the PRIMARY enforcement point
   Database  → tenant isolation / RLS                (unbypassable backstop)  H10
```

The service layer is the primary point because it is **the narrowest place every entry point
must pass through while still having the object and the business context.** The database is
the backstop for the one thing that must never leak regardless of application bugs: tenant
isolation ([H09](H09-multi-tenancy-isolation.md)).

Two failure modes this ordering prevents:

- **"Authorize in the controller"** → new entry points bypass it (the opening example).
- **"Authorize only in the database"** → cannot express business rules, and easy to
  misconfigure the session variable.

---

## Fail closed, everywhere

At *every* layer, an error is a denial ([H01](H01-where-does-authz-live.md)):

```python
def can(self, actor, action, obj) -> bool:
    try:
        return self._evaluate(actor, action, obj)
    except Exception:
        log.error("authz evaluation failed", ...)   # I08
        return False                                 # ✅ error → deny
```

The alternative — an authorization function that returns `True` or throws, wrapped in code
that treats a throw as "allow" — turns a database blip into a full bypass. This is not
hypothetical; it is a recurring cause of real incidents. **Fail closed** is the difference
between an outage and a breach.

---

## Where NOT to enforce

**The UI.** It is UX ([A07](../track-a/A07-client-vs-server.md)). Hide the button *and* check
on the server. The button is a courtesy; the server check is the control.

**Only at the edge/gateway.** A gateway can verify a token and do coarse routing, but it does
not know your objects. "The gateway checked auth" is authentication, not object authorization
([C02](../track-c/C02-authn-vs-authz-vs-session.md), [H12](H12-authz-in-microservices.md)).

**Scattered ad-hoc in each handler.** If every controller re-implements the ownership check,
they will drift, and one will be wrong. Centralise the *decision* (one `authz.can()`), even if
the *enforcement* happens at multiple layers.

---

## The pattern that scales

Separate the **decision** from the **enforcement** ([H01](H01-where-does-authz-live.md)'s PDP
vs PEP):

```python
# ONE decision function (the PDP) — the single source of truth.
class AuthzService:
    def can(self, actor, action, resource) -> bool: ...

# MANY enforcement points (PEPs) — all delegate to the one PDP.
#   - middleware: authz.can(user, "access", route)
#   - service:    authz.can(actor, "delete", document)
#   - RLS:        the DB policy, derived from the same rules
```

Now the *rules* live in one place ([H01](H01-where-does-authz-live.md)'s PAP), the *decision*
is one function, and enforcement happens at every layer that needs it — without duplicating
logic. This is exactly what a policy engine gives you at scale
([H11](H11-opa-cedar-or-sql.md)): one PDP, many PEPs.

---

## Terms defined in this chapter

`fail closed`, `middleware`

---

## What to remember

1. **The higher you enforce, the more paths can forget it. The lower, the harder to bypass.**
2. **Middleware does route-level rules; it is blind to *which object*.** Necessary, never
   sufficient.
3. **Object-level authorization belongs in the service layer** — after the object is loaded,
   and the one door every entry point passes through.
4. **Make the service the only path to the data**, and "a new entry point bypassed the check"
   stops happening.
5. **The database (RLS) is the unbypassable backstop** — use it for tenant isolation.
6. **Fail closed at every layer.** An error is a denial, or an outage becomes a breach.
7. **Separate the decision (one PDP) from enforcement (many PEPs).** Rules in one place,
   checks everywhere.

---

## Sources

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html) — "enforce authorization checks in the server-side code"
- [OWASP Top 10 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- *API Security in Action* (Neil Madden), Ch. 8 (identity-based access control)

---

**Next:** [H03 — Access control lists and direct permissions](H03-acls-and-direct-permissions.md)
