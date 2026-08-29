# H01 — Where does authorization actually live in your app?

**Part H · Authorization** · *Builds on [C02](../track-c/C02-authn-vs-authz-vs-session.md)*
---

## The five components of an authorization system

The formal vocabulary ([XACML](https://en.wikipedia.org/wiki/XACML)'s, and worth learning
because policy engines use it — [H11](H11-opa-cedar-or-sql.md)):

```
   ┌──────────────────────────────────────────────────────────────────┐
   │  Request: "may user 4471 DELETE document 42?"                     │
   └───────────────────────────────┬──────────────────────────────────┘
                                   │
   ┌───────────────────────────────▼──────────────────────────────────┐
   │  PEP  (Policy ENFORCEMENT Point)                                  │
   │       Intercepts the request. Asks the PDP. Allows or blocks.     │
   │       ← this is where your code says `if not allowed: abort(403)` │
   └───────────────────────────────┬──────────────────────────────────┘
                                   │ "may they?"
   ┌───────────────────────────────▼──────────────────────────────────┐
   │  PDP  (Policy DECISION Point)                                     │
   │       Evaluates the policy against the facts. Returns yes/no.     │
   └──────────┬────────────────────────────────────┬──────────────────┘
              │ needs facts                          │ needs rules
   ┌──────────▼───────────┐              ┌───────────▼──────────────────┐
   │  PIP (Info Point)     │              │  PAP (Administration Point)  │
   │  Where facts come from│              │  Where policy is written     │
   │  (DB: who owns doc 42,│              │  (roles, rules, relations)    │
   │   what roles 4471 has)│              │                              │
   └──────────────────────┘              └──────────────────────────────┘
```

| Component | Question | In a small app |
|---|---|---|
| **PEP** — enforcement | *Where is it blocked?* | Middleware / your handler |
| **PDP** — decision | *Who decides yes/no?* | A function, or a policy engine |
| **PIP** — information | *Where are the facts?* | Your database |
| **PAP** — administration | *Where are rules written?* | Config, a roles table, a policy file |

In a small application all four can be one function. The value of the vocabulary is that as
you grow, these **separate** — and knowing which is which tells you what to move where
([H12](H12-authz-in-microservices.md), [H11](H11-opa-cedar-or-sql.md)).

A hidden UI button is a **PEP in the browser** — no PEP at all, because the browser is not trusted
([A07](../track-a/A07-client-vs-server.md)).

---

## The two rules that prevent most breaches

Before any model — RBAC, ABAC, ReBAC ([H04](H04-rbac-and-when-it-breaks.md),
[H06](H06-abac.md), [H07](H07-rebac-and-zanzibar.md)) — two principles decide whether you are
safe.

### 1. Deny by default

Every request is denied unless a rule explicitly permits it.

```python
# ❌ allow by default — a route you forget to protect is OPEN
@app.get("/admin/users")
def admin_users():
    return all_users()                    # no check → anyone reaches it

# ✅ deny by default — the framework blocks everything not explicitly allowed
@app.get("/admin/users")
@require_permission("users:list")         # must be present, or access is denied
def admin_users():
    return all_users()
```

The distinction is what happens to a route you *forget*. With allow-by-default, a forgotten
check means an **open** endpoint — a silent vulnerability that ships and works fine until
someone finds it ([H14](H14-attack-your-own-authorization.md)). With deny-by-default, a
forgotten check means a **broken** endpoint — you notice immediately, in development, because
your own legitimate access is denied.

> **Design so that forgetting a check fails *closed* and *loud*, not open and silent.** This
> single choice prevents a large fraction of access-control bugs.

### 2. Fail closed

On *error* — the database is down, the policy engine times out, the permission is
unrecognised — **deny**.

```python
try:
    allowed = pdp.check(user, "delete", doc)
except Exception:
    allowed = False          # ✅ error → deny.  H02.
```

An authorization system that fails *open* turns any outage into a security incident: the
policy service hiccups, and suddenly everyone can do everything. Fail closed, always
([H02](H02-the-enforcement-point.md)).

---

## Authorization is not one check — it is a hierarchy

A naive app has *one* possible check location. Real authorization is layered, and
each layer answers a different question:

```
   1. CAN THIS APP act for this user?        ← scopes (OAuth)        F07
   2. Is this a valid, in-scope request?     ← input validation
   3. Does this ROLE permit this operation?  ← RBAC                  H04
   4. May they act on THIS OBJECT?           ← object authz (IDOR)   H14
   5. Is the DATA itself filtered to them?   ← row-level security    H10
```

The most common serious vulnerability lives at **layer 4**: an app checks 1–3 (the user is
logged in, has the `editor` role, and the request is well-formed) and skips 4 (*is this
particular document theirs?*). That is IDOR ([H14](H14-attack-your-own-authorization.md)),
and it is why [C02](../track-c/C02-authn-vs-authz-vs-session.md) hammers the "subject **and
the object**" framing.

**A scope check is not an object check. A role check is not an object check.** You need all
the layers that apply.

---

## Where the enforcement point actually goes

This is [H02](H02-the-enforcement-point.md)'s question, previewed because it is the practical
core of "where does authorization live":

| Location | Catches | Misses |
|---|---|---|
| **UI** | Nothing (it's UX) | Everything — not a control |
| **Middleware** (per route) | Route-level rules | Object-level rules; routes you forget |
| **Service layer** | Object rules, reused across entry points | Direct DB access |
| **Database** (RLS) | Everything that queries the DB | App-level nuance |

The insight that drives the rest of the track: **the higher up you enforce, the easier it is
to forget a path; the lower down, the harder it is to bypass.** A check in the controller is
missed by the background job, the GraphQL resolver, the admin console, and the CSV export
that all reach the same data another way ([H02](H02-the-enforcement-point.md)). A check in
the database is missed by nothing that uses the database
([H10](H10-row-level-security.md)).

---

## The mental model for the whole track

```
   WHO can do WHAT to WHICH resource, and WHERE is that decided and enforced?
     │            │         │                    │              │
   principal    action    object              PDP            PEP
   (Track D/E)  (verb)   (the thing)        (the model:      (the location:
                                             H03–H08)         H02, H10, H12)
```

Tracks A–G established *who* (authentication, sessions, federation). Track H is *what*,
*which*, and *where*:

- **The model** — how you express "who may do what": ACLs ([H03](H03-acls-and-direct-permissions.md)),
  RBAC ([H04](H04-rbac-and-when-it-breaks.md)), ABAC ([H06](H06-abac.md)),
  ReBAC ([H07](H07-rebac-and-zanzibar.md)).
- **The location** — where it runs: enforcement point ([H02](H02-the-enforcement-point.md)),
  the database ([H10](H10-row-level-security.md)), across services
  ([H12](H12-authz-in-microservices.md)).
- **The proof** — that it happened: audit logging ([H13](H13-audit-logging.md)).
- **The failures** — when it doesn't: IDOR and friends
  ([H14](H14-attack-your-own-authorization.md)).

And the load-bearing fact from [C01](../track-c/C01-auth-is-five-different-problems.md):
**this is the layer you cannot buy** ([C05](../track-c/C05-build-vs-buy.md)). No provider
knows what "may reshare a folder but only inside the company" means in your product. The
model is your domain model. Tools help you *express and enforce* it; they cannot *define* it.

---

## Terms defined in this chapter

`policy`, `policy decision point` (PDP), `policy enforcement point` (PEP),
`policy information point` (PIP), `deny by default`

---

## What to remember

1. **Broken access control is #1 in the OWASP Top 10** — because "where does the check go, on
   every path?" is genuinely hard.
2. **Authorization in the UI is not a control.** It is UX. The PEP must be server-side.
3. Five components: **PEP** (enforce), **PDP** (decide), **PIP** (facts), **PAP** (rules). One
   function in a small app; they separate as you grow.
4. **Deny by default** — so a forgotten check fails *closed and loud*, not open and silent.
5. **Fail closed** — an error is a denial, never an allowance.
6. Authorization is a **hierarchy**: scope → role → **object** → data. IDOR lives where you
   skip the object check.
7. **Higher enforcement is easier to forget; lower is harder to bypass.**
8. **This layer cannot be bought.** The model is your domain.

---

## Sources

- [OWASP Top 10 2021 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [NIST SP 800-162 — Guide to Attribute Based Access Control](https://csrc.nist.gov/pubs/sp/800/162/upd1/final) (the PEP/PDP/PIP/PAP model)

---

**Next:** [H02 — The enforcement point: middleware, service layer, or database?](H02-the-enforcement-point.md)
