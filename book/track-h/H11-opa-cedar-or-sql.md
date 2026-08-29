# H11 — OPA, Cedar, or just SQL?

**Part H · Authorization** · *Builds on [H06](H06-abac.md), [H08](H08-model-drive-in-openfga.md)*
---

## The spectrum

```
   Simpler ◄──────────────────────────────────────────────► More capable
   inline    DB queries    library      policy engine    dedicated authz service
   if/else   (SQL, RLS)    (Casbin,      (OPA/Rego,       (OpenFGA, SpiceDB,
                            Oso)          Cedar)            AuthZed)
   H01/H04   H10           —             H06/H11           H07/H08
```

The rule: **move right only when the pain to your left is real.** Each step buys expressiveness
and central management at the cost of a new component to run, learn, and secure.

---

## The options

### Just code / SQL / RLS — start here

For most applications, authorization is a function and a few database predicates:

```python
def can(user, action, resource) -> bool:
    if user.is_admin: return True
    if action == "read":   return resource.owner == user or shared_with(resource, user)
    if action == "write":  return resource.owner == user and not resource.locked
    return False
```

Plus RLS for the unbypassable tenant filter ([H10](H10-row-level-security.md)). This is
correct, fast, debuggable, and needs no new infrastructure. **The majority of applications
never need more.** The failure of Team A is treating "just code" as embarrassing when it is
often right.

The moment to leave: when the *decision* logic is duplicated across many enforcement points and
drifting ([H02](H02-the-enforcement-point.md)) — which is Team B's failure. The fix for that is
first "centralise the decision into one function," not "adopt a policy engine."

### Embedded library — Casbin, Oso, Cerbos

A library that gives you a policy model and a decision function inside your process:

```python
# Oso-style
oso.authorize(user, "read", document)   # raises if denied
```

**Buys:** a structured model (RBAC/ABAC/ReBAC patterns) without running a separate service;
policies as data rather than scattered `if`s. **Costs:** a dependency and a small learning
curve. A good middle step when your rules outgrow inline code but you don't want new
infrastructure.

### Policy engine — OPA (Rego) or Cedar

A general engine that evaluates policies expressed in a dedicated language, decoupled from your
code ([H06](H06-abac.md)):

**OPA (Open Policy Agent)** — uses **Rego**, a declarative query language. General-purpose:
authorizes APIs, Kubernetes admission, Terraform plans, CI. Runs as a sidecar or library.

```rego
package authz
default allow := false
allow if {
  input.action == "read"
  input.resource.owner == input.subject.id
}
allow if input.subject.roles[_] == "admin"
```

**Cedar (AWS)** — a purpose-built *authorization* language, designed to be **analysable**:
typed, with tooling that can *prove* properties about your policies (e.g. "no policy grants
public write"). More constrained than Rego, and safer for exactly that reason.

```cedar
permit(principal, action == Action::"read", resource)
  when { resource.owner == principal };
```

| | **OPA / Rego** | **Cedar** |
|---|---|---|
| Scope | General policy (any decision) | Authorization specifically |
| Language | Rego (powerful, quirky) | Cedar (typed, analysable) |
| Analysis | Limited | **Formal — can prove properties** |
| Ecosystem | Huge (K8s, CI, cloud) | AWS-native (Verified Permissions), growing |
| Best when | Policy-as-code across your stack | Authorization you want to *verify* |

**Buys** ([H06](H06-abac.md)): policy as code — versioned, tested, reviewed, changeable without
a deploy; one place for rules ([H01](H01-where-does-authz-live.md)'s PAP); rich ABAC.
**Costs:** a language to learn, an engine to operate, a network hop (as a sidecar), and the
"who can access X?" problem stays hard.

### Dedicated authorization service — OpenFGA, SpiceDB

A ReBAC/Zanzibar system ([H07](H07-rebac-and-zanzibar.md), [H08](H08-model-drive-in-openfga.md)):
relationships as data, a `check` API, global consistency.

**Buys:** the sharing/inheritance model nothing else expresses, at scale
([H04](H04-rbac-and-when-it-breaks.md)). **Costs:** the most infrastructure — a stateful service,
data sync, the `list-objects` cost ([H08](H08-model-drive-in-openfga.md)).

---

## The decision tree

```
Is authorization "roles + own-your-stuff", roughly?
│
├── YES ──> Just code + RLS.  H10.  Don't add a system.  ← most apps
│
└── NO ──> What KIND of complexity?
           │
           ├── Cross-cutting ATTRIBUTE/context rules
           │   (confidential + Legal + business hours) ──> ABAC engine:
           │                                               OPA or Cedar.  H06
           │   └── Want to PROVE policy properties? ──> Cedar.
           │
           ├── Sharing / hierarchy / RELATIONSHIPS
           │   (Drive-style, folders→docs) ────────────> ReBAC service:
           │                                               OpenFGA / SpiceDB.  H07/H08
           │
           └── Rules outgrowing if/else but no new
               infra wanted ──────────────────────────> Embedded library
                                                          (Oso, Casbin, Cerbos).
```

Read it as: **the model follows the requirement** ([H06](H06-abac.md),
[H07](H07-rebac-and-zanzibar.md)). Attribute rules → policy engine. Relationship rules → ReBAC
service. Neither, just growing → a library. Simple → code. Match the tool to the *kind* of
authorization you actually have, not to what's fashionable.

---

## Regardless of the engine: PDP vs PEP

Whatever you choose, the architecture from [H01](H01-where-does-authz-live.md)/[H02](H02-the-enforcement-point.md)
holds:

- **The engine is the PDP** (decision) — OPA, Cedar, OpenFGA, or your own function.
- **Your code is the PEP** (enforcement) — it *calls* the PDP and blocks, at the service layer,
  failing closed ([H02](H02-the-enforcement-point.md)).

A policy engine does not enforce anything — it *answers questions*. You still have to ask it,
everywhere it matters, and act on the answer. Adopting OPA does not fix a missing check
([H14](H14-attack-your-own-authorization.md)); it centralises the *logic* of the checks you
still have to write.

Two more universals:

- **Fail closed.** If the engine is unreachable, deny ([H02](H02-the-enforcement-point.md)). A
  policy sidecar going down must not open your doors.
- **Cache decisions carefully.** A network call per authorization is latency; caching is
  correctness risk (stale grants). Short TTLs, and invalidate on grant changes.

---

## The honest recommendation

1. **Start with code + RLS.** Resist the urge to adopt a system before you feel the pain. Team
   A's mistake is the common one among engineers who've read this track.
2. **When decision logic duplicates and drifts, centralise it into one function first** — that
   alone fixes Team B, without new infrastructure.
3. **Adopt an engine when the *kind* of rule demands it:** a policy engine for attribute rules,
   a ReBAC service for sharing. Let the requirement pick the tool.
4. **Prefer analysable tools where you can** (Cedar over Rego, if the fit is right) — being able
   to *prove* "no policy grants public write" is worth a lot.

There is no prize for the most sophisticated authorization stack. There is a prize for one you
can reason about, that a forgotten check fails closed on, and that answers "who can do what?"
when an auditor asks ([I11](../track-i/I11-compliance.md)).

---

## Terms defined in this chapter

`OPA`, `Rego`, `Cedar`, `policy as code`

---

## What to remember

1. The question is **"how much machinery does *this* system justify?"** — and both over- and
   under-engineering are common failures.
2. **Start with code + RLS.** Most applications never need more.
3. When rules **duplicate and drift, centralise the decision into one function** before
   reaching for an engine.
4. **The model follows the requirement:** attribute/context rules → **OPA or Cedar**;
   sharing/hierarchy → **OpenFGA/SpiceDB**; growing-but-simple → an **embedded library**.
5. **Cedar is analysable** — you can prove policy properties; prefer it where it fits.
6. **The engine is the PDP; your code is the PEP.** An engine centralises logic; it does not
   enforce or fix a missing check.
7. **Fail closed** if the engine is unreachable; cache decisions with short TTLs.

---

## Sources

- [Open Policy Agent (OPA) / Rego](https://www.openpolicyagent.org/docs/latest/)
- [Cedar Policy Language](https://www.cedarpolicy.com/) and [AWS Verified Permissions](https://aws.amazon.com/verified-permissions/)
- [OpenFGA](https://openfga.dev/) / [SpiceDB](https://authzed.com/) ([H08](H08-model-drive-in-openfga.md))
- [Oso](https://www.osohq.com/) / [Cerbos](https://cerbos.dev/) / [Casbin](https://casbin.org/) — embedded options

---

**Next:** [H12 — Authorization in microservices: who decides, and where?](H12-authz-in-microservices.md)
