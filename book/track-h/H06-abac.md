# H06 — ABAC and policy-based access control

**Part H · Authorization** · *Builds on [H04](H04-rbac-and-when-it-breaks.md)*
---

## What ABAC is

> **Attribute-based access control makes decisions by evaluating a *policy* against the
> attributes of the subject, the resource, the action, and the environment.**

```
   ALLOW if:
     subject.department == "Legal"          ← who they are (attribute)
     AND resource.tag == "confidential"     ← what they're accessing (attribute)
     AND action == "read"                    ← what they're doing
     AND environment.ip in company_range     ← the context (attribute)
     AND environment.time in business_hours
```

The four attribute categories (from [NIST SP 800-162](https://csrc.nist.gov/pubs/sp/800/162/upd1/final)):

| Category | Examples |
|---|---|
| **Subject** | department, clearance, role, age, employment status |
| **Resource** | owner, tag, classification, project, creation date |
| **Action** | read, write, delete, share, export |
| **Environment** | time, IP, location, device trust, risk score |

Where RBAC asks *"what role does the user have?"*, ABAC asks *"do the attributes satisfy the
policy?"* — a far more expressive question, because attributes can describe anything, including
things that change per request (time, IP, [D18](../track-d/D18-step-up-auth-and-aal.md)'s risk
signals).

---

## A tiny policy engine

```python
from dataclasses import dataclass

@dataclass
class Context:
    subject: dict        # {'department': 'Legal', 'clearance': 3}
    resource: dict       # {'tag': 'confidential', 'owner': 'u_99'}
    action: str          # 'read'
    environment: dict    # {'ip': '10.0.0.5', 'hour': 14}

def can_read_confidential(ctx: Context) -> bool:
    return (
        ctx.subject.get("department") == "Legal"
        and ctx.resource.get("tag") == "confidential"
        and ctx.action == "read"
        and in_company_range(ctx.environment.get("ip"))
        and 9 <= ctx.environment.get("hour", 0) < 18
    )
```

In practice you would not hand-write each rule as a function — you would express them in a
**policy language** so rules are data, not code. That is **policy-based access control (PBAC)**
— ABAC with the policies externalised into a language like Rego (OPA) or Cedar
([H11](H11-opa-cedar-or-sql.md)):

```rego
# OPA / Rego
allow if {
    input.subject.department == "Legal"
    input.resource.tag == "confidential"
    input.action == "read"
    net.cidr_contains("10.0.0.0/8", input.environment.ip)
}
```

The value of externalising: policies become **auditable, testable, versioned, and changeable
without a deploy** ([H11](H11-opa-cedar-or-sql.md)) — "policy as code."

---

## ABAC's power and its cost

### The power

ABAC expresses rules no role model can:

- **Cross-cutting rules** — "confidential documents, Legal department" spans every document.
- **Contextual rules** — time, location, device, risk ([D18](../track-d/D18-step-up-auth-and-aal.md)).
- **Fine-grained conditions** — "own documents freely; others' only if in the same project."
- **Dynamic attributes** — evaluated fresh each request, so a change in department or a rise in
  risk takes effect immediately (no stale role assignment).

This makes ABAC the model for **compliance and regulatory** requirements
([I11](../track-i/I11-compliance.md)), which are almost always attribute-and-context rules
("PII may only be accessed by trained staff, from managed devices, within the EU").

### The cost

ABAC's expressiveness is also its liability:

**1. "Who can access this?" becomes hard to answer.** With RBAC you query the role table. With
ABAC, access depends on runtime attributes, so the only way to know who can reach a resource is
to evaluate the policy against every possible subject and context — often infeasible. This
hurts audits ([H13](H13-audit-logging.md)) and reverse queries
([H08](H08-model-drive-in-openfga.md) — "list objects").

**2. Attributes must be trustworthy and available.** The policy is only as good as its inputs
([H01](H01-where-does-authz-live.md)'s PIP). Where does `subject.department` come from? Is it
current? What if the attribute source is down ([H02](H02-the-enforcement-point.md) — fail
closed)? A stale or spoofable attribute is an authorization bug.

**3. Policies get complex and interact.** Many overlapping rules produce conflicts (one allows,
one denies) and unexpected combinations. You need a clear **combining algorithm** (deny
overrides? first applicable?) and thorough testing, or the policy set becomes unanalysable.

**4. Performance.** Gathering attributes and evaluating rich policies on every request costs
more than an RBAC lookup. Caching helps but complicates freshness.

---

## RBAC vs ABAC — and why you use both

| | **RBAC** | **ABAC** |
|---|---|---|
| Decision from | Roles | Attributes + policy |
| Expresses | "editors can edit" | "Legal reads confidential from EU during hours" |
| "Who can access X?" | Easy (query roles) | **Hard** (evaluate all subjects) |
| Contextual rules | ❌ | ✅ |
| Cross-cutting rules | ❌ | ✅ |
| Auditability | ✅ Clear | ⚠️ Depends on attributes |
| Performance | Fast | Slower |
| Complexity | Low | High |

**Neither is the whole answer.** The mature pattern is **RBAC as the base, ABAC for the
conditions**:

```
   RBAC decides the coarse grant:   "editors may edit documents"
   ABAC refines it:                 "...unless the document is locked,
                                      or after the deadline, or from an
                                      untrusted device"
```

This hybrid — sometimes called RBAC-with-attributes, or "attribute-refined RBAC" — gives you
RBAC's auditability for the common case and ABAC's expressiveness for the exceptions. It is
what most real systems converge on, and it is why [H11](H11-opa-cedar-or-sql.md) frames the
choice as "which engine," not "RBAC or ABAC."

---

## Where ABAC does *not* fit

ABAC handles attribute-and-rule authorization. It handles **relationship** authorization
poorly — "Bob can view this document because it's in a folder shared with his team" is a graph
traversal, not an attribute check ([H07](H07-rebac-and-zanzibar.md)). You *can* encode
relationships as attributes, but it is awkward and it reintroduces the "who can access this?"
problem in its worst form.

```
   Attribute rules ("confidential + Legal")     → ABAC          H06
   Relationship rules ("shared via a folder")   → ReBAC         H07
   Role rules ("editors edit")                  → RBAC          H04
```

Most large systems use all three, for the parts each fits. Recognising which requirement is
which — attribute, relationship, or role — is the skill; [H11](H11-opa-cedar-or-sql.md) is how
you choose the tooling.

---

## Terms defined in this chapter

`ABAC`, `attribute`, `PBAC`

---

## What to remember

1. **ABAC decides from the attributes of subject, resource, action, and environment** — and a
   policy over them.
2. It expresses what RBAC cannot: **cross-cutting rules** ("Legal + confidential") and
   **contextual rules** (time, IP, risk, device).
3. **PBAC** externalises those policies into a language (Rego, Cedar) — "policy as code":
   auditable, testable, versioned, deploy-free changes ([H11](H11-opa-cedar-or-sql.md)).
4. The cost: **"who can access X?" becomes hard**, attributes must be trustworthy and
   available (fail closed if not), policies interact, and evaluation is slower.
5. **Use RBAC as the base, ABAC for the conditions.** The hybrid is what real systems converge
   on.
6. ABAC handles **relationships poorly** — those are ReBAC ([H07](H07-rebac-and-zanzibar.md)).
   Match the requirement (attribute / relationship / role) to the model.

---

## Sources

- [NIST SP 800-162 — Guide to Attribute Based Access Control (ABAC)](https://csrc.nist.gov/pubs/sp/800/162/upd1/final)
- [OPA / Rego documentation](https://www.openpolicyagent.org/docs/latest/) ([H11](H11-opa-cedar-or-sql.md))
- [AWS Cedar](https://www.cedarpolicy.com/) ([H11](H11-opa-cedar-or-sql.md))

---

**Next:** [H07 — ReBAC and the Zanzibar model](H07-rebac-and-zanzibar.md)
