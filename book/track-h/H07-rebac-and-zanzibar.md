# H07 — ReBAC and the Zanzibar model

**Part H · Authorization** · *Builds on [H04](H04-rbac-and-when-it-breaks.md)*
---

## Why it matters

The requirement that broke RBAC ([H04](H04-rbac-and-when-it-breaks.md)) and does not fit ABAC
([H06](H06-abac.md)):

> *"Bob can view this document **because** it's in a folder that Alice shared with the
> engineering team, and Bob is on that team."*

Trace the *because*:

```
   Bob ──member of──▶ eng-team ──viewer of──▶ folder:7 ──parent of──▶ document:42
```

Bob's access to document 42 is not a role (RBAC) or an attribute (ABAC). It is a **path
through a graph of relationships.** The model built for exactly this is **ReBAC**, and Google
formalised it at planetary scale in a system called **Zanzibar**.

This is how Google Drive, GitHub, and most modern collaboration software actually work.

---

## What ReBAC is

> **Relationship-based access control derives permissions by traversing a graph of
> relationships between subjects and objects.**

The atomic fact is a **relation tuple**:

```
   object # relation @ subject
   ─────────────────────────────
   document:42 # viewer @ bob                  Bob is a viewer of document 42
   folder:7    # editor @ eng-team#member      members of eng-team edit folder 7
   folder:7    # parent @ document:42          document 42 is inside folder 7
   eng-team    # member @ bob                  Bob is a member of eng-team
```

Every grant is a tuple. A question — "may Bob view document 42?" — is answered by **searching
the graph** for a path from Bob to that permission on that object.

Notice the tuple `document:42 # viewer @ bob` *is* an ACL entry
([H03](H03-acls-and-direct-permissions.md)). ReBAC generalises ACLs: direct grants are still
just tuples, but now grants can also be *derived* through relationships you don't have to
enumerate.

---

## The two derivations that make it powerful

ReBAC's expressiveness comes from two ways a relation can be *computed* rather than stated
directly (Zanzibar calls these **userset rewrites**):

### 1. Computed userset — "editors are also viewers"

Within one object, one relation implies another:

```
   RULE:  viewer of X includes editor of X
   TUPLE: document:42 # editor @ carol
   ─────────────────────────────────────
   Carol is an editor → therefore also a viewer. No separate viewer tuple needed.
```

This is RBAC's role hierarchy ([H04](H04-rbac-and-when-it-breaks.md)), expressed as a graph
rule. One tuple, multiple implied permissions.

### 2. Tuple-to-userset — inheritance through the graph

The one that solves the opening example — a relation on one object derived through *another*
object:

```
   RULE:  viewer of a DOCUMENT includes viewer of its PARENT folder
   TUPLES:
     folder:7    # viewer @ eng-team#member     (eng-team can view the folder)
     folder:7    # parent @ document:42          (document 42 is in folder 7)
     eng-team    # member @ bob                  (Bob is on eng-team)
   ─────────────────────────────────────
   "May Bob view document:42?"
     → follow parent to folder:7
     → is Bob a viewer of folder:7?
     → follow to eng-team#member, is Bob a member? YES
   → ALLOW, without ever writing "document:42 # viewer @ bob"
```

**This is the whole game.** Folder sharing cascades to documents *automatically*, because
document access is *derived from* folder access through the `parent` relation. No copying
grants to every child ([H03](H03-acls-and-direct-permissions.md)); no role per object
([H04](H04-rbac-and-when-it-breaks.md)). One `parent` tuple, and inheritance falls out.

---

## Why Google built Zanzibar

Google runs Drive, YouTube, Photos, Cloud, and Maps on **one** authorization system —
Zanzibar. The design goals tell you what ReBAC has to solve at scale
([Zanzibar paper](https://research.google/pubs/pub48190/), 2019):

- **The check API** — one question, answered fast: *"may subject S do relation R on object
  O?"* Google answers billions per second, at single-digit-millisecond latency.
- **Global consistency** — the hard part. If Alice removes Bob's access and *then* shares a
  secret, Bob must not see it. Zanzibar's **"zookies"** (consistency tokens) ensure a check
  reflects at least a given snapshot, so authorization changes are never bypassed by
  replication lag. This is a genuinely deep distributed-systems problem, and it is why you
  should not hand-roll a global ReBAC system.
- **Flexibility** — every product models its own types and relations, on one engine.

The takeaways for *you* are the model (relation tuples + rewrites) and the API shape (a `check`
call), not the planetary infrastructure. Open-source implementations
([H08](H08-model-drive-in-openfga.md)) give you Zanzibar's model without running Google.

---

## The check API, and its hard sibling

ReBAC's core operation is the **check**:

```
   check(subject, relation, object) → allow | deny
   check(bob, viewer, document:42) → allow
```

Fast, because it is a targeted graph traversal from a known subject to a known object.

Its reverse is much harder:

```
   list-objects(subject, relation) → "which documents may Bob view?"
   list-subjects(object, relation) → "who may view document:42?"   ← "who can access this?"
```

This is the same "who can access X?" problem ABAC had ([H06](H06-abac.md)), and in ReBAC it
means traversing the graph *backwards* from every reachable object — expensive, and a known
scaling challenge ([H08](H08-model-drive-in-openfga.md)). Systems handle it with indexes and
approximations. The lesson: **design around `check` being cheap and `list` being costly** —
paginate list results, cache them, and don't put a reverse query on a hot path.

---

## ReBAC vs the others

| | RBAC | ABAC | **ReBAC** |
|---|---|---|---|
| Decides from | Roles | Attributes | **Relationships (a graph)** |
| Object-specific access | ❌ ([H04](H04-rbac-and-when-it-breaks.md)) | Awkward | ✅ **native** |
| Inheritance (folders→docs) | ❌ | Awkward | ✅ **tuple-to-userset** |
| Sharing ("share with Bob") | ❌ role explosion | ❌ | ✅ **one tuple** |
| "Who can access X?" | Easy | Hard | **Hard (list)** |
| Cross-cutting attribute rules | ❌ | ✅ | ❌ (not its job) |
| Best for | Functional/admin permissions | Compliance, context | **Collaboration, sharing** |

Read the "best for" row: **each model owns a different kind of requirement.** ReBAC owns
sharing and hierarchy — the core of collaboration software. It does *not* replace ABAC's
attribute rules ("confidential + Legal + business hours" is still ABAC) or RBAC's functional
roles ("who can access the admin panel"). A real Google-Drive-scale system uses:

- **ReBAC** for document/folder sharing and inheritance.
- **RBAC** for organisational/admin roles.
- **ABAC** for compliance overlays (data residency, classification).

---

## When to reach for ReBAC

✅ **Your app's core is sharing and collaboration** — documents, folders, projects, repos.
This is the [H04](H04-rbac-and-when-it-breaks.md) breaking point, and ReBAC is its answer.
✅ **Access inherits through a hierarchy** — folders to files, orgs to repos, projects to
resources.
✅ **Fine-grained, per-object, per-user grants** at scale.

❌ **Simple role-based needs** — RBAC is lighter; don't bring a graph engine to
"admins/editors/viewers."
❌ **Purely attribute/context rules** — that's ABAC.
❌ **You need "who can access X?" as a hot-path query** — possible, but design for it
deliberately.

The honest note: ReBAC is more machinery than RBAC. Adopt it when the sharing model demands it
(and it will demand it, the moment [H04](H04-rbac-and-when-it-breaks.md)'s sentence lands), not
speculatively. [H08](H08-model-drive-in-openfga.md) builds a real one so you can feel the
trade.

---

## Terms defined in this chapter

`ReBAC`, `Zanzibar`, `relation tuple`, `userset`, `userset rewrite`, `computed userset`,
`tuple-to-userset`, `check API`

---

## What to remember

1. **ReBAC derives permissions by traversing a graph of relationships.** The atomic fact is a
   **relation tuple**: `object#relation@subject`.
2. A direct tuple **is** an ACL entry — ReBAC generalises ACLs by *deriving* grants you'd
   otherwise enumerate.
3. **Two derivations do the work:** computed userset (editor ⇒ viewer) and **tuple-to-userset**
   (folder sharing cascades to documents). The second solves the sharing/inheritance problem.
4. **Zanzibar** is Google's planetary ReBAC system — one `check` API, global consistency via
   consistency tokens. You want the *model*, not the infrastructure.
5. **`check` is cheap; the reverse "who can access X?" (`list`) is hard.** Design around it.
6. ReBAC owns **sharing and hierarchy**; RBAC owns **roles**; ABAC owns **attribute rules.**
   Large systems use all three.
7. Reach for ReBAC when sharing is your core — [H08](H08-model-drive-in-openfga.md) builds one.

---

## Sources

- Pang et al., [*Zanzibar: Google's Consistent, Global Authorization System*](https://research.google/pubs/pub48190/) (USENIX ATC 2019) — the foundational paper
- [zanzibar.academy](https://zanzibar.academy/) — an approachable walkthrough of the model
- [OpenFGA documentation](https://openfga.dev/docs) ([H08](H08-model-drive-in-openfga.md))
- [SpiceDB](https://authzed.com/docs) — another open Zanzibar implementation

---

**Next:** [H08 — Model Google Drive's sharing rules in OpenFGA](H08-model-drive-in-openfga.md)
