# H08 — Model Google Drive's sharing rules in OpenFGA

**Part H · Authorization** · *Builds on [H07](H07-rebac-and-zanzibar.md)*
---

## The authorization model

OpenFGA models declare **types**, their **relations**, and the **rewrite rules** that derive
relations ([H07](H07-rebac-and-zanzibar.md)):

```python
# OpenFGA DSL
model
  schema 1.1

type user

type organization
  relations
    define member: [user]

type folder
  relations
    define owner: [user]
    define parent: [folder]
    define viewer: [user, organization#member] or editor or viewer from parent
    define editor: [user] or owner or editor from parent

type document
  relations
    define parent: [folder]                          # a document lives in a folder
    define owner: [user]
    # editors: direct grants, OR the owner, OR editors of the parent folder
    define editor: [user] or owner or editor from parent
    # viewers: direct grants (incl. anyone via public), OR editors, OR viewers of the parent
    define viewer: [user, user:*] or editor or viewer from parent
```

Read the two lines that do the heavy lifting:

**`viewer from parent`** — this is **tuple-to-userset** ([H07](H07-rebac-and-zanzibar.md)). "A
viewer of this document includes anyone who is a viewer of its parent folder." *That single
clause is folder-sharing-cascades-to-documents* (requirement 2). No copying grants to children.

**`editor or viewer`** on `viewer` — **computed userset**: every editor is automatically a
viewer (requirement 3). Owners are editors (via `owner` in the `editor` definition), so owners
can do everything.

**`user:*`** in document `viewer` — the **public** wildcard (requirement 4). A single tuple
makes a document world-viewable.

**`organization#member`** in folder `viewer` — org membership grants folder access (requirement
5). This is a *userset* — "all members of this org" — referenced without enumerating them.

The entire Drive sharing model, in ~20 lines. That is the payoff of ReBAC.

---

## The relationship tuples (the facts)

The model is the *rules*; tuples are the *facts* ([H07](H07-rebac-and-zanzibar.md)):

```python
tuples = [
    # Alice owns folder:planning; document:budget is inside it.
    ("user:alice",              "owner",  "folder:planning"),
    ("folder:planning",         "parent", "document:budget"),   # ← the inheritance link

    # Alice shares folder:planning with the engineering team (viewer).
    ("organization:acme#member","viewer", "folder:planning"),

    # Bob is a member of Acme.
    ("user:bob",                "member", "organization:acme"),

    # Carol gets DIRECT edit access to one document.
    ("user:carol",              "editor", "document:budget"),

    # document:public-memo is world-readable.
    ("user:*",                  "viewer", "document:public-memo"),
]
```

Now the checks resolve *without any tuple ever saying "Bob is a viewer of document:budget":*

```python
check("user:bob",   "viewer", "document:budget")   # → ALLOW
#   bob member of acme → acme#member viewer of folder:planning
#   → folder:planning parent of document:budget → viewer from parent → ALLOW

check("user:carol", "editor", "document:budget")   # → ALLOW (direct)
check("user:carol", "viewer", "document:budget")   # → ALLOW (editor ⇒ viewer)
check("user:dave",  "viewer", "document:budget")   # → DENY  (no path)
check("user:dave",  "viewer", "document:public-memo") # → ALLOW (user:* wildcard)
```

Bob's access is *derived*, live, from the graph. Remove the `folder:planning#parent` tuple, or
Bob's org membership, and his access to the document vanishes — no cascade of deletes, because
it was never stored per-document.

---

## Enforcing it in your app

OpenFGA is the **PDP** ([H01](H01-where-does-authz-live.md)); your service layer is the **PEP**
([H02](H02-the-enforcement-point.md)):

```python
import openfga_sdk

fga = openfga_sdk.OpenFgaClient(config)

class DocumentService:
    def get(self, actor: str, doc_id: str) -> Document:
        # The check call — the PDP decides. H07.
        allowed = fga.check(user=f"user:{actor}",
                            relation="viewer",
                            object=f"document:{doc_id}").allowed
        if not allowed:                     # fail closed — H02
            raise Forbidden()
        return self.repo.get(doc_id)

    def share(self, actor: str, doc_id: str, target: str, relation: str):
        # Sharing is itself authorized — only owners share. H03.
        if not fga.check(f"user:{actor}", "owner", f"document:{doc_id}").allowed:
            raise Forbidden()
        # Writing a tuple IS the grant.
        fga.write(tuples=[(f"user:{target}", relation, f"document:{doc_id}")])
        self.audit.record(actor, "share", doc_id, target, relation)   # H13
```

Two things to notice:

- **Sharing = writing a tuple.** The "Share" button in the UI writes one relation tuple. That
  is the entire grant ([H03](H03-acls-and-direct-permissions.md)).
- **Sharing is authorized too** — only owners may share, checked before the write
  ([H03](H03-acls-and-direct-permissions.md)). Forgetting this is a privilege escalation
  ([H14](H14-attack-your-own-authorization.md)).

---

## The reverse query, in practice

"Which documents can Bob view?" is the hard `list-objects` query
([H07](H07-rebac-and-zanzibar.md)):

```python
docs = fga.list_objects(user="user:bob", relation="viewer", type="document")
# Returns the document IDs Bob can view — by traversing the graph backwards.
```

OpenFGA supports it, but it is **more expensive than `check`** and has practical limits.
Design guidance ([H07](H07-rebac-and-zanzibar.md)):

- **Don't put `list-objects` on a hot path.** Use it for a "shared with me" page, cached and
  paginated — not per-request.
- **Prefer `check` where possible.** To render a document, `check` it; don't `list` everything
  and filter.
- **Combine with your database.** List the candidate documents from your DB (by owner, recent,
  etc.), then `check` the page of results — often faster than a global `list`.

This is the standard tension of ReBAC: `check` is cheap, reverse queries are costly, and good
architecture keeps the costly one off the critical path.

---

## Consistency: the Zanzibar hard part, handled for you

Recall Zanzibar's consistency problem ([H07](H07-rebac-and-zanzibar.md)): if you revoke Bob's
access and *then* share a secret, Bob must not see it. OpenFGA (and SpiceDB) expose
consistency controls so a `check` can be required to reflect a recent write:

```python
fga.check(..., consistency="HIGHER_CONSISTENCY")   # reflect recent writes; slower
# default: MINIMIZE_LATENCY — may lag slightly, faster
```

Use higher consistency immediately after a security-sensitive change (a revocation, a
share-then-restrict sequence). This is exactly the problem you would get wrong hand-rolling a
ReBAC system, and the reason to use a real implementation ([H07](H07-rebac-and-zanzibar.md)).

---

## Should you adopt OpenFGA?

The honest trade ([C05](../track-c/C05-build-vs-buy.md), [H11](H11-opa-cedar-or-sql.md)):

**Yes, if** sharing and hierarchy are your product's core (collaboration tools, anything
Drive-shaped), you're at real scale, and per-object grants are proliferating past what your DB
can model cleanly.

**No, if** your needs are role-based ([H04](H04-rbac-and-when-it-breaks.md)) — a dedicated
authorization service is overkill for admins/editors/viewers. Start with RBAC and a bit of
ACL; adopt ReBAC when [H04](H04-rbac-and-when-it-breaks.md)'s breaking point actually arrives.

The alternatives ([H11](H11-opa-cedar-or-sql.md)): **SpiceDB** (another Zanzibar
implementation), **Ory Keto**, or — for simpler cases — modelling relationships directly in
your database with recursive queries ([H10](H10-row-level-security.md)). OpenFGA is chosen here
because it is open, close to the paper, and easy to run locally
([repo tag `ep-H08-openfga`](../../README.md)).

---

## Terms defined in this chapter

`list-objects`, `OpenFGA`, `authorization model`

---

## What to remember

1. **ReBAC finally expresses Drive's sharing rules** — the whole model is ~20 lines of types
   and rewrite rules.
2. **`viewer from parent` (tuple-to-userset) is folder-sharing-cascades-to-documents.** One
   clause, inheritance for free ([H07](H07-rebac-and-zanzibar.md)).
3. **Sharing = writing one relation tuple.** The Share button writes a tuple; that is the
   grant.
4. **Sharing is itself authorized** — only owners share. Check before the write.
5. **OpenFGA is the PDP; your service layer is the PEP.** `check` before every access, fail
   closed.
6. **`check` is cheap; `list-objects` ("shared with me") is costly** — keep it off hot paths,
   paginate, combine with your DB.
7. **Consistency controls** handle the Zanzibar revoke-then-share problem — use higher
   consistency after sensitive changes.
8. Adopt it when **sharing is your core**, not for role-based needs.

---

## Sources

- [OpenFGA documentation](https://openfga.dev/docs) — modeling, the check/list APIs, consistency
- [Zanzibar paper](https://research.google/pubs/pub48190/) ([H07](H07-rebac-and-zanzibar.md))
- [zanzibar.academy](https://zanzibar.academy/) — a guided model walkthrough
- [SpiceDB](https://authzed.com/docs) — an alternative implementation

---

**Next:** [H09 — Multi-tenancy and the isolation problem](H09-multi-tenancy-isolation.md)
