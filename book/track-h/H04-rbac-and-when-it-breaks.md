# H04 — RBAC, and the exact moment it breaks

**Part H · Authorization** · *Builds on [H03](H03-acls-and-direct-permissions.md)*
---

## RBAC, and why it is popular

> **Role-based access control: permissions attach to *roles*; users are assigned roles.
> Users get permissions *through* their roles, never directly.**

```
   USERS          →  ROLES            →  PERMISSIONS
   ─────             ─────               ───────────
   alice          →  admin            →  documents:*, users:*, billing:*
   bob            →  editor           →  documents:read, documents:write
   carol          →  viewer           →  documents:read
   dave           →  editor
```

The insight that makes RBAC powerful: **the user↔permission relationship is factored through
roles.** Instead of granting each user each permission (ACLs —
[H03](H03-acls-and-direct-permissions.md)), you grant *roles* permissions once, and assign
users roles. A new editor gets all editor permissions instantly; changing what "editor" means
updates everyone at once.

```
   Without roles (ACL):  N users × M permissions grants
   With roles (RBAC):    N users → R roles, R roles → M permissions
                         ← far fewer relationships to manage
```

This is why RBAC is everywhere — it matches how organisations actually think ("editors,"
"admins," "viewers"), it is easy to audit ("who is an admin?"), and it collapses permission
management from per-user to per-role.

---

## A clean RBAC implementation

```sql
CREATE TABLE roles (
  id    uuid PRIMARY KEY,
  name  text UNIQUE NOT NULL          -- 'admin', 'editor', 'viewer'
);
CREATE TABLE role_permissions (
  role_id    uuid REFERENCES roles(id),
  permission text NOT NULL,           -- 'documents:read', 'documents:delete'
  PRIMARY KEY (role_id, permission)
);
CREATE TABLE user_roles (
  user_id uuid REFERENCES users(id),
  role_id uuid REFERENCES roles(id),
  PRIMARY KEY (user_id, role_id)
);
```

```python
class RBAC:
    def permissions_of(self, user: User) -> set[str]:
        # Union of permissions across all the user's roles.
        return {p for role in self.roles_of(user)
                  for p in self.permissions_of_role(role)}

    def can(self, user: User, permission: str) -> bool:
        return permission in self.permissions_of(user)

# Enforcement — H02.
@require_permission("documents:delete")     # middleware: role-level
def delete_document(doc_id): ...
```

Clean, fast, cacheable. For "admins manage users, editors write documents, viewers read
them," this is complete and correct.

### Role hierarchies

A common, sensible extension: roles inherit from one another.

```
   admin  ──inherits──▶  editor  ──inherits──▶  viewer
   (everything editor    (everything viewer
    can do, plus...)      can do, plus...)
```

So `admin` automatically has every `editor` and `viewer` permission. This keeps roles small
and non-repetitive, and it is the ranking from ACLs ([H03](H03-acls-and-direct-permissions.md))
generalised. RBAC with hierarchies handles a *lot* — most internal tools never need more.

---

## The exact moment it breaks

RBAC's power is that permissions are **global to a role**: an `editor` can edit *documents* —
all of them they can reach. The model has no natural place for *"this permission, but only for
this one object, for this one person."*

Now the requirement lands:

> *"Share this one document with one external person, read-only."*

Watch what RBAC forces you to do. The external person is not an editor or a viewer of your
*system* — they should see exactly **one document**. RBAC's roles are global, so there is no
role that means "viewer of document 42 only." Your options:

**Option A — a role per document.** Create `viewer-of-document-42`. Now every shared document
spawns a role. Ten thousand shared documents, ten thousand roles. The role table *is* the ACL
table, badly ([H03](H03-acls-and-direct-permissions.md)) — you have reinvented ACLs inside
RBAC and lost RBAC's whole benefit.

**Option B — a role per (document, permission) pair.** `viewer-of-42`, `editor-of-42`,
`viewer-of-43`... Worse. This is **role explosion**, and it is RBAC's defining failure mode.

**Option C — bolt an ACL onto RBAC.** Keep RBAC for global permissions, add a per-object ACL
for sharing. This *works* — and it is what most "RBAC" systems actually are — but you now have
two authorization models, two enforcement paths, and the seam between them is where bugs live.

```
   RBAC roles are GLOBAL:          "editors can edit documents"
   Sharing is PER-OBJECT:          "Bob can view THIS document"
                    │
                    ▼
   RBAC has no way to express per-object grants without a role
   per object → ROLE EXPLOSION.
```

The breaking point is precise: **RBAC breaks the moment authorization depends on the specific
object, not just the type of object.** "Can edit documents" is RBAC's home turf. "Can edit
*this* document" is not.

---

## Why this matters — it is not a toy example

Document sharing was chosen as this book's running app for exactly this reason
([README](../../README.md)). Sharing is not an edge case; it is the core of collaboration
software, and it breaks role-based access control every time.

The same shape appears constantly:

- **Google Drive** — "share this file with this person" is per-object, per-user
  ([H07](H07-rebac-and-zanzibar.md), [H08](H08-model-drive-in-openfga.md)).
- **GitHub** — "this user is an admin of *this* repo," not admin globally.
- **Multi-tenant SaaS** — a role scoped to *this* tenant, not the whole system
  ([H09](H09-multi-tenancy-isolation.md)).
- **Any app with "share," "invite to," or "grant access to a specific thing."**

If your product has any of these, pure RBAC will not carry you, and the moment you discover
that is usually mid-project, when the role table is already a mess.

---

## What the breakage motivates

The failure of RBAC to express object-scoped and rule-based access is the reason the next four
chapters exist:

| Requirement RBAC can't express | Model | Chapter |
|---|---|---|
| "This permission, on THIS object, for THIS user" | **ReBAC** (relationships) | [H07](H07-rebac-and-zanzibar.md) |
| "Anyone in Legal can read anything tagged confidential" | **ABAC** (attributes) | [H06](H06-abac.md) |
| "Folder sharing cascades to its documents" | **ReBAC** (inheritance via relations) | [H07](H07-rebac-and-zanzibar.md) |
| "Roles, but scoped to a tenant/project" | RBAC + scoping, or ReBAC | [H09](H09-multi-tenancy-isolation.md) |

**ReBAC** ([H07](H07-rebac-and-zanzibar.md)) is the direct answer to the sharing problem:
model access as a *graph of relationships* — `bob is viewer of document:42`, `document:42 is
in folder:7`, `alice is owner of folder:7` — and derive permissions by traversing it. That is
how Google Drive actually works, and modelling it is [H08](H08-model-drive-in-openfga.md).

---

## Should you use RBAC at all?

Yes — for most of your system, most of the time. The lesson is not "RBAC is bad." It is:

> **RBAC for global, type-level permissions. Something else for per-object sharing. Know
> which parts of your app are which *before* you build the role table.**

A realistic large app uses:

- **RBAC** for administrative and functional permissions (who can access the admin panel, who
  can manage billing, who can invite users).
- **ReBAC or per-object ACLs** for resource sharing (who can view *this* document).
- **ABAC** for cross-cutting rules (confidentiality tags, time windows, IP restrictions).

The mistake is trying to force all three into RBAC because it was the first model you reached
for. Recognising the breaking point — object-specific access — early is what saves you from
the role explosion.

---

## Terms defined in this chapter

`RBAC`, `role`, `permission`, `role explosion`

---

## What to remember

1. **RBAC: permissions attach to roles; users get permissions through roles.** It factors the
   user↔permission relationship, which is why it scales and audits well.
2. **Role hierarchies** (admin ⊃ editor ⊃ viewer) handle most internal tools completely.
3. **RBAC breaks the moment authorization depends on the *specific object*, not the object
   type.** "Can edit documents" ✅; "can edit *this* document" ✗.
4. **The break is role explosion** — a role per object recreates ACLs inside RBAC and loses
   its benefit.
5. **Sharing is not an edge case** — it is the core of collaboration software, and it breaks
   RBAC every time (Drive, GitHub, multi-tenant SaaS).
6. The breakage motivates **ReBAC** (object-scoped, relationship-derived —
   [H07](H07-rebac-and-zanzibar.md)) and **ABAC** (rule-based — [H06](H06-abac.md)).
7. Use **RBAC for global permissions, ReBAC/ACLs for sharing, ABAC for cross-cutting rules.**
   Know which is which before building the role table.

---

## Sources

- [NIST RBAC model (INCITS 359)](https://csrc.nist.gov/projects/role-based-access-control) — the formal model, including role hierarchies
- [Google Zanzibar paper](https://research.google/pubs/pub48190/) — why Google *didn't* use RBAC for Drive ([H07](H07-rebac-and-zanzibar.md))
- *API Security in Action* (Neil Madden), Ch. 8

---

**Next:** [H05 — Roles vs permissions vs scopes vs groups](H05-roles-permissions-scopes-groups.md)
