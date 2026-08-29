# H03 — Access control lists and direct permissions

**Part H · Authorization** · *Builds on [H01](H01-where-does-authz-live.md)*
---

## Why it matters

You are building the document-sharing app. The first authorization requirement:

> "Alice can share a specific document with Bob."

The simplest possible model handles this perfectly: a list, per document, of who may do what.

```
   document 42:  [ (alice, owner), (bob, viewer) ]
```

That is an **access control list**, and for direct, per-object sharing it is exactly right.
The failure comes later, when the lists multiply past what you can reason about — but starting
here, with the simplest model that works, is correct. This chapter is that model, its
strengths, and the exact point where you outgrow it.

---

## What an ACL is

> **An access control list attaches, to each object, an explicit list of who may do what to
> it.**

```
   Object          Subject   Permission
   ──────          ───────   ──────────
   document 42     alice     owner
   document 42     bob       viewer
   document 42     carol     editor
   folder 7        alice     owner
   folder 7        team-eng  viewer      ← a group can be a subject
```

The defining property: **permissions live *with the object*.** To ask "who can access document
42?" you look at document 42's list. To ask "what can Alice access?" you search every list —
which is the first hint of where ACLs strain.

This is the model behind Unix file permissions (extended ACLs), AWS S3 bucket ACLs, and every
"Share" dialog you have ever used. It is direct, auditable, and intuitive.

---

## A minimal ACL

```sql
CREATE TABLE acl_entries (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  resource_type text NOT NULL,       -- 'document', 'folder'
  resource_id   uuid NOT NULL,
  subject_type  text NOT NULL,       -- 'user', 'group'
  subject_id    uuid NOT NULL,
  permission    text NOT NULL,       -- 'owner', 'editor', 'viewer'
  granted_by    uuid,                -- who shared it — for audit  H13
  created_at    timestamptz NOT NULL DEFAULT now(),
  UNIQUE (resource_type, resource_id, subject_type, subject_id, permission)
);

CREATE INDEX ON acl_entries (resource_type, resource_id);   -- "who can access X?"
CREATE INDEX ON acl_entries (subject_type, subject_id);     -- "what can Y access?"
```

```python
PERMISSION_RANK = {"viewer": 1, "editor": 2, "owner": 3}

class ACL:
    def can(self, user: User, action: str, resource) -> bool:
        needed = ACTION_TO_PERMISSION[action]     # 'read'→'viewer', 'delete'→'owner'
        # The user's own entries...
        subjects = [("user", user.id)] + [("group", g) for g in user.group_ids]
        entries = self.repo.entries_for(resource, subjects)
        # ...highest permission wins.
        best = max((PERMISSION_RANK[e.permission] for e in entries), default=0)
        return best >= PERMISSION_RANK[needed]

    def grant(self, granter: User, resource, subject, permission: str):
        # ★ Can the GRANTER share? Only owners share, typically.
        if not self.can(granter, "share", resource):
            raise Forbidden()
        self.repo.add_entry(resource, subject, permission, granted_by=granter.id)  # H13
```

Two design points worth flagging:

**Permissions have a rank.** `owner > editor > viewer`. Store the grant; compute "does the
best grant meet the requirement?" This ranking is the seed of RBAC's role hierarchy
([H04](H04-rbac-and-when-it-breaks.md)).

**Granting is itself an authorized action** (the ★). "Who can share?" is a permission too, and
forgetting to check it is how a viewer grants themselves ownership — a privilege escalation
([H14](H14-attack-your-own-authorization.md)). The full "can Bob reshare, and to whom?"
question is where sharing models get genuinely hard ([H07](H07-rebac-and-zanzibar.md)).

---

## Capabilities — the inside-out alternative

There is a second way to express direct permissions, worth knowing because it appears
throughout this book without the name:

> **A capability *is* the permission.** Instead of the system checking a list, the subject
> holds an unforgeable token that grants the access directly.

```
   ACL:         "is alice in document 42's list?"      ← the system looks up
   Capability:  alice holds a token that IS access to 42 ← possession is the grant
```

You have met capabilities repeatedly:

- **A share link** ([D10](../track-d/D10-magic-links-and-email-otp.md)) — the URL *is* the
  permission. Whoever holds it, gets in.
- **A bearer token** ([C03](../track-c/C03-the-vocabulary.md)) — possession is sufficient.
- **A signed download URL** — the signature *is* the authorization.

Capabilities are simple and decentralised (no lookup), but they inherit the bearer problem:
**possession = access, so a leaked capability is a breach** ([A01](../track-a/A01-what-happens-when-you-type-a-url.md)
— URLs leak). They are excellent for time-boxed, single-purpose grants (a signed URL that
expires in an hour); they are poor when you need revocation, listing, or audit — which is
where ACLs win.

Most systems use both: ACLs for durable, auditable access; capabilities for ephemeral shares.

---

## When ACLs are right

✅ **Direct, per-object sharing** — "share this document with this person." The native case.
✅ **A manageable number of grants per object.** A document shared with ten people: fine.
✅ **When "who can access this?" is a common question** — the answer is one indexed lookup.
✅ **Small systems** where the whole model fits in your head.

They are correct, and [H01](H01-where-does-authz-live.md)'s advice — start with the simplest
model that works — often means starting here.

---

## Where they break

ACLs strain as the *number and complexity* of grants grows:

**1. The grants explode.** A folder with 10,000 documents, each shared with 50 people, is
500,000 ACL entries. Managing, auditing, and changing them becomes unwieldy.

**2. No inheritance.** "Share this folder" should mean "share everything in it." A flat ACL
has no notion of the folder containing the documents, so you either copy the grant to every
child (and re-copy on every add) or write custom inheritance logic — which is the beginning of
[H07](H07-rebac-and-zanzibar.md)'s relationship model.

**3. Group membership is a separate problem.** ACLs let a *group* be a subject, but "who is in
the group?" is another list to maintain, and nested groups (a team inside a department) push
past what flat ACLs handle cleanly.

**4. No roles.** If every editor should get the same five permissions, ACLs make you grant
five permissions per editor per object. That repetition is exactly what **RBAC** collapses
into a role ([H04](H04-rbac-and-when-it-breaks.md)).

**5. Cross-cutting rules are impossible.** "Anyone in the legal department can read any
document tagged confidential" is not per-object — it is a rule over *attributes*, which is
**ABAC** ([H06](H06-abac.md)).

The pattern: ACLs handle **direct grants** beautifully and **derived, inherited, or
rule-based** access poorly. Every model after this one exists to handle a kind of access ACLs
cannot express directly.

---

## The progression

ACLs are the base of the whole track. Each subsequent model adds a way to *avoid enumerating
every grant*:

```
   ACL         →  explicit grants per object            (this chapter)
   RBAC        →  grants bundled into ROLES             H04
   ABAC        →  grants derived from ATTRIBUTES        H06
   ReBAC       →  grants derived from RELATIONSHIPS     H07 — Google Drive's real model
```

None replaces ACLs entirely — a Zanzibar-style ReBAC system
([H07](H07-rebac-and-zanzibar.md)) still has direct relation tuples that *are* ACL entries at
heart. What changes is how much you can *derive* rather than *enumerate*.

---

## Terms defined in this chapter

`ACL`, `capability`

---

## What to remember

1. **An ACL attaches, per object, an explicit list of who may do what.** Permissions live
   *with the object*.
2. It is the right, simplest model for **direct per-object sharing** — start here.
3. **Granting is itself an authorized action.** Check "who can share?" or a viewer escalates
   themselves.
4. **A capability *is* the permission** — a share link, a bearer token. Great for ephemeral
   grants; a leaked one is a breach.
5. ACLs break on **scale, inheritance, roles, and cross-cutting rules** — exactly what
   RBAC/ABAC/ReBAC exist to express.
6. **ACLs are the base of the track.** Later models derive access instead of enumerating it;
   they don't replace direct grants.

---

## Sources

- *API Security in Action* (Neil Madden), Ch. 8 (access control lists, capabilities)
- [AWS: S3 access control lists](https://docs.aws.amazon.com/AmazonS3/latest/userguide/acl-overview.html)
- Google Zanzibar paper — relation tuples as generalised ACLs ([H07](H07-rebac-and-zanzibar.md))

---

**Next:** [H04 — RBAC, and the exact moment it breaks](H04-rbac-and-when-it-breaks.md)
