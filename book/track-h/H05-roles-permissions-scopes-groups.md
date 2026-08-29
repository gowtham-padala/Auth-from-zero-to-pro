# H05 — Roles vs permissions vs scopes vs groups

**Part H · Authorization** · *Builds on [H04](H04-rbac-and-when-it-breaks.md), [F07](../track-f/F07-access-refresh-scopes.md)*
> Pure vocabulary triage, and unusually valuable. These four words get used interchangeably in
> every codebase and mean four different things. Getting them straight prevents a category of
> bug where the wrong one is checked.

---

## The four, defined

```
   PERMISSION   an atomic allowed operation           documents:delete
   ROLE         a named BUNDLE of permissions          editor = {read, write}
   GROUP        a named SET of principals               eng-team = {alice, bob}
   SCOPE        a bound on what a TOKEN/APP may attempt  documents:read (OAuth)
```

| | **Permission** | **Role** | **Group** | **Scope** |
|---|---|---|---|---|
| Is a set of... | — (atomic) | permissions | **principals** | permissions (for a token) |
| Answers | "which single action?" | "what may this user do?" | "who are these users?" | "what may this *app* attempt?" |
| About | an operation | a user's capability | membership | delegation |
| Set by | you | you | you | the client + user consent |
| Lives in | your code/DB | your DB ([H04](H04-rbac-and-when-it-breaks.md)) | your DB / an IdP | a token ([F07](../track-f/F07-access-refresh-scopes.md)) |
| Track | H | H | H / G | F |

The two axes that separate them:

- **Permission vs role vs scope** differ in *granularity and origin*: a permission is one
  action; a role bundles them for a *user*; a scope bundles them for a *token/app*.
- **Group** is the odd one out — it is a set of **people**, not permissions. It answers
  *"who?"*, never *"what may they do?"*

---

## The distinctions that matter

### Role vs group — the most-confused pair

```
   ROLE:   "editor"     → a bundle of PERMISSIONS   (what you can DO)
   GROUP:  "eng-team"   → a set of PEOPLE           (who you ARE with)
```

They are constantly conflated because a group is often *assigned* a role — "everyone in
`eng-team` is an `editor`." But the direction matters:

```
   GROUPS  →  (are assigned)  →  ROLES  →  (grant)  →  PERMISSIONS
   who         membership        what        the bundle   the action
```

Why keeping them separate matters:

- **A group can have many roles**, and a role can be held by many groups and many individuals.
  Collapse them and you lose that flexibility.
- **Groups often come from elsewhere** — an IdP's directory ([G06](../track-g/G06-claims-vs-scopes-userinfo.md),
  [G13](../track-g/G13-enterprise-directories.md)). The IdP tells you *group membership*; *you*
  decide what roles those groups map to. **Do not treat the IdP's groups as your roles** —
  map them ([H12](H12-authz-in-microservices.md)).
- **Membership changes for HR reasons; role definitions change for product reasons.** They
  evolve on different clocks.

### Scope vs role — the OAuth trap

The distinction from [F07](../track-f/F07-access-refresh-scopes.md), because it is the one that
causes security bugs:

```
   SCOPE:  what the CLIENT (app) may ATTEMPT on the user's behalf
   ROLE:   what the USER may actually DO
```

The critical property: **they are ANDed, never ORed.**

```python
# A token has scope `documents:write`. The user has role `viewer`.
# May they write?

scope_allows = "documents:write" in token.scopes        # True
role_allows  = "documents:write" in user.permissions     # False (viewer can only read)

allowed = scope_allows and role_allows                   # ✅ False — correctly denied
#                     ^^^ AND, not OR
```

A scope can only ever **narrow**: it says "this app is permitted to *attempt* writes for the
user," and the user's own permissions still gate whether the write actually happens
([F07](../track-f/F07-access-refresh-scopes.md)). Checking scope *instead of* role — or ORing
them — lets an app do things its user cannot, which is a privilege-escalation bug
([H14](H14-attack-your-own-authorization.md)).

> **Scope bounds the app. Role bounds the user. The user's action must satisfy both.**

### Permission vs role — granularity

A permission is one operation (`documents:delete`). A role is a named bundle
(`editor = {read, write}`). The reason to separate them ([H04](H04-rbac-and-when-it-breaks.md)):

- **Check permissions, assign roles.** Enforcement code should ask "does the user have
  `documents:delete`?" — not "is the user an admin?" Checking the *role* hardcodes an
  assumption; checking the *permission* survives a role redefinition.

```python
# ❌ hardcodes the role — breaks when you add a new role that should also delete
if user.role == "admin": ...

# ✅ checks the permission — any role granting it works
if rbac.can(user, "documents:delete"): ...
```

This one line of discipline is what lets you add a `moderator` role later without touching
every enforcement point.

---

## Putting it together: one user, all four

Alice, in a realistic system:

```
   Alice IS IN groups:        eng-team, all-staff                    (who she's with)
        │
        │ groups map to roles
        ▼
   Alice HAS roles:           editor (via eng-team), viewer (via all-staff)
        │
        │ roles bundle permissions
        ▼
   Alice HAS permissions:     documents:read, documents:write         (what she can do)

   Meanwhile, the mobile APP she's using HAS scopes:
                              documents:read                          (what the app may attempt)

   May the app delete a document as Alice?
     app scope allows delete?   NO  (scope is read-only)  → denied
     (and even if it did: Alice's permissions allow delete? NO)
```

Every layer is a different question, and the final decision ANDs them. Confuse any two and the
decision is wrong.

---

## The vocabulary map, one more time

```
   WHO          →  GROUP        (a set of principals)         G / H
   ARE ASSIGNED →  ROLE         (a named bundle of permissions) H04
   WHICH GRANT  →  PERMISSION   (an atomic operation)          H01
   —————
   Separately, for delegation:
   THE APP MAY  →  SCOPE        (what a token may attempt)     F07

   Decision = (user has the PERMISSION, via a ROLE, via a GROUP)
              AND (the token/app has the SCOPE)
```

---

## Terms defined in this chapter

`group`

---

## What to remember

1. **Permission** = one action. **Role** = a bundle of permissions (for a user). **Group** =
   a set of people. **Scope** = what a token/app may attempt.
2. **Role vs group is the most-confused pair:** a role is *what you can do*, a group is *who
   you're with*. Groups are assigned roles; keep them separate.
3. **Do not treat an IdP's groups as your roles.** The IdP tells you membership; you map it to
   roles.
4. **Scope and role are ANDed, never ORed.** Scope bounds the app; role bounds the user; the
   action must satisfy both.
5. **Check permissions, assign roles.** `if can(user, "documents:delete")`, not
   `if user.role == "admin"`.
6. One user is simultaneously in groups, holding roles, granting permissions — and the app has
   scopes. The decision ANDs all of it.

---

## Sources

- [NIST RBAC (INCITS 359)](https://csrc.nist.gov/projects/role-based-access-control) — roles vs permissions
- [RFC 6749 §3.3](https://www.rfc-editor.org/rfc/rfc6749#section-3.3) — scopes
- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)

---

**Next:** [H06 — ABAC and policy-based access control](H06-abac.md)
