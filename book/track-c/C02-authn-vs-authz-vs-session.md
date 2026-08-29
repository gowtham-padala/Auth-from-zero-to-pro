# C02 — Authentication vs authorization vs session, once and for all

**Part C · The map** · *Builds on [C01](C01-auth-is-five-different-problems.md)*
---

## Why it matters

```python
@app.get("/api/documents/<int:doc_id>")
@login_required                      # ← this is the only check
def get_document(doc_id):
    return db.query(Document).get(doc_id)
```

`@login_required` is doing exactly what its name says: it verifies there is a valid
session. It has no opinion about *which document*, because it cannot — it does not know
about documents.

An authenticated user changes `9182` to `9183` in the URL and reads a document belonging to
a different company.

This is **IDOR**, the most common serious vulnerability in real applications
([H14](../track-h/H14-attack-your-own-authorization.md)). The cause is a category error:
*authentication was performed and authorization was not*, and the decorator's name made it
feel like both had been.

The whole chapter is here to make that error impossible to make again.

---

## The three questions

| | **Authentication** | **Session** | **Authorization** |
|---|---|---|---|
| Question | **Who are you?** | **Are you still you?** | **May you do this?** |
| Shorthand | authn | — | authz |
| Answers with | An identity | An identity | Yes / no |
| Happens | Once, at login | Every request | Every request |
| Depends on | A credential | A token or cookie | Identity **+ action + resource** |
| Fails with | `401` | `401` | `403` |
| Owned by | Track D | Track E | Track H |

The clean way to hold it:

> **Authentication is about the subject alone.**
> **Authorization is about the subject *and the verb and the object*.**

You can answer "who are you?" with a name. You cannot answer "may you do this?" without
knowing what *this* is. That is why authorization cannot live in a decorator that only sees
the request, and why it cannot be bought from a vendor
([C01](C01-auth-is-five-different-problems.md)).

---

## Why the confusion is structural, not careless

Four reasons this specific pair gets muddled more than any other pair of concepts in
software:

**1. Both abbreviate to "auth."** In conversation, in package names, in directory names.
`/auth/` in a codebase might be either.

**2. `401` is called "Unauthorized" and means unauthenticated.**
([A03](../track-a/A03-methods-status-codes-401-vs-403.md).) The specification has been
wrong about this since 1997 and cannot be fixed.

**3. The `Authorization` header carries an authentication credential.** It is named for
what it enables, not what it contains.

**4. Frameworks blur them.** `@login_required`, `authenticate()`, `is_authenticated`,
`current_user` — the vocabulary of a framework's "auth" module usually covers layers 1 and
2 and stops, while feeling complete.

Knowing that the confusion is built into the vocabulary is itself useful. It means you
should not trust a name; you should ask what check actually ran.

---

## Trace one request

```
  DELETE /api/documents/9182
  Cookie: __Host-session=8f14e45f...

  ┌──────────────────────────────────────────────────────────────────┐
  │ SESSION (layer 2)                                                │
  │   Look up 8f14e45f in the session store.                         │
  │   Found: user 4471, tenant 88, created 3 days ago, not expired.  │
  │   → We now have a PRINCIPAL.                                     │
  │   Fails → 401                                                    │
  └──────────────────────────────────────────────────────────────────┘
                                 │
  ┌──────────────────────────────▼───────────────────────────────────┐
  │ AUTHORIZATION (layer 5)                                          │
  │   Load document 9182.                                            │
  │   Is it in tenant 88?              ← tenant isolation            │
  │   Does 4471 have `delete` on it?   ← the actual policy           │
  │   Is 4471's session strong enough  ← step-up? (D18)              │
  │     for a destructive action?                                    │
  │   Fails → 403 (or 404 — A03)                                     │
  └──────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
                          Do the deletion.
                          Write an audit record. (H13)
```

Authentication (layer 1) does not appear. It happened three days ago. Its *result* is what
the session lookup recovers.

That is the mental model to keep: **authentication produces a fact; the session transports
that fact; authorization consumes it along with the request's specifics.**

---

## The four errors

### 1. Authorization by authentication

The opening example. "They are logged in, so they may proceed."

```python
if current_user:                      # ❌ authenticated ≠ permitted
    return document
```

Being logged in tells you *who*. It says nothing about *this document*.

### 2. Authorization by UI

```jsx
{user.isAdmin && <DeleteButton />}     // ❌ this is UX, not a control
```

Hiding a button removes it from the page, not from the API
([A07](../track-a/A07-client-vs-server.md)). Every hidden control needs a server-side check
behind it. The button is a courtesy; the check is the security.

### 3. Authorization by obscurity

"The document ID is a UUID, so nobody will guess it."

UUIDs leak — in URLs, in `Referer` headers, in shared links, in logs, in support tickets,
in a previous response body. Unguessability is a *nice property* and never an access
control. ([H14](../track-h/H14-attack-your-own-authorization.md).)

### 4. Authorization at the wrong layer

Checking permissions in the controller, then having a background job, a GraphQL resolver,
an admin console, and a CSV export that all reach the same data by other paths.

**Every path to the data needs the check**, which is the argument for pushing enforcement
down — to the service layer, or into the database with row-level security
([H02](../track-h/H02-the-enforcement-point.md),
[H10](../track-h/H10-row-level-security.md)).

---

## Where the session sits, and why it is separate

People often collapse session into authentication. Keeping it separate earns its keep in
three places:

**Sessions expire independently of identity.** You are still you; your session is not still
valid. Timeouts, revocation, and "log out everywhere" are session operations that do not
touch your identity ([E13](../track-e/E13-sessions-across-devices.md)).

**Sessions carry strength, not just identity.** A session created with a password is weaker
than one created with a passkey, and one created ten seconds ago is stronger for a
destructive action than one created a week ago. That is **step-up authentication**
([D18](../track-d/D18-step-up-auth-and-aal.md)), and it only makes sense if a session is a
thing with properties rather than a boolean.

**Sessions are what actually get stolen.** Attackers rarely steal passwords in a modern
compromise; they steal session cookies, because a session cookie skips authentication
entirely — including MFA. That is why [E16](../track-e/E16-xss-is-an-auth-vulnerability.md)
is titled the way it is.

---

## The vocabulary map

Because you will meet all of these, and they are not synonyms:

```
                              ┌─────────────────────┐
                              │     PRINCIPAL       │  the entity being decided about
                              └──────────┬──────────┘
                                         │
             ┌───────────────────────────┼───────────────────────────┐
             ▼                           ▼                           ▼
   ┌──────────────────┐        ┌──────────────────┐       ┌──────────────────┐
   │   CREDENTIAL     │        │      TOKEN       │       │   PERMISSION     │
   │  proves identity │        │ carries identity │       │  grants an action│
   │                  │        │                  │       │                  │
   │  password        │        │  session cookie  │       │  document:delete │
   │  TOTP code       │        │  JWT             │       │  admin role      │
   │  passkey sig     │        │  access token    │       │  viewer relation │
   └──────────────────┘        └──────────────────┘       └──────────────────┘
        AUTHENTICATION              SESSION                 AUTHORIZATION
         (layer 1)                 (layer 2)                  (layer 5)
```

Full definitions in [C03](C03-the-vocabulary.md).

---

## A test you can apply to any codebase

For any endpoint that returns or modifies data, answer both:

1. **"Who is calling?"** — is there a check that establishes a principal, and does it fail
   closed?
2. **"May *this* principal do *this* to *this* object?"** — is there a check that reads the
   object's identity, and does it fail closed?

If question 2 has no answer, you have found an IDOR. Not "possibly." You have found one.

The version that finds them fastest, from [A07](../track-a/A07-client-vs-server.md):

> **Take a valid session for user A and request user B's resource with `curl`. What
> stops it?**

Do this on your own application before you finish this track. It takes ten minutes and it
is the highest-yield security exercise in this book.

---

## Terms defined in this chapter

(Terms are defined in [C01](C01-auth-is-five-different-problems.md) and
[C03](C03-the-vocabulary.md); this chapter fixes their relationships.)

---

## What to remember

1. **Authentication: the subject alone. Authorization: the subject, the verb, and the
   object.** That is the whole distinction.
2. `401` = unauthenticated. `403` = unauthorized. The name of `401` is wrong.
3. **Session is a third thing**, and separating it is what makes expiry, revocation, and
   step-up coherent.
4. `@login_required` is authentication. It is never authorization.
5. Hidden UI, unguessable IDs, and "they're logged in" are not access controls.
6. **Test it:** user A's session, user B's resource, `curl`. What stops it?

---

## Sources

- [OWASP Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP Top 10 2021 — A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/)
- [OWASP API Security Top 10 — API1:2023 Broken Object Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/)

---

**Next:** [C03 — The vocabulary: principal, subject, claim, scope, credential, token](C03-the-vocabulary.md)
