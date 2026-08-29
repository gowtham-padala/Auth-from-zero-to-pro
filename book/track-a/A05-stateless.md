# A05 — What "stateless" means, and why HTTP forgets who you are

**Part A · How the web actually works** · *Builds on [A03](A03-methods-status-codes-401-vs-403.md)*
---

## Why it matters

Here is a login endpoint that works perfectly:

```python
@app.post("/login")
def login():
    user = find_user(request.form["email"])
    if user and check_password(request.form["password"], user.password_hash):
        current_user = user          # ← the bug
        return redirect("/dashboard")
    return render("login.html", error="Invalid credentials")
```

And here is the dashboard, which never works:

```python
@app.get("/dashboard")
def dashboard():
    return render("dashboard.html", user=current_user)   # who?
```

`current_user` was set. It is gone. Not expired, not overwritten — the process that set it
finished, and this is a different request. There is no thread of continuity between them
for the variable to survive in.

Every beginner writes this bug. It is not carelessness. It is a correct intuition about
how programs work, applied to a protocol that does not work that way.

---

## What stateless actually means

> **Stateless:** the server is not required to retain any information about a client
> between requests. Every request must carry everything needed to understand it.

Not "the server has no database." Not "the server has no memory." The database persists
fine. What does not persist is *the association between this request and the previous
one*.

Two requests from the same browser, one second apart, are — to the protocol — completely
unrelated events. There is no built-in identifier connecting them. HTTP has no concept of
a conversation.

```
Request 1:  POST /login       "I am alice, here is my password"
            ← 302 "OK, go to /dashboard"

                  ✂  no connection whatsoever  ✂

Request 2:  GET /dashboard    "Give me the dashboard"
            ← 401 "...who?"
```

The server is not being difficult. It genuinely does not know. Nothing in request 2
mentions Alice.

---

## Why it was designed this way

This looks like an omission. It is a deliberate trade, and understanding the trade is
what makes the rest of Track E make sense.

**Statelessness buys horizontal scalability.** If no server holds per-client memory, any
server can answer any request. Put ten machines behind a load balancer and it just works.
Add an eleventh at 3am with no coordination. Kill one and nobody is logged out.

The alternative — a stateful protocol, where each connection carries session context —
is what FTP and older protocols did. It works, and it means a specific machine owns a
specific client. That machine restarting is that client's problem. Scaling means routing
clients to their machine, forever.

**Statelessness buys crash recovery for free.** A server that remembers nothing loses
nothing when it dies.

**Statelessness buys caching.** A response that depends only on the request can be cached
by any intermediary. The whole CDN industry is downstream of this property.

The cost of all three is that *you* now have to supply continuity. That is what the rest
of this section of the book is about.

---

## The three ways to add state back

There are exactly three, and every authentication design is a choice among them.

### 1. Put the state in the URL

```
/dashboard?session=8f14e45f
```

The oldest technique — `;jsessionid=` in old Java apps. It works, and it is a disaster:

- URLs are logged everywhere ([A01](A01-what-happens-when-you-type-a-url.md)).
- URLs leak via `Referer` to third parties ([A04](A04-headers.md)).
- URLs are shared. A user pastes a link into chat and hands over their session.
- URLs are in browser history, on shared machines.

**Do not do this.** It is here because you will still encounter it, and because the same
reasoning is why access tokens must not travel in query strings.

### 2. Put the state in a header your code attaches

```http
Authorization: Bearer eyJ...
```

Your JavaScript stores a token and attaches it to each request.

- Not automatic, so **immune to CSRF** — a malicious site cannot make the browser attach
  a header it does not possess.
- But the token must live somewhere the script can read, which means anything that can run
  script can read it ([E12](../track-e/E12-where-to-store-a-token.md)).
- And it does not survive a full page navigation, so server-rendered apps cannot use it
  for the primary session.

### 3. Put the state in a cookie the browser attaches for you

```http
Set-Cookie: session=8f14e45f; HttpOnly; Secure; SameSite=Lax
```

- **Automatic.** Works on navigations, form posts, images, everything.
- Can be hidden from JavaScript with `HttpOnly` — the credential becomes unreadable even
  to a successful XSS.
- Because it is automatic, it is attached to requests the user did not intend — which is
  precisely CSRF ([E15](../track-e/E15-csrf.md)) — and needs `SameSite` to be safe.

This is the default answer for first-party web applications, and
[E09](../track-e/E09-should-you-use-jwts-for-sessions.md) argues that position at length.

---

## The second axis: where does the *data* live?

Once you have decided how the identifier travels, a separate question remains: does the
identifier *point at* state, or *contain* it?

```
   ┌──────────────────────────────────────────────────────────────┐
   │  A. REFERENCE                                                │
   │                                                              │
   │  Cookie: session=8f14e45f          ┌───────────────────┐     │
   │           (meaningless)  ──────────>│ sessions table    │    │
   │                                     │ 8f14e45f → alice  │    │
   │                                     └───────────────────┘    │
   │  Server is "stateless" per request, but keeps shared state.  │
   │  ✅ Instant revocation — delete the row.                     │
   │  ❌ A lookup on every request.                               │
   ├──────────────────────────────────────────────────────────────┤
   │  B. SELF-CONTAINED                                           │
   │                                                              │
   │  Cookie: session=eyJzdWIiOiJhbGljZSJ9.<signature>            │
   │           (readable, signed)                                 │
   │                                                              │
   │  Server verifies the signature. No lookup.                   │
   │  ✅ No shared storage. Scales trivially.                     │
   │  ❌ Cannot revoke before expiry ([E11]).                     │
   └──────────────────────────────────────────────────────────────┘
```

Option A is a server-side session ([E03](../track-e/E03-build-server-side-sessions.md)).
Option B is a JWT or a signed cookie ([E05](../track-e/E05-jwt-part-1-three-parts.md),
[E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md)).

Note the vocabulary trap. People say "JWTs are stateless" as if that is a property
*servers* have. It is not — every real system has state; the database is state. The
precise claim is: **verifying this credential requires no lookup.** That is a genuine and
sometimes valuable property. It is also exactly why revocation is hard, because there is
nothing to delete.

---

## What the server must do on every single request

Because nothing is remembered, every request runs the same procedure:

```
1. Extract the credential          (cookie / header / nothing)
2. Validate it                     (lookup, or verify a signature)
3. Resolve it to a principal       ("this is user 4471")
4. Load whatever context is needed (roles, tenant, permissions)
5. Authorize the specific action   (may this principal do this?)
6. Do the work
```

Steps 1–4 are Track E. Step 5 is Track H. The reason
[C02](../track-c/C02-authn-vs-authz-vs-session.md) insists on separating the vocabulary is
that these are genuinely different steps with different failure modes, and this list is
where you can see them apart.

Two failure modes worth naming now:

- **Skipping step 5 because step 3 succeeded.** "The user is logged in, therefore they
  may see this document." That is IDOR ([H14](../track-h/H14-attack-your-own-authorization.md)),
  and it is the most common serious vulnerability in real applications.
- **Doing steps 1–4 in middleware and forgetting one route.** Because it must happen on
  *every* request, the enforcement point matters enormously —
  [H02](../track-h/H02-the-enforcement-point.md).

---

## Terms defined in this chapter

`stateless`, `state`

---

## What to remember

1. Stateless means **no required memory between requests**, not "no database."
2. It was a deliberate trade: continuity given up for scalability, caching, and crash
   recovery. You pay the cost; you also get the benefit.
3. There are three places to put the identifier: URL (never), header (manual, CSRF-immune),
   cookie (automatic, needs `SameSite`).
4. Separately: the identifier can *point at* state or *carry* it. Reference vs
   self-contained. That choice is what revocation difficulty is downstream of.
5. Every request runs steps 1–6. Forgetting step 5 on one route is a breach.

---

## Sources

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) §3.3 ("HTTP is a stateless protocol")
- Roy Fielding, *Architectural Styles and the Design of Network-based Software Architectures*, [chapter 5](https://ics.uci.edu/~fielding/pubs/dissertation/rest_arch_style.htm)
- [The Copenhagen Book — Sessions](https://thecopenhagenbook.com/sessions)

---

**Next:** [A06 — Cookies: what they are, where they live, who sends them](A06-cookies.md)
