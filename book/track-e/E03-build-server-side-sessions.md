# E03 — Build server-side sessions

**Part E · Sessions & tokens** · *Builds on [E01](E01-why-http-needs-sessions.md), [B03](../track-b/B03-randomness.md)*
---

## Why it matters

Sessions in a dictionary:

```python
sessions = {}      # ← in the process's memory
```

It works perfectly in development. Then:

- **You deploy.** Every user is logged out, every time, on every deploy.
- **You add a second server.** Half of all requests fail, apparently at random.
- **You get traffic.** The dictionary grows until the process is killed by the OOM reaper.
- **Nothing expires**, so a session from March still works in November.

Every one of those is the same bug: the session store is **process memory**, and process
memory is not where shared, durable, expiring state belongs.

---

## The design

```
   ┌────────────────────────────────────────────────────────────────┐
   │  Browser                                                       │
   │    Cookie: __Host-session=<32 random bytes, base64url>          │
   └───────────────────────────────┬────────────────────────────────┘
                                   │
   ┌───────────────────────────────▼────────────────────────────────┐
   │  Any app server (they are interchangeable)                     │
   │    1. read the cookie                                          │
   │    2. hash it                                                  │
   │    3. look up the hash in the shared store                     │
   └───────────────────────────────┬────────────────────────────────┘
                                   │
   ┌───────────────────────────────▼────────────────────────────────┐
   │  SESSION STORE (Redis / Postgres)                              │
   │    sha256(id) → { user_id, created_at, auth_time, amr,         │
   │                   ip, user_agent, expires_at, ... }            │
   └────────────────────────────────────────────────────────────────┘
```

The cookie value is **meaningless**. It is a pointer. All the meaning is in the store, which
is why you can change it, inspect it, and delete it at will — the properties a
self-contained token gives up ([E09](E09-should-you-use-jwts-for-sessions.md)).

---

## The schema

```sql
CREATE TABLE sessions (
  id            bytea       PRIMARY KEY,          -- SHA-256 of the token
  user_id       uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,

  created_at    timestamptz NOT NULL DEFAULT now(),
  last_seen_at  timestamptz NOT NULL DEFAULT now(),
  expires_at    timestamptz NOT NULL,             -- idle expiry, slides
  absolute_expires_at timestamptz NOT NULL,       -- hard cap, never slides

  -- Authentication context.  D18.
  auth_time     timestamptz NOT NULL,
  amr           text[]      NOT NULL DEFAULT '{}',   -- ['pwd','otp']
  acr           text        NOT NULL DEFAULT 'aal1',

  -- For the user's device list.  E13.
  ip            inet,
  user_agent    text,
  label         text
);

CREATE INDEX ON sessions (user_id);
CREATE INDEX ON sessions (expires_at);
```

Three decisions worth defending.

### The primary key is the **hash** of the token

```python
db.lookup(sha256(token))     # ✅
db.lookup(token)             # ❌
```

If you store raw session IDs, a **read-only** SQL injection, a leaked backup, a
misconfigured replica, or an over-broad analytics query hands an attacker a working session
for every logged-in user. Store the digest and none of those are usable
([B05](../track-b/B05-hashing-vs-encryption.md)).

**SHA-256, not Argon2id.** The token has 256 bits of entropy, so there is nothing to brute
force — a slow hash would add latency to every request to defend against nothing
([B07](../track-b/B07-fast-hashes-wrong-for-passwords.md)).

### Two expiry columns

- **`expires_at`** — idle timeout. Slides forward on activity.
- **`absolute_expires_at`** — set once at creation. **Never** extended.

Without the absolute cap, an attacker with a stolen cookie keeps it alive indefinitely by
making one request a day. [E04](E04-session-ids.md).

### The authentication context travels with the session

`auth_time`, `amr`, `acr` ([D18](../track-d/D18-step-up-auth-and-aal.md)). Without them you
cannot implement step-up, and "authenticated" collapses back into a boolean.

---

## The implementation

```python
import secrets, hashlib
from datetime import datetime, timedelta, timezone

IDLE_TIMEOUT     = timedelta(days=14)
ABSOLUTE_TIMEOUT = timedelta(days=90)

def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()

def create_session(user_id, request, amr=("pwd",), acr="aal1") -> str:
    token = secrets.token_urlsafe(32)              # 256 bits — B03
    now   = datetime.now(timezone.utc)

    db.execute("""
        INSERT INTO sessions (id, user_id, created_at, last_seen_at,
                              expires_at, absolute_expires_at,
                              auth_time, amr, acr, ip, user_agent, label)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (_hash(token), user_id, now, now,
          now + IDLE_TIMEOUT, now + ABSOLUTE_TIMEOUT,
          now, list(amr), acr,
          client_ip(), request.headers.get("User-Agent", ""),
          friendly_device_name(request)))

    return token          # returned ONCE; never stored anywhere else

def load_session(token: str | None):
    if not token:
        return None
    now = datetime.now(timezone.utc)

    row = db.query_one("""
        SELECT * FROM sessions
        WHERE id = %s AND expires_at > %s AND absolute_expires_at > %s
    """, (_hash(token), now, now))

    if row is None:
        return None

    # Slide the idle window, but never past the absolute cap.
    # Only write when it has moved meaningfully — otherwise every request
    # is a database write.
    if now - row.last_seen_at > timedelta(minutes=5):
        db.execute("""
            UPDATE sessions
               SET last_seen_at = %s,
                   expires_at   = LEAST(%s, absolute_expires_at)
             WHERE id = %s
        """, (now, now + IDLE_TIMEOUT, row.id))

    return row

def destroy_session(token: str) -> None:
    db.execute("DELETE FROM sessions WHERE id = %s", (_hash(token),))

def destroy_all_sessions(user_id, except_token: str | None = None) -> int:
    if except_token:
        return db.execute("DELETE FROM sessions WHERE user_id = %s AND id <> %s",
                          (user_id, _hash(except_token)))
    return db.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
```

The `LEAST(..., absolute_expires_at)` clamp is the line that makes the absolute cap real. It
is easy to omit and easy to miss in review.

The five-minute write threshold matters at scale: without it, every request is a database
write, and your session store becomes your bottleneck.

---

## The middleware

```python
@app.before_request
def attach_session():
    g.session = load_session(request.cookies.get("__Host-session"))
    g.user    = db.get_user(g.session.user_id) if g.session else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if g.user is None:
            if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
                return jsonify({"error": "unauthenticated"}), 401
            return redirect(f"/login?next={quote(request.full_path)}")   # A09
        return fn(*a, **kw)
    return wrapper
```

**This gives you authentication, not authorization.** `@login_required` establishes *who*.
It says nothing about *this document*. Forgetting that is IDOR
([C02](../track-c/C02-authn-vs-authz-vs-session.md),
[H14](../track-h/H14-attack-your-own-authorization.md)).

---

## Rotation on privilege change

```python
def rotate_session(old_token: str) -> str:
    """New ID, same session state. Call on every privilege change."""
    row = load_session(old_token)
    if row is None:
        raise ValueError("no session")

    new_token = secrets.token_urlsafe(32)
    db.execute("UPDATE sessions SET id = %s, auth_time = %s WHERE id = %s",
               (_hash(new_token), datetime.now(timezone.utc), _hash(old_token)))
    return new_token
```

Rotate on: **login, MFA completion, password change, role change, impersonation start and
stop** ([I04](../track-i/I04-admin-impersonation.md)).

This is what prevents **session fixation** — an attacker who plants a known session ID gains
nothing, because the ID changes the moment privileges do
([E04](E04-session-ids.md)).

---

## Where to put the store

| Store | Latency | Durable | Best for |
|---|---|---|---|
| **Redis / Valkey** | ~0.5 ms | With AOF | Most applications |
| **PostgreSQL** | ~1–5 ms | ✅ | Small/medium; one fewer moving part |
| **DynamoDB / Firestore** | ~5–10 ms | ✅ | Serverless; native TTL |
| Memcached | ~0.5 ms | ❌ | Only if losing all sessions is acceptable |
| **In-process memory** | ~0 | ❌ | **Never in production** |

**Start with your existing database.** A session lookup is a primary-key read on a small
table; Postgres does that in a millisecond. Adding Redis before you have measured a problem
is complexity you have not earned.

If you do use Redis, set the TTL natively so expired sessions evict themselves:

```python
r.setex(f"sess:{_hash(token).hex()}", int(IDLE_TIMEOUT.total_seconds()), packed_state)
```

And run a cleanup job regardless, for stores without TTL:

```sql
DELETE FROM sessions
 WHERE expires_at < now() OR absolute_expires_at < now();
```

---

## "But this doesn't scale"

The standard objection to server-side sessions, and it is mostly wrong.

**One primary-key lookup, on a table with one row per active session.** Even at ten million
concurrent sessions that is a small index in memory. Redis handles hundreds of thousands of
such lookups per second on one node.

For comparison, verifying an RS256 JWT costs 0.1–1 ms of CPU **per request** — often *more*
than a Redis round trip, and it burns your application's CPU rather than a store optimised
for exactly this.

What you get for that lookup:

- **Instant revocation.** `DELETE`. ([E11](E11-revocation.md).)
- **Session listing and remote logout.** ([E13](E13-sessions-across-devices.md).)
- **Immediate effect of a role or permission change.**
- **Small cookies.** 44 bytes rather than 800, on every request.
- **No stale data.** The state is read fresh each time.

The genuine cases for stateless tokens are: a service that cannot reach your store, a
third-party API, or a very high-throughput edge. [E09](E09-should-you-use-jwts-for-sessions.md)
argues this properly.

---

## The checklist

```
☐  Token: 32 bytes from a CSPRNG, base64url               B03
☐  Stored as SHA-256 in the database, never raw            B05
☐  Cookie: __Host- prefix, Secure, HttpOnly, SameSite=Lax  E02
☐  TWO expiries: idle (slides) and absolute (never)        E04
☐  Idle slide clamped to the absolute cap
☐  last_seen_at written at most every few minutes
☐  auth_time, amr, acr recorded                            D18
☐  ip, user_agent, label recorded for the device list      E13
☐  ID rotates on EVERY privilege change                    D06
☐  destroy_all_sessions on password change                 D09
☐  Expired rows cleaned up on a schedule
☐  Shared store — never process memory
```

Repo tag `ep-E03-sessions` has all of it.

---

## Terms defined in this chapter

`session store`, `sticky sessions`

---

## What to remember

1. **Never store sessions in process memory.** Deploys, second servers, and OOM.
2. **Store the SHA-256 of the token**, not the token. A read-only leak must not be a
   hijacking kit.
3. **Fast hash, not Argon2id** — 256 bits has nothing to brute force.
4. **Two expiries**, and clamp the sliding one to the absolute cap.
5. **Rotate the ID on every privilege change.** Session fixation.
6. Record `auth_time`, `amr`, `acr`, IP, and user agent — step-up and device listing depend
   on them.
7. **Start with your existing database.** A primary-key lookup is not a scaling problem.
8. `@login_required` is authentication. Authorization is still your job.

---

## Sources

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [The Copenhagen Book — Session management](https://thecopenhagenbook.com/sessions)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) V3 — Session Management

---

**Next:** [E04 — Session IDs: generation, entropy, storage, expiry](E04-session-ids.md)
