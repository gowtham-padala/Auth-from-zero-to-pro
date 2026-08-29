# E04 — Session IDs: generation, entropy, storage, expiry

**Part E · Sessions & tokens** · *Builds on [E03](E03-build-server-side-sessions.md), [B03](../track-b/B03-randomness.md)*
---

## Why it matters

Three session IDs, from three real systems. One of these is safe.

```
A)  1a2b3c4d5e6f7a8b                      16 hex chars from Math.random()
B)  eyJ1c2VyIjo0NDcxLCJyb2xlIjoiYWRtaW4ifQ   base64 of {"user":4471,"role":"admin"}
C)  Vx8kQ2mN7pL4rT9wY6zB1cF5hJ0aS3dG8eR7uI2oP4k
```

**A** is predictable — `Math.random()`'s state is recoverable from a handful of outputs
([B03](../track-b/B03-randomness.md)).

**B** is *editable*. Change `4471` to `1`, re-encode, and you are a different user. Change
`"admin"` and you have escalated. This is not a session ID; it is a client-supplied claim
with no integrity protection ([A07](../track-a/A07-client-vs-server.md)).

**C** is 32 random bytes from a CSPRNG, base64url-encoded. Meaningless, unguessable,
unforgeable.

Only C is a session ID. The other two are bugs that happen to work.

---

## Generation

```python
import secrets
token = secrets.token_urlsafe(32)      # 32 bytes = 256 bits
```

That is the entire correct answer. Three properties:

**Cryptographically random.** From the OS CSPRNG. Never `Math.random()`, `rand()`,
`java.util.Random`, `uniqid()`, or a timestamp. The table of correct functions per language
is in [B03](../track-b/B03-randomness.md); learn the one for your stack.

**At least 128 bits.** OWASP's floor is 64; 128 is the practical standard; 256 costs
nothing.

| Bits | Values | Verdict |
|---|---|---|
| 32 | 4.3 × 10⁹ | Brute-forced in seconds |
| 64 | 1.8 × 10¹⁹ | Feasible for a determined attacker |
| **128** | 3.4 × 10³⁸ | **The floor** |
| 256 | 1.2 × 10⁷⁷ | Free. Use this. |

**Meaningless.** No user ID, no timestamp, no role, no tenant. Any structure is information
you have handed the attacker, and any *derivable* structure is a forgery risk.

### UUIDs

| Version | Safe as a session ID? |
|---|---|
| **v4** | ✅ **If** from a CSPRNG. 122 random bits. Use `crypto.randomUUID()`. |
| v1 | ❌ Encodes a timestamp and MAC address. Predictable. |
| v7 | ❌ Deliberately time-sortable. Great as a database key, useless as a secret. |

UUIDv4 is fine and slightly weaker than 32 random bytes, for no benefit. Prefer
`token_urlsafe(32)`.

---

## Storage

### On the server: hash it

```python
db.insert(id=sha256(token).digest(), user_id=...)     # ✅
db.insert(id=token, user_id=...)                      # ❌
```

Your session table is a table of **live credentials**. Anything that can read it — a
read-only SQL injection, a leaked backup, an over-permissive replica, a debugging query in a
notebook, a support tool — hands over working sessions for every logged-in user.

Hash it and the same leak yields nothing usable
([B05](../track-b/B05-hashing-vs-encryption.md)).

**SHA-256, not Argon2id.** 256 bits of entropy has nothing to brute force
([B07](../track-b/B07-fast-hashes-wrong-for-passwords.md)).

### On the client: an `HttpOnly` cookie

```http
Set-Cookie: __Host-session=...; Path=/; Secure; HttpOnly; SameSite=Lax
```

[E02](E02-cookie-attributes.md) for why each attribute. [E12](E12-where-to-store-a-token.md)
for why not `localStorage`.

### Comparison

If you ever compare a session ID directly rather than looking it up by exact key, use a
constant-time comparison ([B16](../track-b/B16-timing-attacks.md)). An indexed
primary-key lookup does not leak the same way; a linear scan with `==` does.

---

## Expiry — three clocks, not one

```
   created_at ──────────────────────────────────────────> absolute_expires_at
       │                                                          │
       │   ┌── idle window ──┐                                     │
       │   │                 │                                     │
       ▼   ▼                 ▼                                     ▼
   ────●───●─────●───────────●─────────────────────────────────────●────>
    login  req   req      last request                        HARD STOP
                             │                              (never extends)
                             └── expires_at slides forward with activity
```

**Idle timeout** (`expires_at`) — expires after inactivity. Slides on use. Protects the
abandoned-session case: a user walks away from a shared machine.

**Absolute timeout** (`absolute_expires_at`) — set once at creation, **never extended**.
Bounds a stolen session. Without it, an attacker who steals a cookie keeps it alive forever
by making one request a day.

**Renewal / rotation** — issue a new ID for the same session, periodically and on every
privilege change. Limits the window in which any single captured ID is useful.

### Choosing durations

| Application | Idle | Absolute |
|---|---|---|
| Banking, health | 15 min | 8 h |
| Admin console | 30 min | 12 h |
| B2B SaaS | 8 h | 30 d |
| Consumer SaaS | 14 d | 90 d |
| "Remember me" | 30 d | 180 d |
| Public content | Long | Long |

Two practical notes. **Warn before an idle expiry** in short-timeout applications — a
30-second modal offering "stay signed in" prevents an enormous amount of lost work. And
**never allow the idle slide to exceed the absolute cap**; the `LEAST()` clamp in
[E03](E03-build-server-side-sessions.md) is what enforces it.

---

## Session fixation

The attack the rotation rule exists to stop.

```
  1. Attacker obtains a valid session ID, or plants one:
        - from a subdomain they control  (no __Host- prefix → cookie tossing)
        - via a Set-Cookie injection
        - via ?sessionid= in a URL, if your app accepts that

  2. Victim uses that ID and logs in.

  3. If the ID does not change at login, the attacker's known ID
     is now an AUTHENTICATED session.
```

Three defences, all of which you should have:

1. **Rotate the ID on login** — and on MFA completion, password change, role change, and
   impersonation start/stop. [E03](E03-build-server-side-sessions.md).
2. **Never accept a session ID from a URL or a request parameter.** Cookies only.
3. **Use the `__Host-` prefix**, so no subdomain can write your session cookie
   ([E02](E02-cookie-attributes.md)).

---

## Binding a session to context

Tempting: reject the session if the IP or user agent changes.

**Do it as a signal, not as a rule.**

| Binding | Problem |
|---|---|
| IP address | Mobile networks change IP constantly. Corporate NAT pools rotate. Users move between Wi-Fi and cellular mid-page. |
| User agent | Changes on every browser update. |
| Full fingerprint | Unstable, forgeable, and a privacy/regulatory issue ([D17](../track-d/D17-remember-this-device.md)). |

Hard-binding produces constant spurious logouts for legitimate users while an attacker who
has the cookie usually has the headers too — they captured both from the same place.

**The useful version:**

```python
def session_risk(session, request) -> str:
    if geoip_country(client_ip()) != geoip_country(session.ip):
        if impossible_travel(session, request):
            return "high"        # step up, or terminate + notify
        return "elevated"        # step up on the next sensitive action
    return "normal"
```

Escalate, do not block ([D18](../track-d/D18-step-up-auth-and-aal.md),
[I09](../track-i/I09-detecting-account-takeover.md)). Store the IP and user agent regardless
— the user's device list needs them ([E13](E13-sessions-across-devices.md)).

---

## Test your own

```python
import requests, collections

# 1. Entropy: are IDs unpredictable?
ids = []
for _ in range(1000):
    s = requests.Session()
    s.post(f"{BASE}/login", data={"email": TEST_EMAIL, "password": TEST_PASSWORD})
    ids.append(s.cookies.get("__Host-session"))

print("unique:", len(set(ids)), "of", len(ids))          # must be 1000
print("length:", collections.Counter(len(i) for i in ids))

# Crude structure check: character frequency should be near-uniform.
chars = collections.Counter("".join(ids))
print("most common char:", chars.most_common(1), "of", sum(chars.values()))

# 2. Is the ID meaningful? Try to decode it.
import base64
try:
    print("decoded:", base64.urlsafe_b64decode(ids[0] + "=="))   # should be noise
except Exception:
    print("not base64 — good")

# 3. Fixation: does the ID change at login?
s = requests.Session()
s.get(f"{BASE}/login")
before = s.cookies.get("__Host-session")
s.post(f"{BASE}/login", data={"email": TEST_EMAIL, "password": TEST_PASSWORD})
after = s.cookies.get("__Host-session")
print("rotated on login:", before != after)              # must be True

# 4. Absolute expiry: is there a hard cap?
#    Keep a session alive with one request per hour for longer than the
#    documented absolute timeout. It must eventually fail.

# 5. Does logout actually delete the server record?
token = after
s.post(f"{BASE}/logout")
r = requests.get(f"{BASE}/api/me", cookies={"__Host-session": token})
print("session valid after logout:", r.status_code == 200)   # must be False
```

Test 5 is the one that fails most often, and it is [E14](E14-why-logout-is-hard.md).

---

## Terms defined in this chapter

`idle timeout`, `absolute timeout`, `session fixation`

---

## What to remember

1. **`secrets.token_urlsafe(32)`.** CSPRNG, 256 bits, meaningless.
2. UUIDv4 is acceptable; **v1 and v7 are not** — they encode time.
3. **Store the hash, not the token.** Your session table is a table of live credentials.
4. **Idle *and* absolute expiry.** The absolute cap is what bounds a stolen session.
5. **Rotate the ID on every privilege change.** Session fixation.
6. **Never accept a session ID from a URL.**
7. **Context binding is a signal, not a rule.** Hard IP binding logs out mobile users
   constantly.
8. Test: 1000 unique IDs, rotation on login, a real absolute cap, and logout that deletes.

---

## Sources

- [OWASP Session Management Cheat Sheet — Session ID properties](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-properties)
- [OWASP WSTG — Testing for Session Fixation](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/03-Testing_for_Session_Fixation)
- [The Copenhagen Book — Sessions](https://thecopenhagenbook.com/sessions)

---

**Next:** [E05 — What a JWT actually is, part 1: the three parts](E05-jwt-part-1-three-parts.md)
