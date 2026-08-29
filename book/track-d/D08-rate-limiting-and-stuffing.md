# D08 — Rate limiting, lockout, and credential stuffing defense

**Part D · Authentication** · *Builds on [D06](D06-build-login-part-2-login.md)*
---

## Why it matters

A company implements the standard defence: **five failed attempts and the account locks for
thirty minutes.** It works exactly as designed.

An attacker writes twenty lines:

```python
for email in customer_emails:                # scraped, or enumerated — D07
    for _ in range(5):
        requests.post("/login", data={"email": email, "password": "x"})
```

Every customer is locked out. The support queue fills. The company disables the lockout to
restore service — and now has no brute-force defence at all.

The lockout was not a security control. It was a **denial-of-service feature** the attacker
triggered on demand, and it converted an availability attack into a security regression.

---

## Two different attacks

Everything about the defence depends on which one you are facing. They are frequently
conflated and require opposite responses.

### Brute force / credential stuffing — many passwords, one account

```
alice@example.com : password123
alice@example.com : letmein
alice@example.com : Summer2025!
```

**Credential stuffing** is the modern form: not guessing, but *replaying* username/password
pairs breached elsewhere. It works because password reuse is near-universal. Success rates
of 0.1–2% are typical — which against ten million credentials is ten thousand to two
hundred thousand accounts.

**Defence:** per-account limits. And more importantly, the breach blocklist
([D04](D04-password-policies.md)), because stuffing only works on reused passwords.

### Password spraying — one password, many accounts

```
alice@example.com : Winter2026!
bob@example.com   : Winter2026!
carol@example.com : Winter2026!
```

Deliberately stays *under* per-account thresholds. One attempt per account, then move on,
then come back tomorrow with the next seasonal password.

**Per-account rate limiting does nothing against this.** It is designed around it.

**Defence:** global anomaly detection — a spike in failures across many distinct accounts,
a single password appearing in many failures, an unusual source distribution.

> **Per-account limits stop stuffing. Only global detection stops spraying.** Most systems
> implement the first and believe they are protected against both.

---

## The layered defence

No single mechanism works. Six layers, each catching what the previous one misses.

### Layer 1 — Breach blocklist

Reject known-breached passwords at registration and change
([D04](D04-password-policies.md)).

**This is layer 1 because credential stuffing only works against reused passwords.** Remove
the reuse and you remove the attack, rather than rate-limiting it.

Also worth doing: check *existing* users' passwords against new breach corpora at their
next login. If it now appears, force a change. NIST SP 800-63B-4 explicitly permits — and
in effect expects — rotation on evidence of compromise.

### Layer 2 — Rate limiting on multiple keys

```python
LIMITS = [
    ("ip",           "20/15min"),   # one machine, many accounts
    ("account",      "10/15min"),   # many machines, one account
    ("ip+account",   "5/15min"),    # the tightest pairing
    ("global",       "dynamic"),    # spraying detection
]
```

**The rate limit must apply before the expensive work.** Argon2id at 19 MiB is a resource
cost ([D03](D03-how-to-store-passwords.md)) — an unbounded login endpoint is a memory
exhaustion vector. Check the limiter first, then hash.

### Layer 3 — Progressive delay, not lockout

Instead of a binary lock, slow down:

| Failed attempts | Delay before the next is accepted |
|---|---|
| 1–3 | none |
| 4 | 1 s |
| 5 | 2 s |
| 6 | 4 s |
| 7 | 8 s |
| 8+ | 30 s (capped) |

An attacker's throughput collapses. A legitimate user who mistypes twice notices nothing.
And crucially: **there is no state an attacker can push a victim into that denies them
service.** The delay decays; a lock does not.

Cap the delay. Unbounded exponential backoff becomes a lockout with extra steps.

### Layer 4 — Risk-based challenges

Escalate rather than block:

```
Normal        → password only
Suspicious    → password + CAPTCHA
Very unusual  → password + email verification code
Compromised   → password + full reauthentication, and notify the user
```

Signals: new device, new country, impossible travel, a known-bad IP, a datacentre ASN, a
sudden failure spike. [I09](../track-i/I09-detecting-account-takeover.md).

The advantage over blocking is that a legitimate user is never *stopped*, only slowed. That
matters, because the alternative is a support ticket.

### Layer 5 — Detection and alerting

Alert on:

- Failures across many distinct accounts from one source (spraying)
- A single password appearing in many failed attempts across accounts
- A step change in the global failure rate
- Successful logins from a source that just failed against many accounts — **the most
  important signal, because it means the attack worked**

### Layer 6 — Make the credential irrelevant

**Passkeys** ([D14](D14-webauthn-and-passkeys-concepts.md)) cannot be stuffed. There is no
password to reuse, no shared secret, and no phishable code. A user with a passkey is immune
to everything in this chapter.

Everything above is mitigation. This is elimination.

---

## A limiter that works

Token bucket, in Redis, atomic:

```python
import time, redis
r = redis.Redis()

# Lua so check-and-consume is a single atomic operation.
BUCKET = r.register_script("""
local key      = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate     = tonumber(ARGV[2])   -- tokens per second
local now      = tonumber(ARGV[3])

local b = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(b[1]) or capacity
local ts     = tonumber(b[2]) or now

tokens = math.min(capacity, tokens + (now - ts) * rate)

local allowed = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
end

redis.call('HMSET', key, 'tokens', tokens, 'ts', now)
redis.call('EXPIRE', key, math.ceil(capacity / rate) * 2)
return {allowed, tostring(tokens)}
""")

def allow(key: str, capacity: int, per_seconds: int) -> bool:
    allowed, _ = BUCKET(keys=[f"rl:{key}"],
                        args=[capacity, capacity / per_seconds, time.time()])
    return allowed == 1

def login_allowed(email: str, ip: str) -> bool:
    canonical = canonicalize(email)
    return (
        allow(f"ip:{ip}",                    capacity=20, per_seconds=900) and
        allow(f"acct:{canonical}",           capacity=10, per_seconds=900) and
        allow(f"pair:{ip}:{canonical}",      capacity=5,  per_seconds=900)
    )
```

Why a token bucket rather than a fixed window:

- **Fixed windows have a boundary problem.** "10 per minute" allows 20 in two seconds
  across a window edge.
- **Token buckets allow bursts** up to capacity and then enforce a sustained rate, which
  matches how humans actually behave — a few quick retries, then a pause.
- **The Lua script is atomic.** A read-then-write in application code loses the race under
  concurrency, which is exactly when it matters.

### Do not leak through the limiter

From [D07](D07-user-enumeration.md): rate limit **unknown** accounts identically. If
`acct:` keys are only created for real users, an attacker learns which accounts exist by
observing which ones start rejecting.

Track by **submitted email**, whether or not it resolves.

And return `429` with `Retry-After`, not `403`
([A03](../track-a/A03-methods-status-codes-401-vs-403.md)) — but consider that a `429`
itself reveals you are counting. For login specifically, many systems return the same `401`
with an added delay, which leaks less.

---

## What to key on, and its weaknesses

| Key | Stops | Weakness |
|---|---|---|
| IP address | Single-source attacks | Botnets, residential proxies, shared NAT |
| Account | Targeted stuffing | Nothing against spraying |
| IP + account | Both, tightly | Bypassed by rotating either |
| Device fingerprint | Determined attackers | Spoofable; privacy implications |
| ASN / subnet | Datacentre traffic | Blocks legitimate VPN users |
| Global rate | Spraying | Needs a baseline; noisy |

**IPv6 needs care.** A single user may have a /64 with 18 quintillion addresses. Rate limit
IPv6 by **/64 prefix**, not by full address, or the limiter is meaningless.

Residential proxy networks — millions of real consumer IPs, rented by the hour — make
IP-based limiting much weaker than it was five years ago. Assume an attacker has a fresh IP
for every request, and make sure your defence does not depend solely on that key.

---

## When lockout is right

Rarely, but not never:

| Context | Approach |
|---|---|
| Consumer web app | **Progressive delay.** Never lock. |
| B2B SaaS | Progressive delay + tenant-wide alerting |
| Banking / high value | Lockout is acceptable; the DoS trade-off is worth it |
| Internal admin tools | Lockout is fine; small user population, staff can call IT |
| Hardware / device PIN | **Hard lockout** — a 4-digit PIN has 10,000 possibilities |

The device PIN row shows the principle: **lockout is right when the credential space is
small enough that rate limiting alone cannot save it.** A 4-digit PIN with a 1-second delay
falls in under three hours. Ten attempts and wipe is the correct design — and it is why
your phone does that.

For a password with a breach blocklist and 8+ characters, progressive delay is sufficient
and does not hand an attacker a DoS button.

---

## Do not forget the other endpoints

Login gets the attention. These get attacked too:

| Endpoint | Attack | Limit |
|---|---|---|
| Password reset request | Mail bombing, enumeration | 3/hour per account, 10/hour per IP |
| Reset token submission | Token brute force | 5/hour per token |
| Registration | Bulk accounts, spam relay | 5/hour per IP + **global** ([D05](D05-build-login-part-1-registration.md)) |
| Email verification resend | Mail bombing | 3/hour per account |
| **MFA code submission** | 10⁶ brute force | **5 per pending session** ([D12](D12-build-totp.md)) |
| Magic link request | Mail bombing | 3/hour per account |
| API token creation | Resource exhaustion | Per user |
| SSO initiation | IdP abuse | Per tenant |

The **MFA row is the one that gets missed and matters most.** A six-digit TOTP code is
1,000,000 possibilities, and the code is valid for 30–90 seconds. Without a limit, an
attacker who has the password gets through in minutes. Five attempts, then invalidate the
pending session entirely.

---

## Terms defined in this chapter

`rate limiting`, `account lockout`, `exponential backoff`, `credential stuffing`

---

## What to remember

1. **Lockout is a DoS button** an attacker presses on your behalf. Use progressive delay.
2. **Stuffing and spraying are different attacks.** Per-account limits stop the first and
   are designed around by the second.
3. **The breach blocklist is layer 1**, because stuffing only works on reused passwords.
4. Rate limit **before** the expensive hash, or your login is a memory-exhaustion vector.
5. Key on IP, account, and the pair. Rate limit IPv6 by **/64**.
6. **Track unknown accounts too**, or the limiter becomes your enumeration oracle.
7. **Limit MFA code submission.** Six digits is a million, valid for a minute.
8. Passkeys eliminate this entire chapter.

---

## Sources

- [OWASP Credential Stuffing Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Credential_Stuffing_Prevention_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.2.2 (rate limiting), §5.2.2
- [OWASP Blocking Brute Force Attacks](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks)
- [Cloudflare: What is credential stuffing?](https://www.cloudflare.com/learning/bots/what-is-credential-stuffing/)

---

**Next:** [D09 — Account recovery is your real weakest link](D09-account-recovery.md)
