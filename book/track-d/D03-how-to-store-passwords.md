# D03 — How to store passwords in 2026

**Part D · Authentication** · *Builds on [B08](../track-b/B08-salts-peppers-slow-hashes.md)*
---

## Why it matters

A database backup ends up in a public bucket. 2.4 million rows.

What happens next depends entirely on one decision made years earlier by someone who
probably did not think it was a decision.

| Storage | Time to crack 80% of accounts |
|---|---|
| Plaintext | **Zero.** Already done. |
| MD5, unsalted | **Minutes.** Rainbow tables. |
| SHA-256, unsalted | **Hours.** ~10 billion guesses/second on one GPU. |
| SHA-256, salted | **Days.** Salting removes the bulk attack, not the speed. |
| bcrypt, cost 12 | **Years**, and only the weakest passwords. |
| Argon2id, 19 MiB | **Longer**, and expensive enough that most attackers move on. |

Same breach. Same attacker. Six different outcomes, decided by one function call.

---

## The answer, in full

If you read nothing else:

> **Argon2id, with at least 19 MiB of memory, 2 iterations, and 1 degree of parallelism.
> Use your language's library. Do not generate the salt yourself. Store the whole PHC
> string in one column.**

Everything below is why, and what else you need around it.

---

## The code

```python
# pip install argon2-cffi
import unicodedata
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

ph = PasswordHasher(
    memory_cost=19456,   # 19 MiB — the OWASP minimum
    time_cost=2,         # iterations
    parallelism=1,
)

def normalize(pw: str) -> str:
    # B01: NFC, so 'café' typed two ways hashes the same.
    # NIST SP 800-63B-4 requires normalisation of Unicode passwords.
    return unicodedata.normalize("NFC", pw)

# ---------- Registration -------------------------------------------------
def register(email: str, password: str):
    if len(password.encode("utf-8")) < 8:
        raise ValueError("too short")                 # D04
    if is_breached(password):
        raise ValueError("this password appeared in a known breach")   # D04

    user = User(
        email=canonicalize(email),                    # D02
        password_hash=ph.hash(normalize(password)),   # ← the whole thing
    )
    db.save(user)

# ---------- Login --------------------------------------------------------
DUMMY_HASH = ph.hash("a-value-no-user-will-ever-have")

def login(email: str, password: str) -> User | None:
    user = find_user(canonicalize(email))

    try:
        # Always hash, even for unknown users — otherwise timing leaks
        # which accounts exist.  D07 / B16.
        ph.verify(user.password_hash if user else DUMMY_HASH, normalize(password))
        if user is None:
            return None
    except (VerifyMismatchError, InvalidHashError):
        return None

    # Free upgrade path: parameters changed since this hash was made.
    # We have the plaintext right now, and only right now.  I12.
    if ph.check_needs_rehash(user.password_hash):
        user.password_hash = ph.hash(normalize(password))
        db.save(user)

    return user
```

One column:

```sql
CREATE TABLE users (
  id             uuid PRIMARY KEY,
  email          citext UNIQUE NOT NULL,
  password_hash  text NOT NULL,     -- the entire PHC string
  ...
);
```

```
$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
└──┬───┘ └─┬─┘└────┬────────┘└───┬────┘└──────────────┬─────────────────┘
variant version  parameters     salt                 hash
```

**No separate salt column.** No separate algorithm column. No separate iterations column.
The PHC string is self-describing, which is what makes `check_needs_rehash` possible and
what makes migration ([I12](../track-i/I12-migrating-auth.md)) a non-event.

---

## Parameters, and how to choose them

OWASP's current guidance (2025/2026):

| Configuration | Memory | Iterations | Parallelism |
|---|---|---|---|
| **Minimum** | 19 MiB (`m=19456`) | 2 | 1 |
| Alternative | 46 MiB (`m=47104`) | 1 | 1 |
| Comfortable | 64 MiB (`m=65536`) | 3 | 1–4 |

**Do not copy a number from a blog post, including this one.** Measure:

```python
import time
from argon2 import PasswordHasher

for m in (19456, 47104, 65536, 131072):
    ph = PasswordHasher(memory_cost=m, time_cost=2, parallelism=1)
    t0 = time.perf_counter()
    ph.hash("benchmark-password")
    print(f"m={m:>7} KiB  →  {(time.perf_counter()-t0)*1000:6.1f} ms")
```

Target **250–500 ms** on your production hardware. Then do the capacity arithmetic, which
people skip:

> At 64 MiB and 300 ms per hash, 100 concurrent logins need **6.4 GB of RAM** and will
> queue.

Password hashing is a real resource cost and a denial-of-service vector if unbounded. Put a
concurrency limit in front of it, and rate-limit **before** you hash
([D08](D08-rate-limiting-and-stuffing.md)) — otherwise an attacker exhausts your memory
with garbage login attempts.

Re-measure annually and raise the cost. Hardware improves; your parameters should too.
`check_needs_rehash` makes the upgrade automatic.

---

## If you cannot use Argon2id

| Situation | Use |
|---|---|
| Argon2 unavailable | **scrypt**: N=2¹⁷, r=8, p=1 |
| Legacy system, already bcrypt | **bcrypt** cost ≥ 10 (12 preferred). Watch the 72-byte limit. |
| FIPS 140 required | **PBKDF2-HMAC-SHA256**, 600,000+ iterations |
| Anything else | Argon2id |

### The bcrypt 72-byte trap

bcrypt silently truncates at 72 **bytes** ([B01](../track-b/B01-bits-bytes-text-as-numbers.md)).
A passphrase of 40 emoji is 160 bytes; bcrypt sees the first 72 and ignores the rest,
without error.

If you must accept long passwords with bcrypt, pre-hash:

```python
# Pre-hash to a fixed length. Base64, not raw bytes — some bcrypt
# implementations truncate at the first null byte.
import base64, hashlib
pre = base64.b64encode(hashlib.sha256(password.encode("utf-8")).digest())
stored = bcrypt.hashpw(pre, bcrypt.gensalt(12))
```

Document that you did this. A future maintainer who removes the pre-hash locks out every
user.

---

## What NIST actually requires now

**SP 800-63B-4 was finalised on 31 July 2025** and supersedes the previous revision. The
requirements that touch storage and policy:

| Requirement | Detail |
|---|---|
| Minimum length | **8 characters**; **15** if the password is the only authenticator |
| Maximum length | **Accept at least 64 characters** |
| Character set | Accept **all printing ASCII and spaces**, and Unicode |
| Composition rules | **SHALL NOT** impose them — no "one uppercase, one symbol" |
| Periodic expiry | **SHALL NOT** require it. Only on evidence of compromise |
| Blocklist | **SHALL** check against known-breached and common passwords |
| Hints | **SHALL NOT** offer them |
| Knowledge-based questions | **SHALL NOT** use them |
| Paste | **SHALL** allow it — password managers depend on it |
| Normalisation | Normalise Unicode before hashing |
| Storage | Salted hash with a **memory-hard** KDF |
| Rate limiting | **SHALL** limit failed attempts |

Full policy discussion is [D04](D04-password-policies.md). The storage rows are here
because they are storage decisions.

---

## Seven mistakes that still ship

**1. Truncating before hashing.** A `VARCHAR(20)` password field silently caps entropy.
Never store the password; the *hash* is fixed-length regardless of input.

**2. Hashing client-side and treating it as the password.** Then the hash *is* the
password — an attacker with the database can replay hashes directly, and salting is
defeated. Client-side hashing is only ever an *addition* to server-side hashing, never a
replacement, and it usually is not worth the complexity.

**3. Reusing the salt.** If you are touching a salt at all, you are using the wrong API.

**4. Logging the password.** It ends up in request logs, error trackers, and APM traces.
Add `password`, `new_password`, `current_password`, `token`, `secret`, and `authorization`
to your logging redaction list, today ([I08](../track-i/I08-observability.md)).

**5. Comparing with `==`.** You should never be comparing password hashes directly — call
`verify()`. If you find a `==` on a hash, something is wrong
([B16](../track-b/B16-timing-attacks.md)).

**6. Not checking against breach corpora.** The single highest-value password control there
is. [D04](D04-password-policies.md).

**7. Storing a password history in a reversible form.** "Cannot reuse your last 5
passwords" requires storing 5 hashes — which is fine — but some implementations store them
encrypted to allow similarity checks. Now you have five recoverable passwords per user.

---

## Adding a pepper

Optional, and a real improvement if you have a KMS
([B08](../track-b/B08-salts-peppers-slow-hashes.md)).

```python
import hmac, hashlib
PEPPER = os.environ["PASSWORD_PEPPER"]     # ideally: never leaves a KMS — I05

def prehash(password: str) -> bytes:
    return hmac.new(PEPPER.encode(), normalize(password).encode("utf-8"),
                    hashlib.sha256).digest()

stored = ph.hash(prehash(password))
```

Defends the **database-only breach** — SQL injection, a leaked backup, a snapshot with the
wrong permissions. In that scenario every hash becomes uncrackable, because the attacker
is missing an input entirely.

Store a **pepper version** alongside the hash and rotate with rehash-on-login. Without a
rotation plan, and with the pepper sitting in the same `.env` as your database URL, it buys
nothing.

---

## The migration path

You have MD5 hashes. Or SHA-1. Or bcrypt at cost 8. You cannot re-hash without plaintext,
and you do not have plaintext.

**Rehash on login** is the technique ([I12](../track-i/I12-migrating-auth.md)):

```python
if user.password_hash.startswith("$argon2id$"):
    ph.verify(user.password_hash, normalize(password))
elif user.password_hash.startswith("$2b$"):                # bcrypt
    if not bcrypt.checkpw(normalize(password).encode(), user.password_hash.encode()):
        raise VerifyMismatchError
    user.password_hash = ph.hash(normalize(password))      # upgrade now
    db.save(user)
else:                                                       # legacy MD5/SHA1
    if not legacy_check(user.password_hash, password):
        raise VerifyMismatchError
    user.password_hash = ph.hash(normalize(password))
    db.save(user)
```

For accounts that never log in, set a deadline: after N months, force a password reset and
delete the legacy hash. Do not carry MD5 hashes indefinitely because a few users are
dormant.

**The stronger variant**, if the old hashes are genuinely dangerous: wrap them immediately,
without waiting for a login.

```python
# Do this in a batch job, today, over the whole table:
new_hash = ph.hash(base64.b64encode(bytes.fromhex(old_md5_hash)))
```

Now the stored value is Argon2id over the old digest. The weak hash is gone from your
database immediately. On login, hash the password with the legacy algorithm first, then
verify against the Argon2id wrapper — and opportunistically replace it with a direct
Argon2id hash. This is what LinkedIn and others should have done, and it converts
"catastrophic" to "inconvenient" in one batch job.

---

## Terms defined in this chapter

`password`, `password hash`

---

## What to remember

1. **Argon2id, m ≥ 19 MiB, t=2, p=1.** Library-generated salt. One PHC string in one
   column.
2. **Measure on your hardware.** Target 250–500 ms. Then check the RAM arithmetic and bound
   concurrency.
3. `check_needs_rehash` on every login is a free continuous upgrade.
4. **NIST SP 800-63B-4 (July 2025):** 8 chars minimum, no composition rules, no periodic
   expiry, mandatory breach blocklist, allow paste.
5. bcrypt truncates at **72 bytes**. Pre-hash with base64'd SHA-256 if you need long
   passwords.
6. **Always hash a dummy for unknown users**, or timing enumerates your users.
7. Redact `password` from every log, error tracker, and trace.
8. Migrating: rehash on login, or wrap the old hashes in a batch job today.

---

## Sources

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B-4 — Digital Identity Guidelines: Authentication and Authenticator Management](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) (final, 31 July 2025)
- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106)
- [The Copenhagen Book — Password authentication](https://thecopenhagenbook.com/password-authentication)

---

**Next:** [D04 — Password policies that help, and the ones NIST removed](D04-password-policies.md)
