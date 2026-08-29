# B08 — Salts, peppers, and slow hashes: bcrypt, scrypt, argon2id

**Part B · Crypto foundations** · *Builds on [B07](B07-fast-hashes-wrong-for-passwords.md)*
---

## Why it matters

A breached password table, hashed with SHA-256. No salt.

```
email              | password_hash
-------------------+------------------------------------------------------------------
alice@example.com  | 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
bob@example.com    | 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
carol@example.com  | 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
dave@example.com   | ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
```

Before cracking a single hash, you already know:

1. Alice, Bob, and Carol **have the same password**.
2. It is a *common* password, because three of your first four users picked it.
3. Crack it once — one guess against one digest — and you own all three accounts.

(It is `password`. The fourth is `password123`.)

Now the killer property: this is not three separate attacks. **The attacker cracks the
whole database in one pass.** Hash a guess once, compare it against every row
simultaneously. Ten million users cost the same as one.

Salting is what makes that impossible.

---

## Salts

> A **salt** is a unique, random, **non-secret** value mixed into each password before
> hashing.

```
alice:  hash("password" + "a3f9c2e1...")  →  9d4a7f2b...
bob:    hash("password" + "7b2e5d8c...")  →  c1f8e3a9...
```

Same password. Different salts. **Unrelated digests.** The pattern is gone, and so is the
bulk attack.

### What salting buys

| Attack | Without salt | With unique salt |
|---|---|---|
| Rainbow tables | Instant lookup | Useless — a table per user is needed |
| Cracking N users | 1 pass cracks all matches | **N separate attacks** |
| Spotting shared passwords | Trivially visible | Impossible |
| Cross-site correlation | Same hash appears in other breaches | No correlation |

That second row is the important one. Salting converts one attack into N attacks. Combined
with a slow hash ([B07](B07-fast-hashes-wrong-for-passwords.md)), the economics collapse:
cracking one weak password may be cheap, cracking ten million is not.

### The rules

1. **Unique per password.** Not per application, not per user, not "the username." Per
   password — regenerate on every password change.
2. **Random**, from a CSPRNG ([B03](B03-randomness.md)).
3. **At least 16 bytes** (128 bits).
4. **Not secret.** Stored right next to the hash. This surprises people, and it is fine —
   the salt's job is *uniqueness*, not secrecy. It defeats precomputation and bulk attack.
   It is not a key.
5. **You do not implement this yourself.** Every modern password library generates the salt
   and embeds it in the output. If you find yourself concatenating a salt, you are using
   the wrong function.

### The naive-construction trap

If you *were* hand-rolling it (do not), `hash(salt + password)` is subject to length
extension ([B13](B13-message-authentication-hmac.md)), and simple concatenation is
ambiguous — salt `"ab"` + password `"cd"` gives the same bytes as salt `"a"` + password
`"bcd"`. Real KDFs handle length-prefixing and domain separation properly. This is the
strongest argument for using the library: the failure modes are not obvious.

---

## Peppers

> A **pepper** is a secret value added to every password hash, stored **outside the
> database**.

```
stored = argon2id(password + PEPPER, salt)      # conceptually
        └─ better: HMAC-SHA256(PEPPER, password) then Argon2id the result
```

| | Salt | Pepper |
|---|---|---|
| Unique per password? | **Yes** | No — one for the whole system |
| Secret? | **No** | **Yes** |
| Stored where? | With the hash | Env var, KMS, HSM — *not* the database |
| Defends against | Precomputation, bulk cracking | **Database-only breach** |

The threat model is precise and narrow: an attacker who gets the **database but not the
application secrets**. That is a real and common scenario — SQL injection, a leaked backup,
a misconfigured snapshot, an over-permissive read replica. In that world the pepper makes
every hash uncrackable, because the attacker is missing an input entirely.

If they compromise the application server too, the pepper is gone and buys nothing.
Defence in depth: it converts a whole category of breach from catastrophic to survivable.

### Doing it correctly

The right construction is **not** string concatenation. Use an HMAC as a pre-hash:

```python
# Pre-hash with a keyed function, then run the slow KDF.
peppered = hmac.new(PEPPER, password.encode("utf-8"), hashlib.sha256).digest()
stored   = argon2id.hash(peppered)
```

Why this shape:

- HMAC is designed for a secret key; concatenation is not
  ([B13](B13-message-authentication-hmac.md)).
- It produces a fixed 32 bytes, which **neatly sidesteps bcrypt's 72-byte limit** if you
  are using bcrypt.
- The pepper can live in a KMS, so the application never holds it — you call the KMS to
  compute the HMAC ([I05](../track-i/I05-secrets-management.md)).

**The catch:** rotating a pepper requires re-hashing every password, which you cannot do
without the plaintext. The workable pattern is versioning — store a pepper version
alongside the hash, verify with the version stored, and re-hash with the current pepper on
successful login. Same mechanism as
[I12](../track-i/I12-migrating-auth.md)'s rehash-on-login.

**Verdict:** worth it if you have a KMS and a rotation plan. Not worth it if the pepper
ends up in the same `.env` file as your database URL, which defeats the entire threat
model.

---

## The algorithms

### bcrypt (1999)

Based on the Blowfish key schedule, deliberately expensive to set up.

```
$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewKyPUpQnQ4XSRfW
└┬┘ └┬┘ └──────────────────────┬───────────────────────────┘
 │   │                         │
 │   │                         └─ 22 chars salt + 31 chars hash (base64-ish)
 │   └─ cost = 12  →  2¹² = 4096 iterations
 └─ algorithm identifier
```

- **Cost:** each +1 doubles the work. **Minimum 10; 12 is a reasonable 2026 default.**
- **Memory:** 4 KiB, fixed. Some GPU resistance, but not much by modern standards.
- **⚠️ The 72-byte limit.** bcrypt silently truncates input at 72 **bytes**
  ([B01](B01-bits-bytes-text-as-numbers.md) — bytes, not characters). Longer passwords are
  cut without warning. Pre-hash with HMAC-SHA256 if you must accept long passwords.
- **⚠️ Null bytes.** Some implementations truncate at the first `\0`. If you pre-hash, use
  base64 or hex of the digest, not raw bytes.

Still acceptable. Not what you would choose today.

### scrypt (2009)

The first widely-deployed **memory-hard** function. Percival's insight that memory, not
CPU, is what removes an attacker's hardware advantage
([B07](B07-fast-hashes-wrong-for-passwords.md)).

- **OWASP minimum:** N = 2¹⁷, r = 8, p = 1 (about 128 MiB).
- Good, well-analysed, in every standard library. Argon2 does the same job with better
  side-channel properties and clearer parameters.

### Argon2 (2015) — the current recommendation

Winner of the Password Hashing Competition. Three variants:

| Variant | Property | Use |
|---|---|---|
| Argon2d | Data-dependent memory access. Best GPU resistance, **vulnerable to side channels**. | Cryptocurrency |
| Argon2i | Data-independent. Side-channel resistant, weaker against GPUs. | Legacy |
| **Argon2id** | **Hybrid** — data-independent first pass, dependent after. | **Passwords. Use this one.** |

```
$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
└───┬────┘└──┬─┘└───────┬──────┘└────┬───┘└──────────────┬───────────────┘
 variant  version    parameters      salt                hash

  m = memory in KiB    t = iterations    p = parallelism
```

**OWASP-recommended parameters (2025/2026):**

| Configuration | m | t | p | Notes |
|---|---|---|---|---|
| **Minimum** | 19 MiB (19456) | 2 | 1 | The floor. Also the `libsodium` "interactive" ballpark. |
| Alternative | 46 MiB (47104) | 1 | 1 | Equivalent security, more memory / less CPU |
| Higher-resource | 64–128 MiB | 3–4 | 1–4 | If your servers can afford it |

**Tune to your hardware, not to a blog post.** The rule of thumb: pick the highest cost
that keeps verification at roughly **250–500 ms** on your production hardware, at your peak
login rate. Then re-measure annually and raise it.

Do the capacity arithmetic before you deploy: at 64 MiB and 300 ms per hash, 100
simultaneous logins need 6.4 GB of RAM and will queue. Password hashing is a genuine
resource cost, and a denial-of-service vector if unbounded — put logins behind a
concurrency limit.

### PBKDF2

Iterated HMAC. Standardised, FIPS-approved, **not memory-hard**.

Use it only when a compliance regime requires FIPS 140 validation. If you must:
600,000+ iterations with HMAC-SHA256, or 210,000+ with HMAC-SHA512 (OWASP's current
figures). Note the ceiling: PBKDF2's output length is capped by the underlying hash, and
requesting more triggers extra work for the defender only.

---

## Use it

```python
# pip install argon2-cffi
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

ph = PasswordHasher(
    memory_cost=19456,   # 19 MiB — OWASP minimum
    time_cost=2,
    parallelism=1,
)

# --- Registration -----------------------------------------------------------
import unicodedata
def normalize(pw: str) -> str:
    return unicodedata.normalize("NFC", pw)          # B01 — do this, always

stored = ph.hash(normalize(password))
# → '$argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>'
#   Salt generated for you. Parameters embedded. Store this ONE string.

# --- Login ------------------------------------------------------------------
try:
    ph.verify(stored, normalize(submitted))
except (VerifyMismatchError, InvalidHashError):
    return login_failed()          # identical response for both — D07

# Free upgrade path: if params have changed since this hash was made,
# re-hash now, while we have the plaintext. This is I12's rehash-on-login.
if ph.check_needs_rehash(stored):
    user.password_hash = ph.hash(normalize(submitted))
    user.save()

return login_success()
```

Six lines of real logic. Note what you did **not** write: no salt generation, no
concatenation, no comparison, no parameter parsing. The library does all of it, and the
self-describing **PHC string** format is what makes the upgrade path in
`check_needs_rehash` possible.

### The equivalent everywhere else

| Language | Library |
|---|---|
| Python | `argon2-cffi` |
| Node.js | `argon2`, or `@node-rs/argon2` |
| Go | `golang.org/x/crypto/argon2` (`IDKey`) |
| Rust | `argon2` crate |
| Java | Spring Security `Argon2PasswordEncoder`, or BouncyCastle |
| PHP | `password_hash($pw, PASSWORD_ARGON2ID)` — built in |
| Ruby | `argon2` gem |
| .NET | `Konscious.Security.Cryptography.Argon2` |

PHP deserves credit here: `password_hash()` / `password_verify()` / `password_needs_rehash()`
is the best-designed password API in any standard library, and every other ecosystem should
have copied it.

---

## Timing, and the user-enumeration trap

Verification must take the same time whether the user exists or not.

```python
# ❌ leaks account existence through timing — no hashing happens for unknown users
user = find_user(email)
if not user:
    return error("Invalid credentials")     # returns in 2 ms
ph.verify(user.password_hash, password)     # takes 300 ms

# ✅ always do the work
DUMMY = ph.hash("a-fixed-value-that-nobody-uses")
user = find_user(email)
try:
    ph.verify(user.password_hash if user else DUMMY, password)
    ok = user is not None
except VerifyMismatchError:
    ok = False
```

That timing difference is a reliable oracle across a network, and it is
[D07](../track-d/D07-user-enumeration.md) and [B16](B16-timing-attacks.md) in miniature.

---

## Terms defined in this chapter

`salt`, `pepper`, `key derivation function`, `bcrypt`, `scrypt`, `Argon2id`,
`memory-hard`, `PHC string`, `work factor`

---

## What to remember

1. **Salt: unique, random, 16+ bytes, not secret.** It defeats precomputation and turns one
   attack into N.
2. **Pepper: one secret, outside the database.** Defends the database-only breach. Use
   HMAC, not concatenation. Have a rotation plan or skip it.
3. **Argon2id** with ≥19 MiB, t=2, p=1. Tune to ~250–500 ms on your hardware and re-measure
   yearly.
4. bcrypt is acceptable — cost ≥ 10 — but watch the **72-byte** truncation.
5. Never generate the salt yourself. The library embeds everything in a **PHC string**.
6. `check_needs_rehash` on every login is a free, continuous upgrade path.
7. Hash a dummy for unknown users, or your timing leaks your user list.

---

## Sources

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) — parameters current as of 2025
- [RFC 9106 — Argon2 Memory-Hard Function for Password Hashing](https://www.rfc-editor.org/rfc/rfc9106)
- [PHC string format specification](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)
- Colin Percival, [*Stronger Key Derivation via Sequential Memory-Hard Functions*](https://www.tarsnap.com/scrypt/scrypt.pdf)

---

**Next:** [B09 — Symmetric encryption: XOR by hand, then AES](B09-symmetric-encryption.md)
