# B07 — Why fast hashes are the wrong tool for passwords

**Part B · Crypto foundations** · *Builds on [B04](B04-what-a-hash-function-is.md)*
---

## Why it matters

You did everything you were told. You did not store plaintext. You hashed.

```python
password_hash = hashlib.sha256(password.encode()).hexdigest()
```

The database is stolen. Within an hour, 80% of your users' passwords are recovered.

Not because SHA-256 is broken — it is not, and nobody reversed anything. Because SHA-256 is
**fast**, and fast is precisely the wrong property here.

A single consumer GPU computes SHA-256 at roughly **10 billion hashes per second**. A rack
does trillions. The attacker does not need to invert your hash. They guess, hash the guess,
and compare — billions of times a second, against every row at once.

Speed is a feature of SHA-256. For passwords it is the vulnerability.

---

## The asymmetry that ruins everything

Everywhere else in cryptography, defenders and attackers face wildly different problems.
Password hashing is the exception, and understanding why is the whole chapter.

| Attacking | Attacker must | Feasible? |
|---|---|---|
| AES-256 key | Search 2²⁵⁶ | No. Never. |
| A 128-bit session ID | Search 2¹²⁸ | No. |
| **A human-chosen password** | Search **~2²⁰ common ones** | **Yes. Trivially.** |

The number that matters is not the hash's output size. It is the size of the space the
*human* chose from.

Real distribution of human passwords:

- The top 1,000 passwords cover roughly 10% of accounts.
- The top 1,000,000 cover roughly 30%.
- Public breach corpora contain **billions** of real passwords, ranked by frequency.
- Rule-based mangling (`password` → `Password1!` → `P@ssw0rd2024`) multiplies coverage
  cheaply.

An attacker does not brute-force the keyspace. They work down a *ranked list of things
humans actually pick*, and they get most accounts before exhausting the first billion
guesses.

> **A password has perhaps 20–30 bits of real entropy. Your hash function's job is to make
> each of the attacker's 2³⁰ guesses expensive enough that 2³⁰ is unaffordable.**
>
> That is the entire design goal. Everything in [B08](B08-salts-peppers-slow-hashes.md)
> follows from it.

---

## Do the arithmetic

Take a strong-ish password: 8 random lowercase letters and digits. 36⁸ ≈ 2.8 × 10¹²
possibilities — about 41 bits. Sounds decent.

| Algorithm | Rate (one high-end GPU) | Time to exhaust 36⁸ |
|---|---|---|
| MD5 | ~200 billion/s | **14 seconds** |
| SHA-1 | ~70 billion/s | ~40 seconds |
| SHA-256 | ~10 billion/s | **~5 minutes** |
| SHA-512 | ~3 billion/s | ~16 minutes |
| bcrypt (cost 12) | ~20 thousand/s | **~4,400 years** |
| Argon2id (19 MiB, t=2) | ~2 thousand/s | **~44,000 years** |

*(Rates are order-of-magnitude, from public benchmark suites; they climb every year, which
is itself the point.)*

Six orders of magnitude, from the same input, by choosing a different function. The
password did not change. The user did not change. Nothing about the security "policy"
changed. One function call did.

And note: real passwords are much weaker than "8 random alphanumerics." Against `Summer2024!`
even Argon2id only buys you time — which is why [D04](../track-d/D04-password-policies.md)
insists on blocklists, and why [D14](../track-d/D14-webauthn-and-passkeys-concepts.md)
exists.

---

## Two attacks that fast hashes enable

### 1. Rainbow tables

A **rainbow table** is a precomputed structure mapping digests back to inputs, using a
time-memory trade-off so that storing it is feasible.

Precompute once, then crack any *unsalted* hash instantly. Tables for unsalted MD5 and
SHA-1 covering all 8-character alphanumerics are freely downloadable and have been for
twenty years.

**Salting kills this completely** ([B08](B08-salts-peppers-slow-hashes.md)). A unique salt
per password means the attacker would need a separate table per user, which defeats the
entire point of precomputation.

Rainbow tables are largely historical now — GPUs made online brute force cheaper than
storing terabytes of tables — but the lesson stands, and salting is still mandatory for the
reasons in the next section.

### 2. Offline attack at unlimited speed

This is the real threat, and it is the one people underestimate.

**Online**, at your login endpoint, you control everything. Rate limiting, lockout,
CAPTCHA, alerting, IP blocking ([D08](../track-d/D08-rate-limiting-and-stuffing.md)). An
attacker gets maybe a few guesses per account per minute.

**Offline**, once they have your database, you control **nothing**.

```
      ONLINE                                 OFFLINE
      (they attack your server)              (they have your hashes)

      ~10 guesses/minute                     ~10,000,000,000 guesses/second
      You can rate limit          ✅          You cannot do anything     ❌
      You can lock the account    ✅          There is no account        ❌
      You can alert              ✅          You do not know it is       ❌
                                              happening
      You can revoke             ✅          The hash is a static file  ❌
```

Every defence you have is a *server* defence, and the server is not involved.

> **The only control that survives a database breach is the cost of computing one hash.**
>
> That is why this chapter exists. Not "in addition to" rate limiting — *instead of*,
> because rate limiting is gone.

Assume the breach. Design the hash for the world after it.

---

## Why "just add more rounds of SHA-256" is not the answer

The obvious fix: `sha256(sha256(sha256(...)))`, 100,000 times. This is roughly what PBKDF2
does, and PBKDF2 is a real, standardised, FIPS-approved KDF.

It is also the weakest of the acceptable options, for one specific reason: **it is
cheap in hardware**.

SHA-256 needs almost no memory. It is a small, fixed computation, ideal for massive
parallelism. GPUs run thousands of instances at once; FPGAs and ASICs do better still —
the entire Bitcoin mining industry is purpose-built silicon for exactly this operation.

So iterating SHA-256 slows the defender (one CPU) and the attacker (ten thousand GPU
cores) by the *same factor*, leaving the attacker's advantage intact.

The insight that fixes this: **make the function require memory.**

| | Cheap to parallelise? | |
|---|---|---|
| CPU work | Yes — add cores | Attacker wins on budget |
| **Memory** | **No** — RAM is expensive, physical, and per-instance | **Attacker's advantage shrinks** |

Requiring 64 MiB per hash means a GPU with 24 GB of RAM can run at most ~375 instances in
parallel, no matter how many cores it has. Custom hardware must include actual memory, which
costs actual money and area. Memory-hardness is the equaliser.

That is what **scrypt** introduced and **Argon2** refined, and it is why Argon2id is the
current recommendation.

---

## The correct answer, previewed

A password hash needs four things:

1. **Slow** — a tunable work factor you increase as hardware improves.
2. **Memory-hard** — so GPUs and ASICs lose their advantage.
3. **Salted** — unique per password, so precomputation and cross-account attacks fail.
4. **Self-describing** — the stored value records its own algorithm and parameters, so you
   can upgrade without a flag day.

| Algorithm | Slow | Memory-hard | Verdict |
|---|---|---|---|
| MD5, SHA-1, SHA-256 | ❌ | ❌ | **Never** |
| PBKDF2 | ✅ | ❌ | Acceptable when FIPS compliance requires it |
| bcrypt | ✅ | ⚠️ (4 KiB, fixed) | Acceptable; 72-byte input limit |
| scrypt | ✅ | ✅ | Good |
| **Argon2id** | ✅ | ✅ | **Recommended** |

The full parameters, the salt/pepper distinction, and working code are
[B08](B08-salts-peppers-slow-hashes.md). The production checklist is
[D03](../track-d/D03-how-to-store-passwords.md).

---

## Where fast hashes are still correct

Do not overcorrect. Slow hashing is for **low-entropy, human-chosen** secrets. For
high-entropy machine-generated ones, a fast hash is right:

| Secret | Entropy | Hash | Why |
|---|---|---|---|
| User password | ~25 bits | **Argon2id** | Guessable; must be expensive |
| API key (32 random bytes) | 256 bits | **SHA-256** | Unguessable; nothing to slow down |
| Session ID | 256 bits | **SHA-256** | Same |
| Reset token | 256 bits | **SHA-256** | Same |

Using Argon2id on a session ID would add latency to *every request* to defend against an
attack — brute-forcing 2²⁵⁶ — that is already impossible. That is not caution; it is a
performance bug with a security costume.

---

## Terms defined in this chapter

`rainbow table`, `offline attack`, `work factor` (introduced; tuned in B08)

---

## What to remember

1. SHA-256 is not broken. It is **fast**, and fast is the wrong property for passwords.
2. The attacker searches the space *humans* choose from — about 2²⁰–2³⁰ — not the hash's
   output space.
3. **Once the database is stolen, every defence you have is gone except the cost of one
   hash.** Design for that world.
4. Iterating a cheap hash slows attacker and defender equally. **Memory-hardness** is what
   removes the attacker's hardware advantage.
5. Argon2id > scrypt > bcrypt > PBKDF2 ≫ anything fast.
6. Fast hashes remain correct for **high-entropy** secrets: API keys, session IDs, reset
   tokens.

---

## Sources

- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.1.1 (memorized secret verifiers)
- Colin Percival, [*Stronger Key Derivation via Sequential Memory-Hard Functions*](https://www.tarsnap.com/scrypt/scrypt.pdf) (the scrypt paper — the memory-hardness argument in full)
- [Password Hashing Competition](https://www.password-hashing.net/) — how Argon2 was chosen

---

**Next:** [B08 — Salts, peppers, and slow hashes: bcrypt, scrypt, argon2id](B08-salts-peppers-slow-hashes.md)
