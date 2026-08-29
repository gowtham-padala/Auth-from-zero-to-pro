# B03 — Randomness, and why Math.random() will get you breached

**Part B · Crypto foundations** · *Builds on [B01](B01-bits-bytes-text-as-numbers.md)*
---

## Why it matters

Here is a session ID generator. It looks fine. Variants of it are in production right now.

```js
function generateSessionId() {
  return Math.random().toString(36).substring(2) +
         Math.random().toString(36).substring(2);
}
// → "k3j2h4g5f6d7s8a9q1w2e3r4t5y6u7i8"
```

Twenty-six characters of apparent gibberish. Nobody is guessing that.

Nobody has to. `Math.random()` in V8 is **xorshift128+**, a fast, well-studied,
**completely deterministic** generator with 128 bits of internal state. Given a handful of
consecutive outputs, that state can be recovered by solving a system of equations — this
has been public since 2015 and there is working tooling for it.

Recover the state, and you do not guess the next session ID. You **compute** it. And the
previous one. And every one that will ever be issued by that process.

The attack is: register an account, collect your own session IDs, solve for the state, and
mint the session ID that the next person to log in will receive. It is not theoretical.
This class of bug has produced real breaches, and it is almost never taught.

---

## Two kinds of random

The word "random" means two incompatible things, and every bug in this chapter is someone
using the first where the second was required.

### Statistical randomness — "looks random"

Passes distribution tests. Uniform. No obvious patterns. Good for shuffling a playlist,
sampling data, spawning enemies in a game.

`Math.random()`, `rand()`, `random.random()`, `java.util.Random` — all statistically fine.

### Cryptographic randomness — "cannot be predicted"

Even an adversary who has seen **all previous outputs** and knows the algorithm cannot
predict the next bit better than chance.

That is a strictly stronger requirement, and it is the only one that matters for security.

```
Statistical:  "the digits are evenly distributed"
Cryptographic: "knowing 10,000 outputs tells you nothing about output 10,001"
```

A **PRNG** (pseudo-random number generator) produces a deterministic stream from a
**seed**. A **CSPRNG** is a PRNG designed so the stream is unpredictable even given
outputs — typically by drawing entropy from OS-level sources (hardware noise, interrupt
timing, `RDRAND`) and by using a construction that is not invertible.

| | PRNG | CSPRNG |
|---|---|---|
| Deterministic from a seed | Yes | Yes (but the seed is unknowable) |
| Passes statistical tests | Yes | Yes |
| Predictable from outputs | **Yes** | **No** |
| State recoverable | **Yes, often trivially** | No |
| Safe for security | **Never** | Yes |

---

## The demonstration

Do this yourself. It is the fastest way to stop trusting `Math.random()` forever.

### Step 1 — Generate 1000 "session IDs"

```js
// bad.js  —  run with: node bad.js > ids.txt
function generateSessionId() {
  return Math.random().toString(36).substring(2, 15);
}
for (let i = 0; i < 1000; i++) console.log(generateSessionId());
```

Look at the file. It is 1000 lines of convincing noise. No structure visible to a human.

### Step 2 — Recover the state

V8 generates `Math.random()` values in **batches of 64**, filling a cache and serving it
**in reverse order**. That implementation detail is a gift to an attacker — it means a
handful of consecutive observed values come from adjacent internal states.

The recovery works like this (a real one uses an SMT solver such as Z3):

```python
# concept — the real version uses z3-solver
from z3 import *

s0, s1 = BitVecs("s0 s1", 64)
solver = Solver()

# Model xorshift128+ symbolically and constrain it to the observed doubles.
for observed in observed_values:          # ~5 consecutive outputs is enough
    s1_ = s0
    s0_ = s1
    s1_ ^= s1_ << 23
    s1_ ^= LShR(s1_, 17)
    s1_ ^= s0_
    s1_ ^= LShR(s0_, 26)
    s0, s1 = s0_, s1_
    # V8 takes the top 52 bits as the mantissa of a double in [0,1)
    solver.add(LShR(s0, 12) == float_to_mantissa(observed))

solver.check()      # sat
# → the internal state. Now run it forwards for every future value.
```

**Five observed values.** That is the cost. Public tooling has existed for a decade;
searching for "v8 math.random state recovery" finds working implementations in minutes.

### Step 3 — Predict

With the state recovered, iterate the generator forward and produce the next session ID
before the victim's browser has received it. Hand it to the server. You are them.

### Step 4 — The fix

```js
const crypto = require("crypto");

function generateSessionId() {
  return crypto.randomBytes(32).toString("base64url");   // 256 bits of entropy
}
```

One line. No state to recover, because the state is inside the operating system's CSPRNG
and is never exposed. There is no shortcut; an attacker must brute-force 2²⁵⁶.

**Cost of doing it right: zero.** `crypto.randomBytes` is fast enough that no application
has ever been bottlenecked by it. There is no performance argument, no complexity
argument, no compatibility argument. There is only knowing which function to call.

---

## The correct function, per language

Memorise the one for your stack. This is the whole practical takeaway.

| Language | ✅ Use | ❌ Never |
|---|---|---|
| Node.js | `crypto.randomBytes(32)`, `crypto.randomUUID()` | `Math.random()` |
| Browser | `crypto.getRandomValues(new Uint8Array(32))` | `Math.random()` |
| Python | `secrets.token_bytes(32)`, `secrets.token_urlsafe(32)` | `random.*` |
| Go | `crypto/rand.Read` | `math/rand` |
| Java | `SecureRandom` | `java.util.Random`, `Math.random()` |
| Rust | `rand::rngs::OsRng`, `getrandom` | `rand::thread_rng` for keys |
| PHP | `random_bytes(32)`, `bin2hex(random_bytes(16))` | `rand()`, `mt_rand()`, `uniqid()` |
| Ruby | `SecureRandom.bytes(32)` | `Random.rand` |
| C# | `RandomNumberGenerator.GetBytes(32)` | `System.Random` |
| C / POSIX | `getrandom(2)`, `/dev/urandom` | `rand()` |

The naming is a decent heuristic: if it says **crypto**, **secure**, or **secrets**, it is
the right one. If it says **random** and nothing else, it is probably not.

---

## How much entropy?

**Entropy** is unpredictability measured in bits: log₂ of the number of equally likely
possibilities. A value drawn uniformly from 2ⁿ options has *n* bits.

The number that matters is not "how long is it" but "how many possibilities are there."

| Bits | Values | Verdict |
|---|---|---|
| 32 | 4.3 × 10⁹ | Brute-forced in seconds. **Never.** |
| 64 | 1.8 × 10¹⁹ | Feasible for a determined attacker. **No.** |
| **128** | 3.4 × 10³⁸ | **The floor.** Infeasible with any conceivable resources. |
| 256 | 1.2 × 10⁷⁷ | Standard for keys. No reason not to. |

**OWASP requires at least 64 bits for session identifiers, and 128 is the practical
standard.** `crypto.randomBytes(32)` gives 256, costs nothing, and removes the question.

### The trap: entropy is not string length

```js
// 32 characters. 128 bits?  No.
const id = Array.from({length: 32}, () =>
  "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("");
```

Each hex character carries 4 bits, so 32 characters is 128 bits **if the source is a
CSPRNG**. Here the source is `Math.random()`, whose *entire internal state* is 128 bits and
recoverable — so the real entropy is bounded by the state, not the output length.

> **Entropy comes from the source, not from the length.** A 1000-character string derived
> from a 32-bit seed has 32 bits of entropy. Long is not the same as unpredictable.

---

## The other classic mistakes

**UUIDv4 from the wrong source.** UUIDv4 has 122 random bits, which is plenty — *if*
generated from a CSPRNG. Many libraries historically used `Math.random()`. Use
`crypto.randomUUID()` (Node 19+/browsers) or a library documented to use a CSPRNG.

**UUIDv1 as a secret.** UUIDv1 encodes a **timestamp and MAC address**. It is designed to
be unique, not unpredictable. Anyone can generate the UUIDv1s issued in a given
millisecond. Never use it as a token. Same for **UUIDv7**, which is deliberately
time-sortable — great for database keys, useless as a secret.

**Timestamps as tokens.** `Date.now()` has roughly zero bits of entropy against an
attacker who knows approximately when the event happened. Same for `uniqid()` in PHP,
which is a hex timestamp.

**Hashing a weak source.** `sha256(Date.now())` is not stronger than `Date.now()`. Hashing
does not add entropy — it only redistributes what is there. You can enumerate every
millisecond of the last year in about thirty-one billion tries, which is minutes.

**Reusing a nonce.** [B09](B09-symmetric-encryption.md) — nonce reuse under AES-GCM is
catastrophic, not degraded.

**Seeding a CSPRNG yourself.** Do not. The OS handles it, including on boot and after
`fork`. Manual seeding is how you get 15 identical keys across a fleet.

---

## Where randomness carries the whole design

Every one of these is a place where a weak source is a complete break:

| Value | Bits | Chapter |
|---|---|---|
| Session ID | 128+ | [E04](../track-e/E04-session-ids.md) |
| Password reset token | 128+ | [D09](../track-d/D09-account-recovery.md) |
| CSRF token | 128+ | [E15](../track-e/E15-csrf.md) |
| OAuth `state` | 128+ | [F05](../track-f/F05-the-state-parameter.md) |
| PKCE `code_verifier` | 256 (43–128 chars) | [F06](../track-f/F06-pkce.md) |
| OIDC `nonce` | 128+ | [G03](../track-g/G03-id-token-vs-access-token.md) |
| WebAuthn challenge | 128+ | [D14](../track-d/D14-webauthn-and-passkeys-concepts.md) |
| Password salt | 128 | [B08](B08-salts-peppers-slow-hashes.md) |
| API key | 256 | [J02](../track-j/J02-api-keys.md) |
| Recovery codes | 80+ each | [D13](../track-d/D13-recovery-codes.md) |
| Encryption keys / IVs | 256 / per-algorithm | [B09](B09-symmetric-encryption.md) |

Notice that this is *most of the security-relevant values in the entire book*. A single
wrong function call poisons all of them at once. This is why the chapter exists this early.

---

## Terms defined in this chapter

`randomness`, `PRNG`, `CSPRNG`, `seed`, `entropy`, `bits of entropy`

---

## What to remember

1. Statistical randomness ≠ cryptographic randomness. Only the second is a security
   property.
2. **`Math.random()` state is recoverable from ~5 outputs.** Public tooling, ten years old.
3. Use the function with `crypto`, `secure`, or `secrets` in its name. Learn the one for
   your language.
4. **128 bits minimum. 256 costs nothing.**
5. Entropy comes from the source, not the string length. Hashing a weak value does not
   strengthen it.
6. UUIDv1 and UUIDv7 encode time. They are identifiers, never secrets.

---

## Sources

- [OWASP Session Management Cheat Sheet — Session ID entropy](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-id-entropy)
- [NIST SP 800-90A Rev. 1 — Recommendation for Random Number Generation Using Deterministic Random Bit Generators](https://csrc.nist.gov/pubs/sp/800/90/a/r1/final)
- [V8 blog: There's Math.random(), and then there's Math.random()](https://v8.dev/blog/math-random)
- [RFC 4086 — Randomness Requirements for Security](https://www.rfc-editor.org/rfc/rfc4086)

---

**Next:** [B04 — What a hash function is](B04-what-a-hash-function-is.md)
