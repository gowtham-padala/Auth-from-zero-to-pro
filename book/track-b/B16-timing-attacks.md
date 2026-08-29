# B16 — Timing attacks and constant-time comparison

**Part B · Crypto foundations** · *Builds on [B13](B13-message-authentication-hmac.md)*
---

## Why it matters

Here is webhook signature verification. It is correct. It has no bugs in the ordinary
sense — it computes the right value and compares it to the right thing.

```python
expected = hmac.new(SECRET, request.body, hashlib.sha256).hexdigest()
if signature == expected:          # ← the vulnerability
    process(request)
```

`==` on strings compares byte by byte and **returns as soon as it finds a difference**.
That is a sensible optimisation for every other purpose in programming, and here it leaks
the answer.

```
  expected:  a3f9c2e1b8...
  attempt 1: 000000...      → differs at byte 0 → returns after 1 comparison
  attempt 2: a00000...      → differs at byte 1 → returns after 2 comparisons
  attempt 3: a30000...      → differs at byte 2 → returns after 3 comparisons
```

Each additional correct byte makes the function take **measurably longer**. An attacker
who can time the response can determine the signature one byte at a time.

That converts an infeasible search — 2²⁵⁶ for a 32-byte tag — into a linear one:
**64 hex characters × 16 possibilities = ~1,024 attempts.**

From "impossible" to "a few minutes" because of one operator.

---

## What a side channel is

> A **side channel** leaks information through a physical or observable property of the
> computation, rather than through its output.

The output of `==` is one bit: match or not. The *time it took* is additional output the
programmer never intended to produce and the attacker is happy to read.

Timing is the one that matters for web applications. Others exist and are worth knowing
about:

| Channel | Leak | Relevant to you? |
|---|---|---|
| **Timing** | How long an operation took | **Yes.** Remotely measurable. |
| Cache | Which memory was accessed | Yes if you share hardware (cloud, containers) |
| Power | Instantaneous current draw | Physical access — smart cards, HSMs |
| Electromagnetic | RF emissions | Physical access |
| Acoustic | Sound of components | Lab curiosity, mostly |
| **Error messages** | Which check failed | **Yes.** [D07](../track-d/D07-user-enumeration.md) |
| **Response size** | Compressed length | Yes — CRIME/BREACH attacks |

Errors and timing are the two that operate over a plain HTTP connection with no special
access, and they are the two this book cares about.

---

## "But the network is noisy"

The standard objection, and the standard mistake.

Network jitter is far larger than a few hundred nanoseconds of comparison time. So the
attack cannot work over the internet. Right?

**Wrong, and this was settled experimentally in 2009.** Crosby, Wallach, and Riedi
demonstrated that with enough samples, statistical filtering recovers timing differences of
**15–100 microseconds over the internet** and **around 100 nanoseconds on a LAN**.

Noise is *random*. The signal is *consistent*. Take ten thousand samples, use the minimum
or a low percentile rather than the mean (the minimum is the least-perturbed measurement),
and the noise averages away while the signal does not.

Modern conditions make it easier, not harder:

- Attackers frequently run **in the same datacentre** as their target — sub-millisecond
  round trips, minimal jitter.
- HTTP/2 and HTTP/3 allow **request coalescing**, which enables differential timing between
  two requests in the same packet and cancels most network noise.
- Cloud tenancy means shared hardware and cache-timing channels on top.

Assume timing is observable. The defence costs nothing, so there is no reason to argue
about the threshold.

---

## See the leak

```python
import time, statistics, hmac, hashlib

SECRET = b"supersecret"
EXPECTED = hmac.new(SECRET, b"message", hashlib.sha256).hexdigest()

def vulnerable_compare(a, b):
    if len(a) != len(b):
        return False
    for x, y in zip(a, b):
        if x != y:            # ← early return
            return False
    return True

def measure(candidate, trials=20000):
    samples = []
    for _ in range(trials):
        t0 = time.perf_counter_ns()
        vulnerable_compare(candidate, EXPECTED)
        samples.append(time.perf_counter_ns() - t0)
    # The minimum is the least-perturbed sample: no scheduling, no cache miss.
    return min(samples)

print(f"{'candidate':<20} {'min ns':>8}")
for prefix_len in range(0, 9):
    candidate = EXPECTED[:prefix_len] + "0" * (64 - prefix_len)
    print(f"{candidate[:16]+'...':<20} {measure(candidate):>8}")
```

Typical output:

```
candidate               min ns
0000000000000000...        291
a000000000000000...        305      ← 1 byte correct
a3000000000000000...       318      ← 2 bytes correct
a3f000000000000...         332
a3f9000000000000...        347
a3f9c00000000000...        361
a3f9c20000000000...        374
a3f9c2e000000000...        389
a3f9c2e100000000...        402      ← 8 bytes correct
```

A clean, monotonic staircase. Roughly 14 ns per correct byte, entirely predictable.

The attack: for each position, try all 16 hex digits, keep the slowest, move on. Sixty-four
positions × sixteen candidates = 1,024 measurement batches, and you have the tag.

```
   Time
    │                                        ╱
    │                                   ╱────
    │                              ╱────
    │                         ╱────
    │                    ╱────
    │               ╱────
    │          ╱────
    │     ╱────
    │╱────
    └────────────────────────────────────────> Correct prefix length
     0    1    2    3    4    5    6    7    8

    Every step is one byte the attacker has confirmed.
```

---

## The fix

Compare **every byte, always**, and combine the results with arithmetic that has no
branches.

```python
def constant_time_compare(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False              # length is not secret; the content is
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y           # XOR: 0 if equal. OR accumulates any difference.
        # no branch, no early return
    return result == 0
```

`x ^ y` is 0 when the bytes match ([B09](B09-symmetric-encryption.md)). `|=` accumulates —
once any bit is set it stays set. The loop runs the full length regardless of input, so the
time depends only on the length, never on the content.

### Do not write that function

Use the standard library. It is audited, it resists compiler optimisations that could
reintroduce branching, and on some platforms it uses hardware support.

| Language | Function |
|---|---|
| Python | `hmac.compare_digest(a, b)` |
| Node.js | `crypto.timingSafeEqual(bufA, bufB)` — **throws if lengths differ** |
| Go | `crypto/subtle.ConstantTimeCompare(a, b)` |
| Java | `MessageDigest.isEqual(a, b)` |
| Rust | `subtle` crate — `ConstantTimeEq` |
| PHP | `hash_equals($known, $user)` |
| Ruby | `ActiveSupport::SecurityUtils.secure_compare` |
| C# | `CryptographicOperations.FixedTimeEquals` |

A trap worth knowing: **`crypto.timingSafeEqual` in Node throws a `RangeError` if the
buffers differ in length.** Naive code wraps it in try/catch and returns `false` — which
reintroduces a length oracle *and* often crashes on malformed input. Hash both sides to a
fixed length first, or compare lengths explicitly and safely.

### The universal trick: hash both sides first

```python
# Works everywhere, removes both the length and content channels.
def safe_compare(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(
        hashlib.sha256(a).digest(),
        hashlib.sha256(b).digest(),
    )
```

Both inputs become exactly 32 bytes, so length leaks nothing, and finding two inputs that
produce related digests is a collision problem ([B06](B06-collisions.md)). Slightly slower,
completely safe, and it sidesteps every library-specific quirk.

---

## Where this matters

Any comparison where **one side is a secret** and **the other is attacker-controlled**:

| Comparison | Chapter |
|---|---|
| Webhook signature | [J06](../track-j/J06-signing-webhooks.md) |
| JWT signature | [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md) |
| API key lookup | [J02](../track-j/J02-api-keys.md) |
| Session token | [E04](../track-e/E04-session-ids.md) |
| CSRF token | [E15](../track-e/E15-csrf.md) |
| Password reset token | [D09](../track-d/D09-account-recovery.md) |
| TOTP code | [D12](../track-d/D12-build-totp.md) |
| OAuth `state`, PKCE `code_verifier` | [F05](../track-f/F05-the-state-parameter.md), [F06](../track-f/F06-pkce.md) |
| Recovery codes | [D13](../track-d/D13-recovery-codes.md) |

**Password comparison is the exception.** You never compare passwords directly — you call
`ph.verify()`, and every good password library is already constant-time internally
([B08](B08-salts-peppers-slow-hashes.md)).

---

## The other timing leak: control flow

Comparison is not the only source. **Whether you do work at all** is timing too, and this
one is bigger and more commonly exploited.

```python
# ❌ 2 ms if the user does not exist, 300 ms if they do.
#    A 150× difference. No statistics required.
user = find_user(email)
if not user:
    return error("Invalid credentials")
if not ph.verify(user.password_hash, password):
    return error("Invalid credentials")
```

The error messages are identical — which people think is the fix — and the timing gives it
away anyway. That is **user enumeration** ([D07](../track-d/D07-user-enumeration.md)) and
it is far easier to exploit than a byte-level comparison leak, because the difference is
hundreds of milliseconds rather than nanoseconds.

```python
# ✅ Always do the expensive work.
DUMMY_HASH = ph.hash("a-value-nobody-will-ever-use")

user = find_user(email)
try:
    ph.verify(user.password_hash if user else DUMMY_HASH, password)
    ok = user is not None
except VerifyMismatchError:
    ok = False
return success() if ok else error("Invalid credentials")
```

The same principle applies broadly: **early returns leak.** Any `if not found: return` on a
path where existence is sensitive is an oracle. Look for these in account lookup, token
lookup, tenant resolution, and permission checks.

---

## When not to worry

Balance matters, or you will constant-time everything and slow your system down for nothing.

You do **not** need constant-time comparison when:

- Neither side is secret (comparing two public IDs).
- The value is **high-entropy and single-use**, and you also rate-limit — an attacker
  cannot make enough measurements before the token expires. Still: use the safe function.
  It costs nothing.
- You are looking up a value in a database by an indexed column. The database is doing a
  B-tree lookup, not a byte comparison, and the timing signal is dominated by I/O.

The last case has a subtlety worth flagging: `SELECT * FROM tokens WHERE token = ?` is not
a byte-by-byte comparison, so it does not leak the same way — but *whether a row was found*
still leaks through subsequent control flow. Store hashed tokens
([B05](B05-hashing-vs-encryption.md)) and keep the post-lookup path uniform.

---

## Terms defined in this chapter

`timing attack`, `side channel`, `constant-time comparison`, `early return`, `oracle`

---

## What to remember

1. `==` returns early. **That is a leak whenever one side is secret.**
2. Network noise does not save you. Statistical filtering recovers microsecond differences
   over the internet; this was demonstrated in 2009.
3. **Use the standard library's constant-time compare.** Learn its name in your language.
   Watch Node's length-throw.
4. **Hashing both sides first** removes the length channel and works everywhere.
5. The **bigger** leak is usually control flow: doing expensive work only for existing
   users. Always do the work.
6. Password verification is already constant-time inside the library.

---

## Sources

- Crosby, Wallach & Riedi, [*Opportunities and Limits of Remote Timing Attacks*](https://www.cs.rice.edu/~dwallach/pub/crosby-timing2009.pdf) (2009) — the paper that settled the network-noise objection
- Nate Lawson, [*Timing attack in Google Keyczar library*](https://rdist.root.org/2009/05/28/timing-attack-in-google-keyczar-library/)
- [OWASP: Testing for Timing Attacks](https://owasp.org/www-project-web-security-testing-guide/)
- Paul Kocher, [*Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems*](https://paulkocher.com/doc/TimingAttacks.pdf) (1996) — the original

---

**Next:** [B17 — What HTTPS actually protects, and what it doesn't](B17-what-https-protects.md)
