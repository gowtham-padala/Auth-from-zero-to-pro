# B04 — What a hash function is

**Part B · Crypto foundations** · *Builds on [B01](B01-bits-bytes-text-as-numbers.md)*
---

## Why it matters

A support engineer needs to help a user who forgot their password. They open the database:

```
email                | password
---------------------+------------------
alice@example.com    | correcthorsebattery
```

They read it out over the phone. Helpful, fast, and a catastrophe — because when this
database is eventually stolen (and it will be), the attacker does not get "some hashes to
crack." They get a list of email addresses and the passwords those humans use *everywhere
else*. Your breach becomes a breach of their bank.

The fix is a function that lets you *check* a password without *storing* it. That function
is a hash.

---

## The definition

> A **hash function** takes an input of any size and produces a fixed-size output — the
> **digest** — such that computing it forwards is fast and reversing it is infeasible.

```
       any input                    fixed output
   ┌──────────────────┐          ┌──────────────────┐
   │ "a"              │          │                  │
   │ "hello world"    │  ──H──>  │  256 bits        │
   │ a 4 GB video     │          │  always          │
   │ ""  (empty)      │          │                  │
   └──────────────────┘          └──────────────────┘
             ─────────────────────────────>  fast
             <─────────────────────────────  infeasible
```

Four properties define it. Learn the names; specifications use them constantly.

### 1. Deterministic

The same input always gives the same output. Every time, on every machine, forever. Without
this you could not verify anything.

### 2. Fixed-size output

SHA-256 always produces 256 bits (32 bytes, 64 hex characters), whether you hashed one byte
or a terabyte.

An immediate consequence: **information is destroyed**. There are infinitely many possible
inputs and only 2²⁵⁶ possible outputs. Collisions must exist, mathematically. The security
claim is not that they do not exist — it is that you cannot *find* one
([B06](B06-collisions.md)).

### 3. Avalanche effect

Change one bit of input; about half the output bits flip. There is no partial similarity,
no "close" digests.

```
sha256("hello")   → 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
sha256("hellp")   → 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
                     ↑ one letter changed. Nothing in common.
```

This is why you cannot hill-climb your way to a preimage, and why digests are useful as
change detectors.

### 4. One-way (preimage resistance)

Given a digest, you cannot find an input that produces it.

There are three distinct resistance properties, and specifications assume you know which is
which:

| Property | The attacker's task | Difficulty for an *n*-bit hash |
|---|---|---|
| **Preimage** | Given `H(x)`, find `x` | 2ⁿ |
| **Second preimage** | Given `x`, find `y ≠ x` with `H(y) = H(x)` | 2ⁿ |
| **Collision** | Find *any* `x ≠ y` with `H(x) = H(y)` | **2^(n/2)** |

That last row is the surprise, and it has its own chapter
([B06](B06-collisions.md)). Collisions are *far* easier than preimages — quadratically
easier — because the attacker gets to choose both sides.

---

## What a hash is not

**Not encryption.** There is no key and no decryption. A hash is one-way *by design*;
encryption is reversible *by design*. ([B05](B05-hashing-vs-encryption.md).)

**Not compression.** Compression is reversible. Hashing throws information away
permanently.

**Not a checksum.** CRC32 detects accidental corruption. It is trivially forgeable — an
attacker can adjust their tampered data so the CRC still matches. Cryptographic hashes
resist *deliberate* manipulation. Never use CRC32 or Adler-32 for anything security-related.

**Not enough to authenticate a message.** A hash proves the data is unmodified *if you
trust the hash you are comparing against*. An attacker who changes the message can change
the hash too. Fixing that requires a secret — which is [B13](B13-message-authentication-hmac.md).

**Not a way to hide data with low entropy.** `sha256(phone_number)` is not anonymisation.
There are ~10¹⁰ phone numbers; hashing all of them takes seconds. The same applies to email
addresses, national ID numbers, and any small domain. Hashing only hides values an attacker
cannot enumerate.

---

## Which hash function

The landscape as of 2026:

| Family | Status | Use for |
|---|---|---|
| **MD5** | ☠️ Broken (1996 theory, 2004 practice) | Nothing. Non-security checksums at most. |
| **SHA-1** | ☠️ Broken (SHAttered, 2017) | Nothing new. Legacy Git object IDs. |
| **SHA-256 / SHA-512** | ✅ Standard | Default general-purpose choice |
| **SHA-3 (Keccak)** | ✅ Standard | Different internal design; not length-extendable |
| **BLAKE2 / BLAKE3** | ✅ Excellent | Faster than SHA-256, not length-extendable |
| **bcrypt / scrypt / Argon2** | ✅ **Password hashing only** | Deliberately slow — [B08](B08-salts-peppers-slow-hashes.md) |

**Default answer: SHA-256.** It is fast, universally available, and unbroken.

**Except for passwords.** Being fast is exactly wrong there, and that is the entire subject
of [B07](B07-fast-hashes-wrong-for-passwords.md). Do not use SHA-256 for a password. The
list above puts password hashes in their own row for a reason.

### SHA-512/256 and length extension

SHA-256 and SHA-512 are built on the **Merkle–Damgård** construction, which has a
structural quirk: from `H(secret ‖ message)` and the length of `secret`, an attacker can
compute `H(secret ‖ message ‖ padding ‖ anything)` **without knowing the secret**. That is
the **length extension attack**, and it is the reason HMAC exists in the form it does.

SHA-3, BLAKE2, BLAKE3, and the truncated SHA-512/256 are not vulnerable to it. Full
demonstration in [B13](B13-message-authentication-hmac.md), where you will watch the naive
construction break on screen before HMAC is introduced.

---

## Hands on

```bash
# Command line — same answer everywhere.
$ echo -n "hello" | sha256sum
2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824  -

# The -n matters. Without it you hash "hello\n", a different input.
$ echo "hello" | sha256sum
5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  -
```

That trailing-newline trap is not a toy. It is one of the top causes of "my signature does
not match" in webhook verification ([J06](../track-j/J06-signing-webhooks.md)).

```python
import hashlib

print(hashlib.sha256(b"hello").hexdigest())
# 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824

# Avalanche: one bit of difference
a = hashlib.sha256(b"hello").digest()
b = hashlib.sha256(b"hellp").digest()
diff = sum(bin(x ^ y).count("1") for x, y in zip(a, b))
print(f"{diff}/256 bits differ")     # ~128. Every time.

# Determinism across sizes
for data in [b"", b"a", b"a" * 1_000_000]:
    print(len(data), "->", hashlib.sha256(data).hexdigest()[:16], "...")
```

Try to reverse one. You cannot, and neither can anyone else — the only approach is to guess
inputs and hash them until one matches, which is exactly what password crackers do and
exactly why [B08](B08-salts-peppers-slow-hashes.md) makes each guess expensive.

---

## Where hashes appear in this book

| Use | How | Chapter |
|---|---|---|
| Password storage | Slow, salted hash | [D03](../track-d/D03-how-to-store-passwords.md) |
| Message authentication | HMAC (hash + secret) | [B13](B13-message-authentication-hmac.md) |
| Digital signatures | Sign the *digest*, not the message | [B14](B14-digital-signatures.md) |
| PKCE | `code_challenge = BASE64URL(SHA256(verifier))` | [F06](../track-f/F06-pkce.md) |
| TOTP | HMAC-SHA1 over a time counter | [D12](../track-d/D12-build-totp.md) |
| WebAuthn | Signature over `authenticatorData ‖ SHA256(clientDataJSON)` | [D15](../track-d/D15-build-passkeys.md) |
| Token lookup | Store `SHA256(api_key)`, compare digests | [J02](../track-j/J02-api-keys.md) |
| Certificates | Sign the digest of the certificate body | [B15](B15-certificates-and-pki.md) |
| Audit logs | Hash-chain each entry to the previous | [H13](../track-h/H13-audit-logging.md) |
| `at_hash` in OIDC | Bind an ID token to its access token | [G04](../track-g/G04-validate-an-id-token-by-hand.md) |

The pattern to notice: **signatures never sign the message. They sign the digest.** A hash
turns arbitrary-length input into a fixed-size value that asymmetric algorithms can
actually operate on. Without hashing, signing would be impossibly slow and structurally
awkward. This is why B04 must come before B14.

---

## The one rule about comparing digests

When you compare a computed digest against an expected one, use a **constant-time**
comparison, not `==`.

```python
# ❌ leaks how many bytes matched, via timing
if computed == expected: ...

# ✅
import hmac
if hmac.compare_digest(computed, expected): ...
```

The reason — and a graph showing the leak — is [B16](B16-timing-attacks.md). Flagging it
here so the habit forms before the explanation arrives.

---

## Terms defined in this chapter

`hash function`, `digest`, `preimage resistance`, `second preimage resistance`,
`avalanche effect`, `SHA-256`

---

## What to remember

1. A hash is **deterministic, fixed-size, avalanche-y, and one-way.**
2. Collisions must exist; the claim is that you cannot find them. And they are 2^(n/2),
   not 2ⁿ.
3. **SHA-256 by default. Never for passwords** — being fast is the wrong property there.
4. A hash alone does not authenticate a message. That needs a secret ([B13](B13-message-authentication-hmac.md)).
5. Hashing low-entropy data (phone numbers, emails) is not anonymisation.
6. Signatures sign the **digest**, not the message. That is why hashing comes first.
7. Compare digests in constant time.

---

## Sources

- [NIST FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [NIST FIPS 202 — SHA-3 Standard](https://csrc.nist.gov/pubs/fips/202/final)
- Jean-Philippe Aumasson, *Serious Cryptography*, 2nd ed., Ch. 6 (Hash Functions)
- David Wong, *Real-World Cryptography*, Ch. 2

---

**Next:** [B05 — Hashing vs encryption: one-way vs reversible](B05-hashing-vs-encryption.md)
