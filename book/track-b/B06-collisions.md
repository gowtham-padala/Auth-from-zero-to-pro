# B06 — Collisions, and why MD5 and SHA-1 were retired

**Part B · Crypto foundations** · *Builds on [B04](B04-what-a-hash-function-is.md)*
---

## Collisions must exist

Infinite possible inputs, 2²⁵⁶ possible outputs. By the pigeonhole principle, collisions
exist for every hash function, necessarily and unavoidably.

That is not the security claim. The claim is: **you cannot find one.**

A hash function is "broken" when someone finds a practical method to produce collisions
faster than brute force. Which brings us to how fast brute force actually is — and it is
much faster than people expect.

---

## The birthday bound

How many people must be in a room before two share a birthday, with probability > 50%?

Not 183. **Twenty-three.**

The intuition trap is that you count *people*, when the mechanism counts *pairs*. 23 people
form 253 pairs, and each pair has a 1/365 chance. The count of comparisons grows
quadratically while the count of items grows linearly.

Applied to hashes:

> For an *n*-bit hash, a collision appears after roughly **2^(n/2)** attempts, not 2ⁿ.

| Hash | Output bits | Preimage | **Collision (birthday)** |
|---|---|---|---|
| MD5 | 128 | 2¹²⁸ | **2⁶⁴** |
| SHA-1 | 160 | 2¹⁶⁰ | **2⁸⁰** |
| SHA-256 | 256 | 2²⁵⁶ | **2¹²⁸** |
| SHA-512 | 512 | 2⁵¹² | 2²⁵⁶ |

**A hash function has half the collision resistance its output size suggests.** SHA-256
gives you 128 bits of collision resistance — which is why 256 bits is the standard size
rather than 128. The output is doubled to buy back what the birthday bound takes away.

And note the asymmetry: preimage resistance is unbroken for MD5 and SHA-1 to this day. You
still cannot invert an MD5 digest. But collision resistance is gone, and for many uses
that is the property that mattered.

---

## Why MD5 died

- **1996** — Dobbertin finds a weakness in the compression function. Cryptographers begin
  saying "stop using it."
- **2004** — Wang et al. produce actual collisions. Hours on a cluster.
- **2008** — Sotirov et al. use MD5 chosen-prefix collisions to forge a **rogue CA
  certificate**, demonstrated live at CCC. A real, browser-trusted certificate authority
  certificate, obtained by collision.
- **2012** — **Flame**, a nation-state malware platform, forges a Microsoft code-signing
  certificate via an MD5 chosen-prefix collision and distributes itself through **Windows
  Update**. Machines accepted the malware as genuinely Microsoft-signed.
- **Today** — MD5 collisions take under a second on a laptop.

Twelve years from "cryptographers are uneasy" to "used against Windows Update." That
timeline is the argument for migrating on the *first* signal, not the last.

## Why SHA-1 died

- **2005** — Theoretical attack below brute force. NIST begins deprecation.
- **2017** — **SHAttered**: Google and CWI produce the first practical SHA-1 collision.
  Two PDFs, ~6,500 CPU-years compressed into a feasible GPU budget.
- **2019** — **Chosen-prefix** collisions demonstrated for around $45,000.
- **2020** — Cost drops to roughly $45,000 and falling; SHA-1 signatures are declared dead
  in practice.
- **2022** — NIST formally announces SHA-1 retirement, with a 2030 deadline for all
  federal use.

---

## Chosen-prefix is the one that matters

There are two grades of collision, and the difference determines exploitability.

**Identical-prefix collision.** The attacker finds two inputs that differ only in a block of
carefully chosen gibberish. Both files must share everything before and after that block.
Useful for a demo, awkward to weaponise.

**Chosen-prefix collision.** The attacker picks **two arbitrary, meaningful prefixes** and
computes a suffix for each that makes the digests equal.

```
 P₁ = "Alice is authorized to transfer £100"   + [computed garbage] ──┐
                                                                       ├─> same digest
 P₂ = "Alice is authorized to transfer £1,000,000" + [computed garbage]┘
```

Now the attacker controls the meaningful content of *both* documents. This is what the
rogue CA certificate and Flame both used, and it is what makes a collision a real attack
rather than a curiosity.

The trick for hiding the garbage is easier than it sounds: PDF, PostScript, X.509, and
most binary formats have comment fields, unused extensions, or length-prefixed blobs where
arbitrary bytes are ignored by the renderer.

---

## Where collision resistance actually matters

Not everywhere. Knowing which uses need it lets you evaluate legacy systems sensibly
instead of panicking uniformly.

### Collision resistance is **required**

| Use | Why |
|---|---|
| **Digital signatures** | You sign a digest. A collision means the signature covers a document you never saw. |
| **Certificates** | Same, with CA authority attached. |
| **Code signing** | Flame. |
| **Content addressing** (Git, IPFS, deduplication) | Two different objects at one address is a correctness *and* security failure. |
| **Commitment schemes** | You commit to a value; a collision lets you open it as a different one. |
| **Audit log hash chains** | A collision lets you swap a log entry without breaking the chain ([H13](../track-h/H13-audit-logging.md)). |

### Collision resistance is **not** required

| Use | Why it survives |
|---|---|
| **HMAC** | HMAC's security rests on the compression function's PRF property, not collision resistance. **HMAC-MD5 and HMAC-SHA1 are not broken by these collision attacks.** |
| **TOTP** | Uses HMAC-SHA1 by design (RFC 6238) and is fine. This surprises people every time. |
| **Password hashing** | The attacker wants *the* password, which is a preimage problem. (bcrypt/Argon2 do not use these hashes anyway.) |
| **HKDF / key derivation** | PRF property again. |

> **Say this out loud once:** *HMAC-SHA1 is not broken. TOTP is not broken.* Every security
> scanner flags "SHA1" as a finding, and for TOTP the finding is wrong. Being able to
> explain why is a genuine mark of understanding this material.
>
> That said — new designs should use SHA-256, because explaining this to every auditor
> forever is its own cost.

---

## What to use in 2026

| Purpose | Use | Avoid |
|---|---|---|
| General hashing | SHA-256, SHA-3, BLAKE3 | MD5, SHA-1 |
| Signatures | SHA-256 or better | Any SHA-1 signature |
| HMAC | HMAC-SHA256 | (SHA-1 acceptable, but don't start there) |
| Passwords | **Argon2id** ([B08](B08-salts-peppers-slow-hashes.md)) | Any plain hash |
| Fast checksums, non-security | xxHash, CRC32 | — |
| Content addressing | SHA-256, BLAKE3 | SHA-1 |

**Git** is the famous holdout. It uses SHA-1 for object IDs, with a
[collision-detection](https://github.com/cr-marcstevens/sha1collisiondetection) hardening
layer that rejects known attack patterns. SHA-256 repositories exist but adoption is slow —
the ecosystem cost of changing an identifier that appears in every tool, URL, and script is
enormous. A useful lesson in how expensive a hash migration is once identifiers leak into
your interfaces.

---

## The lesson beyond the specific algorithms

Cryptographic primitives have finite lifetimes. MD5 was recommended for a decade after the
first warning sign. SHA-1 the same. Something on today's recommended list will be on the
retired list, and it is not obvious which.

The engineering response is **cryptographic agility**:

1. **Store the algorithm with the data.** The PHC string format
   (`$argon2id$v=19$m=19456,t=2,p=1$...`) does this for password hashes — you can change
   parameters and still verify old ones ([B08](B08-salts-peppers-slow-hashes.md)).
2. **Version your tokens.** A `kid` header in a JWT ([E07](../track-e/E07-jose-family.md))
   lets you rotate keys *and* algorithms without a flag day.
3. **Never hardcode an algorithm in a comparison.** Read it from the stored record, from an
   allowlist of algorithms you accept — never from attacker-controlled input, which is the
   `alg: none` disaster ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)).
4. **Have a migration path before you need one.** [I12](../track-i/I12-migrating-auth.md)
   is the whole chapter, and rehash-on-login is the technique.

The distinction in point 3 is subtle and important: **agility means *you* can change the
algorithm, not that the *message* can.** Systems that read the algorithm from the token get
broken by the sender. That is the single most instructive failure in this book, and it
lands in [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md).

---

## Terms defined in this chapter

`collision`, `collision resistance`, `birthday bound`, `MD5`, `SHA-1`,
`chosen-prefix collision`

---

## What to remember

1. Collisions must exist. The claim is only that you cannot find them.
2. **Birthday bound: collisions cost 2^(n/2), not 2ⁿ.** SHA-256 gives 128 bits of collision
   resistance.
3. MD5 and SHA-1 are broken for **collisions**, not preimages. That distinction decides
   what is actually at risk.
4. **Chosen-prefix** collisions are the dangerous kind. Rogue CA certificate (2008), Flame
   (2012).
5. **HMAC-SHA1 and TOTP are not affected.** Be able to explain why.
6. Every primitive has a lifetime. Build agility in — store the algorithm with the data,
   never read it from the message.

---

## Sources

- [SHAttered — the first SHA-1 collision](https://shattered.io/) (Stevens, Bursztein, Karpman, Albertini, Markov, 2017)
- Stevens et al., [*Chosen-prefix collisions for MD5 and applications*](https://marc-stevens.nl/research/papers/IJACT12-SLdW.pdf)
- [NIST: NIST Retires SHA-1 Cryptographic Algorithm](https://www.nist.gov/news-events/news/2022/12/nist-retires-sha-1-cryptographic-algorithm) (2022)
- [RFC 6151 — Updated Security Considerations for MD5 and HMAC-MD5](https://www.rfc-editor.org/rfc/rfc6151) (the HMAC distinction, normatively)

---

**Next:** [B07 — Why fast hashes are the wrong tool for passwords](B07-fast-hashes-wrong-for-passwords.md)
