# B09 — Symmetric encryption: XOR by hand, then AES

**Part B · Crypto foundations** · *Builds on [B01](B01-bits-bytes-text-as-numbers.md), [B05](B05-hashing-vs-encryption.md)*
---

## Do it by hand first

Get a pen. This takes ninety seconds and it is the load-bearing exercise of the chapter.

### XOR

**XOR** (exclusive or, written ⊕) compares two bits and outputs 1 if they differ:

```
0 ⊕ 0 = 0
0 ⊕ 1 = 1
1 ⊕ 0 = 1
1 ⊕ 1 = 0
```

One property is everything:

> **`x ⊕ k ⊕ k = x`**
>
> XOR with the same value twice and you are back where you started. **Encryption and
> decryption are the same operation.**

### Encrypt one letter

Plaintext: `H`. From [B01](B01-bits-bytes-text-as-numbers.md), that is 72 = `01001000`.

Key: one byte, say `01011010` (90).

```
    plaintext   0 1 0 0 1 0 0 0     (H = 72)
    key         0 1 0 1 1 0 1 0     (90)
    XOR         ─────────────────
    ciphertext  0 0 0 1 0 0 1 0     (18)
```

Work down the columns. Same → 0, different → 1. Ciphertext is 18, which is a control
character — unprintable, meaningless-looking. Encrypted.

### Decrypt it

```
    ciphertext  0 0 0 1 0 0 1 0     (18)
    key         0 1 0 1 1 0 1 0     (90)
    XOR         ─────────────────
    plaintext   0 1 0 0 1 0 0 0     (72 = H)  ✅
```

Same operation, same key, original back.

**You have just performed symmetric encryption.** Not a simplification of it — the actual
operation. Every stream cipher in the world, including the one protecting this page over
TLS, is: *generate a keystream, XOR it with the plaintext.* The only thing AES and
ChaCha20 add is a very good way to generate the keystream.

### Why one byte of key is not enough

Encrypt `HELLO` with the single key byte 90 and every `L` produces the same ciphertext
byte. Frequency analysis breaks it instantly — this is a Vigenère cipher, solved in the
19th century.

The fix is a keystream **as long as the message and never reused**. If that keystream is
truly random and used exactly once, you have a **one-time pad**, which is provably
unbreakable — and completely impractical, because the key is as long as the message and
must be shared in advance ([B10](B10-key-distribution-problem.md)).

Real ciphers approximate it: a short key, expanded deterministically into a
pseudorandom keystream. Which is why **nonce reuse is catastrophic** — reuse the keystream
and you are back to Vigenère:

```
c₁ = m₁ ⊕ ks
c₂ = m₂ ⊕ ks
c₁ ⊕ c₂ = m₁ ⊕ m₂        ← the key vanishes. Two plaintexts XORed together.
```

Two plaintexts XORed together is readable by anyone with a frequency table and an
afternoon. Hold onto this; it is the single most important operational rule in the chapter.

---

## AES is the same idea, with structure

**AES** — the Advanced Encryption Standard, standardised 2001 — is a **block cipher**: it
transforms exactly 16 bytes at a time under a key.

| Key size | Rounds |
|---|---|
| AES-128 | 10 |
| AES-192 | 12 |
| AES-256 | **14** |

Each round does four things to the 16-byte block:

1. **SubBytes** — replace each byte via a lookup table (the S-box). Non-linearity.
2. **ShiftRows** — rotate the rows of the 4×4 byte grid. Diffusion across columns.
3. **MixColumns** — mix each column mathematically. Diffusion within columns.
4. **AddRoundKey** — **XOR with a key derived from the main key.**

Step 4 is the operation you just did by hand. Steps 1–3 exist to make sure that after
fourteen rounds, every output bit depends on every input bit and every key bit in a way
nobody has found a shortcut through — the avalanche effect
([B04](B04-what-a-hash-function-is.md)) applied to encryption.

That is the whole reveal: **AES is XOR, plus fourteen rounds of thorough mixing so the
keystream cannot be recovered.**

**You will never implement this.** You do not need to. What you need is the intuition that
the cipher operates on *one block*, and that everything interesting — and everything
dangerous — is in how you apply it to *many* blocks.

---

## Modes of operation

A block cipher encrypts 16 bytes. Your data is not 16 bytes. The **mode** is how you get
from one to the other, and it is where the security actually lives.

### ECB — Electronic Codebook ❌

Each block encrypted independently with the same key.

```
 P₁ → [AES] → C₁      identical P ⟹ identical C
 P₂ → [AES] → C₂
 P₃ → [AES] → C₃
```

**Never use ECB.** It leaks equality, which leaks structure. The penguin. The Adobe breach
([B05](B05-hashing-vs-encryption.md)). The block-swapping attack at the top of this
chapter — because blocks are independent, they can be reordered, duplicated, and spliced
freely.

### CBC — Cipher Block Chaining ⚠️

Each block is XORed with the previous ciphertext before encryption. The first uses a random
**IV** (initialisation vector).

```
 IV ─┐
     ▼
 P₁ ⊕ → [AES] → C₁ ─┐
                     ▼
 P₂ ─────────── ⊕ → [AES] → C₂ ─┐
                                 ▼
 P₃ ─────────────────────── ⊕ → [AES] → C₃
```

Fixes the equality leak. Introduces new problems: it needs padding, and **padding oracle
attacks** (Vaudenay, 2002) can decrypt the entire message if the server distinguishes
"bad padding" from "bad data." It is also malleable — flipping a ciphertext bit flips a
predictable plaintext bit in the *next* block.

Use only with a MAC, in encrypt-then-MAC order, and only if you cannot use GCM.

### CTR — Counter mode ⚠️

Turns the block cipher into a stream cipher: encrypt a counter, XOR the result with the
plaintext.

```
 E(K, nonce‖1) ⊕ P₁ = C₁
 E(K, nonce‖2) ⊕ P₂ = C₂
```

No padding needed, parallelisable, random access. **Absolutely no integrity** — flip any
ciphertext bit and exactly that plaintext bit flips. And **nonce reuse is fatal**, exactly
as shown above.

### GCM — Galois/Counter Mode ✅

CTR mode plus an authentication tag computed over the ciphertext.

```
 encrypt (CTR) ──> ciphertext ──> GHASH ──> 16-byte tag
```

This is **AEAD** — Authenticated Encryption with Associated Data. One operation gives you
confidentiality *and* integrity. Decryption fails loudly if a single bit was modified.

**This is the default answer.** AES-GCM, or ChaCha20-Poly1305 where AES hardware
acceleration is unavailable (older ARM, some embedded).

> **⚠️ The GCM nonce rule.** Never reuse a (key, nonce) pair. GCM nonce reuse does not
> merely leak plaintext — it leaks the **authentication key**, letting an attacker forge
> arbitrary messages. This is worse than the general nonce-reuse problem: a single reuse
> can be a total break.
>
> Use a 96-bit random nonce and rotate the key well before the birthday bound (~2³² messages
> per key), or use a deterministic counter you are certain never repeats. If you cannot
> guarantee either, use **XChaCha20-Poly1305** (192-bit nonce, random reuse is
> statistically impossible) or a nonce-misuse-resistant mode like **AES-GCM-SIV**.

### The mode table

| Mode | Confidentiality | Integrity | Verdict |
|---|---|---|---|
| ECB | Per-block only | ❌ | **Never** |
| CBC | ✅ | ❌ | Only with a MAC; prefer GCM |
| CTR | ✅ | ❌ | Only with a MAC |
| **GCM** | ✅ | ✅ | **Default** |
| **ChaCha20-Poly1305** | ✅ | ✅ | **Default without AES-NI** |
| XChaCha20-Poly1305 | ✅ | ✅ | When nonce management is hard |
| AES-GCM-SIV | ✅ | ✅ | When nonce reuse is a real risk |

---

## Do it in code

```python
# pip install cryptography
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key   = AESGCM.generate_key(bit_length=256)     # keep this safe — I05
aead  = AESGCM(key)
nonce = os.urandom(12)                          # 96 bits, unique per message — B03

plaintext = b"the answer is 42"
aad       = b"user-id:4471"                     # authenticated, NOT encrypted

ct = aead.encrypt(nonce, plaintext, aad)
print(aead.decrypt(nonce, ct, aad))             # b'the answer is 42'

# Tamper with one bit anywhere and decryption REFUSES.
bad = bytearray(ct); bad[0] ^= 1
try:
    aead.decrypt(nonce, bytes(bad), aad)
except Exception as e:
    print("rejected:", type(e).__name__)        # InvalidTag ✅

# Change the associated data and it also refuses.
try:
    aead.decrypt(nonce, ct, b"user-id:9999")
except Exception as e:
    print("rejected:", type(e).__name__)        # InvalidTag ✅
```

The **associated data** parameter is the underused feature. It is authenticated but not
encrypted — so you can bind a ciphertext to its context. Encrypt a session payload with
`aad = user_id`, and the ciphertext cannot be moved to a different user's session, even
though the payload itself is unchanged. That is a cheap, powerful defence against exactly
the block-swapping class of attack.

**Store the nonce with the ciphertext.** It is not secret. The usual layout is
`nonce ‖ ciphertext ‖ tag`, which most libraries produce for you.

---

## Where symmetric encryption shows up in auth

| Use | Chapter |
|---|---|
| Encrypting TOTP secrets at rest | [D12](../track-d/D12-build-totp.md) |
| Encrypting third-party refresh tokens | [E10](../track-e/E10-token-lifetimes-and-rotation.md) |
| JWE — encrypted JWTs | [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md) |
| Encrypted session cookies | [E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md) |
| The bulk of a TLS connection, after key exchange | [B17](B17-what-https-protects.md) |
| Envelope encryption in a KMS | [I05](../track-i/I05-secrets-management.md) |

Notice how few of these there are relative to hashing and signing. **Most of authentication
does not need encryption.** It needs *integrity* and *authenticity*, which are
[B13](B13-message-authentication-hmac.md) and [B14](B14-digital-signatures.md). Reaching
for encryption when you needed a signature is a common and expensive design error.

---

## Terms defined in this chapter

`symmetric encryption`, `XOR`, `block cipher`, `AES`, `mode of operation`, `IV`, `AEAD`,
`nonce`

---

## What to remember

1. **`x ⊕ k ⊕ k = x`.** Encryption and decryption are the same operation. Everything else
   is keystream generation.
2. **AES is XOR plus fourteen rounds of mixing.** You will never implement it.
3. The **mode** is where security lives. ECB leaks structure — never use it.
4. **Use AEAD: AES-GCM or ChaCha20-Poly1305.** Encryption without authentication does not
   prevent tampering.
5. **Never reuse a (key, nonce) pair.** Under GCM this leaks the authentication key, not
   just plaintext.
6. Use the **associated data** field to bind a ciphertext to its context.
7. Most auth problems need integrity, not confidentiality. Reach for a MAC first.

---

## Sources

- [NIST FIPS 197 — Advanced Encryption Standard](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38D — Galois/Counter Mode](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [RFC 8439 — ChaCha20 and Poly1305](https://www.rfc-editor.org/rfc/rfc8439)
- Jean-Philippe Aumasson, *Serious Cryptography*, 2nd ed., Ch. 4 (Block Ciphers), Ch. 8 (AE)
- [The ECB Penguin](https://words.filippo.io/the-ecb-penguin/)

---

**Next:** [B10 — The key distribution problem](B10-key-distribution-problem.md)
