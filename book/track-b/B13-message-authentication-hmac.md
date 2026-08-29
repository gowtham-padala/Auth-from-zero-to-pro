# B13 — Message authentication: hashing with a secret, and HMAC

**Part B · Crypto foundations** · *Builds on [B04](B04-what-a-hash-function-is.md), [B09](B09-symmetric-encryption.md)*
---

## Why it matters

A download link with an integrity check:

```
https://cdn.example.com/installer.exe?sha256=2cf24dba5fb0a30e...
```

The page tells you to verify the hash. Good practice, surely.

An attacker who can modify the download can modify the page. They swap the installer and
swap the hash. Both match. You verify successfully and install malware.

**A hash proves nothing about origin.** It proves the data matches *some* hash — and the
attacker supplied the hash.

What you need is a value only the *legitimate sender* could have produced. That requires a
secret. This chapter is how to add one, and — critically — how the obvious way to add one
is broken.

---

## What a MAC is

> A **MAC** (message authentication code) is a tag computed from a message *and a secret
> key*, proving the message came from someone holding that key and was not modified.

```
   Sender                                        Receiver
   ──────                                        ────────
   tag = MAC(key, message)                       expected = MAC(key, message)
        │                                             │
        └── sends: message ‖ tag ──────────────────>  compare tag == expected
                                                          (in constant time — B16)
```

Two properties, and the vocabulary is worth keeping precise:

- **Integrity** — the message was not changed.
- **Authenticity** — it came from a holder of the key.

Note what a MAC does **not** give you: **non-repudiation**. Both parties hold the same key,
so either could have produced the tag. The receiver knows the sender sent it; the receiver
cannot *prove that to a third party*, because the receiver could have forged it themselves.
For that you need a signature ([B14](B14-digital-signatures.md)), where only one party can
produce and everyone can verify.

---

## The obvious construction, and why it fails

The natural first attempt:

```python
tag = sha256(secret + message).hexdigest()      # ❌ BROKEN
```

It looks fine. An attacker who does not know `secret` cannot compute the tag for a modified
message. Right?

Wrong. And the reason is a structural property of SHA-256 that has nothing to do with
whether SHA-256 is a good hash.

### Length extension

SHA-256, SHA-1, and MD5 use the **Merkle–Damgård** construction. The message is padded to a
multiple of the block size, then processed block by block, with each block updating an
internal state. **The final state *is* the output.**

```
   [state₀] → block₁ → [state₁] → block₂ → [state₂] → ... → [stateₙ] = DIGEST
                                                                 │
                                             the digest IS the internal state
```

So if I hand you a digest, I have handed you the complete internal state of the hash
function at that point.

You can **resume from it**. You do not need to know what was hashed to get there — only how
*long* it was, so you can reconstruct the padding.

```
 Attacker knows:   tag  = SHA256(secret ‖ "user=alice&role=guest")
                   msg  = "user=alice&role=guest"
                   guess: len(secret) — a few dozen tries at most

 Attacker computes, WITHOUT the secret:
                   tag' = SHA256(secret ‖ "user=alice&role=guest" ‖ padding ‖ "&role=admin")
```

And `tag'` is **valid**. The server recomputes `SHA256(secret ‖ received_message)`, gets
the same value, and accepts. The attacker never learned the secret and never needed to.

Note that the appended data goes at the *end*, so this works beautifully against formats
where later values win — query strings, some JSON parsers, many configuration formats.
`&role=admin` after `&role=guest` is a privilege escalation in most query-string parsers.

### Watch it break

```python
# pip install pure25519  →  no. Use: pip install hashpumpy
import hashpumpy, hashlib

SECRET = b"supersecretkey"                     # attacker does NOT know this
message = b"user=alice&role=guest"

# What the server produced:
tag = hashlib.sha256(SECRET + message).hexdigest()
print("original tag:", tag)

# The attacker knows only `tag`, `message`, and guesses len(SECRET) == 14.
new_tag, new_message = hashpumpy.hashpump(tag, message, b"&role=admin", 14)

print("forged msg  :", new_message)
# b'user=alice&role=guest\x80\x00...\x01\x18&role=admin'
print("forged tag  :", new_tag)

# The server's verification, unchanged:
print("server accepts:", hashlib.sha256(SECRET + new_message).hexdigest() == new_tag)
# True   ← the forgery is accepted
```

`True`. A message the attacker wrote, with a tag the attacker computed, without the key.

This was not a hypothetical. **Flickr's API signing scheme was broken this way in 2009.**
So was the authentication in several other production APIs, all using the same intuitive
and wrong construction.

### What about `sha256(message + secret)`?

Not length-extendable. But now the tag's security depends on the *collision resistance* of
the hash ([B06](B06-collisions.md)) — find a collision in `message`, and the two colliding
messages produce the same tag regardless of the secret. Against MD5 or SHA-1 that is a real
attack today.

The point generalises: **there is no obvious way to combine a hash and a secret that is
actually safe.** Each variation fails differently. That is why a specific, analysed
construction exists.

---

## HMAC

**HMAC** — hash-based message authentication code, RFC 2104 — is the construction that
works.

```
HMAC(K, m) = H( (K' ⊕ opad) ‖ H( (K' ⊕ ipad) ‖ m ) )
```

Unpacking it:

- `K'` — the key, padded with zeros to the hash's block size (64 bytes for SHA-256). If the
  key is *longer* than the block size, it is hashed first.
- `ipad` — the byte `0x36`, repeated to block size.
- `opad` — the byte `0x5c`, repeated to block size.
- **Two passes.** Hash the inner, then hash the outer over that result.

### Why two passes fixes it

The inner hash produces a digest. The outer hash consumes it **along with a key-derived
prefix** — so the final output is *not* the internal state of a hash over
`secret ‖ message`. It is the state of a hash over `something ‖ inner_digest`, and the
attacker cannot extend that into anything meaningful because they do not know
`K' ⊕ opad`.

The nesting is what breaks the resumption. That is the whole reason for the ceremony, and
it is why HMAC looks arbitrary until you have watched the naive version fail.

Why `0x36` and `0x5c`? They differ in many bits, so `K ⊕ ipad` and `K ⊕ opad` are
substantially different keys. The construction has a security proof: HMAC is a secure MAC
as long as the underlying compression function is a decent pseudorandom function — **even
if the hash is not collision-resistant.**

That proof is exactly why **HMAC-SHA1 and HMAC-MD5 are not broken** by the collision
attacks in [B06](B06-collisions.md), and why TOTP's use of HMAC-SHA1 is fine
([D12](../track-d/D12-build-totp.md)). Being able to explain this distinction is a real
marker of understanding.

---

## Use it

```python
import hmac, hashlib, secrets

key = secrets.token_bytes(32)              # 256 bits from a CSPRNG — B03
message = b"user=alice&role=guest"

tag = hmac.new(key, message, hashlib.sha256).hexdigest()
print(tag)

# Verification — ALWAYS constant-time. Never ==.  (B16)
def verify(key, message, tag):
    expected = hmac.new(key, message, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, tag)

print(verify(key, message, tag))                       # True
print(verify(key, b"user=alice&role=admin", tag))      # False ✅
```

Now try to length-extend it. You cannot. The construction removes the attack.

```bash
# Same thing from a shell
$ echo -n "user=alice&role=guest" | openssl dgst -sha256 -hmac "supersecretkey"
```

**Do not implement HMAC yourself.** Every language has it in the standard library. The
formula is in this chapter so the construction is not magic, not so you can write it.

---

## Where HMAC carries the design

This is the most reused primitive in the book:

| Use | How | Chapter |
|---|---|---|
| **TOTP** | `HMAC-SHA1(secret, time_counter)`, truncated to 6 digits | [D12](../track-d/D12-build-totp.md) |
| **JWT `HS256`** | HMAC over `header.payload` | [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md) |
| **Signed cookies** | HMAC over the cookie value | [E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md) |
| **Webhook signatures** | HMAC over the raw request body | [J06](../track-j/J06-signing-webhooks.md) |
| **API key verification** | HMAC or hash of the key | [J02](../track-j/J02-api-keys.md) |
| **CSRF tokens** | HMAC binding the token to the session | [E15](../track-e/E15-csrf.md) |
| **Password peppers** | `HMAC(pepper, password)` before the KDF | [B08](B08-salts-peppers-slow-hashes.md) |
| **HKDF** | Key derivation, built entirely from HMAC | TLS, [I06](../track-i/I06-key-rotation.md) |
| **AWS SigV4** | Chained HMACs over a canonical request | — |

[D12](../track-d/D12-build-totp.md) is where this chapter pays off most visibly. TOTP is
*just* HMAC over a time counter, truncated. Readers who have understood this chapter build
working two-factor authentication in twenty minutes and feel the pieces connect.

---

## Four ways to use HMAC wrong

**1. Comparing with `==`.** Leaks how many bytes matched, through timing. Use
`hmac.compare_digest`. This is [B16](B16-timing-attacks.md) and it is the single most
common HMAC bug.

**2. Verifying over a re-serialised message.** The classic webhook failure:

```python
# ❌ You parsed the JSON and re-encoded it. Whitespace and key order changed.
verify(key, json.dumps(request.json).encode(), signature)

# ✅ Verify over the exact bytes received.
verify(key, request.get_data(), signature)
```

Every webhook integration guide says this and it is ignored constantly
([J06](../track-j/J06-signing-webhooks.md)).

**3. Not authenticating everything that matters.** If the tag covers only the body, an
attacker can change the URL, the method, or a header. Include everything that affects
interpretation — and include a **timestamp** to bound replay
([J06](../track-j/J06-signing-webhooks.md)).

**4. Using one key for multiple purposes.** A key used for both session cookies and
password-reset tokens allows a token minted for one purpose to be presented for the other.
Derive per-purpose keys with HKDF, or use separate keys. **Domain separation** — prefixing
the message with a context string like `"session-v1:"` — is the cheap version and is almost
always worth doing.

---

## MAC vs signature: which do you need?

| | HMAC | Signature |
|---|---|---|
| Keys | One shared secret | Key pair |
| Who can verify | **Only key holders** | **Anyone** |
| Who can forge | **Any key holder** | Only the private key holder |
| Non-repudiation | ❌ | ✅ |
| Speed | Very fast | ~1000× slower |
| Tag size | 32 bytes | 64–512 bytes |

The decision rule:

> **One party, or a set of parties who mutually trust each other? HMAC.**
> **Many verifiers who must not be able to forge? Signature.**

Concretely: a session cookie only your own server reads → HMAC. A JWT that five
microservices and a partner must verify → signature, because sharing the HMAC secret with
five services gives all five the ability to mint admin tokens
([B10](B10-key-distribution-problem.md), [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)).

---

## Terms defined in this chapter

`MAC`, `integrity`, `authenticity`, `length extension attack`, `HMAC`, `ipad / opad`, `tag`

---

## What to remember

1. A hash proves nothing about origin. Authentication needs a **secret**.
2. **`hash(secret ‖ message)` is broken** by length extension on SHA-256/SHA-1/MD5. Flickr,
   2009.
3. **HMAC's two-pass nesting is what stops the resumption.** That is why it looks like
   ceremony.
4. HMAC's security does **not** depend on collision resistance — so HMAC-SHA1 and TOTP are
   fine.
5. **Always `compare_digest`, never `==`.**
6. **Verify over the raw bytes received**, never a re-serialised parse.
7. Separate keys — or at least domain-separating prefixes — per purpose.
8. HMAC when verifiers may forge; signatures when they may not.

---

## Sources

- [RFC 2104 — HMAC: Keyed-Hashing for Message Authentication](https://www.rfc-editor.org/rfc/rfc2104)
- [RFC 6151 — Updated Security Considerations for MD5 and HMAC-MD5](https://www.rfc-editor.org/rfc/rfc6151)
- Bellare, Canetti, Krawczyk, [*Keying Hash Functions for Message Authentication*](https://cseweb.ucsd.edu/~mihir/papers/kmd5.pdf) (1996) — the security proof
- [hashpumpy](https://github.com/bwall/HashPump) — the length extension tool used above

---

**Next:** [B14 — Digital signatures: asymmetric encryption run backwards](B14-digital-signatures.md)
