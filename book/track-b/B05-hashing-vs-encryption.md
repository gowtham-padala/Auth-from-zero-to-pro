# B05 — Hashing vs encryption: one-way vs reversible

**Part B · Crypto foundations** · *Builds on [B04](B04-what-a-hash-function-is.md)*
---

## The two operations

| | **Hashing** | **Encryption** |
|---|---|---|
| Direction | One-way | Two-way |
| Key | None | **Required** |
| Output size | Fixed | Roughly input-sized |
| Goal | Verify without storing | Read later, but only with the key |
| Reversal | Infeasible **for anyone**, including you | Trivial **with the key**, infeasible without |
| Failure mode | Someone finds a collision | Someone gets the key |

```
  HASHING — a shredder                    ENCRYPTION — a safe

  "password"                              "password"
      │                                       │
      ▼  H()                                  ▼  E(key, ·)
  ┌────────┐                              ┌────────┐
  │ 2cf24d…│                              │ 8a3f2b…│
  └────────┘                              └───┬────┘
      │                                       │  D(key, ·)
      ✗  no way back, ever                    ▼
                                          "password"
```

---

## The question that decides which one

For any piece of sensitive data, ask:

> **Do I ever need to see this value again?**

- **No** → **hash it.** Passwords, API keys, reset tokens, session tokens. You only ever
  need to answer "is the value someone just gave me the same as the one I saw before?" A
  hash answers that. Nothing else is required.

- **Yes** → **encrypt it.** Credit-card numbers you must charge, OAuth refresh tokens you
  must present to a third party, documents, messages, a user's home address. You will need
  the plaintext, so you need a key — and now the key becomes the thing you protect
  ([I05](../track-i/I05-secrets-management.md)).

The mistake is almost always in one direction: encrypting something that should have been
hashed, because encryption *feels* stronger. It is not stronger. It is **reversible**, which
is strictly worse when you never needed to reverse it. Encrypting a password takes something
that could have been permanently unrecoverable and makes its safety contingent on key
management.

---

## Worked examples

### Passwords → hash. Always.

You never need the password. You need to answer "did the user type the right one?"

```
Registration:  store  slow_hash(password, salt)
Login:         compute slow_hash(submitted, stored_salt), compare
```

The salt and the slowness matter enormously ([B07](B07-fast-hashes-wrong-for-passwords.md),
[B08](B08-salts-peppers-slow-hashes.md)). But the shape is fixed: **hash, never encrypt.**

### API keys → hash, and show once.

Same reasoning. When the user creates a key, show it once and store only
`SHA256(key)`. On each request, hash what arrives and look up the digest.

You can never show them the key again — and that is *correct*. Every good API provider
does this, and it is why they all say "copy this now, you will not see it again."
([J02](../track-j/J02-api-keys.md).)

Note that API keys use a **fast** hash, unlike passwords. The reason is entropy: a
256-bit random key cannot be brute-forced, so there is nothing to slow down. Slow hashing
protects *low-entropy human-chosen* secrets. This distinction confuses people constantly;
it is worked through in [J02](../track-j/J02-api-keys.md).

### Password reset tokens → hash.

A reset token in your database is a live credential. Store `SHA256(token)`, email the
token, hash what comes back. A database leak then yields nothing usable.
([D09](../track-d/D09-account-recovery.md).)

### Session IDs → hash (usually).

Same logic. If your session table stores raw session IDs, a read-only SQL injection is a
session-hijacking tool for every logged-in user. Store the digest.
([E04](../track-e/E04-session-ids.md).)

### Third-party refresh tokens → encrypt.

You must send the actual token to the provider later. Hashing makes it useless. Encrypt
with a key from a KMS, and accept that key management is now part of your threat model.

### Credit cards, national IDs, addresses → encrypt.

You need the values. Encrypt, and confine the plaintext to as small a region as possible.
For payment cards, prefer **not holding them at all** — tokenise via your payment provider,
so the sensitive value never enters your system.

---

## Three ways to get this wrong

### 1. "Encrypted" passwords

Adobe, 2013. 153 million records. The passwords were **encrypted, not hashed** — with
3DES in **ECB mode** and no salt.

ECB encrypts identical blocks identically. So identical passwords produced identical
ciphertext, and the (unencrypted) password *hints* were right there in the dump. Users had
helpfully written hints like "same as my name." Cross-reference the hints across the
repeated ciphertexts and the passwords fell out en masse — a crossword puzzle rather than a
cryptographic attack.

Two failures, both from this chapter: reversible where one-way was required, and a mode of
operation that leaks equality ([B09](B09-symmetric-encryption.md)).

### 2. Hashing something you need back

A team hashes OAuth refresh tokens "for security," then discovers at renewal time that they
cannot present the token to the provider. They cannot recover it. Every user must
re-authorise. This is a real outage, and it comes from applying the password rule without
asking the question.

### 3. Encoding, and calling it either one

`base64(password)` is neither. [B02](B02-encoding-is-not-encryption.md).

---

## A subtlety: encryption alone does not prevent tampering

Encryption gives **confidentiality**. It does not, by itself, give **integrity**.

With some modes an attacker who cannot read your ciphertext can still *modify* it in ways
that produce predictable changes in the plaintext. CBC mode is bit-flippable. CTR and
stream ciphers are worse: flipping a ciphertext bit flips exactly that plaintext bit.

So "it is encrypted, therefore it cannot be tampered with" is false. You need
authentication as well — either an **AEAD** mode like AES-GCM that does both, or an
explicit MAC ([B13](B13-message-authentication-hmac.md)).

This is the same lesson that makes JWTs signed rather than merely encoded, and it comes up
again in [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md).

**Practical rule:** use AEAD (AES-GCM, ChaCha20-Poly1305). Never hand-roll
encrypt-then-MAC. Never use unauthenticated encryption for anything.

---

## The decision table

| Data | Operation | Why |
|---|---|---|
| User password | **Slow hash** (Argon2id) | Never needed back; low entropy |
| API key / token you issued | **Fast hash** (SHA-256) | Never needed back; high entropy |
| Password reset token | **Fast hash** | Never needed back; high entropy |
| Session ID | **Fast hash** | Never needed back; high entropy |
| TOTP shared secret | **Encrypt** | Needed to compute codes ([D12](../track-d/D12-build-totp.md)) |
| Third-party refresh token | **Encrypt** | Must be sent to the provider |
| Recovery codes | **Slow hash** if short, fast if 128-bit random | Depends on entropy ([D13](../track-d/D13-recovery-codes.md)) |
| Credit card | **Encrypt**, or better, don't store | Needed to charge |
| Email address | **Plaintext** (encrypt at rest at the storage layer) | Needed constantly; hashing breaks everything |
| Audit log entry | **Plaintext + hash chain** | Needed for reading; chain gives tamper evidence |

The email row is worth dwelling on. People occasionally propose hashing email addresses for
privacy. It breaks login, breaks search, breaks support, and provides almost no privacy —
an email address is enumerable ([B04](B04-what-a-hash-function-is.md)). Encrypt at the
storage layer if you must; do not hash.

---

## Terms defined in this chapter

`one-way`, `encryption`, `plaintext`, `ciphertext`, `key`

---

## What to remember

1. **Do I need this value again?** No → hash. Yes → encrypt. That one question decides it.
2. **A system that can email you your password is storing it wrong.** No exceptions.
3. Encryption is not "stronger" than hashing. It is reversible, which is worse when you
   never needed to reverse.
4. Hash passwords **slowly**; hash high-entropy tokens **fast**. Slowness defends
   low-entropy secrets.
5. Encryption without authentication does not prevent tampering. Use AEAD.
6. Adobe 2013: encrypted (not hashed) + ECB + no salt + plaintext hints = 153 million
   passwords.

---

## Sources

- Jean-Philippe Aumasson, *Serious Cryptography*, 2nd ed., Ch. 1 and Ch. 4
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [Naked Security: Anatomy of a password disaster — Adobe's giant-sized cryptographic blunder](https://news.sophos.com/en-us/2013/11/04/anatomy-of-a-password-disaster-adobes-giant-sized-cryptographic-blunder/)

---

**Next:** [B06 — Collisions, and why MD5 and SHA-1 were retired](B06-collisions.md)
