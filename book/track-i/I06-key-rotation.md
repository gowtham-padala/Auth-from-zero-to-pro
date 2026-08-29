# I06 — Key rotation without downtime: kid, JWKS, overlap windows

**Part I · Identity lifecycle & operations** · *Builds on [E07](../track-e/E07-jose-family.md), [I05](I05-secrets-management.md)*
> Invisible until the day it isn't. Get the *order* wrong, and you log out every user
> simultaneously.

---

## Why rotate at all

Keys must rotate — it is not optional maintenance ([I05](I05-secrets-management.md)):

- **Limit exposure.** A key used for years, if compromised, has signed years of tokens. Regular
  rotation bounds the blast radius of any single key ([I10](I10-incident-response.md)).
- **Recover from leaks.** When a key *is* compromised, rotation is the recovery — you can only do
  it under pressure if you've practised it under calm ([I05](I05-secrets-management.md)).
- **Compliance.** Many regimes mandate periodic rotation ([I11](I11-compliance.md)).
- **Cryptographic agility.** Rotation is also how you change *algorithms* over time
  ([B06](../track-b/B06-collisions.md)) — retire RS256 for ES256, say.

A system that *cannot* rotate its keys is one leak away from a catastrophe it can't recover from.
The ability to rotate cleanly is the point.

---

## The mechanism: kid + a JWKS with overlap

Rotation without downtime rests on two things from [E07](../track-e/E07-jose-family.md):

- **`kid`** (key ID) — every token's header names *which* key signed it.
- **A JWKS** that can hold **multiple keys at once** — so both the old and new key are published
  *during the transition*.

```
   JWKS during rotation:
   {
     "keys": [
       { "kid": "2026-05", ... },    ← the OLD key, still verifying old tokens
       { "kid": "2026-08", ... }     ← the NEW key, verifying new tokens
     ]
   }
```

A verifier reads the token's `kid`, finds the matching key in the JWKS, and verifies. As long as
*both* keys are in the JWKS, tokens signed by either verify correctly. That overlap is what
makes zero-downtime rotation possible — and it is what the failed team skipped.

---

## The overlap window — the order that matters

The rotation is a **sequence**, and the order is the whole thing:

```
   ① PUBLISH the new key in the JWKS, alongside the old one.
      → Both keys are now available to verifiers.
      → NOTHING is signed with the new key yet.
                        │
   ② WAIT for verifier caches to expire.
      → Every verifier refetches the JWKS and now knows the new key.
      → Wait AT LEAST the JWKS Cache-Control max-age.  E07.
                        │
   ③ START signing with the new key (new kid).
      → New tokens verify, because step ② ensured verifiers have the key.
      → Old tokens STILL verify — the old key is still published.
                        │
   ④ WAIT for all old tokens to expire (the longest token lifetime).
                        │
   ⑤ REMOVE the old key from the JWKS.
      → No token in existence was signed by it anymore.
```

```
   ┌── old key signs ──┐
   │                   │◄──── overlap: BOTH keys published & trusted ────►│
   │                   ┌── new key signs ──────────────────────────────...│
   │                   │                                                   │
   published: OLD      OLD + NEW                                    OLD + NEW → NEW only
   ①                   ②③                                          ④        ⑤
```

**The failed team did ③ before ②** — signed with the new key before verifiers knew about it.
Do steps ① and ③ in the wrong order, and you get the simultaneous-logout outage. The wait in
step ② is not padding; it is the mechanism.

---

## The signing side

```python
class KeyManager:
    def __init__(self):
        self.keys = load_keys()                    # {kid: key}, from KMS — I05
        self.active_kid = current_active_kid()     # which one to SIGN with

    def sign(self, claims: dict) -> str:
        # Sign with the ACTIVE key; stamp its kid in the header. E06/E07.
        return jwt.encode(claims, self.keys[self.active_kid].private,
                          algorithm="ES256", headers={"kid": self.active_kid})

    def jwks(self) -> dict:
        # Publish ALL currently-trusted PUBLIC keys — the overlap set.
        return {"keys": [k.public_jwk(kid) for kid, k in self.keys.items()
                         if k.trusted_for_verification]}    # includes old + new
```

The verifying side is unchanged from [G04](../track-g/G04-validate-an-id-token-by-hand.md)/[E07](../track-e/E07-jose-family.md):
select the key by `kid` from the cached JWKS, refetch once on an unknown `kid`, rate-limit the
refetch. **The refetch-on-unknown-kid is the safety net** — even if a verifier's cache is stale
when you start signing with a new key, its first failed lookup triggers a refetch that picks up
the new key. Cache correctly *and* refetch on miss, and rotation is robust to timing slop.

The rotation itself is an operational sequence, ideally automated:

```python
def rotate_signing_key():
    new_kid = generate_key_in_kms()               # I05 — key never leaves the KMS
    publish_to_jwks(new_kid, trusted=True)        # ① publish, don't sign yet
    wait(jwks_cache_max_age + margin)             # ② let caches expire
    set_active_signing_kid(new_kid)               # ③ NOW sign with it
    schedule(after=max_token_lifetime,            # ④/⑤ retire the old key later
             fn=lambda: remove_from_jwks(old_kid))
```

---

## Rotating the *other* kinds of keys

The kid/JWKS/overlap pattern is for *asymmetric verification* keys (JWT signing). Other secrets
rotate differently ([I05](I05-secrets-management.md)):

**Symmetric secrets (HS256, HMAC, webhook secrets — [B13](../track-b/B13-message-authentication-hmac.md)).**
No public JWKS, so overlap means the verifier must **accept either the old or the new secret**
during the window:

```python
def verify(msg, tag):
    return (verify_hmac(NEW_SECRET, msg, tag)      # try new
            or verify_hmac(OLD_SECRET, msg, tag))   # fall back to old, during overlap
```

This is exactly what a well-designed webhook receiver does ([J06](../track-j/J06-signing-webhooks.md)) —
providers publish two active secrets during rotation so you can roll without missing events.

**Passwords with a pepper ([B08](../track-b/B08-salts-peppers-slow-hashes.md)).** You can't
re-hash without the plaintext, so version the pepper: store which pepper version made each hash,
verify with that version, and **re-hash with the current pepper on next login** — the same
rehash-on-login technique as [I12](I12-migrating-auth.md).

**Encryption keys ([I05](I05-secrets-management.md)).** With envelope encryption, rotate the
*master* key and re-wrap the data keys — the bulk ciphertext doesn't change, only the small
wrapped keys. Cheap, and no need to re-encrypt the data.

The common thread: **during rotation, accept both old and new; sign/encrypt with new; retire old
only after everything it touched has expired.**

---

## Rotate under calm, so you can rotate under fire

The reason to build and *practise* rotation before you need it: when a key is compromised
([I10](I10-incident-response.md)), you must rotate *immediately* — and that is the worst moment
to discover your architecture can't do it without downtime. An incident-driven emergency
rotation collapses the overlap window (you can't wait — the old key is compromised), which
*will* log some users out and reject some tokens. That's an acceptable cost during an incident;
it's an unacceptable one during routine maintenance.

So: automate routine rotation with full overlap, run it regularly, and you get two things — a
smaller blast radius from every key, and a rotation muscle that works when you're under fire.

---

## Terms defined in this chapter

`key rotation`, `overlap window`, `cache TTL`

---

## What to remember

1. **Get the order wrong and you log out every user at once.** Rotation is easy; the sequence is
   the skill.
2. **The mechanism is `kid` + a JWKS holding multiple keys** ([E07](../track-e/E07-jose-family.md))
   — both old and new published during the transition.
3. **The order: ① publish new (don't sign) → ② wait for caches → ③ sign with new → ④ wait for old
   tokens to expire → ⑤ remove old.** Step ② is the mechanism, not padding.
4. **Refetch-on-unknown-kid is the safety net** — verify correctly *and* refetch on miss.
5. **Symmetric secrets rotate by accepting either** during overlap ([J06](../track-j/J06-signing-webhooks.md));
   **peppers by versioning + rehash-on-login** ([I12](I12-migrating-auth.md)); **encryption keys
   by re-wrapping data keys** ([I05](I05-secrets-management.md)).
6. **Practise routine rotation under calm**, so an emergency rotation ([I10](I10-incident-response.md))
   is a known procedure, not a first attempt.

---

## Sources

- [RFC 7517 — JSON Web Key Set](https://www.rfc-editor.org/rfc/rfc7517) ([E07](../track-e/E07-jose-family.md))
- [Auth0 / Okta: key rotation documentation](https://auth0.com/docs/get-started/tenant-settings/signing-keys)
- [NIST SP 800-57 Part 1 — Key Management: cryptoperiods](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final)

---

**Next:** [I07 — Testing auth: the tests everyone skips](I07-testing-auth.md)
