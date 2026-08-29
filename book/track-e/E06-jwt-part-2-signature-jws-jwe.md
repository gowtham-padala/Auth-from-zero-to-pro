# E06 — What a JWT actually is, part 2: the signature, JWS vs JWE

**Part E · Sessions & tokens** · *Builds on [E05](E05-jwt-part-1-three-parts.md), [B13](../track-b/B13-message-authentication-hmac.md), [B14](../track-b/B14-digital-signatures.md)*
---

## Why it matters

Two lines. No key. Administrator.

```python
import base64, json

header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=")
payload = base64.urlsafe_b64encode(b'{"sub":"1","role":"admin"}').rstrip(b"=")
forged  = header + b"." + payload + b"."          # ← note the empty signature
```

Send it. If the verifier reads `alg` from the token and dispatches on it, `alg: none` means
"unsigned," and an unsigned token verifies trivially — because there is nothing to verify.

This was in the specification. Multiple production libraries implemented it faithfully. It
has produced real breaches.

The root cause is one design decision worth stating plainly:

> **The token tells the verifier which algorithm to use. The token comes from the attacker.**

Everything in this chapter follows from refusing that.

---

## What the signature covers

```
signing_input = base64url(header) + "." + base64url(payload)
signature     = SIGN(key, signing_input)
```

Over the **encoded** segments, joined by a dot. Not the decoded JSON.

That detail matters for the same reason it matters in webhooks
([J06](../track-j/J06-signing-webhooks.md)): if you parse and re-serialise the JSON before
verifying, key order and whitespace change, and the signature will not match — or worse, you
verify a *different* document than the one you go on to use.

**Verify over the bytes you received.**

---

## `HS256` is not a signature

The `alg` values look like a uniform family. They are not.

| `alg` | Primitive | Key | Who can verify | Who can forge |
|---|---|---|---|---|
| `HS256` | **HMAC**-SHA256 | One shared secret | **Anyone holding the secret** | **Anyone holding the secret** |
| `RS256` | RSA PKCS#1 v1.5 | Key pair | Anyone with the public key | Only the private key holder |
| `PS256` | RSA-PSS | Key pair | Same | Same |
| `ES256` | ECDSA P-256 | Key pair | Same | Same |
| `EdDSA` | Ed25519 | Key pair | Same | Same |

**`HS256` is a MAC, not a signature** ([B13](../track-b/B13-message-authentication-hmac.md),
[B14](../track-b/B14-digital-signatures.md)). Every party that can verify can also mint.

The consequence, and the decision rule:

```
                How many parties need to VERIFY?
                            │
            ┌───────────────┴────────────────┐
        One party                      More than one
   (or mutually trusting)          (or across a trust boundary)
            │                                │
         HS256                        ES256 / EdDSA / RS256
   fast, 32-byte tag                 verifiers hold only a
   one shared secret                 PUBLIC key — cannot forge
```

Sharing an HMAC secret with five microservices gives all five the power to forge an admin
token. A compromise of the least important one is a compromise of the most important one
([B10](../track-b/B10-key-distribution-problem.md)).

**`HS256` for a single application signing tokens only it reads. Asymmetric for anything
else.** For new asymmetric deployments prefer **`ES256`** — 64-byte signatures instead of
256, faster verification, smaller keys ([B11](../track-b/B11-asymmetric-encryption.md)).

---

## The two `alg` attacks

### 1. `alg: none`

The forgery at the top of this chapter.

`alg: none` is a legitimate JOSE value meaning "unsecured JWS" — intended for cases where
integrity is provided by an outer layer. In a token verifier, it is a total bypass.

**Defence:** never accept it. Which follows from the general fix below.

### 2. Algorithm confusion (RS256 → HS256)

Subtler, and it defeats systems that correctly reject `alg: none`.

```
1. Your server signs with RS256. The public key is published at /jwks.json.
   That is fine — it is a PUBLIC key.

2. Attacker fetches it and crafts a token with alg: HS256,
   using the PEM bytes of your public key as the HMAC secret.

3. Your verifier reads alg: HS256, looks up "the key," gets the RSA
   public key, and runs HMAC with it.

4. It matches. The forgery verifies.
```

The attacker used a value you deliberately published. The bug is that the verifier let the
token choose *how* to interpret the key.

### The one-line fix for both

```python
# ❌ trusts the token
jwt.decode(token, key)
jwt.decode(token, key, algorithms=jwt.get_unverified_header(token)["alg"])

# ✅ the VERIFIER decides
jwt.decode(token, key, algorithms=["ES256"])       # an explicit allowlist
```

> **Never read the algorithm from the token. Pin it in configuration.**
>
> Cryptographic agility means *you* can change the algorithm
> ([B06](../track-b/B06-collisions.md)) — not that the *message* can.

Modern libraries require the `algorithms` parameter for exactly this reason. If yours does
not, that is a signal about its age.

---

## Verification is nine checks, not one

A verified signature proves the bytes are unmodified since *someone* signed them
([B14](../track-b/B14-digital-signatures.md)). It proves nothing else.

```python
import jwt
from jwt import PyJWKClient

jwks = PyJWKClient("https://auth.example.com/.well-known/jwks.json",
                   cache_keys=True, lifespan=3600)          # I06

def verify(token: str) -> dict:
    # ① Which key? By `kid`, from a JWKS fetched over HTTPS from a URL
    #    derived from the ISSUER — never a key embedded in the token.
    signing_key = jwks.get_signing_key_from_jwt(token).key

    claims = jwt.decode(
        token,
        signing_key,
        algorithms=["ES256"],                    # ② pinned, not from the token
        issuer="https://auth.example.com",       # ③ iss
        audience="https://api.example.com",      # ④ aud   ← most skipped
        leeway=60,                               # ⑤ exp/nbf, with clock skew
        options={
            "require": ["exp", "iat", "iss", "aud", "sub"],   # ⑥ present at all
            "verify_signature": True,
            "verify_exp": True,
            "verify_aud": True,
            "verify_iss": True,
        },
    )

    # ⑦ Token type — an ID token must not be accepted as an access token.  G03.
    if jwt.get_unverified_header(token).get("typ") not in ("at+jwt", "JWT"):
        raise ValueError("wrong token type")

    # ⑧ Revocation, if you maintain a denylist.  E11.
    if is_revoked(claims["jti"]):
        raise ValueError("revoked")

    # ⑨ Authorization. A valid token is not permission.  Track H.
    return claims
```

| # | Check | Missing it means |
|---|---|---|
| ① | Key selected by `kid` from a trusted JWKS | Attacker-supplied keys (`jwk`/`jku` header injection) |
| ② | **Algorithm pinned** | `alg: none`, algorithm confusion |
| ③ | `iss` matches | A token from any issuer is accepted |
| ④ | **`aud` matches** | **Confused deputy** ([F08](../track-f/F08-audience-and-resource-indicators.md)) |
| ⑤ | `exp` / `nbf` enforced | Expired tokens accepted forever |
| ⑥ | Required claims present | An empty payload verifies fine |
| ⑦ | Token type correct | ID token used as an access token ([G03](../track-g/G03-id-token-vs-access-token.md)) |
| ⑧ | Not revoked | [E11](E11-revocation.md) |
| ⑨ | Authorization performed | A valid token is authentication, not permission |

### Header injection: `jwk`, `jku`, `x5u`

JOSE lets a token carry or reference its own key:

```json
{ "alg": "RS256", "jwk": { "kty": "RSA", "n": "...attacker's key...", "e": "AQAB" } }
```

A verifier that uses it verifies the attacker's signature with the attacker's key. **Always
successfully.**

**Never resolve keys from the token.** Use `kid` only as an *index* into a key set you
fetched yourself, from a URL derived from a configured issuer. If a `jku` is supported at
all, it must be an exact-match allowlist ([A09](../track-a/A09-redirects.md) — parse, never
string-match).

---

## JWS vs JWE

| | **JWS** — signed | **JWE** — encrypted |
|---|---|---|
| Parts | 3 | **5** |
| Payload | **Readable by anyone** | Confidential |
| Guarantees | Integrity, authenticity | Confidentiality + integrity |
| Usage | ~99% of JWTs | Rare |

```
JWS:  header.payload.signature
JWE:  header.encrypted_key.iv.ciphertext.tag
```

**Five segments means JWE.** That is how you tell at a glance.

JWE uses hybrid encryption ([B10](../track-b/B10-key-distribution-problem.md)): a random
content key encrypts the payload with AES-GCM, and the content key is encrypted to the
recipient's public key.

### When to use JWE

Almost never, and it is worth being blunt:

- Your transport is already encrypted ([B17](../track-b/B17-what-https-protects.md)).
- The recipient can read the plaintext anyway — encryption protects it from
  *intermediaries*, not from the party you sent it to.
- **If the data is confidential, it should not be in a token at all.** Use an opaque
  reference and keep the data server-side ([E08](E08-signed-cookies-vs-jwt-vs-opaque.md)).
- Nested JWS-in-JWE ("sign then encrypt") is correct and genuinely fiddly to implement.

Legitimate cases: a token that must pass through an untrusted intermediary that should not
read it; some regulated environments; certain federation profiles where an assertion
transits the browser.

**Default to JWS. Reach for JWE only with a specific reason you can name.**

---

## Key rotation, briefly

Signing keys must rotate ([I06](../track-i/I06-key-rotation.md)). The mechanism is the `kid`
header plus a JWKS ([E07](E07-jose-family.md)):

```
1. Generate the new key. Publish it in the JWKS alongside the old one.
2. WAIT for verifiers' caches to expire (respect your own Cache-Control).
3. Only then, start signing with the new kid.
4. After the longest possible token lifetime, remove the old key.
```

**Doing steps 2 and 3 in the wrong order logs out every user simultaneously**, because
verifiers hold a cached key set that does not contain the new `kid`. This is the single most
common self-inflicted auth outage.

---

## Terms defined in this chapter

`JWE`, `alg`, `alg: none`, `algorithm confusion`

---

## What to remember

1. **`alg: none` is a two-line total forgery** if the verifier trusts the token's `alg`.
2. **Algorithm confusion** turns your published *public* key into an HMAC secret.
3. **Pin the algorithm in configuration.** Never read it from the token. One line, two
   attacks closed.
4. **`HS256` is a MAC, not a signature.** Every verifier can forge. Multi-party → `ES256`.
5. **Verification is nine checks.** `aud` is the most-skipped and enables the confused
   deputy.
6. **Never resolve keys from the token** — no `jwk`, no unvalidated `jku`. `kid` indexes a
   key set *you* fetched.
7. **Five segments = JWE.** You almost certainly want JWS. Confidential data does not belong
   in a token.
8. Rotate with `kid`: **publish, wait for caches, then sign.** The wrong order is an outage.

---

## Sources

- [RFC 7515 — JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515)
- [RFC 7516 — JSON Web Encryption](https://www.rfc-editor.org/rfc/rfc7516)
- [RFC 7518 — JSON Web Algorithms](https://www.rfc-editor.org/rfc/rfc7518)
- [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725) — §3.1 is the algorithm rule, normatively
- [Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/) (Tim McLean, 2015) — the original disclosure

---

**Next:** [E07 — JOSE, JWK, JWKS, JWA: the acronym family, untangled](E07-jose-family.md)
