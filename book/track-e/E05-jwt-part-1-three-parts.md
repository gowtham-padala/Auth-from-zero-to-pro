# E05 — What a JWT actually is, part 1: the three parts

**Part E · Sessions & tokens** · *Builds on [B02](../track-b/B02-encoding-is-not-encryption.md)*
---

## Do this now

Take any JWT — from your own application's Network tab, or this one:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0NDcxIiwibmFtZSI6IkFsaWNlIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzU2MzQ1MjAwLCJleHAiOjE3NTYzNDg4MDB9.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

Three parts, separated by dots:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9  .  eyJzdWIiOiI0NDcxIiwi...  .  dBjftJeZ4CVP-mB92K27...
└────────────── header ─────────────┘     └────── payload ──────┘     └──── signature ────┘
```

Decode the first two with a command you already have:

```bash
echo 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' | base64 -d
# {"alg":"HS256","typ":"JWT"}

echo 'eyJzdWIiOiI0NDcxIiwibmFtZSI6IkFsaWNlIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzU2MzQ1MjAwLCJleHAiOjE3NTYzNDg4MDB9' | base64 -d
# {"sub":"4471","name":"Alice","role":"admin","iat":1756345200,"exp":1756348800}
```

**No key involved.** Nothing decrypted. Everyone holding this token can read every claim in
it — including the user, including any script on the page, including whatever proxy logged
it.

### Now break it

Change one character in the payload and watch verification fail:

```python
import jwt   # pip install pyjwt

SECRET = "your-256-bit-secret"
token = jwt.encode({"sub": "4471", "role": "user"}, SECRET, algorithm="HS256")
print(token)
print(jwt.decode(token, SECRET, algorithms=["HS256"]))     # ✅ {'sub': '4471', 'role': 'user'}

# Tamper: flip one character of the payload segment.
h, p, s = token.split(".")
tampered = f"{h}.{p[:-1]}{'A' if p[-1] != 'A' else 'B'}.{s}"

try:
    jwt.decode(tampered, SECRET, algorithms=["HS256"])
except jwt.InvalidSignatureError:
    print("❌ signature verification failed")               # ← every time
```

**That is the entire lesson of JWTs in two demonstrations:**

1. **You can read it.** Anyone can. It is public.
2. **You cannot change it.** Not without the key.

Readable, tamper-evident. Everything else is detail.

---

## Part 1: the header

```json
{
  "alg": "HS256",
  "typ": "JWT",
  "kid": "2026-08-key-1"
}
```

| Field | Meaning |
|---|---|
| `alg` | The signing algorithm. **Never trust this** — [E06](E06-jwt-part-2-signature-jws-jwe.md). |
| `typ` | The media type. `JWT`, or a specific type like `at+jwt` for access tokens. |
| `kid` | Which key signed it — for rotation ([E07](E07-jose-family.md), [I06](../track-i/I06-key-rotation.md)). |

The `alg` field is **attacker-controlled**, because the attacker holds the token. Two of the
most famous JWT vulnerabilities are consequences of verifiers trusting it: `alg: none` and
algorithm confusion. Both in [E06](E06-jwt-part-2-signature-jws-jwe.md).

---

## Part 2: the payload

JSON, with each name/value pair called a **claim**
([C03](../track-c/C03-the-vocabulary.md)).

### Registered claims — learn these seven

Defined in [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) §4.1. Three-letter names,
deliberately short.

| Claim | Name | Meaning | Verify? |
|---|---|---|---|
| `iss` | Issuer | Who minted it | **Yes** |
| `sub` | Subject | Who it is about | Yes |
| **`aud`** | **Audience** | **Who may accept it** | **Yes — most skipped** |
| `exp` | Expiration | Not valid after (Unix seconds) | **Yes** |
| `nbf` | Not before | Not valid until | Yes |
| `iat` | Issued at | When it was created | Usually |
| `jti` | JWT ID | Unique identifier, for denylists | If revoking |

Two notes people get wrong:

**All times are Unix seconds**, not milliseconds. A JavaScript `Date.now()` in `exp`
produces a token valid until the year 57,000. This ships regularly.

**`aud` is the most commonly skipped check**, and skipping it is how the confused deputy
attack works: a token issued for service A is replayed against service B, which never
checked that it was the intended audience
([F08](../track-f/F08-audience-and-resource-indicators.md)).

### Public and private claims

Anything else you like:

```json
{
  "sub": "4471",
  "tenant": "acme",
  "roles": ["editor"],
  "https://example.com/plan": "enterprise"
}
```

Namespace custom claims with a URI if the token crosses organisational boundaries, so you do
not collide with someone else's meaning of `roles`.

### What must never go in

```json
{
  "ssn": "123-45-6789",            ❌ readable by anyone
  "credit_card": "4111...",        ❌
  "internal_risk_score": 0.87,     ❌ readable by the user
  "password_hash": "$argon2id$...", ❌
  "api_key": "sk_live_...",        ❌
  "email": "alice@example.com",    ⚠️  fine internally; PII in a third-party token
  "notes": "flagged for fraud"     ❌ readable by the person you flagged
}
```

The pattern: **anything you would not show the token's holder does not belong in a JWT.**
For genuinely confidential claims you need JWE ([E06](E06-jwt-part-2-signature-jws-jwe.md)),
or — much more sensibly — an opaque token pointing at server-side state
([E08](E08-signed-cookies-vs-jwt-vs-opaque.md)).

There is also a size argument. A JWT travels in a header on **every** request. Keep it under
~1 KB; some proxies and servers cap total header size at 4–8 KB, and a token stuffed with
permissions will eventually produce `431 Request Header Fields Too Large` for your
most-privileged users — a bug that only affects admins and is therefore found late.

---

## Part 3: the signature

Computed over the first two parts:

```
signature = HMAC-SHA256(
    base64url(header) + "." + base64url(payload),
    secret
)
```

Note that it covers the **encoded** parts, joined by a dot — not the decoded JSON. This
matters: re-serialising the JSON and signing that produces a different result, which is the
same trap as webhook verification ([B13](../track-b/B13-message-authentication-hmac.md),
[J06](../track-j/J06-signing-webhooks.md)).

Full treatment of what "signature" means here — and why `HS256` is not actually a signature
— is [E06](E06-jwt-part-2-signature-jws-jwe.md).

---

## base64url, and the classic bug

JWTs use **base64url without padding**
([B02](../track-b/B02-encoding-is-not-encryption.md)):

| Standard base64 | base64url |
|---|---|
| `+` | `-` |
| `/` | `_` |
| `=` padding | **omitted** |

Which produces the most common JWT bug in the world:

```python
import base64

# ❌ Fails on roughly two-thirds of tokens, seemingly at random.
base64.b64decode(payload_segment)     # binascii.Error: Invalid padding

# ✅
def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
```

The failure depends on payload length mod 3, so it passes your tests and fails in
production for some users and not others. Re-pad before decoding.

---

## What a JWT is *for*

The genuine advantage, stated precisely: **verification requires no lookup.** Any party with
the verification key can check a token without contacting the issuer.

That is valuable when:

- **Many services must verify.** An identity provider signs; twelve microservices verify
  independently, with only a public key ([E06](E06-jwt-part-2-signature-jws-jwe.md)).
- **The verifier cannot reach the issuer.** A different company, a different network, an
  edge function.
- **Verification volume is enormous** and a central lookup would be a bottleneck.

That is *not* valuable when there is one application with one database that is already
handling the request. There, a lookup costs a millisecond and buys instant revocation
([E03](E03-build-server-side-sessions.md)).

The cost of "no lookup" is exactly that: **no lookup.** Which means:

- **You cannot revoke it** before it expires ([E11](E11-revocation.md)).
- **The claims are stale** the moment anything changes. Demote an admin and their token says
  `admin` until it expires.
- **It is bigger** than a session ID, on every request.

[E08](E08-signed-cookies-vs-jwt-vs-opaque.md) makes the comparison properly and
[E09](E09-should-you-use-jwts-for-sessions.md) takes a position.

---

## Where you will meet JWTs

| Use | Signed by | Verified by | Chapter |
|---|---|---|---|
| **OIDC ID token** | The identity provider | Your app | [G03](../track-g/G03-id-token-vs-access-token.md) |
| **OAuth access token** | The authorization server | Resource servers | [F12](../track-f/F12-introspection-vs-local-validation.md) |
| Service-to-service | Your auth service | Your services | [H12](../track-h/H12-authz-in-microservices.md) |
| `private_key_jwt` | The OAuth client | The authorization server | [F09](../track-f/F09-public-vs-confidential-clients.md) |
| DPoP proof | The client | The resource server | [F16](../track-f/F16-sender-constrained-tokens.md) |
| Web session | Your app | Your app | ⚠️ [E09](E09-should-you-use-jwts-for-sessions.md) |

The first two are what JWTs were designed for: **crossing a trust boundary**. The last one
is the contested case.

---

## Terms defined in this chapter

`JWT`, `compact serialization`, `JWS` (introduced; detailed in E06)

---

## What to remember

1. **Three parts: `header.payload.signature`**, all base64url, joined by dots.
2. **The payload is readable by anyone.** Signing is integrity, not confidentiality. Nothing
   goes in a JWT that you would not print on a postcard.
3. **Change one character and verification fails.** That is the whole guarantee.
4. Seven registered claims: `iss`, `sub`, **`aud`**, `exp`, `nbf`, `iat`, `jti`. **`aud` is
   the most-skipped check.**
5. **Times are Unix *seconds*.** `Date.now()` produces a token valid for millennia.
6. **base64url without padding.** Re-pad before decoding, or two-thirds of tokens fail
   randomly.
7. The advantage is **verification without a lookup**. The cost is **no revocation and stale
   claims**. Same property, both directions.
8. Keep it under ~1 KB or you will produce `431` for your admins.

---

## Sources

- [RFC 7519 — JSON Web Token](https://www.rfc-editor.org/rfc/rfc7519) §4.1 (registered claims)
- [RFC 7515 — JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515) §2 (base64url without padding)
- [jwt.io](https://jwt.io/) — paste a token, see the parts (and note: it decodes without a key)
- [RFC 8725 — JSON Web Token Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)

---

**Next:** [E06 — What a JWT actually is, part 2: the signature, JWS vs JWE](E06-jwt-part-2-signature-jws-jwe.md)
