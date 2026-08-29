# F12 — Token introspection vs local validation

**Part F · Delegated authorization — OAuth 2** · *Builds on [F07](F07-access-refresh-scopes.md), [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)*
---

## Two ways to validate a token

```
   LOCAL VALIDATION                       INTROSPECTION
   ────────────────                       ─────────────
   RS verifies the signature itself       RS asks the AS "is this valid?"
   using the AS's public key (JWKS).      on every request.

   Token → verify → decide                Token → POST /introspect → decide
       (no network)                            (network round trip)

   Requires: a JWT (self-contained)       Works with: opaque OR JWT tokens
   Fast, offline, scalable                Fresh, revocable, centralised
   Stale until expiry                     A dependency and a bottleneck
```

The choice mirrors the token-type decision from
[E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md): **carry the state, or point at
it.** Local validation trusts what the token carries; introspection asks the source of
truth.

---

## Local validation

The resource server verifies the token's signature and claims without contacting the AS —
the nine-check procedure from [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md):

```python
import jwt
from jwt import PyJWKClient

jwks = PyJWKClient("https://auth.example.com/.well-known/jwks.json",
                   cache_keys=True, lifespan=3600)     # E07 — cache!

def validate_local(token: str) -> dict:
    key = jwks.get_signing_key_from_jwt(token).key
    return jwt.decode(
        token, key,
        algorithms=["ES256"],                          # pinned — E06
        issuer="https://auth.example.com",
        audience="https://api.example.com",            # aud — F08
    )
```

Requires the token to be a JWT following the OAuth access-token profile
([RFC 9068](https://www.rfc-editor.org/rfc/rfc9068), `typ: at+jwt`).

**Pros:** fast (~0.1 ms), no network, no AS dependency, scales horizontally.
**Con:** you learn the token's *issued* state, not its *current* state. A token revoked one
minute ago still validates until `exp`.

---

## Introspection (RFC 7662)

The resource server asks the AS whether a token is *currently* valid:

```http
POST /introspect HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(rs_client_id:rs_secret)      ← the RS authenticates

token=2YotnFZFEjr1zCsicMWpAA
```

```json
{
  "active": true,
  "sub": "user-4471",
  "aud": "https://api.example.com",
  "scope": "photos:read",
  "exp": 1756348800,
  "client_id": "printco"
}
```

```python
def validate_introspect(token: str) -> dict:
    r = requests.post("https://auth.example.com/introspect",
                      data={"token": token},
                      auth=(RS_CLIENT_ID, RS_SECRET), timeout=5)
    body = r.json()
    if not body.get("active"):                         # ← the whole point
        raise Invalid("token inactive")
    if RS_ID not in as_list(body.get("aud", [])):      # aud still matters — F08
        raise Invalid("wrong audience")
    return body
```

The single most important field is **`active`** — a boolean the AS computes *now*, reflecting
revocation, expiry, and any other current state. That is the freshness local validation
cannot give you.

Requirements from the spec, each a real bug when missing:

- **The RS must authenticate** to the introspection endpoint. An unauthenticated endpoint is
  a token-validity oracle for attackers.
- **`active: false` for anything invalid** — the AS reveals nothing else about a bad token.
- Works with **opaque tokens**, which cannot be validated locally at all — this is often the
  real reason to use it.

**Pros:** fresh, real revocation, centralised policy, works with opaque tokens.
**Con:** a network call per request; the AS is now on the critical path.

---

## The comparison

| | Local validation | Introspection |
|---|---|---|
| Token type | JWT only | **Opaque or JWT** |
| Network per request | None | One round trip |
| Latency | ~0.1 ms | ~5–50 ms |
| **Revocation** | ❌ Stale until expiry | ✅ **Immediate** |
| AS dependency | Only for JWKS (cached) | **Every request** |
| Scales | ✅ Trivially | ⚠️ AS is the bottleneck |
| Fails if AS is down | No (JWKS cached) | **Yes** |
| Best for | High-volume, short-lived tokens | High-value, revocation-critical |

---

## The hybrid — what mature systems actually do

You do not have to choose globally. Combine them by risk and by caching.

### Cached introspection

Introspect, but cache the result for a short window (30–60 s). You get *most* of the freshness
with a fraction of the calls:

```python
def validate_cached(token: str) -> dict:
    key = f"introspect:{sha256(token)}"          # cache by hash — B05
    hit = cache.get(key)
    if hit:
        return hit
    result = validate_introspect(token)
    ttl = min(60, result["exp"] - int(time.time()))
    cache.set(key, result, ttl)
    return result
```

Revocation now takes effect within the cache TTL rather than instantly — a tunable
compromise. A 30-second window is usually an acceptable revocation latency, and it cuts AS
load by orders of magnitude.

### Route-based

Local validation for the common, low-risk path; introspection for the sensitive one:

```python
@app.get("/photos")                 # high-volume, low-stakes
def photos():
    claims = validate_local(bearer())          # fast

@app.post("/photos/delete-all")     # rare, destructive
def delete_all():
    claims = validate_introspect(bearer())     # confirm it is still valid NOW
```

The reasoning matches step-up ([D18](../track-d/D18-step-up-auth-and-aal.md)): spend the
network round trip where the action justifies it.

### Short tokens + local validation — often the best answer

The cleanest resolution is the one from [E11](../track-e/E11-revocation.md): make access
tokens so short-lived (5 minutes) that revocation latency is bounded by expiry, and validate
locally. Revocation happens at the **refresh** step — delete the refresh token, and no new
access token is issued ([E10](../track-e/E10-token-lifetimes-and-rotation.md)). You get
local-validation speed and a 5-minute worst case, with no per-request AS call.

This is why so many production systems land on "short-lived JWT access tokens + opaque
revocable refresh tokens": it sidesteps the introspection trade entirely.

---

## Choosing

```
Do you need revocation faster than your access-token lifetime?
│
├── NO ──> Local validation, short-lived JWTs. Revoke at refresh.   ← usually this
│
└── YES ─> Are tokens opaque?
           │
           ├── YES ──> Introspection (no local option), cached
           │
           └── NO ───> Introspection for sensitive routes,
                       local for the rest; or cached introspection
```

---

## Terms defined in this chapter

`introspection`, `local validation`

---

## What to remember

1. **Local validation:** RS verifies the JWT itself. Fast, offline, scalable — but **stale
   until expiry**.
2. **Introspection:** RS asks the AS `active?` on each request. Fresh and revocable — but a
   round trip and an AS dependency.
3. **`active` is the field that matters** — the AS computes current validity. The RS must
   **authenticate** to the endpoint.
4. Introspection is often the real answer for **opaque tokens**, which cannot be validated
   locally.
5. **Cache introspection results** for 30–60 s to trade a little freshness for a lot of load.
6. **Route-based:** local for volume, introspection for destructive actions.
7. **The cleanest answer is usually short-lived JWTs + local validation + revoke-at-refresh.**
   Check `aud` either way.

---

## Sources

- [RFC 7662 — OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
- [RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §4.9

---

**Next:** [F13 — Consent screens, and the UX that prevents phishing](F13-consent-screens.md)
