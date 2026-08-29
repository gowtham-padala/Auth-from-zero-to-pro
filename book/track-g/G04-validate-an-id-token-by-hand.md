# G04 — Validate an ID token by hand: JWKS, iss, aud, nonce, exp

**Part G · Federated identity & SSO** · *Builds on [G03](G03-id-token-vs-access-token.md), [E07](../track-e/E07-jose-family.md)*
> **This is the payoff chapter for Track B.** Fetch the JWKS, pick the key by `kid`, verify
> the signature, check every claim. Every primitive — hashing, signatures, certificates,
> constant-time comparison — becomes concrete here.

---

## Why it matters

```python
import jwt
claims = jwt.decode(id_token, options={"verify_signature": False})   # ← catastrophe
user = find_user(email=claims["email"])
login(user)
```

`verify_signature: False`. The developer wanted to "just read the claims." An attacker crafts
an ID token with any `email` they like, unsigned, and logs in as anyone. This is a two-line
total compromise, and it ships regularly because the library *let* them decode without
verifying.

An ID token you have not fully validated is a base64-encoded suggestion from a stranger
([E05](../track-e/E05-jwt-part-1-three-parts.md)). Validation *is* the login. Here is every
check.

---

## The ten checks

```
   ①  Signature       — verify against the IdP's JWKS (by kid)      E06/E07
   ②  Algorithm       — pinned, from config, never the token        E06
   ③  iss             — issued by the IdP you expect
   ④  aud             — issued for YOUR client_id                   F08
   ⑤  exp             — not expired (small leeway)
   ⑥  iat / nbf       — issued in the past, not future-dated
   ⑦  nonce           — matches the one YOU sent                    G02
   ⑧  auth_time       — recent enough, if you required max_age      D18
   ⑨  acr / amr       — meets the assurance you required, if any    D18
   ⑩  at_hash         — binds to the access token, if present        G03
```

Skip any and you weaken or break the login. The famous ones are ① (the `verify_signature`
disaster), ② (`alg: none` and confusion — [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)),
and ④ (audience — the most-skipped, [F08](../track-f/F08-audience-and-resource-indicators.md)).

---

## The build, step by step

### Setup: discovery and JWKS

The IdP publishes its configuration and keys ([G05](G05-discovery-and-well-known.md),
[E07](../track-e/E07-jose-family.md)):

```python
import requests, jwt
from jwt import PyJWKClient

# Discovery: fetch ONCE at startup, cache. G05.
config = requests.get(
    "https://accounts.google.com/.well-known/openid-configuration"
).json()

ISSUER   = config["issuer"]                    # "https://accounts.google.com"
JWKS_URI = config["jwks_uri"]

# The JWKS client caches keys and refetches on a kid miss. E07.
jwks_client = PyJWKClient(JWKS_URI, cache_keys=True, lifespan=3600)

MY_CLIENT_ID = "your-client-id.apps.googleusercontent.com"
```

Two rules from [E07](../track-e/E07-jose-family.md), both load-bearing:

- **Derive `jwks_uri` from discovery, from a configured issuer URL.** Never from the token.
  A `jku`/`jwk` header inside the token is an attacker-supplied key — ignore it
  ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)).
- **Cache the JWKS**, refetch **once** on an unknown `kid`, and **rate-limit** the refetch.

### The validation function

```python
from jwt.exceptions import (InvalidTokenError, ExpiredSignatureError,
                            InvalidAudienceError, InvalidIssuerError)

def validate_id_token(id_token: str, expected_nonce: str,
                      max_age: int | None = None) -> dict:
    # ① Select the signing key by `kid` from the cached JWKS.
    #    (An unknown kid triggers one rate-limited refetch. E07.)
    signing_key = jwks_client.get_signing_key_from_jwt(id_token).key

    try:
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=["RS256", "ES256"],     # ② PINNED. Never token-supplied. E06.
            issuer=ISSUER,                     # ③ iss
            audience=MY_CLIENT_ID,             # ④ aud — reject if not me. F08.
            leeway=60,                         # ⑤/⑥ clock skew tolerance
            options={
                "require": ["iss", "aud", "exp", "iat", "sub"],   # must be present
                "verify_signature": True,
                "verify_exp": True,            # ⑤
                "verify_iat": True,            # ⑥
                "verify_aud": True,            # ④
                "verify_iss": True,            # ③
            },
        )
    except ExpiredSignatureError:
        raise LoginFailed("token expired")
    except (InvalidAudienceError, InvalidIssuerError):
        raise LoginFailed("token not for us")
    except InvalidTokenError as e:
        raise LoginFailed(f"invalid token: {e}")

    # ⑦ nonce — the library does NOT check this. YOU must. G02.
    if claims.get("nonce") != expected_nonce:
        raise LoginFailed("nonce mismatch — possible replay")

    # ⑧ auth_time — if you required recent authentication. D18.
    if max_age is not None:
        auth_time = claims.get("auth_time")
        if auth_time is None or (time.time() - auth_time) > max_age + 60:
            raise LoginFailed("authentication too old")

    # ⑨ acr/amr — if you required an assurance level. D18.
    #    e.g. if you asked for AAL2, verify claims["acr"] reflects it.

    # ⑩ at_hash — if an access token was also issued. G03.
    #    Verify it matches hash(access_token) when present.

    return claims
```

### Using it

```python
@app.get("/callback")
def callback():
    # state and PKCE first (OAuth layer). F05/F06.
    check_state(request.args["state"], session.pop("oauth_state"))
    tokens = exchange_code(request.args["code"], session.pop("code_verifier"))

    # THE login: validate the ID token.
    claims = validate_id_token(
        tokens["id_token"],
        expected_nonce=session.pop("oauth_nonce"),   # the nonce we generated. G02.
        max_age=None,
    )

    # Identity = (iss, sub). Stable, unique-per-issuer. C03/G12.
    identity = (claims["iss"], claims["sub"])

    # email_verified BEFORE any linking. D02/G12.
    if not claims.get("email_verified", False):
        # Do not link to an existing account on this email.
        pass

    user = find_or_create_user(identity, claims)     # G12
    session_id = create_session(user.id,             # E03 — YOUR session
                                amr=claims.get("amr", []),   # D18
                                acr=claims.get("acr"))
    ...
```

---

## Why each check, and what breaks without it

| Check | Without it |
|---|---|
| **① Signature** | Anyone forges any token — the `verify_signature: False` disaster |
| **② Algorithm pinned** | `alg: none` (unsigned) and algorithm confusion (RS256→HS256) ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)) |
| **③ `iss`** | A token from *any* issuer is accepted — including an attacker's own IdP |
| **④ `aud`** | A token minted for a *different app* logs the user in ([G01](G01-sign-in-with-google.md)'s attack) |
| **⑤ `exp`** | Expired tokens work forever |
| **⑥ `iat`/`nbf`** | Future-dated or pre-dated tokens accepted |
| **⑦ `nonce`** | An ID token captured from one login is replayed into another |
| **⑧ `auth_time`** | "Recent authentication" (step-up) is unenforced ([D18](../track-d/D18-step-up-auth-and-aal.md)) |
| **⑨ `acr`/`amr`** | You asked for AAL2 and silently accepted AAL1 |
| **⑩ `at_hash`** | An attacker swaps in a different access token |

The three that stop the headline attacks are ①, ②, and ④. But a validator that does those and
skips ⑦ (`nonce`) has a replay hole, and one that skips ⑧/⑨ silently ignores the assurance it
requested. **Do all ten.**

---

## The `nonce` subtlety libraries do not handle

Notice check ⑦ is *manual* — most JWT libraries validate `iss`, `aud`, and `exp` but do **not**
know your `nonce`, because it is application state, not a standard claim rule.

```
1. At /authorize: generate nonce, store it in YOUR session. G02.
2. IdP embeds nonce inside the ID token.
3. At /callback: after signature validation, compare claims["nonce"]
   to the value from YOUR session. Mismatch → reject.
```

This is the OIDC-specific replay defence, and it is the one people forget precisely because
the library does not remind them. `state` protects the callback; `nonce` protects the token
([F05](../track-f/F05-the-state-parameter.md)). You need both.

---

## Two provider-specific traps

**Google's `iss` has two forms.** `https://accounts.google.com` and `accounts.google.com`
(no scheme) both appear historically. Accept the documented value(s) for your provider
exactly; do not guess.

**Multi-tenant issuers.** For Microsoft Entra multi-tenant apps, the `iss` contains the
tenant ID and *varies per tenant*. You cannot pin a single `iss` string — you validate the
issuer against a pattern the provider documents, and additionally check the `tid` (tenant)
claim ([G09](G09-multi-tenant-sso.md)). Getting this wrong either breaks multi-tenant login
or accepts tokens from tenants you did not intend to trust.

---

## Should you use a library for all this?

Yes — a *maintained* OIDC library (not just a JWT decoder) does the flow, discovery, JWKS
caching, and most checks for you, and it is the right production choice
([C05](../track-c/C05-build-vs-buy.md)).

But build it by hand **once**, as here, because:

- You will debug it, and you cannot debug what you have never seen.
- Libraries vary in which checks they do by default — `nonce`, `at_hash`, and `acr` are
  commonly *not* automatic. Knowing the ten checks lets you audit whether your library
  actually performs them.
- The `verify_signature: False` disaster happens *inside* library usage. Understanding what
  the library is doing is what stops you disabling it.

---

## Terms defined in this chapter

`clock skew`

---

## What to remember

1. **Validation is the login.** An unverified ID token is a suggestion from a stranger.
2. **Ten checks.** The three that stop the headline attacks: **signature**, **pinned
   algorithm**, **`aud`**.
3. **Fetch keys from `jwks_uri` derived from discovery** — never from the token. Cache,
   refetch once on a `kid` miss, rate-limit.
4. **`nonce` is a manual check** — libraries do not know your nonce. Compare it to *your*
   session value.
5. Enforce **`auth_time`/`acr`** if you requested them, or step-up is silently ignored.
6. Watch **provider-specific `iss`** — Google's two forms, Entra's per-tenant issuer.
7. Use a maintained OIDC library in production, but **know the ten checks** so you can audit
   it.

---

## Sources

- [OpenID Connect Core 1.0 §3.1.3.7](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) — ID Token Validation (the normative list)
- [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [RFC 9207 — Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207)
- [PyJWT documentation](https://pyjwt.readthedocs.io/) — and read which checks are default vs manual

---

**Next:** [G05 — Discovery and .well-known: how clients configure themselves](G05-discovery-and-well-known.md)
