# F14 — Build a minimal authorization server

**Part F · Delegated authorization — OAuth 2** · *Builds on [F06](F06-pkce.md), [F12](F12-introspection-vs-local-validation.md)*
---

## What an AS must do

Four responsibilities:

1. **Register clients** — `client_id`, secret (if confidential), and **exact** redirect URIs.
2. **Authorize** (`/authorize`) — authenticate the user, get consent, mint a code.
3. **Issue tokens** (`/token`) — validate the code exchange, issue access/refresh tokens.
4. **Support the ecosystem** — a JWKS endpoint ([E07](../track-e/E07-jose-family.md)), and
   ideally introspection ([F12](F12-introspection-vs-local-validation.md)) and revocation
   ([E11](../track-e/E11-revocation.md)).

---

## The core

Storage (a database in reality; in-memory here for clarity):

```python
import secrets, hashlib, time, base64
import jwt   # for signing access tokens

clients = {
    "printco": {
        "secret_hash": sha256("cs_live_..."),         # store the HASH — B05
        "redirect_uris": {"https://printco.example/callback"},   # a SET of EXACT URIs
        "type": "confidential",
        "allowed_scopes": {"photos:read", "photos:write"},
    },
}
codes    = {}     # code -> {client_id, redirect_uri, scope, challenge, user_id, exp, used}
tokens   = {}     # refresh_token_hash -> {...}   (access tokens are self-contained JWTs)

def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
```

### `/authorize` — the front channel

```python
@app.get("/authorize")
def authorize():
    client = clients.get(request.args.get("client_id"))
    redirect_uri = request.args.get("redirect_uri", "")

    # ① VALIDATE THE CLIENT AND REDIRECT URI *BEFORE ANYTHING ELSE*.
    #    If either is wrong, do NOT redirect — show an error page.
    #    Redirecting an error to an unvalidated URI is an open redirect. F20.
    if client is None:
        return render("error.html", msg="Unknown client"), 400
    if redirect_uri not in client["redirect_uris"]:      # EXACT match, from a set
        return render("error.html", msg="Invalid redirect_uri"), 400

    # From here, errors CAN be redirected to the (now-validated) redirect_uri.
    def err(code, state):
        return redirect(f"{redirect_uri}?error={code}&state={state}")

    state = request.args.get("state", "")

    if request.args.get("response_type") != "code":
        return err("unsupported_response_type", state)    # no implicit — F15

    # ② PKCE is required. F06.
    challenge = request.args.get("code_challenge")
    method    = request.args.get("code_challenge_method")
    if not challenge or method != "S256":                 # never accept plain
        return err("invalid_request", state)

    # ③ Requested scope must be a subset of what the client is allowed.
    requested = set(request.args.get("scope", "").split())
    if not requested <= client["allowed_scopes"]:
        return err("invalid_scope", state)

    # ④ Authenticate the USER (their session with the AS) and get consent.
    user = current_as_user() or (return redirect(f"/login?return={quote(request.url)}"))
    if not consent_given(user, client, requested):
        return render("consent.html", client=client, scopes=requested)   # F13

    # ⑤ Mint a single-use, short-lived code bound to everything.
    code = b64url(secrets.token_bytes(32))                # B03
    codes[code] = {
        "client_id":    request.args["client_id"],
        "redirect_uri": redirect_uri,                     # bind the URI
        "scope":        requested,
        "challenge":    challenge,                        # bind the PKCE challenge
        "user_id":      user.id,
        "exp":          time.time() + 60,                 # 60 seconds
        "used":         False,
    }
    return redirect(f"{redirect_uri}?code={code}&state={state}")
```

### `/token` — the back channel

```python
@app.post("/token")
def token():
    grant = request.form.get("grant_type")
    if grant == "authorization_code":
        return _authorization_code_grant()
    if grant == "refresh_token":
        return _refresh_grant()
    return {"error": "unsupported_grant_type"}, 400

def _authorization_code_grant():
    code = request.form.get("code")
    entry = codes.get(code)

    # ① Code must exist, be unexpired, and UNUSED.
    if entry is None or entry["exp"] < time.time():
        return {"error": "invalid_grant"}, 400
    if entry["used"]:
        # REUSE. Someone may have intercepted it. Kill any tokens from it. RFC 9700.
        revoke_tokens_issued_from(code)
        return {"error": "invalid_grant"}, 400

    # ② Authenticate the client (confidential).
    client_id, client_secret = client_auth(request)
    client = clients.get(client_id)
    if client is None:
        return {"error": "invalid_client"}, 401
    if entry["client_id"] != client_id:                  # code was issued to THIS client
        return {"error": "invalid_grant"}, 400
    if client["type"] == "confidential":
        if not secrets.compare_digest(sha256(client_secret or ""), client["secret_hash"]):  # B16
            return {"error": "invalid_client"}, 401

    # ③ redirect_uri must match the one from /authorize.
    if request.form.get("redirect_uri") != entry["redirect_uri"]:
        return {"error": "invalid_grant"}, 400

    # ④ PKCE: SHA256(verifier) must equal the stored challenge. F06.
    verifier = request.form.get("code_verifier", "")
    computed = b64url(hashlib.sha256(verifier.encode()).digest())
    if not secrets.compare_digest(computed, entry["challenge"]):   # B16
        return {"error": "invalid_grant"}, 400

    # ⑤ Everything checks out. Mark the code used (ATOMICALLY in a real DB).
    entry["used"] = True

    # ⑥ Issue tokens.
    access = jwt.encode({
        "iss": "https://auth.example.com",
        "sub": entry["user_id"],
        "aud": "https://api.example.com",                # F08
        "scope": " ".join(entry["scope"]),
        "iat": int(time.time()),
        "exp": int(time.time()) + 900,                   # 15 min
        "jti": b64url(secrets.token_bytes(16)),          # for revocation — E11
    }, SIGNING_KEY, algorithm="ES256", headers={"kid": CURRENT_KID})   # E06/E07

    refresh = b64url(secrets.token_bytes(32))
    tokens[sha256(refresh)] = {                          # store the hash — B05
        "user_id": entry["user_id"], "client_id": client_id,
        "scope": entry["scope"], "family": b64url(secrets.token_bytes(16)),
        "exp": time.time() + 30 * 86400,
    }

    return {
        "access_token": access, "token_type": "Bearer",
        "expires_in": 900, "refresh_token": refresh,
        "scope": " ".join(entry["scope"]),
    }
```

---

## The check-by-check reasoning

This table is the point of the whole chapter — every check, and the attack it stops.

| Check | Stops |
|---|---|
| Validate client + redirect URI **before redirecting** | Open redirect via the error path ([F20](F20-attack-your-own-oauth.md)) |
| `redirect_uri` **exact match against a set** | `redirect_uri` smuggling — the #1 OAuth attack ([F20](F20-attack-your-own-oauth.md)) |
| PKCE **required, S256 only** | Code interception on public clients ([F06](F06-pkce.md)) |
| Requested scope ⊆ allowed | Privilege escalation via scope ([F07](F07-access-refresh-scopes.md)) |
| Code **single-use**, reuse → revoke descendants | Replay of an intercepted code ([F03](F03-authorization-code-flow.md)) |
| Code **short-lived** (60 s) | The interception window |
| Code bound to **this client** | A code stolen from one client used by another |
| `redirect_uri` in exchange == in authorize | Mix-and-match interception |
| PKCE verifier hash == challenge | The party redeeming is the one that started ([F06](F06-pkce.md)) |
| Client authenticated | App impersonation ([F09](F09-public-vs-confidential-clients.md)) |
| Constant-time secret comparison | Timing recovery of the secret ([B16](../track-b/B16-timing-attacks.md)) |
| `aud` set on the access token | Confused deputy ([F08](F08-audience-and-resource-indicators.md)) |
| Store hashes of codes/refresh tokens | A database read yielding live credentials ([B05](../track-b/B05-hashing-vs-encryption.md)) |

Read that list against the client you built in [F04](F04-build-oauth-client-raw-http.md).
Every parameter the client sends, the server checks — and now you know why each one exists.

---

## What this model omits (and a real AS must not)

- **Discovery** (`/.well-known/oauth-authorization-server`) so clients self-configure
  ([G05](../track-g/G05-discovery-and-well-known.md)).
- **JWKS endpoint** and **key rotation** with `kid` ([E07](../track-e/E07-jose-family.md),
  [I06](../track-i/I06-key-rotation.md)).
- **Introspection** and **revocation** endpoints ([F12](F12-introspection-vs-local-validation.md),
  [E11](../track-e/E11-revocation.md)).
- **Refresh token rotation with reuse detection** ([E10](../track-e/E10-token-lifetimes-and-rotation.md)).
- **Rate limiting** on every endpoint ([D08](../track-d/D08-rate-limiting-and-stuffing.md)).
- **`iss` in the authorization response** ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)),
  to defeat mix-up ([F20](F20-attack-your-own-oauth.md)).
- **Atomic** code-marking and token operations under concurrency.
- **A hardened consent UI**, frame-busted ([F13](F13-consent-screens.md)).
- **OIDC** on top, if you want login ([G02](../track-g/G02-oidc-on-top-of-oauth.md)).

Each is a chapter. Together they are why "use a maintained one" is the real advice.

---

## Terms defined in this chapter

(No new glossary terms; this chapter assembles the whole track's mechanisms.)

---

## What to remember

1. **Do not run a hand-built AS in production.** Build it to *understand* it; run a
   maintained one.
2. **Validate the client and redirect URI before you redirect anything** — including errors.
3. **Exact-match `redirect_uri` against a registered set.** This is the single most important
   check.
4. **Require PKCE (S256).** Bind the code to the client, the redirect URI, and the challenge.
5. **Codes are single-use and short-lived; reuse invalidates the tokens issued from them.**
6. **Set `aud`; store hashes; compare secrets in constant time.**
7. Building the AS is what makes the client side make sense: every parameter is a check with
   a reason.

---

## Sources

- [RFC 6749 — OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) §4.1, §5
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) — the full AS threat model
- [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636), [RFC 9207 — Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207)
- [Ory Hydra](https://www.ory.sh/hydra/) / [Keycloak](https://www.keycloak.org/) — production servers to read and run

---

**Next:** [F15 — Implicit and password grants: why they're dead](F15-implicit-and-password-grants.md)
