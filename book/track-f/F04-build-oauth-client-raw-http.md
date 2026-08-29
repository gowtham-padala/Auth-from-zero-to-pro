# F04 — Build an OAuth client with raw HTTP, no SDK

**Part F · Delegated authorization — OAuth 2** · *Builds on [F03](F03-authorization-code-flow.md)*
---

## Why it matters

Every "add Google login in 5 minutes" tutorial hands you an SDK and three lines:

```python
oauth.register("google", ...)
return oauth.google.authorize_redirect(redirect_uri)
# ... and it works, and you have no idea what happened
```

Then something breaks — a `redirect_uri` mismatch, a state error, a token that will not
validate — and you cannot debug it, because the SDK hid **exactly the parts that matter**.
You do not know where `state` is stored, whether PKCE is on, or which channel the token came
back on.

So we build it once with raw HTTP. Every parameter visible, every step yours. After this,
switching to a library ([F17](F17-oauth-for-spas-and-bff.md)) is a *relief* — you will know
precisely what it is doing and why to trust it.

---

## The whole client

A complete, working OAuth client. Server-side confidential client
([F09](F09-public-vs-confidential-clients.md)), authorization code flow with PKCE. ~90 lines.

```python
import secrets, hashlib, base64, time
import requests
from flask import Flask, request, redirect, session, abort

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)          # for the session cookie — E03

# ── Configuration ─────────────────────────────────────────────────────────
# These come from registering your app with the provider.
CLIENT_ID     = "your-client-id"
CLIENT_SECRET = os.environ["OAUTH_CLIENT_SECRET"]   # A10 — never in the bundle
REDIRECT_URI  = "https://yourapp.example/callback"  # must EXACTLY match registration
AUTHORIZE_URL = "https://auth.example.com/authorize"
TOKEN_URL     = "https://auth.example.com/token"
API_URL       = "https://api.example.com/v1/me"
SCOPE         = "openid profile email"

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()   # B02

# ── Step 1: start the flow ─────────────────────────────────────────────────
@app.get("/login")
def login():
    # state: CSRF protection. Unguessable, stored server-side. F05.
    state = b64url(secrets.token_bytes(32))                    # B03

    # PKCE: a secret we keep, and its hash we send. F06.
    code_verifier  = b64url(secrets.token_bytes(32))
    code_challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())

    # Store both in OUR session, bound to this browser. NOT in the URL.
    session["oauth_state"]    = state
    session["code_verifier"]  = code_verifier
    session["oauth_started"]  = time.time()

    params = {
        "response_type":         "code",              # F03 — code, not token
        "client_id":             CLIENT_ID,
        "redirect_uri":          REDIRECT_URI,
        "scope":                 SCOPE,
        "state":                 state,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",              # F06 — never "plain"
    }
    return redirect(f"{AUTHORIZE_URL}?{requests.compat.urlencode(params)}")

# ── Step 2: the AS sends the browser back here ──────────────────────────────
@app.get("/callback")
def callback():
    # (a) Did the AS return an error? (User denied, etc.)
    if "error" in request.args:
        return f"Authorization failed: {request.args['error']}", 400

    # (b) Verify state FIRST, before touching the code. F05.
    returned_state = request.args.get("state")
    expected_state = session.pop("oauth_state", None)
    if not expected_state or not secrets.compare_digest(returned_state or "",
                                                        expected_state):   # B16
        abort(403, "state mismatch — possible CSRF")

    # (c) The flow must be recent.
    if time.time() - session.pop("oauth_started", 0) > 600:
        abort(400, "authorization flow expired")

    code = request.args.get("code")
    if not code:
        abort(400, "no code")

    code_verifier = session.pop("code_verifier", None)
    if not code_verifier:
        abort(400, "no code_verifier — session lost")

    # ── Step 3: exchange the code for tokens, on the BACK CHANNEL. F03 ──────
    resp = requests.post(
        TOKEN_URL,
        data={
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  REDIRECT_URI,           # must match step 1
            "code_verifier": code_verifier,          # PKCE proof
        },
        auth=(CLIENT_ID, CLIENT_SECRET),             # confidential client auth. F09
        headers={"Accept": "application/json"},
        timeout=10,
    )
    if resp.status_code != 200:
        # 400 invalid_grant is the usual failure. E10.
        abort(400, f"token exchange failed: {resp.status_code} {resp.text}")

    tokens = resp.json()
    access_token  = tokens["access_token"]
    refresh_token = tokens.get("refresh_token")     # store server-side. E10 / E12

    # ── Step 4: use the token ───────────────────────────────────────────────
    me = requests.get(API_URL,
                      headers={"Authorization": f"Bearer {access_token}"},
                      timeout=10).json()

    # ── Step 5: this is where OAuth ends and YOUR session begins. ───────────
    # Do NOT use the access token as your web session. Create your own. E09.
    user = find_or_create_user(me)                  # G12 — account linking
    session["user_id"] = user.id                    # your session, your rules
    store_oauth_tokens(user.id, access_token, refresh_token)   # for calling the API later

    return redirect("/")
```

That is a complete, correct, PKCE-protected OAuth client. Nothing is hidden. Run it against
any real provider and watch every parameter in the Network tab
([A02](../track-a/A02-reading-http-in-dev-tools.md)).

---

## The details the SDK would have hidden

### Where `state` and `code_verifier` live

**In the server-side session, bound to this browser.** Not in the URL, not in a cookie the
client reads, not in a global variable ([A05](../track-a/A05-stateless.md) — a global loses
the value across requests and across servers).

This is the detail SDKs vary on and get wrong most often. If `state` is stored somewhere not
tied to *this specific browser session*, the CSRF protection it provides evaporates
([F05](F05-the-state-parameter.md)).

### Why `secrets.compare_digest` for state

Constant-time comparison ([B16](../track-b/B16-timing-attacks.md)). `state` is a secret
being compared against attacker-influenced input; `==` leaks it byte by byte.

### The `redirect_uri` appears twice

Once in the authorization request (step 1), once in the token exchange (step 3), and they
**must be identical**. The AS checks this — it is one of the defences against code
interception. Registered value, request value, and exchange value: all three the same.

### Client authentication vs PKCE

This client is **confidential**, so it uses *both* the client secret (`auth=`) and PKCE.
They defend different things:

- The **client secret** proves *which application* is exchanging the code.
- **PKCE** proves *this is the same client instance that started the flow*.

A **public** client ([F09](F09-public-vs-confidential-clients.md)) drops the `auth=` line —
it has no usable secret — and relies on PKCE alone. That is why PKCE had to become mandatory
for everyone ([F06](F06-pkce.md)): it is the *only* protection a public client has for the
code exchange.

### The token exchange is a `POST` with form encoding

Not JSON. OAuth's token endpoint uses `application/x-www-form-urlencoded`, per the
specification. Sending JSON is a common first bug.

---

## The step everyone gets wrong: step 5

```python
# ❌ Using the provider's access token as your session.
session["access_token"] = access_token

# ✅ Creating YOUR OWN session, keyed to YOUR user.
user = find_or_create_user(me)
session["user_id"] = user.id
```

The access token belongs to the **resource server** and has *its* audience, lifetime, and
scope ([F08](F08-audience-and-resource-indicators.md)). It is not your web session
([E09](../track-e/E09-should-you-use-jwts-for-sessions.md)). Using it as one couples your
login state to a third party's token lifetime and breaks the moment they rotate.

**Exchange the OAuth result for your own session, once, at login.** Store the OAuth tokens
separately, server-side, for when you need to call the API again
([E10](../track-e/E10-token-lifetimes-and-rotation.md)).

If your goal was *authentication* — "who is this user?" — you should not be reading a profile
from a resource server at all. You should be using **OIDC** and validating an ID token
([Track G](../track-g/G04-validate-an-id-token-by-hand.md)). Reading `email` from a userinfo
endpoint and trusting it is a known account-takeover path
([G12](../track-g/G12-account-linking.md)).

---

## Refreshing, by hand

When the access token expires, use the refresh token — again, raw
([E10](../track-e/E10-token-lifetimes-and-rotation.md)):

```python
def refresh_access_token(user_id: str) -> str:
    stored = get_oauth_tokens(user_id)
    resp = requests.post(TOKEN_URL, data={
        "grant_type":    "refresh_token",
        "refresh_token": stored.refresh_token,
    }, auth=(CLIENT_ID, CLIENT_SECRET), timeout=10)

    if resp.status_code != 200:
        # invalid_grant → the refresh token is dead. Re-authorize. E10.
        raise ReauthorizationRequired()

    new = resp.json()
    # The provider may ROTATE the refresh token — store the new one. E10.
    store_oauth_tokens(user_id, new["access_token"],
                       new.get("refresh_token", stored.refresh_token))
    return new["access_token"]
```

---

## The checklist

```
☐  response_type=code (never token)                          F03
☐  state: 256-bit, server-side, session-bound, checked first F05
☐  PKCE: S256, verifier stored server-side                   F06
☐  redirect_uri identical in request and exchange            F03
☐  Token exchange on the back channel, form-encoded          F03
☐  Client secret from env, never in a bundle                 A10
☐  Constant-time state comparison                            B16
☐  Access token used for the API — NOT as your session       E09
☐  Your own session created at step 5                        E03
☐  Refresh token stored server-side; rotation handled        E10
☐  Errors from the AS handled (error param, non-200 exchange)
```

Repo tag `ep-F04-oauth-client` has this running against a local authorization server
([F14](F14-build-an-authorization-server.md)), so you can step through every request.

---

## What to remember

1. **Build it once by hand.** The SDK hides `state`, PKCE, and which channel the token came
   back on — the exact things you need to debug.
2. **`state` and `code_verifier` live in the server-side session, bound to this browser.**
   Not the URL.
3. **`redirect_uri` must be identical** in the authorization request and the token exchange.
4. The token exchange is a **form-encoded `POST` on the back channel.**
5. Confidential clients use secret **and** PKCE; public clients use **PKCE alone**.
6. **Step 5 is where OAuth ends and your session begins.** Never use the access token as
   your web session.
7. For *authentication*, use OIDC and validate an ID token — do not trust a profile read.

---

## Sources

- [RFC 6749 §4.1](https://www.rfc-editor.org/rfc/rfc6749#section-4.1) — authorization code grant, request/response formats
- [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- Aaron Parecki, [oauth.com — Server-Side Apps](https://www.oauth.com/oauth2-servers/server-side-apps/)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700)

---

**Next:** [F05 — The state parameter: CSRF for OAuth](F05-the-state-parameter.md)
