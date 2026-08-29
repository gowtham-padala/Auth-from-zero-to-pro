# D06 — Build a login, part 2: login and error handling

**Part D · Authentication** · *Builds on [D05](D05-build-login-part-1-registration.md)*
---

## Why it matters

Helpful error messages:

```python
user = find_user(email)
if not user:
    return error("No account found with that email address.")
if not verify(user.password_hash, password):
    return error("Incorrect password.")
```

Excellent user experience. Also a free membership-testing API.

```bash
$ curl -d 'email=alice@example.com&password=x' https://app.example.com/login
{"error": "Incorrect password."}          ← alice HAS an account

$ curl -d 'email=bob@example.com&password=x' https://app.example.com/login
{"error": "No account found..."}          ← bob does not
```

Ten thousand addresses, ten thousand requests, and now the attacker has a verified user
list to aim credential stuffing at ([D08](D08-rate-limiting-and-stuffing.md)) or to
spear-phish.

And even if you fix the messages, the **timing** still leaks — the "no account" path skips
Argon2id and returns in 2 ms instead of 300
([B16](../track-b/B16-timing-attacks.md)).

---

## The handler

```python
from datetime import datetime, timezone

GENERIC_ERROR = "The email or password is incorrect."
DUMMY_HASH = ph.hash("a-value-no-real-user-will-ever-have")

@app.post("/login")
@rate_limit(key=lambda: client_ip(),                  limit="20/15min")   # D08
@rate_limit(key=lambda: canonicalize(request.form.get("email", "")),
                                                      limit="10/15min")
def login():
    email    = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not email or not password:
        return render("login.html", error=GENERIC_ERROR), 400

    user = db.find_user_by_canonical_email(canonicalize(email))

    # --- Constant work, whether or not the user exists.  B16 / D07 ---------
    ok = False
    try:
        ph.verify(user.password_hash if user else DUMMY_HASH,
                  unicodedata.normalize("NFC", password))
        ok = user is not None
    except (VerifyMismatchError, InvalidHashError):
        ok = False

    if not ok:
        record_failed_attempt(email, client_ip())                    # D08
        audit_log("login.failed", email=email, ip=client_ip())       # H13
        return render("login.html", error=GENERIC_ERROR), 401

    # --- Post-authentication gates ----------------------------------------
    if user.email_verified_at is None:
        # Deliberately the SAME generic error. Verification state is
        # account state, and revealing it is still enumeration.
        send_verification_email_again(user)
        return render("login.html", error=GENERIC_ERROR), 401

    if user.disabled_at is not None:
        return render("login.html", error=GENERIC_ERROR), 401

    # --- Free upgrade while we hold the plaintext.  I12 -------------------
    if ph.check_needs_rehash(user.password_hash):
        db.update_password_hash(user.id, ph.hash(password))

    # --- Second factor, if enrolled.  D12 ---------------------------------
    if user.totp_secret is not None:
        pending = create_pending_mfa_session(user.id, ttl_seconds=300)
        return redirect(f"/login/mfa?t={pending.id}")

    # --- Success ----------------------------------------------------------
    clear_failed_attempts(email, client_ip())
    session_id = create_session(user.id, request)          # E03
    audit_log("login.success", user_id=user.id, ip=client_ip())

    resp = redirect(safe_next(request.args.get("next")))   # A09
    resp.set_cookie(
        "__Host-session", session_id,                      # A06 / E02
        httponly=True, secure=True, samesite="Lax",
        path="/", max_age=60 * 60 * 24 * 14,
    )
    return resp
```

---

## The seven decisions

### 1. One error message, for everything

`GENERIC_ERROR` covers: no such account, wrong password, unverified email, disabled
account, and locked account.

The instinct to be helpful is exactly the vulnerability. "Your account is locked" tells an
attacker the account exists *and* that they are making progress.

> **The person who needs the specific information is the account owner. Tell them by
> email, on a channel they control — not on a page anyone can load.**

Log the specific reason server-side, always. Return the ambiguous one.

### 2. Constant work

`DUMMY_HASH` is verified when the user does not exist, so the expensive Argon2id
computation happens either way. Without it, response time is a 150× oracle and no message
uniformity saves you.

Generate `DUMMY_HASH` once at start-up, with the **same parameters** as your real hashes.
If you upgrade parameters, regenerate it — otherwise the dummy path becomes measurably
faster again.

### 3. Rate limit on two keys

- **By IP** — stops one machine trying many accounts (password spraying).
- **By account** — stops many machines trying one account (targeted stuffing).

Neither alone is sufficient. Botnets defeat IP limits; a single-IP attacker defeats
account-only limits. [D08](D08-rate-limiting-and-stuffing.md).

### 4. `POST` → `303` → `GET`

Redirect after success. Prevents re-POST on refresh
([A02](../track-a/A02-reading-http-in-dev-tools.md)), and keeps credentials out of the
browser's history and out of any `Referer` header.

### 5. Validate the `next` parameter

`safe_next()` from [A09](../track-a/A09-redirects.md). A login page that redirects anywhere
is a phishing launchpad on your own domain, wrapped around a *successful* login — the most
convincing moment possible.

### 6. Regenerate the session ID

`create_session` issues a **fresh** identifier. If the user arrived with an existing
anonymous session, its ID must not be reused.

This prevents **session fixation** ([E04](../track-e/E04-session-ids.md)): an attacker
plants a known session ID in the victim's browser, waits for them to log in, and — if the
ID survives the login — is now authenticated as them.

**Regenerate on every privilege change:** login, MFA completion, password change, role
change, impersonation start and stop.

### 7. Audit both outcomes

Success and failure. Failures are the signal for takeover detection
([I09](../track-i/I09-detecting-account-takeover.md)). Successes are what the user needs
when they ask "was that me?" ([E13](../track-e/E13-sessions-across-devices.md)).

**Never log the password**, and never log the session ID
([I08](../track-i/I08-observability.md)).

---

## The MFA step

Splitting login into two requests introduces a state you must handle carefully.

```python
@app.post("/login/mfa")
@rate_limit(key=lambda: request.form["t"], limit="5/5min")
def login_mfa():
    pending = load_pending_mfa_session(request.form["t"])
    if pending is None or pending.expired():
        return redirect("/login")

    user = db.get_user(pending.user_id)
    code = request.form.get("code", "")

    if not verify_totp(user.totp_secret, code):          # D12
        record_failed_attempt(user.email, client_ip())
        return render("mfa.html", t=pending.id, error="Incorrect code."), 401

    consume_pending_mfa_session(pending.id)   # single-use, atomically

    session_id = create_session(user.id, request, amr=["pwd", "otp"])   # D18
    ...
```

Four properties the pending state must have, each of which is a real vulnerability when
missing:

| Property | Missing it means |
|---|---|
| **Short-lived** (5 min) | A stale half-login is a standing credential |
| **Single-use** | The token can be replayed |
| **Not a session** | It grants nothing except the right to submit a code |
| **Rate limited** | Six digits is 10⁶; unlimited attempts is minutes of brute force |

That last row is the one that gets missed. TOTP is only strong because guessing is bounded.
Five attempts per five minutes, then invalidate the pending state entirely.

Record **how** the user authenticated in the session — the `amr` claim
([D18](D18-step-up-auth-and-aal.md)). A session created with password + TOTP is stronger
than one created with password alone, and later you will want to know.

---

## The login form

```html
<form method="post" action="/login">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">   <!-- E15 -->

  <label for="email">Email</label>
  <input type="email" id="email" name="email"
         autocomplete="username" required autofocus>

  <label for="password">Password</label>
  <input type="password" id="password" name="password"
         autocomplete="current-password" required>
  <!-- No maxlength. No onpaste blocker. D04. -->

  <button type="submit">Log in</button>
</form>
```

The `autocomplete` values are not cosmetic. `username` and `current-password` are what let
password managers and passkey autofill work correctly; getting them wrong silently degrades
the experience for the users with the best security hygiene. Use `new-password` on
registration and password-change forms.

---

## What "logged in" now means

The response set a cookie. From this point the user is authenticated on **every subsequent
request** by presenting that cookie — which is session management, layer 2, and Track E.

Authentication is finished. It happened once. What follows is a different problem with
different failure modes ([C01](../track-c/C01-auth-is-five-different-problems.md)).

---

## What to remember

1. **One generic error for every failure.** Tell the owner by email; tell the page nothing.
2. **Hash a dummy for unknown users.** Message uniformity without timing uniformity is not
   uniformity.
3. Rate limit **by IP and by account**. Different attacks.
4. **Regenerate the session ID on login** and on every privilege change. Session fixation.
5. Validate the `next` parameter. A login page is the best possible phishing moment.
6. The MFA pending state is short-lived, single-use, rate-limited, and **not a session**.
7. Correct `autocomplete` attributes. Password managers are a security control.
8. Audit success and failure. Never log the password or the session ID.

---

## Sources

- [OWASP Authentication Cheat Sheet — Login](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [The Copenhagen Book — Password authentication](https://thecopenhagenbook.com/password-authentication)
- [OWASP Session Management Cheat Sheet — Renew the session ID after login](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [MDN: autocomplete attribute values for login forms](https://developer.mozilla.org/en-US/docs/Web/HTML/Attributes/autocomplete)

---

**Next:** [D07 — User enumeration: how your error messages leak your user list](D07-user-enumeration.md)
