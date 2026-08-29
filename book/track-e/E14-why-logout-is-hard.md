# E14 — Why logging out is genuinely hard

**Part E · Sessions & tokens** · *Builds on [E11](E11-revocation.md), [E13](E13-sessions-across-devices.md)*
---

## Why it matters

Logout, as written by almost everyone the first time:

```python
@app.post("/logout")
def logout():
    resp = redirect("/")
    resp.delete_cookie("session")
    return resp
```

The browser forgets the cookie. The user sees the logged-out page. Everyone is satisfied.

**The session is still valid on the server.**

Anyone who captured that cookie — from a proxy log, a shared computer's browser profile, an
XSS payload, a backup — can still use it, for the full remaining lifetime. The logout
changed the *client's* memory and nothing else.

Then it gets worse. The user was logged in via "Sign in with Google." They are still logged
in to Google. They click "sign in" again and are logged straight back in without a prompt —
which on a shared computer means the *next* person is logged in as them.

Logout looks like the easiest feature in authentication. It is one of the hardest, because
"logged in" is a state that exists in five places at once.

---

## The five places

```
   ┌────────────────────────────────────────────────────────────────────┐
   │ 1. THE BROWSER          the cookie, localStorage, in-memory state  │
   │ 2. YOUR SERVER          the session record, refresh tokens         │
   │ 3. LIVE CONNECTIONS     WebSockets, SSE, long-polling, jobs        │
   │ 4. OTHER APPLICATIONS   anything sharing the same SSO session      │
   │ 5. THE IDENTITY PROVIDER  the IdP's own session cookie             │
   └────────────────────────────────────────────────────────────────────┘
```

Naive logout clears **1**. Correct first-party logout clears **1, 2, and 3**. Federated
logout needs **4 and 5**, and that is where it becomes genuinely hard
([G11](../track-g/G11-federated-sessions-single-logout.md)).

---

## Doing the first three properly

```python
@app.post("/logout")
def logout():
    token = request.cookies.get("__Host-session")

    if token:
        session_hash = sha256(token.encode()).digest()
        row = db.get_session(session_hash)

        with db.transaction():
            # 2. THE SERVER — the part that actually matters.
            db.execute("DELETE FROM sessions WHERE id = %s", (session_hash,))

            if row:
                db.delete_refresh_family_for_session(session_hash)   # E10
                db.delete_pending_mfa_for_session(session_hash)      # D06
                audit_log("session.logout", user_id=row.user_id)     # H13

        # 3. LIVE CONNECTIONS
        pubsub.publish("session.revoked", {"session": session_hash.hex()})

    # 1. THE BROWSER — every attribute must match the Set-Cookie exactly,
    #    or you create a SECOND cookie instead of deleting the first.
    resp = redirect("/")
    resp.set_cookie("__Host-session", "", max_age=0, path="/",
                    secure=True, httponly=True, samesite="Lax")
    resp.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    resp.headers["Cache-Control"]   = "no-store"
    return resp
```

Five details:

**Delete the server record.** Everything else is cosmetic without this.

**Cookie deletion must match exactly** — name, path, domain, and prefix constraints. A
mismatch creates a second cookie and leaves the first in place
([A06](../track-a/A06-cookies.md)).

**`Clear-Site-Data`** tells the browser to drop cache, cookies, and storage for the origin.
Supported in Chromium and Firefox; treat it as a bonus, not the mechanism.

**Publish a revocation event** so live connections close
([E13](E13-sessions-across-devices.md)).

**Logout should be a `POST`.** A `GET /logout` is CSRF-able — trivial, low severity, and
genuinely annoying: an attacker can log users out of your site from anywhere. It also means
a prefetching browser or a mail scanner can log the user out by following a link.

---

## Should logout be CSRF-protected?

A small debate worth resolving.

**Arguments for:** it is a state-changing action, and forced logout is a nuisance attack.

**Arguments against:** if the CSRF token is stale (expired session, restored tab), logout
*fails* — which is the worse failure. A user trying to log out on a shared computer and
seeing an error is a real security problem; a user being logged out unexpectedly is an
annoyance.

**The resolution:** `POST` plus `SameSite=Lax` gives you the protection without a token,
because the browser will not send the cookie on a cross-site `POST`
([E02](E02-cookie-attributes.md)). Add a CSRF token if you like, but **never let its
validation failure prevent logout** — on a token mismatch, log out anyway and log the
anomaly.

---

## Logout everywhere vs logout here

Two different actions, and users mean different things:

| | Local logout | Global logout |
|---|---|---|
| Ends | This session | All sessions ([E13](E13-sessions-across-devices.md)) |
| Also ends | This device's refresh tokens | **All** refresh families, trusted devices |
| Default? | ✅ Yes | Offered separately |
| Requires step-up? | No | ✅ Yes ([D18](../track-d/D18-step-up-auth-and-aal.md)) |

Default to local. Offer global prominently — on the logout confirmation, on the session
list, and in the "was this you?" email.

---

## The stateless problem

If your session is a self-contained token
([E09](E09-should-you-use-jwts-for-sessions.md)), you **cannot** invalidate it on logout.
Deleting the cookie is *all* logout does.

```
   Server-side session:  DELETE  →  actually logged out  ✅
   Self-contained token: delete the cookie → the token still verifies ❌
```

Which forces one of the mitigations from [E11](E11-revocation.md):

| Approach | Cost |
|---|---|
| Short lifetime (5–15 min) | The window is small. **Usually enough.** |
| `jti` denylist until expiry | A lookup per request |
| `token_version` bump | A user lookup per request |
| Opaque revocable refresh token | ✅ **The right answer** — logout deletes it |

The last row is the pattern: the access token expires on its own within minutes, and the
refresh token — the thing that grants continued access — is server-side and deleted.

**If you cannot answer "what does logout actually do?" for your architecture, that is a
finding.** It is the most common gap between a design's intent and its behaviour.

---

## Idle logout, and the confirmation problem

Two related requirements that interact badly:

**Idle timeout** ends a session after inactivity ([E04](E04-session-ids.md)). Necessary, and
it destroys unsaved work if it fires silently.

The mitigation: **warn before expiry.**

```js
// 2 minutes before the idle timeout
showModal({
  title: "You'll be signed out shortly",
  body:  "For your security, we sign you out after 30 minutes of inactivity.",
  actions: [
    {label: "Stay signed in", onClick: () => fetch("/session/extend", {method: "POST"})},
    {label: "Sign out now",   onClick: () => logout()},
  ],
});
```

Two rules: **do not let a background keep-alive poll count as activity** (it defeats the
timeout entirely), and **preserve unsaved work across a forced logout** — a draft in
`sessionStorage`, restored after the next login.

---

## The shared computer problem

The scenario logout exists for, and where every gap shows:

```
1. User logs in at a library.
2. Clicks logout.
3. Closes the browser.
4. Next person opens it and presses Back.
```

What they might see:

- **A cached authenticated page.** ← the common failure.
  Fix: `Cache-Control: no-store` on every authenticated response
  ([A04](../track-a/A04-headers.md)).
- **Autofilled credentials.** Fix: correct `autocomplete` attributes
  ([D06](../track-d/D06-build-login-part-2-login.md)); the browser's own credential UI is
  better than fighting it.
- **A restored session cookie**, from session restore
  ([A06](../track-a/A06-cookies.md)). Fix: the server record is gone, so it does not matter.
- **They are logged straight back in via SSO.** ← the one people miss entirely.
  The IdP's session is untouched ([G11](../track-g/G11-federated-sessions-single-logout.md)).

That last one is why federated logout needs its own chapter, and why an application using
"Sign in with Google" must think carefully about what its logout button promises.

---

## What logout should promise

Be precise in the interface, because the honest version is short:

```
   ✅  "You've been signed out of this device."
   ✅  "You've been signed out of all your devices."       (if you did that)
   ⚠️  "You may still be signed in to Google."            (if federated)
```

Never imply more than you deliver. A user who believes they are fully logged out and is not
will make decisions based on that belief — like walking away from a library computer.

---

## Terms defined in this chapter

(No new terms. This chapter assembles [E11](E11-revocation.md) and
[E13](E13-sessions-across-devices.md).)

---

## What to remember

1. **Deleting the cookie is not logout.** Delete the server record, or nothing happened.
2. "Logged in" lives in **five places**: browser, server, live connections, other
   applications, the IdP.
3. Cookie deletion must match **every attribute**, or you create a second cookie.
4. **Logout is a `POST`**, protected by `SameSite`. **Never let a CSRF failure block
   logout.**
5. **Publish a revocation event** so WebSockets close.
6. **With self-contained tokens, logout is a lie** unless the refresh token is opaque and
   deleted.
7. **Warn before idle expiry**, and never let a keep-alive poll count as activity.
8. Say exactly what logout did. If the IdP session survives, say so.

---

## Sources

- [OWASP Session Management Cheat Sheet — Session termination](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#session-expiration)
- [MDN: Clear-Site-Data](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data)
- [OpenID Connect Back-Channel Logout 1.0](https://openid.net/specs/openid-connect-backchannel-1_0.html)

---

**Next:** [E15 — CSRF: what it is, and why SameSite mostly killed it](E15-csrf.md)
