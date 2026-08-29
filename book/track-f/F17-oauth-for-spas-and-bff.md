# F17 — OAuth for SPAs, and the backend-for-frontend pattern

**Part F · Delegated authorization — OAuth 2** · *Builds on [F06](F06-pkce.md), [E12](../track-e/E12-where-to-store-a-token.md)*
---

## Why the browser is a bad place for tokens

Everything in [E12](../track-e/E12-where-to-store-a-token.md), applied to OAuth:

| Storage | XSS steals it? | Verdict |
|---|---|---|
| `localStorage` | ✅ trivially, persistently | ❌ |
| `sessionStorage` | ✅ | ❌ |
| In-memory JS variable | ✅ while page open | ⚠️ access token only |
| `HttpOnly` cookie | ❌ (can't read) but XSS can still *use* it | best available in-browser |

A SPA is a **public client** ([F09](F09-public-vs-confidential-clients.md)) — it cannot keep
a secret, and any token it holds is reachable by any script on the origin. There is no
storage location in the browser that survives XSS. So the winning move is to not store tokens
there.

---

## The backend-for-frontend pattern

> **A small server component (the BFF) becomes the OAuth client. It holds the tokens
> server-side. The browser gets only a session cookie.**

```
   BEFORE (SPA holds tokens)          AFTER (BFF holds tokens)
   ─────────────────────────          ────────────────────────
   Browser                            Browser
     │ access + refresh token           │ __Host-session cookie (opaque). That's ALL.
     │ (public client, exposed)         │ HttpOnly, Secure, SameSite      E02
     ▼                                  ▼
   ── XSS steals everything ──        BFF (a confidential client)
                                        │ access + refresh token, SERVER-SIDE
                                        │ proxies API calls, attaches the token
                                        ▼
                                      Resource server
```

The transformation is precise:

- The **BFF is a confidential client** ([F09](F09-public-vs-confidential-clients.md)) — it
  runs on a server, holds a real client secret, does the code-flow-with-PKCE, and stores the
  tokens.
- The **browser holds an opaque session cookie** ([E03](../track-e/E03-build-server-side-sessions.md),
  [E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md)) — `HttpOnly`, so script cannot
  read it; `SameSite`, for CSRF ([E15](../track-e/E15-csrf.md)).
- The **BFF proxies API calls**, attaching the access token server-side.

An XSS can now, at worst, make requests *through* the BFF while the page is open — it cannot
steal a token, because there is no token in the browser to steal. Same-origin, revocable,
bounded ([E12](../track-e/E12-where-to-store-a-token.md)).

---

## The BFF

```python
# The BFF is a confidential OAuth client (F04/F09) AND a session server (E03).

@app.get("/auth/login")
def login():
    # Standard code flow with PKCE — but the BFF, not the browser, runs it.
    state = secrets.token_urlsafe(32)                       # F05
    verifier = secrets.token_urlsafe(32)                    # F06
    session["oauth_state"] = state
    session["code_verifier"] = verifier
    return redirect(build_authorize_url(state, challenge_of(verifier)))

@app.get("/auth/callback")
def callback():
    check_state(request.args["state"], session.pop("oauth_state"))   # F05
    tokens = exchange_code(                                           # back channel — F03
        code=request.args["code"],
        verifier=session.pop("code_verifier"),
        client_secret=CLIENT_SECRET,                                 # BFF is confidential
    )
    user = resolve_user(tokens)                                      # G12

    # Tokens stay HERE. The browser gets only a session cookie.
    sid = create_session(user.id)                                   # E03
    store_tokens_for_session(sid, tokens)                           # server-side, encrypted
    resp = redirect("/")
    resp.set_cookie("__Host-session", sid, httponly=True, secure=True,
                    samesite="Lax", path="/")                       # E02
    return resp

# ── Everything the SPA calls goes through the BFF ──
@app.route("/api/<path:p>", methods=["GET", "POST", "PUT", "DELETE"])
def proxy(p):
    session_id = session_from_cookie()                              # E03
    if not session_id:
        return {"error": "unauthenticated"}, 401
    require_csrf()                                                  # same-origin; E15

    tokens = get_tokens_for_session(session_id)
    if tokens.access_expired():
        tokens = refresh_tokens(session_id)                        # BFF refreshes; E10

    return forward(f"{API_BASE}/{p}",
                   method=request.method, body=request.get_data(),
                   headers={"Authorization": f"Bearer {tokens.access}"})
```

The SPA's code becomes trivially simple — it just calls same-origin `/api/...` with the
session cookie, which the browser attaches automatically:

```js
// No tokens. No Authorization header. No refresh logic. No token storage.
const photos = await fetch("/api/photos", {credentials: "same-origin"}).then(r => r.json());
```

All the OAuth complexity — PKCE, state, code exchange, token storage, refresh, rotation —
moved to the server, where it belongs.

---

## What the BFF buys you

| Property | SPA holds tokens | **BFF** |
|---|---|---|
| Tokens reachable by XSS | ✅ | ❌ **not in the browser** |
| Client type | Public | **Confidential** ([F09](F09-public-vs-confidential-clients.md)) |
| Refresh token exposure | In the browser | Server-side, encrypted ([I05](../track-i/I05-secrets-management.md)) |
| Revocation | Hard | **Delete the session** ([E11](../track-e/E11-revocation.md)) |
| CORS complexity | Cross-origin to the API | **Same-origin** — no CORS ([A11](../track-a/A11-same-origin-and-cors.md)) |
| CSRF | N/A (header auth) | Needs `SameSite` + token ([E15](../track-e/E15-csrf.md)) |
| Session listing / logout | Hard | **Free** ([E13](../track-e/E13-sessions-across-devices.md)) |

Two of these are worth dwelling on. **Same-origin** means the whole CORS headache
([A11](../track-a/A11-same-origin-and-cors.md)) disappears — the SPA and its `/api` prefix
are one origin. And **revocation becomes trivial** — it is the server-side session
([E09](../track-e/E09-should-you-use-jwts-for-sessions.md)), so logout, "log out
everywhere," and offboarding all just work.

The one thing you take on: **CSRF** ([E15](../track-e/E15-csrf.md)). Cookie-based auth is
CSRF-relevant, where header-based auth was not. But `SameSite=Lax` handles the common case
and a token handles the rest — a well-understood, solved problem, unlike XSS token theft.

---

## The trade, stated honestly

The BFF is not free:

- **It is a server component to run** — for a purely static SPA, that is new infrastructure.
- **It is a proxy hop** — a little latency, and it must scale with traffic.
- **It concentrates the tokens** — the BFF is now a high-value target; secure it accordingly
  ([I05](../track-i/I05-secrets-management.md)).

For a SPA that already has a backend (most do), the BFF is often *that* backend, and the cost
is small. For a genuinely static, backendless SPA, you are adding a server — which is exactly
the point: **there was no safe place for tokens without one.**

---

## When you cannot add a BFF

If a BFF is truly impossible, the fallback ([E12](../track-e/E12-where-to-store-a-token.md)):

```
✅  Authorization code + PKCE                           F06
✅  Access token IN MEMORY only (module-scoped, not window)
✅  Refresh token in an HttpOnly cookie, Path=/auth/refresh
✅  Strict CSP with connect-src                         E16
✅  Short access-token lifetime                          E10
✅  Consider DPoP with a non-extractable key            F16
```

This is meaningfully weaker than a BFF — the access token is still XSS-reachable while the
page is open — but it keeps the *refresh* token (the persistent credential) out of script's
reach. It is the second-best answer, and the OAuth-for-browser-apps guidance treats it as
such.

**The current recommendation, from the IETF's own browser-apps draft: use a BFF.** SPAs
holding tokens is the pattern to move away from.

---

## Terms defined in this chapter

`BFF`

---

## What to remember

1. **PKCE protects the code, not the tokens.** A SPA holding tokens is still XSS-exposed.
2. **A SPA is a public client. A BFF is a confidential one.** The BFF holds the tokens
   server-side; the browser gets an opaque session cookie.
3. An XSS against a BFF architecture can *use* the session while the page is open but
   **cannot steal a token** — there is none in the browser.
4. The BFF also gives you **same-origin (no CORS)** and **trivial revocation** — the tokens
   are a server-side session.
5. The cost is **CSRF** (solved by `SameSite`), a proxy hop, and a server to run.
6. **The IETF recommends the BFF.** If you truly cannot: access token in memory, refresh
   token in a path-scoped `HttpOnly` cookie, strict CSP.

---

## Sources

- [OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/) — the normative BFF recommendation
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §4.2
- [Duende: The BFF Security Pattern](https://docs.duendesoftware.com/identityserver/v7/bff/)

---

**Next:** [F18 — OAuth for mobile: deep links and app-claimed URLs](F18-oauth-for-mobile.md)
