# E02 — Cookie attributes that matter: HttpOnly, Secure, SameSite, `__Host-`

**Part E · Sessions & tokens** · *Builds on [A06](../track-a/A06-cookies.md)*
---

## The five that matter

```http
Set-Cookie: __Host-session=8f14e45f...; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=1209600
            └────┬─────┘                 └─┬─┘  └─┬─┘  └───┬───┘  └────┬─────┘  └─────┬──────┘
              prefix                     Path  Secure  HttpOnly   SameSite       lifetime
```

That line is the answer. The rest of the chapter is why each piece is there.

---

## `Secure` — HTTPS only

The cookie is never sent over plain HTTP.

**Always set it.** Without it, one accidental HTTP request — a hardcoded link, a redirect,
an old bookmark, an attacker on a café network forcing a navigation to `http://` — leaks the
session in cleartext.

**Development note:** `localhost` is treated as a secure context, so `Secure` cookies work
on `http://localhost`. They do **not** work on `http://192.168.1.5` or
`http://staging.internal`, which is a common source of "works in prod, breaks locally" cookie confusion
([A06](../track-a/A06-cookies.md)). Use HTTPS in staging.

---

## `HttpOnly` — invisible to JavaScript

```js
document.cookie   // → "theme=dark"     the session cookie is not there
```

The cookie is still **sent** on every request. It cannot be **read** by script.

This is the single highest-value flag, because of what it does to an XSS
([E16](E16-xss-is-an-auth-vulnerability.md)):

| | Without `HttpOnly` | With `HttpOnly` |
|---|---|---|
| Attacker's script can | **Read the cookie, send it to their server, use it from their own machine, forever** | Make requests *as* the user, only while the page is open |
| Damage | Full, persistent, offline account takeover | Serious, bounded, ends when the tab closes |
| Detectable | No — they log in from their own browser | Yes — the requests come from the user's session |

Neither is good. The difference between "permanent takeover" and "temporary abuse" is one
attribute, and it is the strongest argument in
[E12](E12-where-to-store-a-token.md) for cookies over `localStorage`.

---

## `SameSite` — the CSRF control

The most consequential cookie attribute of the last decade.

| Value | Cookie sent on cross-site requests? |
|---|---|
| `Strict` | **Never.** Not even following a link from another site. |
| `Lax` | Only on **top-level `GET` navigations**. |
| `None` | Always. **Requires `Secure`.** |

Precisely, `Lax` sends the cookie when *all* of these hold: it is a **top-level navigation**
(not an iframe, image, fetch, or form-post), and the method is **safe**
([A03](../track-a/A03-methods-status-codes-401-vs-403.md)).

So `Lax` blocks:

- cross-site `POST` form submissions ← **the classic CSRF attack**
- `fetch`/`XHR` with credentials
- iframes, images, and scripts

and allows a user clicking a link from another site to arrive logged in. That combination is
what "SameSite mostly killed CSRF" means ([E15](E15-csrf.md)).

### `Lax` is the default

Modern browsers apply `Lax` when the attribute is absent. **Set it explicitly anyway** —
defaults differ by browser and version, and explicit is auditable.

### When you need `Strict`

`Strict` blocks the cookie even when a user clicks a link from another site, so they arrive
logged out and must click again. Bad for most products; correct for banking and admin
consoles.

**The good pattern:** two cookies.

```http
Set-Cookie: __Host-session=...;      Secure; HttpOnly; SameSite=Lax
Set-Cookie: __Host-session-strict=...; Secure; HttpOnly; SameSite=Strict
```

Ordinary reads require the `Lax` cookie. **Sensitive actions require the `Strict` one.** The
user arriving from an external link is logged in and browsing normally, and a cross-site
request can never perform a dangerous action — because the `Strict` cookie was not sent.

### When you need `None`

Only when the cookie must travel in a genuinely third-party context: an embedded widget, an
SSO flow using iframes ([G11](../track-g/G11-federated-sessions-single-logout.md)), a
payment frame.

`SameSite=None` **requires** `Secure`, and browsers are progressively restricting
third-party cookies regardless. If your design depends on them, it has a deadline.

---

## `Domain` — omit it

```http
Set-Cookie: a=1                        → app.example.com ONLY (host-only)
Set-Cookie: a=1; Domain=example.com    → example.com AND EVERY subdomain
```

**Omitting `Domain` is the restrictive option**, which is the opposite of most people's
intuition.

Set it and the cookie goes to every subdomain — including ones created later, ones run by
other teams, ones on third-party platforms, and ones an attacker takes over via a dangling
DNS record.

Only set `Domain` if you genuinely need cross-subdomain sessions. If you do, treat **every**
subdomain as part of your security perimeter, and audit them.

---

## `Path` — hygiene, not security

`Path=/admin` restricts the cookie to that path. It is **not a security boundary**: any page
on the origin can read another path's cookies via script or an iframe. The same-origin
policy does not partition by path.

Use `Path=/` and control access properly ([Track H](../track-h/H01-where-does-authz-live.md)).

---

## The `__Host-` prefix

Not an attribute — a **name prefix the browser enforces**.

A cookie named `__Host-*` is accepted **only if**:

- `Secure` is set
- `Path=/`
- **no `Domain` attribute**

```http
Set-Cookie: __Host-session=abc; Path=/; Secure; HttpOnly; SameSite=Lax   ✅
Set-Cookie: __Host-session=abc; Domain=example.com; Path=/; Secure       ❌ rejected
Set-Cookie: __Host-session=abc; Path=/admin; Secure                      ❌ rejected
```

What that buys you: **a subdomain cannot set or overwrite it.** Because there is no `Domain`
attribute and the browser enforces its absence, `promo.example.com` has no way to write a
cookie that `app.example.com` will read.

That also closes **cookie tossing**, where an attacker on a
subdomain overwrites your session cookie with a value they know, producing session fixation
([E04](E04-session-ids.md)).

**This is the strongest cookie binding available. It costs one prefix. Almost nobody uses
it.**

(`__Secure-` is the weaker sibling: requires `Secure`, permits `Domain`. Use `__Host-`
unless you truly need cross-subdomain.)

---

## Lifetime

```http
Set-Cookie: s=...                    → session cookie: gone when the browser closes
Set-Cookie: s=...; Max-Age=1209600   → persistent: 14 days
```

"Gone when the browser closes" is **unreliable** — session-restore features routinely bring
them back. Never depend on it.

> **The cookie's expiry is a hint to the browser. The server-side session expiry is the
> real one.** Enforce both, and treat the server's as authoritative
> ([E04](E04-session-ids.md)).

Use `Max-Age` (seconds) rather than `Expires` (an absolute date) — no clock-skew problems,
no date parsing.

---

## The complete set

```python
resp.set_cookie(
    "__Host-session",                 # prefix: no subdomain can write it
    session_id,                       # 256 bits from a CSPRNG — B03
    max_age=60 * 60 * 24 * 14,        # 14 days; server enforces the real expiry
    path="/",                         # required by __Host-
    secure=True,                      # required by __Host-
    httponly=True,                    # invisible to script — survives XSS
    samesite="Lax",                   # CSRF default
    # domain=... deliberately absent  # required by __Host-
)
```

Deleting one — every attribute must match, or you create a *second* cookie:

```python
resp.set_cookie("__Host-session", "", max_age=0, path="/",
                secure=True, httponly=True, samesite="Lax")
```

And always, on any authenticated response:

```http
Cache-Control: no-store
```

Otherwise a shared cache or the browser's disk cache retains an authenticated page
([A04](../track-a/A04-headers.md)).

---

## The audit

Run this against your own application today:

```bash
curl -sI https://app.example.com/login | grep -i set-cookie
```

```
☐  Every session cookie has HttpOnly
☐  Every session cookie has Secure
☐  Every session cookie has SameSite (explicitly)
☐  Session cookies use the __Host- prefix
☐  No Domain attribute unless cross-subdomain is genuinely required
☐  Path=/
☐  Cache-Control: no-store on authenticated responses
☐  No sensitive data in the cookie VALUE — it is readable by the user
☐  CSRF cookies are readable by script (they must be) but are NOT the session
```

That last line catches a real mistake: double-submit CSRF tokens
([E15](E15-csrf.md)) must be script-readable, so they cannot be `HttpOnly`. Keep them in a
**separate** cookie from the session, and never make the session readable to accommodate
them.

---

## Terms defined in this chapter

`HttpOnly`, `Secure`, `SameSite`, `__Host- prefix`, `cookie jar`

---

## What to remember

1. **`__Host-session=...; Path=/; Secure; HttpOnly; SameSite=Lax`.** Memorise the line.
2. **`HttpOnly` turns an XSS from permanent takeover into temporary abuse.** The
   highest-value flag.
3. **`SameSite=Lax` is the default and blocks classic CSRF.** Set it explicitly anyway.
4. **Two cookies — `Lax` for reading, `Strict` for sensitive actions** — is the best
   available pattern.
5. **Omitting `Domain` is the restrictive choice.** Setting it opens every subdomain,
   forever.
6. **`Path` is not a security boundary.**
7. **`__Host-` stops subdomains overwriting your session.** One prefix, an entire attack
   class closed.
8. The server-side expiry is the real one. `Max-Age`, not `Expires`.

---

## Sources

- [RFC 6265bis — HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis) §4.1.3 (cookie name prefixes), §5.5 (SameSite)
- [MDN: Set-Cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie)
- [OWASP Session Management Cheat Sheet — Cookies](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#cookies)

---

**Next:** [E03 — Build server-side sessions](E03-build-server-side-sessions.md)
