# E15 — CSRF: what it is, and why SameSite mostly killed it

**Part E · Sessions & tokens** · *Builds on [E02](E02-cookie-attributes.md)*
---

## The attack

You are logged in to your bank in one tab. In another, you open a page that contains:

```html
<form action="https://bank.example.com/transfer" method="POST" id="f">
  <input type="hidden" name="to" value="attacker">
  <input type="hidden" name="amount" value="5000">
</form>
<script>document.getElementById("f").submit()</script>
```

The form submits. **Your browser attaches your bank's session cookie automatically**, because
that is what cookies do ([A06](../track-a/A06-cookies.md)). The bank sees a valid,
authenticated request and performs the transfer.

The attacker never saw your cookie. They could not read the response — the same-origin policy
prevents that ([A11](../track-a/A11-same-origin-and-cors.md)). **They did not need to.** The
side effect was the goal.

> **CSRF is the attacker using your browser's ambient authority.** The browser will
> faithfully authenticate any request it sends, including ones the user never intended.

---

## Why the same-origin policy does not stop it

The single most common misconception in web security
([A11](../track-a/A11-same-origin-and-cors.md)):

```
   Same-origin policy blocks:  READING a cross-origin response
   Same-origin policy allows:  SENDING a cross-origin request
```

CSRF does not read anything. A transfer is a write.

Nor does CORS help. A CORS error is generated **in the victim's browser, after the server
has already processed the request**. If the money moved, it moved.

---

## Why `SameSite` mostly killed it

Since roughly 2020, browsers default cookies to `SameSite=Lax` when the attribute is absent
([E02](E02-cookie-attributes.md)).

`Lax` sends the cookie only on **top-level navigations using safe methods**. Which means:

| Attack vector | With `Lax` |
|---|---|
| Cross-site `POST` form ← **the classic attack** | ❌ **Blocked** |
| Cross-site `fetch`/XHR with credentials | ❌ Blocked |
| `<img src="...">` | ❌ Blocked |
| `<iframe>` | ❌ Blocked |
| A user clicking a link to your site | ✅ Allowed (correctly) |

**The canonical CSRF attack no longer works by default in modern browsers.** That is a real,
platform-level fix, and it is why this chapter is shorter than it would have been in 2018.

---

## Why you still need a defence

Five reasons, and the first two are the ones that matter.

### 1. `GET` requests that change state

`Lax` allows cross-site top-level `GET` navigations. So:

```html
<img src="https://app.example.com/account/delete">
<a href="https://app.example.com/subscribe?plan=premium">Click for a free gift</a>
```

If those endpoints act, `SameSite` does not save you. This is why
[A03](../track-a/A03-methods-status-codes-401-vs-403.md) insists that `GET` be safe: the
browser's default protection is **built on that promise**, and breaking it opts you out of a
defence you did not know you had.

### 2. `SameSite=None`

If your cookie must work in a third-party context — embedded widgets, iframe-based SSO
([G11](../track-g/G11-federated-sessions-single-logout.md)), payment frames — you set
`SameSite=None`, and you are back in 2018 with no default protection at all.

### 3. Same-site does not mean same-origin

`Lax` protects against *cross-site*, computed on the registrable domain
([A11](../track-a/A11-same-origin-and-cors.md)). `evil.example.com` is **same-site** with
`app.example.com`. A subdomain takeover, or a third-party page builder on a subdomain, gives
an attacker a same-site position — and `SameSite` does nothing.

### 4. Not every client is a current browser

Old browsers, embedded webviews, unusual HTTP clients. Defence in depth
([C04](../track-c/C04-threat-modeling.md)) means not relying on one control.

### 5. The two-minute Lax window

Chrome historically allowed cross-site `POST` for cookies **less than two minutes old**
without an explicit `SameSite`, to avoid breaking SSO flows. Set `SameSite` explicitly and
this does not apply to you — which is one more reason to set it rather than rely on the
default.

---

## The defences, in order

### 1. `SameSite=Lax` explicitly, plus safe `GET`s

Free, and it handles the majority.

```http
Set-Cookie: __Host-session=...; Path=/; Secure; HttpOnly; SameSite=Lax
```

**And make every `GET` genuinely safe.** No state changes, ever, on a safe method.

### 2. Check `Origin` / `Sec-Fetch-Site`

Cheap, stateless, and underused. The browser sets both and **a page cannot forge either**
([A04](../track-a/A04-headers.md)):

```python
ALLOWED_ORIGINS = {"https://app.example.com"}

@app.before_request
def csrf_origin_check():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return

    # Sec-Fetch-Site: browser-computed, unforgeable by script.
    site = request.headers.get("Sec-Fetch-Site")
    if site in ("same-origin", "same-site"):
        return
    if site == "cross-site":
        abort(403)

    # Fallback for clients that do not send Sec-Fetch-*.
    origin = request.headers.get("Origin")
    if origin is not None:
        if origin not in ALLOWED_ORIGINS:
            abort(403)
        return

    # No Origin and no Sec-Fetch-Site → not a browser (curl, a mobile app).
    # Those are not subject to CSRF; the credential is what protects them.
```

The reasoning in that last comment is worth internalising: **CSRF is a browser-only attack**,
because it depends on the browser's automatic credential attachment. A `curl` request has no
ambient authority to abuse. So the absence of browser headers is not suspicious in itself —
what matters is that a *browser* cannot be tricked.

### 3. CSRF tokens

The classic defence, and still correct where you need certainty.

```python
# Issue: bind the token to the session, so it is not transferable.
def csrf_token(session_id: bytes) -> str:
    return hmac.new(CSRF_KEY, session_id, hashlib.sha256).hexdigest()   # B13

# Verify:
def check_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    submitted = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    expected  = csrf_token(current_session_hash())
    if not hmac.compare_digest(submitted, expected):     # B16 — constant time
        abort(403)
```

```html
<form method="post" action="/transfer">
  <input type="hidden" name="csrf_token" value="{{ csrf_token }}">
  ...
</form>
```

Three properties that make a CSRF token work, and each is a real bug when missing:

| Property | Missing it means |
|---|---|
| **Unpredictable** | Guessable. Use HMAC or a CSPRNG ([B03](../track-b/B03-randomness.md)). |
| **Bound to the session** | An attacker uses *their own* valid token against your session. |
| **Compared in constant time** | A timing oracle recovers it ([B16](../track-b/B16-timing-attacks.md)). |

Deriving the token via HMAC over the session ID gives you all three with **no server-side
storage** — it is recomputable, so there is nothing to look up and nothing to expire.

### 4. Double-submit cookie

Stateless. Put the same random value in a cookie and in the request; compare them.

```
Cookie:  csrf=a3f9c2e1
Body:    csrf_token=a3f9c2e1
```

An attacker cannot read your cookie ([A11](../track-a/A11-same-origin-and-cors.md)), so they
cannot put the right value in the body.

**The flaw:** an attacker on a **same-site** subdomain *can* set a cookie on your domain
(cookie tossing — [E02](E02-cookie-attributes.md)) and then submit a matching body value.

**The fix:** the *signed* double-submit — the cookie contains
`value|HMAC(secret, value ‖ session_id)`, so a value the attacker planted will not verify.
Or simply use the `__Host-` prefix, which prevents subdomains writing the cookie at all.

### 5. Custom header for JSON APIs

```js
fetch("/api/transfer", {
  method: "POST",
  headers: {"Content-Type": "application/json", "X-Requested-With": "XMLHttpRequest"},
  body: JSON.stringify({to, amount}),
});
```

A cross-site request *cannot* set a custom header or a JSON `Content-Type` without a
successful CORS preflight ([A11](../track-a/A11-same-origin-and-cors.md)). An HTML form can
only send three content types, none of which is `application/json`.

**So a JSON-only API that rejects form-encoded bodies has meaningful CSRF resistance by
construction.** Verify the `Content-Type` server-side and reject
`application/x-www-form-urlencoded` and `multipart/form-data` on state-changing endpoints.

---

## Test your own

```html
<!-- Save as attack.html, open from file:// or a different origin.
     Point it at YOUR staging app while logged in. -->
<h1>You have won a prize</h1>

<!-- 1. Cross-site POST — SameSite=Lax should block this. -->
<form id="post" action="https://staging.example.com/api/profile" method="POST">
  <input name="email" value="attacker@evil.test">
</form>

<!-- 2. State-changing GET — SameSite does NOT block this. -->
<img src="https://staging.example.com/account/delete" style="display:none">

<!-- 3. JSON via fetch — needs CORS with credentials to even be sent. -->
<script>
  document.getElementById("post").submit();
  fetch("https://staging.example.com/api/transfer", {
    method: "POST", credentials: "include",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({to: "attacker", amount: 1}),
  }).catch(e => console.log("blocked:", e));
</script>
```

Then check the server: **did anything change?** The browser console will show CORS errors
regardless — those are irrelevant. The only question is whether the state changed.

---

## The recommendation

```
☐  SameSite=Lax explicitly on every cookie          E02
☐  __Host- prefix (blocks subdomain cookie tossing) E02
☐  Every GET is genuinely safe                      A03
☐  Reject cross-site on state-changing requests, via Sec-Fetch-Site / Origin
☐  CSRF tokens on HTML form posts (HMAC over the session ID — no storage)
☐  JSON APIs: require application/json, reject form encodings
☐  SameSite=Strict cookie required for sensitive actions   E02
☐  Never let a CSRF failure block LOGOUT             E14
```

Layers 1–3 are free. Layer 4 is one middleware. Layer 5 is what most frameworks already
give you.

---

## Terms defined in this chapter

`CSRF`, `CSRF token`, `double-submit cookie`

---

## What to remember

1. **CSRF is the attacker using your browser's ambient authority.** They never read the
   response and do not need to.
2. **The same-origin policy does not stop it** — it blocks reading, not sending.
3. **`SameSite=Lax` is the default and kills the classic attack.** Set it explicitly anyway.
4. **State-changing `GET`s opt you out of that protection.** The browser's defence is built
   on `GET` being safe.
5. **`SameSite=None` puts you back in 2018.** So does a same-site subdomain.
6. **`Sec-Fetch-Site` is unforgeable by script** and is the cheapest good check available.
7. CSRF tokens must be **unpredictable, session-bound, and constant-time compared.** HMAC
   over the session ID gives all three with no storage.
8. **A JSON-only API that rejects form encodings is CSRF-resistant by construction.**

---

## Sources

- [OWASP CSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [RFC 6265bis §5.5](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis) — SameSite
- [MDN: Sec-Fetch-Site](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site)
- [PortSwigger: CSRF](https://portswigger.net/web-security/csrf) — free labs

---

**Next:** [E16 — XSS is an auth vulnerability](E16-xss-is-an-auth-vulnerability.md)
