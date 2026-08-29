# A06 — Cookies: what they are, where they live, who sends them

**Part A · How the web actually works** · *Builds on [A05](A05-stateless.md)*
---

## What a cookie is

A cookie is a **name, a value, and a set of rules about when to send it back**. It is
stored by the browser, keyed by domain, and attached automatically to matching requests.

The server creates one with a response header:

```http
HTTP/1.1 200 OK
Set-Cookie: session=8f14e45fceea167a5a36dedd4bea2543; Path=/; HttpOnly; Secure; SameSite=Lax
```

The browser sends it back on every qualifying request:

```http
GET /dashboard HTTP/1.1
Cookie: session=8f14e45fceea167a5a36dedd4bea2543
```

Note the asymmetry, which trips people up constantly:

- **`Set-Cookie`** goes server → browser. One cookie per header. Carries all the
  attributes.
- **`Cookie`** goes browser → server. *All* matching cookies in one header,
  semicolon-separated, **name and value only**. The attributes are gone.

> Your server cannot see whether a cookie arrived with `HttpOnly` or `Secure` set. It sees
> `session=8f14e45f` and nothing more. The attributes are instructions to the browser, not
> data you get back. There is no way to "check" them on receipt — you can only set them
> correctly on send.

---

## Where cookies live

In a store the browser maintains, usually a SQLite file on disk. Not encrypted in any
meaningful sense — modern browsers encrypt them with an OS-level key, which stops *other
users* of the machine but not the user themselves and not malware running as them.

This means:

- **The user can read every cookie you set.** Dev tools shows them in a table.
- **The user can edit them.** In the same table, by double-clicking.
- **Anything in a cookie is attacker-controlled input on the way back.** Signing exists
  precisely because of this ([E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md)).

The cookie store is scoped by *domain*, not by origin, which is the source of a
surprising amount of security subtlety. `http://example.com` and `https://example.com`
share a cookie jar — the same-origin policy does not apply here in the way you would
expect. That is why `Secure` exists as a separate flag, and why cookie security is its own
topic rather than a corollary of origin security. Full treatment:
[E02](../track-e/E02-cookie-attributes.md).

---

## The attributes

Every one of these is a rule about *when the browser will send this cookie*, or *who can
read it*. This chapter introduces them; [E02](../track-e/E02-cookie-attributes.md) turns
them into a policy.

### `Domain` — which hosts get it

```
Set-Cookie: a=1                        → sent to app.example.com only (host-only)
Set-Cookie: a=1; Domain=example.com    → sent to example.com AND all subdomains
```

Counter-intuitively, **omitting `Domain` is the restrictive option**. With `Domain` set,
the cookie broadens to every subdomain — including `blog.example.com`, including
`user-content.example.com`, including any subdomain an attacker manages to take over.

Subdomain takeover plus a `Domain`-scoped session cookie equals full account compromise.
Omit `Domain` unless you genuinely need cross-subdomain sharing.

### `Path` — which URLs get it

```
Set-Cookie: a=1; Path=/admin    → sent to /admin and below only
```

Weak as a security control — `Path` is not a security boundary, because any page on the
origin can read another path's cookies via script and iframes. Use it for hygiene, never
for isolation.

### `Expires` / `Max-Age` — how long it lives

```
Set-Cookie: a=1                         → session cookie: gone when the browser closes
Set-Cookie: a=1; Max-Age=2592000        → persistent: 30 days
```

"Gone when the browser closes" is less reliable than it sounds — session restore features
routinely bring them back. Never rely on it for security. The server-side session expiry
is the real one ([E04](../track-e/E04-session-ids.md)).

### `Secure` — HTTPS only

Never sent over plain HTTP. **Always set this.** A classic bug is this attribute meeting an HTTP dev environment: the cookie is
silently dropped over plain `http://`, so login fails only in local development.

(`localhost` is treated as a secure context by modern browsers, so `Secure` cookies do
work on `http://localhost` — but not on `http://192.168.1.5` or `http://staging.internal`.
That is usually where the surprise happens.)

### `HttpOnly` — invisible to JavaScript

```js
document.cookie   // → "theme=dark"     the session cookie is simply not there
```

The cookie is still sent on every request. It just cannot be *read* by script. This turns
a successful XSS from "the attacker exfiltrates your session and uses it forever from
their own machine" into "the attacker can act as you while you are on the page." Still
bad — much less bad. ([E16](../track-e/E16-xss-is-an-auth-vulnerability.md).)

### `SameSite` — cross-site behaviour

The most consequential attribute of the last decade.

| Value | Sent on cross-site requests? |
|---|---|
| `Strict` | Never. Even following a link from another site. |
| `Lax` | Only on top-level `GET` navigations. **Default in modern browsers.** |
| `None` | Always. **Requires `Secure`.** |

`Lax` being the default is what "mostly killed CSRF" ([E15](../track-e/E15-csrf.md)). It is
also why `SameSite=None; Secure` is mandatory for cookies used in an embedded/third-party
context — and why a lot of OAuth and SSO flows broke when the default changed. See
[G11](../track-g/G11-federated-sessions-single-logout.md).

Notice how `Lax` depends on `GET` being safe ([A03](A03-methods-status-codes-401-vs-403.md)).
A state-changing `GET` endpoint opts you out of the browser's default CSRF protection.

### `__Host-` and `__Secure-` prefixes

Not attributes — *name prefixes* the browser enforces:

```
Set-Cookie: __Host-session=abc; Path=/; Secure          ✅
Set-Cookie: __Host-session=abc; Domain=example.com      ❌ rejected
```

A cookie named `__Host-*` is only accepted if it is `Secure`, has `Path=/`, and has **no
`Domain`**. That combination makes it impossible for a subdomain to set or overwrite it —
which closes an entire class of attack where `evil.example.com` writes a session cookie
that `app.example.com` then trusts.

**This is the strongest cookie binding available, it costs one prefix, and almost nobody
uses it.** Use it.

---

## Build: watch the whole lifecycle

Minimal server, no framework magic. (Node's standard library; the shape is identical in
any language.)

```js
// server.js — run with: node server.js
const http = require("http");
const crypto = require("crypto");

const sessions = new Map();   // sessionId -> { user, createdAt }

function parseCookies(header = "") {
  return Object.fromEntries(
    header.split(";").map(c => c.trim().split("=").map(decodeURIComponent))
          .filter(p => p.length === 2)
  );
}

http.createServer((req, res) => {
  const cookies = parseCookies(req.headers.cookie);
  const session = sessions.get(cookies.session);

  if (req.url === "/login") {
    // 32 bytes from a CSPRNG. Why this and not Math.random(): see B03.
    const id = crypto.randomBytes(32).toString("base64url");
    sessions.set(id, { user: "alice", createdAt: Date.now() });

    res.writeHead(302, {
      "Set-Cookie": `__Host-session=${id}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600`,
      "Location": "/",
    });
    return res.end();
  }

  if (req.url === "/logout") {
    sessions.delete(cookies.session);          // ← the state that actually matters
    res.writeHead(302, {
      "Set-Cookie": "__Host-session=; Path=/; HttpOnly; Secure; Max-Age=0",
      "Location": "/",
    });
    return res.end();
  }

  res.writeHead(200, { "Content-Type": "text/html" });
  res.end(session
    ? `<p>Hello ${session.user}. <a href="/logout">Log out</a></p>`
    : `<p>Not logged in. <a href="/login">Log in</a></p>`);
}).listen(3000);
```

Four things to notice, each of which is a chapter later:

1. **Logout deletes the server record, not just the cookie.** Clearing the cookie alone
   leaves a working session ID that anyone who copied it can still use. This distinction
   is the whole of [E14](../track-e/E14-why-logout-is-hard.md).
2. **`Max-Age=0` with the same name, path, and domain** is how you delete a cookie. Any
   mismatch and you have created a *second* cookie instead of removing the first. This is
   a common and confusing bug.
3. **`crypto.randomBytes`, never `Math.random()`.** [B03](../track-b/B03-randomness.md)
   demonstrates what happens if you get this wrong: predictable session IDs, and anyone
   can be anyone.
4. **The cookie value is meaningless.** It is a pointer into `sessions`. That is the
   reference model from [A05](A05-stateless.md).

Run it, open dev tools, and watch the `Set-Cookie` appear, the storage row appear, and the
`Cookie` header appear on the next request. Then edit the cookie value in dev tools and
reload — you are logged out, because the map has no such key. Now you have seen the entire
mechanism.

---

## Cookies are not the same as the same-origin policy

Worth stating explicitly, because the mismatch causes real bugs:

| | Scoped by |
|---|---|
| Same-origin policy | **origin** = scheme + host + port |
| Cookies | **domain** (+ path), ignoring scheme and port |

So: `http://example.com:8080` and `https://example.com` are different origins that share
one cookie jar. A cookie set by a page on port 3000 is sent to port 8080. `Secure` is the
only attribute that reintroduces a scheme distinction, and there is no port isolation at
all.

This mismatch is old, unfixable, and the reason `__Host-` was invented. Details in
[A11](A11-same-origin-and-cors.md).

---

## Terms defined in this chapter

`cookie`, `Set-Cookie`, `Cookie header`, `cookie attribute`, `Domain attribute`,
`Path attribute`, `session cookie`

---

## What to remember

1. **A rejected cookie is silent.** Always verify in the browser's storage panel.
2. `Set-Cookie` carries attributes; the returning `Cookie` header does not. You cannot
   check attributes server-side — only set them correctly.
3. **Omitting `Domain` is the restrictive choice.** Setting it opens the cookie to every
   subdomain.
4. `HttpOnly`, `Secure`, `SameSite=Lax`, and the `__Host-` prefix, by default, always.
5. Logging out means deleting **server-side state**. Clearing the cookie is cosmetic.
6. Cookies are scoped by domain, not origin. That mismatch is a permanent sharp edge.

---

## Sources

- [RFC 6265bis — HTTP State Management Mechanism](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis) (the current, authoritative draft)
- [MDN: Using HTTP cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)

---

**Next:** [A07 — Client vs server: which of your code can an attacker read?](A07-client-vs-server.md)
