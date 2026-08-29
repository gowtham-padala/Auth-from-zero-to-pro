# A11 — Same-origin policy and CORS, explained without the panic

**Part A · How the web actually works** · *Builds on [A06](A06-cookies.md), [A07](A07-client-vs-server.md)*
---

## Why it matters

```
Access to fetch at 'https://api.example.com/documents' from origin
'https://app.example.com' has been blocked by CORS policy: No
'Access-Control-Allow-Origin' header is present on the requested resource.
```

The developer searches, finds a Stack Overflow answer, and pastes:

```js
app.use(cors({ origin: "*", credentials: true }));
```

The error disappears. Two things are now true. First, that configuration is *invalid* —
browsers reject `*` with credentials, so the credentialed case is still broken and will
resurface later, confusingly. Second, and worse: they have just spent an afternoon
attacking a security mechanism that was protecting their users, without ever finding out
what it does.

CORS is not a firewall. CORS does not stop anyone from calling your API. Almost everything
people believe about it is wrong in a way that produces both unnecessary panic and real
vulnerabilities.

---

## First: what an origin is

From [A01](A01-what-happens-when-you-type-a-url.md):

> **origin = (scheme, host, port)**

All three must match. No partial credit.

| URL A | URL B | Same origin? |
|---|---|---|
| `https://example.com/a` | `https://example.com/b` | ✅ path is irrelevant |
| `https://example.com` | `http://example.com` | ❌ scheme differs |
| `https://example.com` | `https://www.example.com` | ❌ host differs |
| `https://example.com` | `https://example.com:8443` | ❌ port differs |
| `https://a.example.com` | `https://b.example.com` | ❌ host differs |

Note the last row. Subdomains are **different origins**. But — and this is the source of
much confusion — they are the same *site*.

**Site** is a coarser boundary: roughly "the registrable domain," computed using the
[Public Suffix List](https://publicsuffix.org/) so that `foo.github.io` and
`bar.github.io` count as different sites despite sharing a suffix.

| Concept | Granularity | Used by |
|---|---|---|
| **origin** | scheme + host + port | same-origin policy, CORS, `postMessage`, WebAuthn RP ID |
| **site** | registrable domain (+ scheme) | `SameSite` cookies, `Sec-Fetch-Site` |

So `a.example.com` and `b.example.com` are **cross-origin** but **same-site**. A
`SameSite=Strict` cookie *is* sent between them; a `fetch()` between them *is* subject to
CORS. Both statements are true simultaneously, and holding them together is most of what
it takes to reason about this correctly.

---

## The same-origin policy

> **A script running on origin A cannot read data from origin B.**

That is the whole rule. It exists because your browser holds credentials for hundreds of
sites at once. Without it, any page you visit could read your email, your bank balance,
and your company's internal dashboards — using *your* cookies — and send the contents
anywhere.

The word doing the work is **read**.

### What is blocked

- Reading the response body of a cross-origin `fetch`/`XHR` (unless CORS permits it).
- Reading the DOM of a cross-origin iframe.
- Reading a cross-origin image's pixels from a canvas (it becomes "tainted").
- Reading `localStorage` of another origin.

### What is *not* blocked

This list is the point of the chapter:

- **Sending** a cross-origin request. Always allowed. Always was.
- `<img src="https://other.com/anything">` — sent, with cookies.
- `<form method="POST" action="https://other.com/transfer">` — sent, with cookies,
  submittable by script.
- `<script src="https://other.com/x.js">` — fetched *and executed*, in your origin.
- Navigating the top window anywhere.

> **The browser sends the request. It just refuses to show your script the answer.**

That single sentence resolves the two biggest misconceptions at once:

**Misconception 1: "CORS protects my API."** It does not. `curl` has no same-origin
policy. Neither does any server, script, or mobile app. The request arrives regardless; a
CORS error is generated *in the victim's browser, after the response has already been
produced*. Your API is protected by **authentication and authorization**, and by nothing
else. ([A07](A07-client-vs-server.md).)

**Misconception 2: "The same-origin policy stops CSRF."** It does not, and this is the
important one. CSRF does not need to *read* the response. Transferring money is a write.
The attacker's page submits a form to your bank, the browser attaches your cookies, the
transfer happens, the attacker's script is denied the response body — and does not care.
CSRF is stopped by `SameSite` and CSRF tokens ([E15](../track-e/E15-csrf.md)), not by the
same-origin policy.

---

## CORS: the opt-in relaxation

**CORS** — Cross-Origin Resource Sharing — is how a server says *"it is fine for that
origin's scripts to read my responses."*

It is a **relaxation** of the same-origin policy, not an addition to it. Every CORS header
you add makes the browser *less* restrictive. That framing prevents the whole category of
mistakes where people treat CORS configuration as hardening.

### Simple requests

Some requests are sent immediately, no preflight, because a plain HTML form could have
made them anyway. Roughly: `GET`, `HEAD`, or `POST`, with only a short list of allowed
headers, and a `Content-Type` of `application/x-www-form-urlencoded`, `multipart/form-data`,
or `text/plain`.

```http
GET /documents HTTP/1.1
Origin: https://app.example.com
```

```http
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://app.example.com
```

If that header is absent or does not match, the browser discards the response and logs the
error. **The server still did the work.** If that `GET` deleted something, it is deleted.

Note that `Content-Type: application/json` is *not* on the simple list. That is why almost
every JSON API triggers a preflight, and why "just use JSON" is a mild CSRF mitigation on
its own.

### Preflight

For anything else, the browser asks permission first:

```http
OPTIONS /documents HTTP/1.1
Origin: https://app.example.com
Access-Control-Request-Method: DELETE
Access-Control-Request-Headers: authorization, content-type
```

```http
HTTP/1.1 204 No Content
Access-Control-Allow-Origin: https://app.example.com
Access-Control-Allow-Methods: GET, POST, DELETE
Access-Control-Allow-Headers: authorization, content-type
Access-Control-Max-Age: 86400
```

Only if the preflight approves does the real request go out. `Access-Control-Max-Age`
caches the approval, which is the fix for "every API call is doubled."

### Credentialed requests

By default `fetch` sends **no cookies** cross-origin. To send them:

```js
fetch("https://api.example.com/me", { credentials: "include" })
```

Now the server must be stricter, and the browser enforces it:

```http
Access-Control-Allow-Origin: https://app.example.com   ← an exact origin. NEVER "*"
Access-Control-Allow-Credentials: true
```

**`Access-Control-Allow-Origin: *` with `Allow-Credentials: true` is rejected by every
browser.** This is deliberate: the combination would mean "any website may read this
user's authenticated data," which is precisely the catastrophe the same-origin policy
exists to prevent.

So the very first thing most people paste is invalid, which is why their credentialed
requests keep failing after they "fixed CORS."

---

## The dangerous configuration

Here is the pattern that turns a CORS misconfiguration into a real breach:

```js
// NEVER DO THIS
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", req.headers.origin);   // reflect anything
  res.header("Access-Control-Allow-Credentials", "true");
  next();
});
```

Reflecting the `Origin` header means *every origin is allowed*. Combined with credentials,
any website your logged-in user visits can now read their data from your API and exfiltrate
it. You have manually rebuilt the world the same-origin policy exists to prevent.

Related bugs in the same family:

| Bug | Why it fails |
|---|---|
| `origin.endsWith("example.com")` | `evil-example.com` and `notexample.com` pass |
| `origin.includes("example.com")` | `https://evil.com/?x=example.com` passes |
| Regex `/example\.com/` | Unanchored; matches anywhere in the string |
| Allowing `null` | `null` is the origin of sandboxed iframes and `file://` — trivially obtainable |
| Trusting all subdomains | One subdomain takeover reads your whole API |

**Correct approach:** a hardcoded allowlist, exact string comparison, and reflect only on
an exact match.

```js
const ALLOWED = new Set([
  "https://app.example.com",
  "https://admin.example.com",
]);

app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && ALLOWED.has(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Access-Control-Allow-Credentials", "true");
    res.header("Vary", "Origin");     // ← or a CDN caches one origin's answer for all
  }
  next();
});
```

That `Vary: Origin` line is not optional. Without it, a shared cache can serve the
`Access-Control-Allow-Origin` header computed for one origin to a request from another —
turning a correct configuration into a reflecting one at the CDN layer.

---

## The decision table

| Situation | What to do |
|---|---|
| Frontend and API on the **same origin** | Nothing. No CORS involved at all. |
| Frontend and API on **different subdomains** | Exact-origin allowlist + `credentials: true` + `Vary: Origin`. Cookie with `Domain=example.com`, or use a BFF. |
| **Public**, unauthenticated API | `Access-Control-Allow-Origin: *`, no credentials. Correct and safe. |
| **Mobile app** calling your API | Irrelevant — no browser, no CORS. |
| Server-to-server | Irrelevant. |
| You want to "turn CORS off" | You cannot. It is a browser behaviour. You can only widen it, at your users' expense. |

**The best CORS configuration is no CORS configuration.** Serve your frontend and your API
from the same origin — a path prefix like `/api`, or a reverse proxy. You get:
same-origin simplicity, cookies that just work, `SameSite=Strict` as a real option, no
preflight latency, and no misconfiguration surface. This is a large part of why the
backend-for-frontend pattern is recommended in
[F17](../track-f/F17-oauth-for-spas-and-bff.md).

---

## Related mechanisms you will meet

- **`Sec-Fetch-Site`** — the browser tells you `same-origin` / `same-site` / `cross-site`,
  unforgeably ([A04](A04-headers.md)). A cheap, powerful CSRF check.
- **`postMessage`** — the sanctioned way for two origins to talk. **Always check
  `event.origin`.** Omitting that check is a standard finding.
- **CORP / COOP / COEP** — newer headers isolating your page from cross-origin resources,
  required for `SharedArrayBuffer` and useful against Spectre-class attacks.
- **CSP `connect-src`** — restricts where *your* page may send requests. The outbound
  counterpart to CORS's inbound ([E16](../track-e/E16-xss-is-an-auth-vulnerability.md)).

---

## Terms defined in this chapter

`origin`, `same-origin policy`, `CORS`, `preflight`, `credentialed request`, `site`

---

## What to remember

1. **origin = scheme + host + port.** **site** = registrable domain. CORS uses origin;
   `SameSite` uses site. They are different, and both matter.
2. The same-origin policy blocks **reading**, never **sending**. Your API is called
   regardless.
3. **CORS is not a security control for your API.** It is a relaxation of a browser
   restriction. Auth protects your API.
4. The same-origin policy does not stop CSRF, because CSRF does not need to read the
   response.
5. Never reflect `Origin`. Never `*` with credentials (browsers reject it anyway). Always
   `Vary: Origin`.
6. Same-origin deployment beats any CORS configuration. Aim for zero CORS.

---

## Sources

- [Fetch Standard — CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol) (the normative source)
- [MDN: Cross-Origin Resource Sharing](https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS)
- [PortSwigger: CORS misconfiguration](https://portswigger.net/web-security/cors)
- [The Public Suffix List](https://publicsuffix.org/)

---

**Track A complete.** You now know what an HTTP request contains, who can read it, who can
change it, where state comes from, and where the trust boundary sits. That is the
substrate. Track B builds the tools.

**Next:** [B01 — Bits, bytes, and how text becomes numbers](../track-b/B01-bits-bytes-text-as-numbers.md)
