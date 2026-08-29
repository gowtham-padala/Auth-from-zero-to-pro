# A04 — Headers: the metadata every request carries

**Part A · How the web actually works** · *Builds on [A02](A02-reading-http-in-dev-tools.md)*
---

## Why it matters

An internal admin service checks whether a request came from the office network:

```python
if request.headers.get("X-Forwarded-For", "").startswith("10."):
    grant_admin_access()
```

An attacker sends:

```http
GET /admin/users HTTP/1.1
X-Forwarded-For: 10.0.0.1
```

They are now an administrator.

The bug is not the string comparison. The bug is believing a header. `X-Forwarded-For` is
a header your *proxy* is supposed to set — and headers are just text in a request, and the
request comes from the attacker. Unless something you control has *overwritten* it, it
means nothing.

This chapter is about which headers you may believe and which you may not.

---

## What a header is

A name, a colon, a value, one per line, between the request line and the body:

```http
POST /api/documents HTTP/1.1
Host: app.example.com
Content-Type: application/json
Content-Length: 47
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImsxIn0...
Cookie: session=8f14e45fceea167a5a36dedd4bea2543
Origin: https://app.example.com

{"title": "Q3 plan", "body": "..."}
```

Names are case-insensitive. Values are text. Order is not significant. In HTTP/2 and
HTTP/3 they are compressed binary rather than literal text, but the model is identical.

---

## The trust question

Every header falls into exactly one of three buckets, and knowing which is most of the
skill.

### Bucket 1 — Set by the attacker. Believe nothing.

`User-Agent`, `Referer`, `Accept-Language`, `X-Forwarded-For`, `X-Real-IP`,
`X-Requested-With`, and every custom header you invent.

A browser sets these honestly. `curl` sets them to whatever you type. Since your server
cannot tell the two apart ([A02](A02-reading-http-in-dev-tools.md), exercise 4), *none of
them is evidence of anything*.

Use them for analytics, for debugging, for shaping a response. Never for a security
decision.

> **The bright-line rule:** if a header being wrong lets someone in, you have a
> vulnerability. Rewrite the check so that it depends on a credential instead.

### Bucket 2 — Set by the browser, and the browser will not let a script lie.

This is a genuinely small list, and it is precious. There is a
[forbidden header list](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name)
that scripts running in a page cannot set or override:

| Header | Set by browser to | Why it is trustworthy |
|---|---|---|
| `Origin` | The origin that initiated the request | A page cannot forge another site's origin |
| `Host` | The target host | Determined by the connection |
| `Cookie` | The cookies matching this request | Managed by the cookie jar, not by script |
| `Referer` | The originating URL (subject to policy) | Set by the browser; policy-controlled |
| `Sec-Fetch-Site` | `same-origin`, `same-site`, `cross-site`, `none` | Browser-computed, unforgeable by script |
| `Sec-Fetch-Mode` | `navigate`, `cors`, `no-cors`, … | Same |
| `Sec-Fetch-Dest` | `document`, `image`, `script`, … | Same |
| `Content-Length` | The actual body length | Computed |

The critical qualifier, which people miss: **this guarantee only holds against a browser.**
A `curl` request sets `Origin` to anything. So these headers are useful for *defending a
user's browser against a malicious website* — which is exactly the CSRF threat model
([E15](../track-e/E15-csrf.md)) — and useless for *defending your server against a
direct attacker*, who is not using a browser at all.

Get that distinction right and `Origin`-checking makes sense. Get it wrong and you either
dismiss a real defence or over-rely on it.

The `Sec-Fetch-*` family is the most underused security feature in modern HTTP. A single
check — reject state-changing requests where `Sec-Fetch-Site: cross-site` — is a
meaningful CSRF defence with no tokens and no state.

### Bucket 3 — Set by *your* infrastructure. Trustworthy only if you overwrite.

`X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host`, and anything your gateway,
mesh, or authenticating proxy injects.

These are the dangerous ones, because they *look* like bucket 2 and behave like bucket 1.
`X-Forwarded-For` is an ordinary header. If a client sends one and your proxy *appends*
rather than *replaces*, the attacker's value is in the list — and your "trusted" parse
picks it up.

Three rules that make this safe:

1. **The edge proxy must overwrite, not append,** for headers you will trust.
2. **Trust only the hop your proxy added.** With appending proxies, count from the right,
   using a known trusted-proxy count. Never take the leftmost value.
3. **Strip unknown `X-Forwarded-*` and any internal auth headers at the edge.** If your
   internal services trust `X-User-Id`, and your edge does not delete an inbound
   `X-User-Id`, you have an authentication bypass one header long. This exact bug has
   shipped in production at large companies more than once, and it is the reason
   [H12](../track-h/H12-authz-in-microservices.md) argues against unsigned identity
   headers between services.

---

## The headers that carry credentials

### `Authorization`

```http
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9...
Authorization: Basic dXNlcjpwYXNzd29yZA==
Authorization: DPoP eyJhbGciOiJFUzI1NiJ9...
```

A scheme, a space, and a value. Three notes:

- **`Basic` is base64, not encryption.** `dXNlcjpwYXNzd29yZA==` decodes to
  `user:password` with zero effort. It is safe only inside TLS, and even then it means
  the raw password crosses the wire on every request.
  ([B02](../track-b/B02-encoding-is-not-encryption.md).)
- **`Bearer` means possession is sufficient.** Anyone holding the string can use it. No
  proof of anything else. That is the whole security model, and its whole weakness
  ([F16](../track-f/F16-sender-constrained-tokens.md) is the fix).
- **`Authorization` is not sent automatically.** Unlike cookies, your code attaches it
  explicitly. This is the *entire reason* token-in-header schemes are immune to CSRF: a
  malicious site can make your browser send a request, but it cannot make your browser
  attach a header it does not have.

### `Cookie`

Sent automatically, by the browser, based on rules the server set earlier. The automation
is the feature and the vulnerability. [A06](A06-cookies.md) and
[E02](../track-e/E02-cookie-attributes.md).

### `WWW-Authenticate`

The response header that accompanies `401` and says how to authenticate. Covered in
[A03](A03-methods-status-codes-401-vs-403.md); it becomes structurally important in
[J08](../track-j/J08-mcp-and-oauth-21.md).

---

## Response headers that are security controls

These are not metadata. They are enforcement, delivered as text.

| Header | What it does |
|---|---|
| `Strict-Transport-Security` | Browser refuses plain HTTP to this host for `max-age` seconds. Kills SSL-stripping. |
| `Content-Security-Policy` | Restricts which scripts may run. Your last line of defence against XSS ([E16](../track-e/E16-xss-is-an-auth-vulnerability.md)). |
| `X-Content-Type-Options: nosniff` | Stops the browser guessing a content type and executing your JSON as script. |
| `X-Frame-Options` / `frame-ancestors` | Stops your page being framed. Anti-clickjacking — which matters for consent screens ([F13](../track-f/F13-consent-screens.md)). |
| `Referrer-Policy` | Controls how much URL leaks to third parties. Set it to `strict-origin-when-cross-origin` at minimum. |
| `Cache-Control: no-store` | Keeps authenticated responses out of caches and disk. Mandatory on token responses. |
| `Set-Cookie` | Creates state in the browser. [A06](A06-cookies.md). |
| `Access-Control-Allow-*` | Relaxes the same-origin policy. [A11](A11-same-origin-and-cors.md). |

`Cache-Control: no-store` deserves a highlight. OAuth's token endpoint response is
*required* to carry it. Without it, an intermediate cache or the browser's disk cache can
retain an access token, and a shared machine becomes a credential leak. The same applies
to any page showing a recovery code or a session listing.

---

## Where headers leak

Four places auth data escapes through headers, all of which have caused real incidents:

1. **`Referer` to third parties.** If your reset link is
   `/reset?token=abc` and that page loads an analytics script, the token goes to the
   analytics vendor. Fix: `Referrer-Policy`, and do not put secrets in URLs.
2. **Logs.** Access logs commonly record request headers. `Authorization` and `Cookie`
   end up in your log aggregator, which now stores live credentials in plaintext and
   searchable. ([I08](../track-i/I08-observability.md) makes this a rule.)
3. **Error trackers.** Client-side error reporting frequently serialises request headers
   into the report. Same problem, different vendor.
4. **`Server` and `X-Powered-By`.** Not credentials, but free reconnaissance. Remove
   them.

---

## Terms defined in this chapter

`header`, `Authorization header`, `Content-Type`

---

## What to remember

1. Headers are text in a request. Text in a request comes from whoever sent the request.
2. The browser guarantees `Origin`, `Cookie`, and `Sec-Fetch-*` — but *only against a
   browser*. They defend users from malicious sites, not servers from direct attackers.
3. `X-Forwarded-*` and internal identity headers must be **stripped and rewritten at your
   edge**, or they are an authentication bypass.
4. `Authorization` is manual; `Cookie` is automatic. That single difference decides which
   of them is vulnerable to CSRF.
5. `Cache-Control: no-store` on every response that contains a credential. Not optional.

---

## Sources

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) §6.3, §11 (authentication)
- [MDN: Forbidden header names](https://developer.mozilla.org/en-US/docs/Glossary/Forbidden_header_name)
- [MDN: Sec-Fetch-Site](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Sec-Fetch-Site)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

---

**Next:** [A05 — What "stateless" means, and why HTTP forgets who you are](A05-stateless.md)
