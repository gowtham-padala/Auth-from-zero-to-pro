# A09 — Redirects, and why the address bar is a security boundary

**Part A · How the web actually works** · *Builds on [A03](A03-methods-status-codes-401-vs-403.md)*
---

## Why it matters

You receive this link. Read it carefully before scrolling.

```
https://app.example.com/login?next=https://app.exarnple.com/login
```

It is genuinely `app.example.com`. Real domain, real TLS certificate, real login page. You
log in. Correct password, correct 2FA code. It works.

Then your app redirects you — as it always does after login — to the `next` parameter.

Which is `exarnple.com`. **r** and **n**, not **m**. A different domain entirely, showing
a pixel-perfect copy of your app, asking you to log in "again" because the session
"expired."

You just typed your credentials into an attacker's site, immediately after a *successful*
login on the real one. Your muscle memory did the rest. Nothing was compromised
cryptographically. The app has an **open redirect**, and that was enough.

---

## What a redirect is

A response that says "not here, go there."

```http
HTTP/1.1 302 Found
Location: /dashboard
```

The browser reads `Location`, makes a new request to it, and — the part that matters —
**updates the address bar**.

| Code | Name | Method preserved? | Use for |
|---|---|---|---|
| `301` | Moved Permanently | No (→ GET) | Permanent URL change. Cached hard. |
| `302` | Found | In practice, no | Legacy general-purpose. Ambiguous. |
| `303` | See Other | **No, explicitly → GET** | **After a POST.** The correct choice. |
| `307` | Temporary Redirect | **Yes, body too** | When you must preserve method |
| `308` | Permanent Redirect | Yes | Permanent, method-preserving |

### The one that bites

`307` and `308` **re-send the request body**. Redirect a login `POST` with `307` and the
browser re-POSTs the username and password to the new location. If an attacker influences
that location, you have just forwarded credentials to them.

After a form submission, use **`303`**. The POST/Redirect/GET pattern
([A02](A02-reading-http-in-dev-tools.md)) depends on the method *changing* to GET.

Also note: `301` is cached aggressively and persistently. A `301` to a URL you later
regret is very hard to take back — browsers will keep following the cached one for a long
time without asking you.

---

## Why auth uses redirects constantly

Because they are the only way to move a user between two web applications while keeping
them in one browser session.

**Login:** unauthenticated request → redirect to `/login` → POST → redirect to the
original destination.

**OAuth:** the entire protocol is a redirect dance
([F03](../track-f/F03-authorization-code-flow.md)):

```
Your app                Browser                 Authorization server
   │                       │                            │
   │  302 → /authorize ────>│                           │
   │                        │  GET /authorize ─────────>│
   │                        │                           │ user logs in,
   │                        │                           │ consents
   │                        │<── 302 → your redirect_uri│  ?code=xyz
   │<── GET /callback?code=xyz                          │
   │                        │                           │
   │  ──────── POST /token (back channel, direct) ─────>│
```

Every arrow in that diagram is a redirect except the last one, and the last one is
different *precisely because* redirects go through the browser and the browser cannot be
trusted with a secret.

**SSO:** same shape, one more hop
([G01](../track-g/G01-sign-in-with-google.md)).

If you understand redirects, the shape of Track F is already familiar. If you do not,
OAuth reads as an incomprehensible sequence of hops.

---

## The address bar is a security boundary

This is the sentence to carry out of the chapter.

The address bar is **the only part of the browser window a website cannot forge**.
Everything else — the padlock drawing, the page chrome, a fake browser window rendered in
HTML, an entire simulated desktop — can be counterfeited by a sufficiently motivated page.
The URL displayed by the browser cannot.

Which is why the correct answer to "should I type my password here?" is, always and only:
**look at the address bar.**

Three consequences that shape real protocol design:

### 1. It is why OAuth redirects instead of embedding

The user must type their password **on the identity provider's own domain**, with that
domain visible. That is the only reason to accept an OAuth login at all. An app that shows
you a Google-branded username/password form *inside its own page* is doing the 2008 thing
with better styling, and you should never type into it.

This is also why embedding an IdP login page in an iframe or a webview is discouraged —
it destroys the user's ability to check. It is why mobile OAuth uses the system browser
rather than an in-app webview ([F18](../track-f/F18-oauth-for-mobile.md)), and why native
apps use `ASWebAuthenticationSession` / Custom Tabs, which show the URL.

### 2. It is why WebAuthn is phishing-resistant

A passkey signature is cryptographically bound to the **origin** the browser is actually
on ([D14](../track-d/D14-webauthn-and-passkeys-concepts.md)). The browser supplies that
origin from the real address bar; the page cannot influence it.

So a user on `exarnple.com` *cannot* produce a valid signature for `example.com`, no
matter how convincing the page or how cooperative the user. The check that a human fails
at is performed by the browser, mechanically, every time.

That is the whole reason passkeys beat TOTP. A TOTP code
([D12](../track-d/D12-build-totp.md)) is six digits the user reads out; a phishing site
relays them in real time and is inside. There is no relay against WebAuthn, because the
signature simply will not verify.

### 3. It is why `redirect_uri` must be exactly matched

The whole OAuth flow ends with the authorization server sending a browser — carrying an
authorization code — to a URL supplied *in the request*. If the server accepts an
attacker's URL there, the attacker receives the code and the flow is compromised.

This is `redirect_uri` smuggling, and it is
[F20](../track-f/F20-attack-your-own-oauth.md)'s opening act.

---

## Open redirects

An endpoint that will send a user to any URL supplied as a parameter:

```python
@app.get("/login")
def login():
    return redirect(request.args["next"])     # ← anything at all
```

By itself it looks harmless — no data leaks, no privilege gained. It is rated low severity
by scanners and ignored by teams. It is also a component in a large fraction of real
attack chains:

- **Phishing with a legitimate domain.** The link is genuinely your domain. Email
  filters, security-awareness training, and the user's own judgement all pass it.
- **Token theft via the `Referer` header.** The attacker's page learns the URL you came
  from, including anything in its query string.
- **OAuth code exfiltration.** If `https://app.example.com/redirect?to=...` is registered
  as a valid `redirect_uri`, an attacker chains it: the authorization server dutifully
  sends the code to a registered URI, which dutifully forwards it — and the code lands on
  the attacker's server. The AS did nothing wrong. Your open redirect did.
  ([F20](../track-f/F20-attack-your-own-oauth.md).)
- **Bypassing SSRF and referrer allowlists.** Any allowlist keyed on domain is defeated by
  a redirector on an allowed domain.

### Fixing it, in order of preference

**1. Do not redirect to user-supplied URLs.** Store the destination server-side, in the
session, keyed by an opaque token. Best answer where possible.

**2. Allow only relative paths.** Reject anything with a scheme or authority:

```python
from urllib.parse import urlparse

def safe_next(raw):
    if not raw:
        return "/"
    # Reject absolute URLs, protocol-relative URLs, and backslash tricks
    if raw.startswith(("//", "/\\", "\\")) or urlparse(raw).netloc or urlparse(raw).scheme:
        return "/"
    if not raw.startswith("/"):
        return "/"
    return raw
```

**3. Allowlist exact URLs**, if you truly need cross-host redirects. Compare against a
fixed list. Never a substring match.

### The bypasses your validation will meet

Every one of these has defeated a real filter:

| Input | Why it slips through |
|---|---|
| `//evil.com` | Protocol-relative. A "starts with `/`" check passes it. |
| `/\evil.com` | Some parsers treat `\` as `/`. |
| `https://example.com@evil.com` | Everything before `@` is userinfo. The host is `evil.com`. |
| `https://example.com.evil.com` | `startswith("https://example.com")` passes. |
| `https://evil.com/?x=example.com` | A `contains("example.com")` check passes. |
| `https://exam%70le.com` | Percent-encoding, decoded after your check. |
| `javascript:alert(1)` | Not http at all. Becomes XSS if used as an `href`. |

**Never validate a URL with string operations.** Parse it, then compare structured
components — scheme, host, port — against an allowlist. This applies identically to
`redirect_uri` validation in [F14](../track-f/F14-build-an-authorization-server.md).

---

## Redirects and the things that ride along

Two more behaviours to hold on to:

**Headers you set are not automatically re-sent.** An `Authorization` header attached by
your code does not follow a redirect in most HTTP clients — and where it does, that is a
credential-leak risk if the redirect crosses hosts. Cookies *do* follow, subject to their
own rules.

**Redirect chains leak through `Referer`.** Each hop may tell the next where it came from.
`Referrer-Policy: strict-origin-when-cross-origin` limits this to the origin. If your URLs
contain secrets, no policy saves you — [A04](A04-headers.md).

---

## Terms defined in this chapter

`redirect`, `Location header`, `address bar`, `open redirect`

---

## What to remember

1. A redirect updates the address bar. That is what makes it both useful and dangerous.
2. Use `303` after a POST. `307`/`308` re-send the body, including credentials.
3. **The address bar is the only unforgeable part of the browser.** OAuth, SSO, and
   passkeys are all built on that single fact.
4. WebAuthn is phishing-resistant because the *browser* checks the origin, not the human.
5. Open redirects are rated low and used constantly. They turn your domain into a phishing
   launchpad and can exfiltrate OAuth codes.
6. **Parse URLs; never validate them with string matching.** Every string check on this
   page's table has been bypassed in production.

---

## Sources

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) §15.4 (redirection)
- [OWASP: Unvalidated Redirects and Forwards Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html)
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://www.rfc-editor.org/rfc/rfc9700) §4.1 (redirect URI validation)

---

**Next:** [A10 — Where secrets live: env vars, and never in your frontend bundle](A10-where-secrets-live.md)
