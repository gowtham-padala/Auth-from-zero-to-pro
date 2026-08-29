# A01 — What happens when you type a URL and press enter

**Part A · How the web actually works**
---

## The one-sentence version

You type a name, your machine turns it into a number, opens a connection to that number,
wraps the connection in encryption, sends a small block of text asking for something, and
gets a bigger block of text back.

Now the same sentence, slowly.

---

## Step 1 — The URL is parsed

A **URL** is not a string. It is a structured record that happens to be written as a
string. Here is one with every part populated:

```
https://app.example.com:443/docs/42?share=true#comments
└─┬─┘   └───────┬───────┘└┬┘└──┬───┘└────┬────┘└───┬───┘
scheme        host      port  path     query   fragment
```

| Part | What it does | Sent to the server? |
|---|---|---|
| **scheme** | Which protocol to speak. `https` means "HTTP inside TLS". | Not literally, but it determines everything |
| **host** | The name of the machine. | Yes, in the `Host` header |
| **port** | Which program on that machine. Defaults: 80 for http, 443 for https. | No — it's the destination of the connection |
| **path** | Which resource on that server. | Yes |
| **query** | Parameters, after the `?`. | Yes |
| **fragment** | After the `#`. | **No. Never.** |

Three of these rows matter later and are worth marking now.

**The fragment is never sent to the server.** It exists purely for the browser. That fact
is the entire reason the OAuth implicit grant existed, and a large part of why it died
([F15](../track-f/F15-implicit-and-password-grants.md)). Put a token after `#` and the
server never logs it — but every script on the page can read it.

**The query string *is* sent, and it is logged.** Web servers, proxies, and CDNs write
full URLs into access logs by default. Anything you put in a query string should be
assumed to be sitting in plaintext in a log file somewhere, probably forever. This is why
password reset tokens in URLs are a real problem
([D09](../track-d/D09-account-recovery.md)) and why access tokens must never go in a
query string ([F07](../track-f/F07-access-refresh-scopes.md)).

**The `(scheme, host, port)` triple has a name: the origin.** It is the fundamental unit
of browser security. `https://example.com` and `http://example.com` are *different
origins*, because the schemes differ. So are `example.com` and `www.example.com`. We
come back to this properly in [A11](A11-same-origin-and-cors.md), but the triple is worth
seeing here, in its natural habitat.

---

## Step 2 — The name becomes a number

Computers do not route to `app.example.com`. They route to `93.184.216.34`, or an IPv6
equivalent. **DNS** — the Domain Name System — is the lookup that converts one to the
other.

Your machine asks a resolver, which asks a chain of servers, which eventually answers.
The answer is cached at several layers for a duration the answer itself specifies.

Two consequences you will meet again:

- **DNS is a dependency of your security model.** If an attacker controls what
  `app.example.com` resolves to, they receive your connection. TLS is what stops that
  from being fatal ([B17](../track-b/B17-what-https-protects.md)) — the attacker gets
  the connection but cannot produce a valid certificate for that name.
- **DNS caching is why "just point it at the new server" takes hours.** Also why
  key rotation needs an overlap window ([I06](../track-i/I06-key-rotation.md)): anything
  cached is by definition stale somewhere.

---

## Step 3 — A TCP connection opens

**TCP** gives you a reliable, ordered stream of bytes between two machines. It handles
retransmission, ordering, and flow control so you do not have to.

It gives you exactly nothing else. TCP does not encrypt. It does not authenticate. Anyone
on the path — the coffee shop router, the ISP, a compromised backbone — can read every
byte and change every byte.

This is why the next step exists.

---

## Step 4 — TLS wraps the connection

**TLS** — Transport Layer Security — does two separable jobs, and confusing them causes
real bugs:

1. **Encryption.** Nobody on the path can read the bytes.
2. **Server authentication.** You are talking to the machine that genuinely holds the
   private key for a certificate covering `app.example.com`, and a certificate authority
   your browser already trusts vouched for that.

Job 2 is the one people forget. Encryption to an attacker is worthless. The padlock does
not mean "this site is trustworthy" — it means "this connection reaches the site named in
the address bar, and nobody in between can read it." A phishing site has a padlock. It
has a *valid certificate for the phishing domain*, which is exactly what TLS promises and
all it promises.

The full machinery — how the certificate proves anything, why your browser trusts a
stranger — is [B15](../track-b/B15-certificates-and-pki.md) and
[B17](../track-b/B17-what-https-protects.md). For now, hold two facts:

> **TLS protects data in transit, between two endpoints. It protects nothing at either
> end.**

The server can log whatever it receives. The browser can be read by any script running on
the page, and by the person holding the laptop. "We use HTTPS" is not an answer to
"where does this secret live?" — that is [A10](A10-where-secrets-live.md).

---

## Step 5 — An HTTP request is sent

Inside the encrypted tunnel, your browser sends text. Genuinely text — this is what goes
across:

```http
GET /docs/42?share=true HTTP/1.1
Host: app.example.com
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) ...
Accept: text/html,application/xhtml+xml
Accept-Language: en-GB,en;q=0.9
Cookie: session=8f14e45fceea167a5a36dedd4bea2543
```

Four things are worth naming.

**The first line is a method, a path, and a version.** `GET /docs/42?share=true HTTP/1.1`.
Methods are [A03](A03-methods-status-codes-401-vs-403.md).

**The `Host` header exists because one IP address serves many sites.** The connection
went to a number; the `Host` header says which of the several hundred sites on that
machine you actually want. Note that the hostname was already visible outside the tunnel,
in the TLS handshake — see **SNI** in [B17](../track-b/B17-what-https-protects.md).

**The fragment is gone.** `#comments` never left the browser, exactly as promised.

**The `Cookie` header appeared without you doing anything.** You did not attach it. The
browser did, automatically, because a previous response asked it to and the cookie's rules
say this request qualifies. That automatic, invisible attachment is the single most
important behaviour in web authentication. It is what makes sessions work
([E01](../track-e/E01-why-http-needs-sessions.md)) and what makes CSRF possible
([E15](../track-e/E15-csrf.md)). Cookies get their own chapter,
[A06](A06-cookies.md), for this reason.

---

## Step 6 — A response comes back

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 4821
Set-Cookie: session=8f14e45f...; HttpOnly; Secure; SameSite=Lax
Strict-Transport-Security: max-age=31536000

<!doctype html>
<html>...
```

A status code, headers, a blank line, then the body. `Set-Cookie` is the instruction that
made the browser store the cookie you saw in step 5. Headers are
[A04](A04-headers.md).

---

## Step 7 — The browser builds a page, and makes more requests

The HTML is parsed. It references stylesheets, scripts, images, fonts — each of which is
another request, often to a different origin entirely.

This is the step most mental models skip, and it is where a surprising number of security
properties live:

- A `<script src="https://cdn.example.net/analytics.js">` runs **with the full privileges
  of your origin**. It can read your DOM, read anything in `localStorage`, and make
  requests as the user. You have delegated your security to that CDN.
  ([E16](../track-e/E16-xss-is-an-auth-vulnerability.md).)
- Requests to *other* origins are governed by the same-origin policy. The browser will
  often *send* them but refuse to let your script *read* the response.
  ([A11](A11-same-origin-and-cors.md).)
- Whether cookies ride along on those cross-origin requests depends on the `SameSite`
  attribute. ([E02](../track-e/E02-cookie-attributes.md).)

---

## The whole picture

```
   YOU                    THE PATH                       THE SERVER
    │                        │                                │
    │  1. parse URL          │                                │
    │  2. DNS: name → IP ────┼──> resolvers (can be poisoned) │
    │  3. TCP connect ───────┼──> routers, ISPs               │
    │                        │    (see everything, plaintext) │
    │  4. TLS handshake ─────┼──> ✅ from here, encrypted     │
    │     ┌──────────────────┴────────────────────────────┐   │
    │  5. │ HTTP request  (method, path, headers, cookie) │──>│
    │  6. │ HTTP response (status, headers, body)         │<──│
    │     └──────────────────┬────────────────────────────┘   │
    │  7. parse, run scripts,│                                │
    │     make more requests │                                │
    ▼                        ▼                                ▼
 Attacker with your      Attacker on the path        Attacker who has
 laptop or your JS       sees: IP addresses,         breached the server
 sees: EVERYTHING        hostname (SNI), sizes,      sees: EVERYTHING
                         timing. Not content.        you stored
```

Three attacker positions, three completely different sets of capabilities. Every design
decision in this book is an answer to "which of these three am I defending against?"
That question gets formalised in [C04](../track-c/C04-threat-modeling.md).

---

## What people get wrong

**"It's HTTPS, so it's secure."** Secure against the *middle* attacker only. Not against
someone reading your JavaScript bundle, not against someone who breached your database,
not against the user themselves — who is, in many threat models, the attacker.

**"The URL is private."** It is not. It is in browser history, in server access logs, in
CDN logs, in the `Referer` header sent to third parties, and in any analytics script on
the page.

**"The frontend validated it."** The frontend is a suggestion. See
[A07](A07-client-vs-server.md), which is the highest-leverage chapter in this track.

---

## Terms defined in this chapter

`URL`, `scheme`, `host`, `port`, `path`, `query`, `fragment`, `DNS`, `TCP`, `TLS`,
`HTTP`, `request`, `response`, `client`, `server`, `origin`

---

## What to remember

1. A URL has six parts. The fragment is never sent; the query is always logged.
2. `(scheme, host, port)` is an **origin** — the browser's unit of security.
3. TLS protects the *path*, and proves the *server's name*. Nothing else.
4. Cookies attach themselves. You never write that code, and that is the point.
5. There are three attacker positions — endpoint, path, server — and they see different
   things. Always know which one you are designing against.

---

## Sources

- [MDN: What is a URL?](https://developer.mozilla.org/en-US/docs/Learn/Common_questions/Web_mechanics/What_is_a_URL)
- [RFC 3986 — Uniform Resource Identifier: Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986)
- Ilya Grigorik, *High Performance Browser Networking* — [free online](https://hpbn.co/), chapters 1–4

---

**Next:** [A02 — Reading HTTP requests and responses in your browser dev tools](A02-reading-http-in-dev-tools.md)
