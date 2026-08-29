# B17 — What HTTPS actually protects, and what it doesn't

**Part B · Crypto foundations** · *Builds on [B12](B12-key-exchange.md), [B15](B15-certificates-and-pki.md)*
---

## What HTTPS is

HTTP inside TLS. Everything from Track A, wrapped in everything from Track B:

```
   ┌──────────────────────────────────────────────────────────┐
   │  HTTP        GET /docs/42, headers, cookies, body         │
   ├──────────────────────────────────────────────────────────┤
   │  TLS         ① authenticate the server   (B15 — certs)    │
   │              ② agree a session key       (B12 — ECDHE)    │
   │              ③ encrypt + authenticate    (B09 — AEAD)     │
   ├──────────────────────────────────────────────────────────┤
   │  TCP         reliable byte stream                         │
   ├──────────────────────────────────────────────────────────┤
   │  IP          routing                                      │
   └──────────────────────────────────────────────────────────┘
```

Three guarantees, and it is worth naming them separately because people collapse them:

1. **Confidentiality** — nobody on the path reads the content.
2. **Integrity** — nobody on the path modifies it undetected.
3. **Server authentication** — you are talking to a host that holds the private key for a
   certificate covering the name in the address bar, vouched for by a CA in your trust
   store.

That third one is the one people forget, and it is the one that makes the first two
meaningful. Encryption to an attacker is worthless.

---

## ✅ What it protects against

| Attack | Protected? | Why |
|---|---|---|
| Coffee-shop Wi-Fi sniffing | ✅ | Encrypted |
| ISP reading your traffic | ✅ | Encrypted |
| Injecting ads or malware into pages | ✅ | Integrity |
| SSL stripping (downgrade to HTTP) | ✅ **with HSTS** | Browser refuses plain HTTP |
| DNS hijack redirecting to a fake server | ✅ | Attacker cannot get a valid certificate for the name |
| Modifying a form in flight | ✅ | Integrity |
| Replaying a captured connection | ✅ | Per-session keys |
| Decrypting old traffic after a key theft | ✅ **TLS 1.3** | Forward secrecy ([B12](B12-key-exchange.md)) |

The DNS row is worth pausing on. An attacker who poisons DNS *does* receive your
connection — and then cannot do anything with it, because they cannot present a valid
certificate. TLS turns a total compromise into a denial of service. That is the whole
value of [B15](B15-certificates-and-pki.md).

---

## ❌ What it does not protect against

This is the useful half.

### 1. Anything at either endpoint

TLS protects the *road*. Both ends are wide open.

- **The server logs everything it receives.** Your `Authorization` header is in an access
  log ([A04](../track-a/A04-headers.md), [I08](../track-i/I08-observability.md)).
- **The browser is inspectable.** Dev tools, extensions, malware, and the person holding
  the laptop see everything ([A07](../track-a/A07-client-vs-server.md)).
- **Your database is not encrypted by TLS.** "Encrypted in transit" and "encrypted at rest"
  are unrelated claims.

### 2. Malicious or compromised endpoints

A phishing site has a **valid certificate**. `exarnple.com` gets a free DV certificate in
thirty seconds ([B15](B15-certificates-and-pki.md)), and the browser shows a padlock,
correctly.

> **The padlock means "this connection is private and reaches the name in the address
> bar." It does not mean "this site is trustworthy."**

The 2019 removal of the EV green bar was an acknowledgement of exactly this: users read
the padlock as a trust signal it was never able to provide. Which is why phishing
resistance has to come from somewhere else — the origin binding in WebAuthn
([D14](../track-d/D14-webauthn-and-passkeys-concepts.md)).

### 3. Application vulnerabilities

TLS is orthogonal to every one of these:

XSS, SQL injection, CSRF, IDOR, broken access control, weak passwords, session fixation,
open redirects, mass assignment, SSRF.

All of Tracks D through H happen *inside* a perfectly secure TLS connection.

### 4. What leaks anyway

Even with TLS 1.3, an observer on the path learns:

| Leak | Detail | Mitigation |
|---|---|---|
| **IP addresses** | Who is talking to whom | Nothing at this layer |
| **SNI** | The **hostname**, sent in the clear in the handshake | Encrypted ClientHello (ECH) — deploying now, not universal |
| **DNS queries** | The hostname again | DoH / DoT |
| **Certificate** | Encrypted in TLS 1.3 ✅ | (Was cleartext in 1.2) |
| **Traffic sizes and timing** | Which page, which video, sometimes which keystrokes | Padding — rarely deployed |

**Traffic analysis** is more powerful than people expect. Published research has identified
which page of a site a user loaded, which video was streamed, and which language a
voice-over-IP call was in — all from encrypted traffic, using sizes and timings alone.

For a threat model that includes a nation-state observer, "we use HTTPS" is not a complete
answer to "is this private?"

### 5. Anyone with the private key

Steal the server key and you can impersonate the server. Forward secrecy limits the damage
to *future* connections rather than recorded past ones — which is a large improvement and
not a cure ([B12](B12-key-exchange.md)).

### 6. Interception the user consented to

Corporate TLS inspection works by installing a **corporate root CA** on managed devices.
The proxy then mints certificates on the fly, and every device trusts them. TLS is
functioning exactly as specified; the trust store was changed.

The same mechanism is how you use Burp Suite or mitmproxy on your own traffic, and why
"our mobile app uses TLS" does not prevent anyone from reading its API calls
([A07](../track-a/A07-client-vs-server.md)).

**Certificate pinning** is the counter, and it is a genuine trade-off: it breaks corporate
inspection (good or bad, depending on who you are), and a pinning mistake can brick your
app until users update. Pin in mobile apps where you control the update cycle; do not pin
in browsers ([HPKP was removed](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins)
for exactly this reason).

---

## The configuration that matters

Most TLS configuration is now defaults. Four things still need deciding:

### 1. HSTS

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

Tells the browser: **never contact this host over plain HTTP again**, for a year. Closes
the first-visit SSL-stripping window and stops a user reaching your site over HTTP at all.

`preload` gets you into a list shipped inside browsers, so even the *first* visit is
protected. Note that it is **very hard to reverse** — removal takes months to propagate. Do
not preload until every subdomain is HTTPS-only and will stay that way.

### 2. Redirect HTTP → HTTPS, and set `Secure` on every cookie

A cookie without `Secure` is sent over plain HTTP, which means a single accidental HTTP
request leaks the session ([A06](../track-a/A06-cookies.md),
[E02](../track-e/E02-cookie-attributes.md)).

### 3. TLS 1.2 minimum, 1.3 preferred

1.0 and 1.1 are deprecated ([RFC 8996](https://www.rfc-editor.org/rfc/rfc8996)) and
disabled in all current browsers. Disable them server-side too.

### 4. Automate certificate renewal

Lifetimes are heading to 47 days by 2029 ([B15](B15-certificates-and-pki.md)). Manual
renewal is no longer a viable operational model.

Check your configuration at [SSL Labs](https://www.ssllabs.com/ssltest/) or with
`testssl.sh`. Aim for A+; it is achievable with defaults plus HSTS.

---

## Beyond the edge

The commonest real-world gap: TLS terminates at the load balancer, and traffic inside the
network is plaintext.

```
   Browser ══TLS══> Load balancer ──plaintext──> App ──plaintext──> Database
                         ▲                  ▲                  ▲
                    "we use HTTPS"    anyone on this      unencrypted
                                      network reads       replication,
                                      everything          backups, logs
```

This was standard practice for years, on the theory that the internal network is trusted.
[A07](../track-a/A07-client-vs-server.md) already explained why "internal" is not a
security property.

The modern answer is **encryption everywhere**: TLS to the app, TLS to the database, and
**mTLS** between services so each hop authenticates the other
([J04](../track-j/J04-mtls.md), [J05](../track-j/J05-workload-identity-spiffe.md)). A
service mesh can do this transparently.

---

## The honest summary

Say this instead of "we use HTTPS":

| Question | HTTPS answers it? |
|---|---|
| Can someone on the network read this? | ✅ **Yes** |
| Can someone on the network change this? | ✅ **Yes** |
| Am I talking to the right *host*? | ✅ **Yes** |
| Is the site I am talking to *honest*? | ❌ No |
| Is the data safe once it arrives? | ❌ No |
| Is it safe in the database? | ❌ No |
| Is it safe in the logs? | ❌ No |
| Can an XSS steal the session? | ❌ No |
| Can a user access another user's data? | ❌ No |
| Is who I am talking to private? | ⚠️ Partly — IP and SNI leak |

HTTPS is **necessary and insufficient**. It is the floor, not the building. Everything from
Track C onward happens inside a connection that is already perfectly encrypted.

---

## Terms defined in this chapter

`man in the middle`, `HTTPS`, `HSTS`, `SNI`, `traffic analysis`

---

## What to remember

1. HTTPS = confidentiality + integrity + **server authentication**, in transit, between two
   endpoints.
2. **The padlock means the connection is private, not that the site is honest.** Phishing
   sites have valid certificates.
3. Both endpoints are wide open. Logs, databases, browsers, extensions, dev tools.
4. Every application vulnerability in Tracks D–H works perfectly over TLS.
5. IP addresses, SNI, DNS, and traffic sizes still leak. ECH is fixing SNI, slowly.
6. **HSTS, `Secure` cookies, TLS 1.2+, automated renewal.** Four decisions.
7. Do not stop at the load balancer. Encrypt internal hops too.

---

## Sources

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446)
- [RFC 6797 — HTTP Strict Transport Security](https://www.rfc-editor.org/rfc/rfc6797)
- [RFC 8996 — Deprecating TLS 1.0 and TLS 1.1](https://www.rfc-editor.org/rfc/rfc8996)
- [Mozilla SSL Configuration Generator](https://ssl-config.mozilla.org/) — the practical config source
- [Encrypted Client Hello explainer (Cloudflare)](https://blog.cloudflare.com/announcing-encrypted-client-hello/)

---

**Track B complete.** You now have hashing, randomness, symmetric and asymmetric
encryption, MACs, signatures, certificates, and the side channels that undermine all of
them. Everything from here on is these primitives, arranged into protocols.

**Next:** [C01 — "Auth" is five different problems](../track-c/C01-auth-is-five-different-problems.md)
