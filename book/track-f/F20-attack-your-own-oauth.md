# F20 — OAuth's failure modes: redirect_uri smuggling, mix-up, token leakage

**Part F · Delegated authorization — OAuth 2** · *Builds on [F14](F14-build-an-authorization-server.md), [F05](F05-the-state-parameter.md)*

> OAuth's security lives in a handful of checks. This chapter is the failure modes an OAuth deployment
> must defend against — drawn from [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), the OAuth
> Security Best Current Practice — and why each one happens.

---

## Why it matters

An authorization server matches redirect URIs loosely — a prefix check, say. A client is registered
with `https://app.example.com/callback`. An attacker sends the user through a flow with:

```
redirect_uri=https://app.example.com/callback/../evil
```

The prefix matches. The authorization server sends the browser — carrying the authorization code
([F03](F03-authorization-code-flow.md)) — to a URL the attacker controls. The attacker has the code.

That is **redirect_uri smuggling**, and it is the most common serious OAuth vulnerability. It, and the
other failures below, are why the flow has as many checks as it does.

---

## redirect_uri smuggling

The `redirect_uri` decides where the authorization server sends the code
([F03](F03-authorization-code-flow.md)). If the server accepts an attacker-influenced value, the
attacker receives the code. Loose matching is the root cause, and every one of these has defeated a
real matcher:

| Attacker input | Why a naive check passes it |
|---|---|
| `https://app.example.com/callback/../evil` | Path traversal past a prefix check |
| `https://app.example.com.evil.com/callback` | Suffix / "starts-with" check |
| `https://app.example.com@evil.com/callback` | Everything before `@` is userinfo — host is `evil.com` ([A09](../track-a/A09-redirects.md)) |
| `https://evil.com/?x=app.example.com` | Substring check |

**The prevention:** exact match against a **registered set** of complete URIs — scheme, host, port,
and path ([F14](F14-build-an-authorization-server.md)). Never prefix, suffix, substring, or regex.
And validate the client and redirect URI *before* redirecting anything, including error responses —
redirecting an error to an unvalidated URI is itself an open redirect.

**The open-redirect chain.** Even with exact matching, the attack revives if a *registered* redirect
URI is itself an open redirect ([A09](../track-a/A09-redirects.md)): the attacker points the flow at
the registered URI, which forwards the code onward. So: no open redirects anywhere on a domain that
hosts a registered `redirect_uri`.

---

## Missing or unchecked `state` — login CSRF

`state` binds the authorization *response* to the request a specific browser started
([F05](F05-the-state-parameter.md)). Omit it, or fail to check it, and an attacker can complete a flow
with *their* account and trick a victim's browser into finishing it — logging the victim into the
attacker's account (or connecting the attacker's data to the victim's account).

**The prevention** ([F05](F05-the-state-parameter.md)): `state` must be unguessable, **bound to this
browser's session**, checked *before* the code is used, single-use, and compared in constant time. The
session-binding is the property implementations most often miss — `state` stored somewhere not tied to
*this* browser protects nothing.

---

## Code replay and injection

An authorization code should be usable exactly once ([F03](F03-authorization-code-flow.md)). If it
can be replayed, an intercepted code works twice. If a code from one flow can be injected into another
user's session, an attacker's code becomes the victim's login.

**The prevention:** codes are single-use (reuse should revoke the tokens already issued from that
code), short-lived, and bound to the client and `redirect_uri` — and **PKCE**
([F06](F06-pkce.md)) binds each code to the specific client instance that started the flow, which is
what stops injection. PKCE must be *enforced*: if a challenge was sent, a verifier must be required at
the exchange, or the protection is downgradable by simply omitting it.

---

## Mix-up — confusing which identity provider replied

A client that supports several identity providers can be confused about *which* one a response came
from. An attacker who controls one (malicious) provider arranges for a code or credential meant for it
to be sent to a different (honest) provider's endpoint, capturing something they shouldn't have.

**The prevention:** [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) — the authorization server
includes an **`iss` (issuer) parameter** in the response, and the client verifies it matches the
provider it started with. Also: a distinct `redirect_uri` per provider, and recording the expected
issuer alongside the flow's `state`. This is exactly the mix-up defence the MCP authorization spec
mandates ([J08](../track-j/J08-mcp-and-oauth-21.md)).

---

## Audience confusion — the confused deputy

A resource server that verifies a token's *signature* but not its *audience* accepts tokens minted for
a *different* resource server ([F08](F08-audience-and-resource-indicators.md)). A malicious low-trust
service collects tokens users sent it, then replays them against a high-value API that skipped the
`aud` check.

**The prevention:** every resource server must reject tokens whose `aud` is not itself
([F08](F08-audience-and-resource-indicators.md)) — the single most commonly omitted validation in
OAuth. Combined with resource indicators ([RFC 8707](https://www.rfc-editor.org/rfc/rfc8707)) so each
token is scoped to one API, a leaked token is useless elsewhere.

---

## Token leakage

Tokens end up where they shouldn't ([E12](../track-e/E12-where-to-store-a-token.md),
[I08](../track-i/I08-observability.md)):

- In a **URL** — the implicit grant's fatal flaw, which is why it's dead
  ([F15](F15-implicit-and-password-grants.md)). Tokens in URLs land in logs, history, and `Referer`
  headers.
- In **`localStorage`**, where an XSS reads them ([E12](../track-e/E12-where-to-store-a-token.md)).
- In **logs**, when an `Authorization` header is serialised ([I08](../track-i/I08-observability.md)).

**The prevention:** never a token in a URL; tokens off the browser (a backend-for-frontend —
[F17](F17-oauth-for-spas-and-bff.md)) or in an `HttpOnly` cookie; `Referrer-Policy` and no third-party
scripts on callback pages; and redaction so tokens never reach logs.

---

## The three that matter most

If three things are right, most OAuth breaches are closed:

```
   1. redirect_uri  — exact-match a registered set          (this chapter)
   2. PKCE          — enforced, S256, verifier required     (F06)
   3. aud           — validated on every resource server    (F08)
```

Everything else is defence in depth around those three.

---

## Terms defined in this chapter

`redirect_uri smuggling`, `mix-up attack`, `iss in response`

---

## What to remember

1. **redirect_uri smuggling is the #1 OAuth failure** — exact-match a registered set; never prefix,
   suffix, substring, or regex. Watch the `@evil.com` userinfo trick.
2. A registered redirect URI that is **itself an open redirect** revives the attack.
3. **`state` must be session-bound and checked before the code**, or you get login CSRF
   ([F05](F05-the-state-parameter.md)).
4. **PKCE must be enforced** — verifier required whenever a challenge was sent
   ([F06](F06-pkce.md)).
5. **Mix-up** is defeated by verifying **`iss`** in the response
   ([RFC 9207](https://www.rfc-editor.org/rfc/rfc9207)).
6. **`aud` validation** on the resource server is the confused-deputy defence and the most-skipped
   check ([F08](F08-audience-and-resource-indicators.md)).
7. Never a token in a URL, `localStorage`, or a log.

---

## Sources

- [RFC 9700 — OAuth 2.0 Security Best Current Practice](https://www.rfc-editor.org/rfc/rfc9700) — the complete threat model behind this chapter
- [RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification](https://www.rfc-editor.org/rfc/rfc9207)
- [oauth.net — Security](https://oauth.net/security/)

---

**Next:** [G01 — What actually happens when you click "Sign in with Google"](../track-g/G01-sign-in-with-google.md)
