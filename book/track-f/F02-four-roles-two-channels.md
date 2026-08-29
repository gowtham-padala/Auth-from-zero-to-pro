# F02 — Four roles and two channels

**Part F · Delegated authorization — OAuth 2** · *Builds on [F01](F01-the-problem-oauth-solves.md)*
---

## The four roles

```
   ┌──────────────────┐        ┌──────────────────┐
   │  RESOURCE OWNER  │        │      CLIENT      │
   │                  │        │                  │
   │  The USER.       │        │  The APPLICATION │
   │  Owns the data.  │        │  requesting      │
   │  Grants access.  │        │  access.         │
   │                  │        │  NOT the browser.│
   └──────────────────┘        └──────────────────┘

   ┌──────────────────┐        ┌──────────────────┐
   │  AUTHORIZATION   │        │    RESOURCE      │
   │     SERVER (AS)  │        │    SERVER (RS)   │
   │                  │        │                  │
   │  Authenticates   │        │  The API that    │
   │  the user, gets  │        │  holds the data  │
   │  consent, issues │        │  and accepts     │
   │  tokens.         │        │  the token.      │
   └──────────────────┘        └──────────────────┘
```

| Role | Who it is | In "PrintCo prints your Google Photos" |
|---|---|---|
| **Resource owner** | The user | **You** |
| **Client** | The requesting app | **PrintCo** |
| **Authorization server** | Issues tokens | **Google's OAuth server** |
| **Resource server** | Serves the data | **Google Photos API** |

Two clarifications that resolve most confusion:

**The client is the *application*, not the browser.** For a server-side app, "the client" is
your backend. For a mobile app, it is the app process. The browser is a *user agent* — a
messenger the flow passes through, not a participant with a role.

**The AS and RS are often the same company, sometimes the same server.** Google runs both.
But they are distinct *roles*, and separating them is what makes the `aud` claim meaningful
([F08](F08-audience-and-resource-indicators.md)) — the RS must check that a token was
minted by its AS, for it.

---

## The two channels

This is the concept that makes the whole protocol make sense. OAuth uses **two completely
different communication paths**, with different security properties, and every design
decision comes down to which channel something travels on.

```
   FRONT CHANNEL                          BACK CHANNEL
   ─────────────                          ────────────
   Through the BROWSER                    Server → server, direct HTTPS
   (redirects, URL parameters)            (no browser involved)

   👁  Visible to the user                 🔒 Invisible to the user
   👁  Logged (history, server logs)       🔒 Not in any browser log
   👁  Can be tampered with                🔒 TLS end-to-end
   👁  A hostile environment               🔒 Trusted
   ❌  CANNOT carry a secret               ✅ CAN carry a secret
```

### Why two?

Because the client and the AS have **never met** and share no secret channel — the only
thing connecting them is the user's browser ([A08](../track-a/A08-what-an-api-is.md)). So
OAuth needs a way to:

1. Get the user to the AS and back — which *must* go through the browser (the front
   channel), because that is where the user is.
2. Exchange the actual credential — which must *not* go through the browser, because the
   browser leaks everything.

The entire authorization code flow ([F03](F03-authorization-code-flow.md)) is a bridge
between these two channels: something safe-to-expose crosses the front channel, and is then
exchanged for the real token over the back channel.

---

## What goes on which channel

| Travels on the... | Because... | Examples |
|---|---|---|
| **Front channel** | the user must be present, or the browser must route it | authorization request, the user's login, consent, the authorization **code**, `state`, `code_challenge` |
| **Back channel** | it is secret and must not leak | the code **exchange**, client secret, **access token**, **refresh token**, the resource request |

The single most important rule in OAuth follows directly:

> **The authorization code crosses the front channel (it is exposed). The access token is
> obtained on the back channel (it is not). The code is exchanged for the token
> server-to-server, so the token never touches the browser.**

The code is deliberately made safe to expose: short-lived, single-use, and — with PKCE —
useless to anyone but the client that started the flow
([F06](F06-pkce.md)). The token, which is *not* safe to expose, never travels a channel
where it could leak.

This is why the **implicit grant died** ([F15](F15-implicit-and-password-grants.md)): it
put the access token on the front channel, in the URL, where it was logged, cached, and
leaked via `Referer`. The whole two-channel design exists to prevent exactly that, and
implicit threw it away.

---

## The diagram to hold in your head

```
   USER          BROWSER               CLIENT              AUTH SERVER      RESOURCE SVR
    │               │                    │                     │               │
    │  ══════════════ FRONT CHANNEL (through the browser) ══════════           │
    │               │──── authz request ─┼────────────────────>│               │
    │  log in + ────┼────────────────────┼────────────────────>│               │
    │  consent      │                     │                     │               │
    │               │<─── redirect w/ CODE ────────────────────│               │
    │               │──── code ──────────>│                     │               │
    │               │                     │                     │               │
    │               │        ══════════ BACK CHANNEL (direct) ══════           │
    │               │                     │─── code + secret ──>│               │
    │               │                     │<──── TOKEN ─────────│               │
    │               │                     │                     │               │
    │               │                     │─────── token ──────────────────────>│
    │               │                     │<────── data ───────────────────────│
```

Trace the token: it appears only on the back channel and the resource request, **never** in
the browser. Trace the code: it crosses the front channel once, then is spent on the back
channel and never used again. That is the entire security architecture in one picture.

---

## Client types preview

The front/back-channel split forces a question that gets its own chapter
([F09](F09-public-vs-confidential-clients.md)):

- A **confidential client** runs on a server and can keep a client secret. It can
  authenticate itself on the back channel.
- A **public client** — a SPA, a mobile app, a CLI — *cannot* keep a secret
  ([A07](../track-a/A07-client-vs-server.md)). Its "secret" would be in the bundle, readable
  by anyone.

This is the distinction most tutorials blur. A public client has **no usable
client secret**, which is exactly why PKCE ([F06](F06-pkce.md)) exists — to secure the code
exchange *without* one.

---

## Terms defined in this chapter

`resource owner`, `client (OAuth)`, `authorization server`, `resource server`,
`front channel`, `back channel`

---

## What to remember

1. **Four roles:** resource owner (user), client (app), authorization server (issues
   tokens), resource server (serves data).
2. **The client is the application, not the browser.** The browser is a messenger with no
   role.
3. **Two channels.** Front = through the browser, exposed, cannot carry a secret. Back =
   server-to-server, private, carries the token.
4. **The code crosses the front channel; the token is obtained on the back channel.** The
   token never touches the browser.
5. The implicit grant died because it put the token on the front channel.
6. Public clients cannot keep a secret, which is why PKCE exists.

---

## Sources

- [RFC 6749 — OAuth 2.0](https://www.rfc-editor.org/rfc/rfc6749) §1.1 (roles), §1.3 (grant types)
- Aaron Parecki, [oauth.com — The Players](https://www.oauth.com/oauth2-servers/definitions/)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700)

---

**Next:** [F03 — The authorization code flow, drawn slowly](F03-authorization-code-flow.md)
