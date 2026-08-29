# E01 — Why HTTP needs sessions at all

**Part E · Sessions & tokens** · *Builds on [A05](../track-a/A05-stateless.md)*
---

## The gap, precisely

Authentication answers *"who are you?"* — once, expensively, with a credential.

```
POST /login    email + password + TOTP     →  ✅ this is user 4471
```

Then it is over. The connection may close. The next request may reach a different server on
a different continent.

```
GET /documents    ...?
```

Re-authenticating on every request is not an option:

- The user would type a password for every image on the page.
- The password would cross the network hundreds of times a day.
- Every request would cost 300 ms of Argon2id
  ([D03](../track-d/D03-how-to-store-passwords.md)).
- MFA would be unusable.

So: authenticate once, **issue a credential that stands in for that authentication**, and
present the substitute thereafter.

```
POST /login    password + TOTP    →  Set-Cookie: session=8f14e45f
GET  /docs     Cookie: session=8f14e45f    →  "user 4471" ✅
GET  /docs/1   Cookie: session=8f14e45f    →  "user 4471" ✅
```

**That substitute is the session, and from here on it — not the password — is what an
attacker wants.**

---

## The trade you just made

Worth naming explicitly, because everything in this track is a consequence:

| | Password | Session token |
|---|---|---|
| Presented | Once | **Every request** |
| Strength | Argon2id + MFA | **Possession alone** |
| Lifetime | Until changed | Minutes to weeks |
| If stolen | Attacker must still pass MFA | **Attacker is in. MFA is bypassed.** |
| Where it lives | The user's head | A cookie, a header, `localStorage` |

> **A session token is a bearer credential that bypasses everything you built in Track D.**

This is why attackers steal session cookies rather than passwords. It is why
[E16](E16-xss-is-an-auth-vulnerability.md) is titled "XSS is an auth vulnerability." And it
is why passkeys ([D14](../track-d/D14-webauthn-and-passkeys-concepts.md)) improve
authentication without touching this problem at all.

Strong authentication and weak session management give you weak security. The chain is as
strong as its weakest link, and after login the session *is* the link.

---

## What a session actually is

> **A session is server-held knowledge that a series of requests belongs to one
> authenticated principal, plus a credential the client presents to invoke it.**

Two parts, and separating them is the whole design space:

```
   ┌─────────────────────────┐        ┌──────────────────────────────┐
   │  THE IDENTIFIER         │        │  THE STATE                   │
   │  what the client holds  │───────>│  what the server knows       │
   │                         │        │                              │
   │  8f14e45fceea167a...    │        │  user_id: 4471               │
   │                         │        │  created: 2026-08-25T09:14Z  │
   │  Must be:               │        │  auth_time, amr, acr  (D18)  │
   │   • unguessable  (B03)  │        │  ip, user_agent              │
   │   • unforgeable         │        │  tenant_id                   │
   │   • revocable           │        │  expires_at                  │
   └─────────────────────────┘        └──────────────────────────────┘
```

The choice that defines every later chapter: **does the identifier point at the state, or
carry it?**

```
   REFERENCE (server-side session)        SELF-CONTAINED (JWT / signed cookie)
   ────────────────────────────────       ─────────────────────────────────────
   Cookie: session=8f14e45f               Cookie: session=eyJzdWIiOiI0NDcxIn0.<sig>
              │                                       │
              ▼ look it up                            ▼ verify the signature
       ┌──────────────┐                        no lookup at all
       │ session store│
       └──────────────┘
   ✅ revoke instantly — delete the row     ✅ no shared storage; scales trivially
   ✅ store anything, change it any time    ✅ any service can verify independently
   ❌ a lookup per request                  ❌ cannot revoke before expiry  (E11)
                                            ❌ stale the moment anything changes
```

[E03](E03-build-server-side-sessions.md) builds the left. [E05](E05-jwt-part-1-three-parts.md)
and [E06](E06-jwt-part-2-signature-jws-jwe.md) explain the right.
[E08](E08-signed-cookies-vs-jwt-vs-opaque.md) compares them and
[E09](E09-should-you-use-jwts-for-sessions.md) takes a position.

---

## What must be true of any session

Whichever you choose, six requirements do not change:

**1. Unguessable.** 128+ bits from a CSPRNG. `Math.random()` is a breach
([B03](../track-b/B03-randomness.md)).

**2. Unforgeable.** Either meaningless (a reference) or signed (self-contained). A client
must never be able to construct a valid one.

**3. Transmitted safely.** `Secure`, so it never crosses plain HTTP
([E02](E02-cookie-attributes.md)). Never in a URL
([A05](../track-a/A05-stateless.md)).

**4. Stored safely.** `HttpOnly`, so a successful XSS cannot read it
([E12](E12-where-to-store-a-token.md)). Hashed at rest in your database, so a read-only SQL
injection is not a hijacking kit ([E04](E04-session-ids.md)).

**5. Expiring.** Idle timeout and absolute timeout, both
([E04](E04-session-ids.md)).

**6. Revocable.** The user must be able to end it, and so must you
([E11](E11-revocation.md), [E13](E13-sessions-across-devices.md)).

Requirement 6 is the one that self-contained tokens struggle with, and it is the crux of
[E09](E09-should-you-use-jwts-for-sessions.md).

---

## Where the session travels

Three options, from [A05](../track-a/A05-stateless.md), with the property that decides
between them:

| | URL | Header | **Cookie** |
|---|---|---|---|
| Automatic | ✅ (in links) | ❌ your code attaches it | ✅ the browser attaches it |
| Survives navigation | ✅ | ❌ | ✅ |
| Hideable from JavaScript | ❌ | ❌ | ✅ **`HttpOnly`** |
| Leaks in logs and `Referer` | ❌ **badly** | ✅ safe | ✅ safe |
| Vulnerable to CSRF | ✅ | ❌ **immune** | ✅ needs `SameSite` |

Read the last two rows together, because they are the whole argument:

- **Cookies are automatic** — which makes them work everywhere, and makes CSRF possible
  ([E15](E15-csrf.md)).
- **Headers are manual** — which makes them CSRF-immune, and requires the token to live
  somewhere script can read, which makes XSS fatal ([E16](E16-xss-is-an-auth-vulnerability.md)).

Neither is strictly safer. They fail differently:

> **Cookie + `HttpOnly` + `SameSite`: survives XSS, needs CSRF defence.**
> **Header + `localStorage`: immune to CSRF, does not survive XSS.**

XSS is more common and more damaging than CSRF, and `SameSite=Lax` is now the browser
default — so the cookie option is ahead on both counts. That is the case
[E12](E12-where-to-store-a-token.md) argues in full.

---

## Session vs token, as words

People use them interchangeably. They are not quite the same:

- **Session** — the *concept*: continuity of identity across requests. Every application has
  sessions, whatever the mechanism.
- **Session ID / session cookie** — a *reference* to server-held state.
- **Token** — any string standing in for a credential or a decision.
- **Access token** — an OAuth token presented to an API
  ([F07](../track-f/F07-access-refresh-scopes.md)). Related but not the same thing: it is
  *delegated authorization* (layer 3), not *your user's session* (layer 2).

A common and expensive confusion is using an OAuth access token *as* your web session. They
have different lifetimes, different audiences, and different revocation semantics
([E09](E09-should-you-use-jwts-for-sessions.md),
[F17](../track-f/F17-oauth-for-spas-and-bff.md)).

---

## The lifecycle

Every requirement in this track attaches to one of these transitions:

```
   CREATE ──────> USE ──────> RENEW ──────> END
      │            │            │            │
   on login     every         idle       logout, expiry,
   NEW ID       request      extension    password change,
   (D06)       + checks                   revocation
                                          (E11, E13, E14)
```

**Create** — a fresh ID, always. Reusing one is session fixation
([E04](E04-session-ids.md)).

**Use** — validate, check expiry, load the principal, and only *then* authorize the specific
action ([C02](../track-c/C02-authn-vs-authz-vs-session.md)).

**Renew** — extend on activity, within an absolute cap. Rotate the ID on privilege change.

**End** — this is where it gets genuinely hard, and it gets its own chapter
([E14](E14-why-logout-is-hard.md)).

---

## Terms defined in this chapter

`session`, `session ID`

---

## What to remember

1. **Authentication is a moment; a session is a duration.** The session is the substitute
   for the credential.
2. **A session token bypasses everything in Track D**, MFA included. That is why attackers
   want it.
3. Two parts: an **identifier** the client holds, and **state** the server knows. Whether
   the identifier *points at* or *carries* the state defines everything downstream.
4. Six invariants: unguessable, unforgeable, transmitted safely, stored safely, expiring,
   revocable.
5. **Cookie = automatic = CSRF risk. Header = manual = XSS risk.** They fail differently;
   the cookie fails less badly.
6. Create → use → renew → end. Ending is the hard one.

---

## Sources

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [The Copenhagen Book — Sessions](https://thecopenhagenbook.com/sessions)
- [RFC 9110 §3.3](https://www.rfc-editor.org/rfc/rfc9110#section-3.3) — HTTP is stateless

---

**Next:** [E02 — Cookie attributes that matter: HttpOnly, Secure, SameSite, __Host-](E02-cookie-attributes.md)
