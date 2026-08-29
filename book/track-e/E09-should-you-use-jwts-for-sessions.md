# E09 — Should you use JWTs for sessions?

**Part E · Sessions & tokens** · *Builds on [E08](E08-signed-cookies-vs-jwt-vs-opaque.md)*
> This chapter takes a position. The dissent is linked at the end, in full, and it is worth
> reading. But an argument that ends in "it depends" is not useful to someone who has to
> ship on Thursday.

---

## The answer

**For a first-party web application: no. Use server-side sessions with an opaque cookie.**

**For an API consumed by services you do not control, or across a trust boundary: yes, and
keep the token short-lived.**

That is the whole recommendation. The rest is why, and how to tell which one you are.

---

## The failure that decides it

A B2B SaaS company uses JWTs with a 24-hour lifetime.

An admin at a customer discovers that a departing employee has been downloading the
customer list. At 09:15 they revoke the employee's account.

At 09:16, and every minute until 09:15 tomorrow, that employee's JWT still works. Every
service accepts it, because the design's central property is that no service asks the
database.

Support's answer is: *"we can't. Their token is valid until tomorrow."*

That sentence ends the conversation about whether JWTs are appropriate for that product.
Not because JWTs are bad — because the property that makes them fast is exactly the property
that makes that sentence necessary, and the customer does not care about the trade-off.

---

## What people think they are buying

Three claimed benefits. Two do not survive contact.

### "It's stateless, so it scales"

This is the argument that does most of the work, and it is mostly wrong for the case being
argued.

**Your application already has a database.** It is already reading it on the request. A
session lookup is a primary-key read on a small, hot table:

| Operation | Cost |
|---|---|
| Redis `GET` | 0.2–0.5 ms |
| Postgres PK lookup (warm) | 0.5–2 ms |
| **RS256 verify** | **0.1–0.5 ms** |
| ES256 verify | 0.05–0.2 ms |

An RS256 verification is in the same range as a Redis lookup, and burns **your** CPU rather
than a store built for exactly this.

The genuine benefit is not speed. It is **reach** — being able to verify without your store
being reachable at all. If your verifier is already talking to your database on this
request, you are paying for reach you are not using.

### "No shared session store"

You need shared state anyway. For a revocation list, for "log out everywhere"
([E13](E13-sessions-across-devices.md)), for the device list, for rate limiting, for
anything.

The store does not disappear. Only its use for authentication does.

### "It's the modern way"

It is the *popular* way, which is not the same thing. JWTs became ubiquitous because they
are the right answer for OAuth and OIDC — protocols where a token genuinely crosses a trust
boundary. That correctness got generalised into "tokens good, sessions old," and the
generalisation does not hold.

---

## What you actually pay

**No revocation.** The core tradeoff. Every mitigation — a denylist, short expiry with
refresh, a "token version" column — reintroduces the lookup you were avoiding
([E11](E11-revocation.md)).

**Stale claims.** Change a role, remove someone from a tenant, downgrade a plan — the token
still says the old thing. Every claim in a JWT is a cached copy with no invalidation.

**Size.** 500–1500 bytes on every request, versus 44. At scale that is real bandwidth; and a
token stuffed with permissions eventually produces `431 Request Header Fields Too Large` for
your most-privileged users, which is a bug you find late because it only affects admins.

**A larger attack surface.** `alg: none`, algorithm confusion, `jku`/`jwk` injection,
unverified `aud`, missing `exp`, unpinned algorithms
([E06](E06-jwt-part-2-signature-jws-jwe.md)). A
random 256-bit string has none of these, because there is nothing to interpret.

**Key management.** Rotation, JWKS caching, overlap windows
([I06](../track-i/I06-key-rotation.md)). An opaque session ID has no keys.

**Storage pressure.** A JWT is often too big for a cookie's comfort, so people move it to
`localStorage`, which makes XSS fatal ([E12](E12-where-to-store-a-token.md)). The format
choice quietly drags the storage choice with it, and the storage choice is the more
dangerous one.

---

## The test

One question:

> **Does something outside your application need to verify this credential without asking
> you?**

**No** → opaque session. The lookup you are avoiding is one you are already making.

**Yes** → JWT. That is precisely what it is for.

Worked through:

| Situation | Answer | Why |
|---|---|---|
| Server-rendered web app | **Opaque session** | One party |
| SPA + your own API, same site | **Opaque session cookie** | One party. [F17](../track-f/F17-oauth-for-spas-and-bff.md) |
| SPA + your API, different origins | **Opaque session** + CORS, or a BFF | Still one party |
| Mobile app + your API | **Opaque token**, or short JWT + refresh | Your API; your store |
| Microservices, internal | **Short-lived JWT** (60 s–5 min) minted at the edge | Many verifiers |
| Third-party API consumers | **JWT** or introspection | Crosses a boundary |
| OIDC ID token | **JWT** — not a choice | The specification says so |
| OAuth access token to another org | **JWT** with strict `aud` | [F08](../track-f/F08-audience-and-resource-indicators.md) |
| Serverless / edge with no store access | **JWT** | Genuine statelessness requirement |

Notice how many rows say opaque. Most applications are one party.

---

## If you use JWTs anyway

There are legitimate reasons — an existing architecture, a platform constraint, a team
decision already made. Make them safe:

```
☐  Short lifetime: 5–15 minutes. Not hours. Not a day.
☐  Refresh tokens, rotated, with reuse detection             E10
☐  Refresh tokens are OPAQUE and server-side — so you CAN revoke
☐  Algorithm pinned in configuration; never read from the token   E06
☐  ES256 or EdDSA, not HS256, if more than one party verifies
☐  aud, iss, exp verified on every request                   E06
☐  In an HttpOnly cookie, not localStorage                    E12
☐  Identity in the token; PERMISSIONS looked up at use        H12
☐  kid + JWKS, cached, with a rotation overlap window         I06
☐  A revocation path for the "fired at 09:15" case            E11
```

The pattern that makes this work: **a short-lived JWT plus an opaque, revocable refresh
token.** The JWT's staleness window shrinks to minutes, and the refresh token is a
server-side record you can delete. You get most of the reach and keep the revocation.

That is the design used by every mature OAuth deployment, and it is the honest version of
"stateless auth."

---

## The hybrid, again

For anything non-trivial, [E08](E08-signed-cookies-vs-jwt-vs-opaque.md)'s hybrid is the
answer:

```
   Browser ──[opaque session cookie]──> Edge / BFF
                                            │  session lookup (E03)
                                            │  mint a 60-second JWT
                                            ▼
                                      Internal services
                                      verify locally, no store
```

Revocation is instant at the edge. Internal services never touch the store. The browser
holds nothing readable. Internal tokens are too short-lived for staleness to matter.

This is where large systems converge, and it is worth designing toward from the start —
because it costs almost nothing early and is awkward to retrofit.

---

## The dissent

Read these. They are the strongest versions of the counter-argument, and the second one is
the strongest version of *this* argument.

**For JWTs as sessions:**

- **[Auth0: Ten Things You Should Know About Tokens and Cookies](https://auth0.com/blog/ten-things-you-should-know-about-tokens-and-cookies/)** — the mainstream case for tokens, from a vendor with genuine expertise.
- **[Okta: Why JWTs Suck as Session Tokens](https://developer.okta.com/blog/2017/08/17/why-jwts-suck-as-session-tokens)** — notable because it is a vendor arguing *against* their own default, and it is the honest treatment of the trade-offs.

**Against:**

- **[Sven Slootweg (joepie91): Stop using JWT for sessions](http://cryto.net/~joepie91/blog/2016/06/13/stop-using-jwt-for-sessions/)** and [the follow-up](http://cryto.net/~joepie91/blog/2016/06/19/stop-using-jwt-for-sessions-part-2-why-your-solution-doesnt-work/) — the canonical statement of the position this chapter takes. Read both.
- **[The Copenhagen Book — Sessions](https://thecopenhagenbook.com/sessions)** — the modern, calm, implementation-focused version.

**On what JWTs are actually for:**

- **[RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)**
- **[RFC 9068 — JWT Profile for OAuth Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)** — note the framing: *access tokens*. Not sessions.

If you disagree after reading those, you have disagreed for good reasons, and your system
will probably be fine — because you will have thought about revocation, which is the thing
that actually matters.

---

## Terms defined in this chapter

(No new terms. This chapter is a decision.)

---

## What to remember

1. **First-party web app → opaque server-side session.** **Crossing a trust boundary → JWT.**
2. **"Stateless scales better" does not survive measurement.** RS256 verification costs
   about what a Redis lookup costs, on your CPU.
3. **You will need shared state anyway** — revocation, device lists, "log out everywhere."
4. The cost is **no revocation and stale claims.** Fired at 09:15, access until tomorrow.
5. **The test: does something outside your application need to verify this without asking
   you?** Most applications: no.
6. If you use JWTs: **5–15 minutes**, opaque revocable refresh tokens, pinned algorithm,
   `HttpOnly` cookie, permissions looked up at use.
7. **The hybrid** — opaque at the edge, short JWTs internally — is where large systems land.
8. Read the dissent. Disagreeing for good reasons is a fine outcome.

---

**Next:** [E10 — Token lifetimes, refresh tokens, and rotation](E10-token-lifetimes-and-rotation.md)
