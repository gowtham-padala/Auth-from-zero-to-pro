# E11 — Revocation: the thing stateless tokens are bad at

**Part E · Sessions & tokens** · *Builds on [E10](E10-token-lifetimes-and-rotation.md)*
---

## Why it is hard

```
   REFERENCE TOKEN                        SELF-CONTAINED TOKEN
   ───────────────                        ────────────────────
   Cookie: session=8f14e45f               Cookie: eyJzdWIiOiI0NDcxIn0.<sig>
              │                                      │
              ▼  look it up                          ▼  verify the signature
      ┌──────────────┐                        no lookup at all
      │ session store│
      └──────────────┘                        Revoke by...?
                                              There is nothing to delete.
      Revoke: DELETE. Instant. ✅             The token is self-validating. ❌
```

A self-contained token is a **signed statement about the past**: *"at 08:50, this user was
authenticated with these claims."* That statement remains true. The signature keeps
verifying because the bytes have not changed.

> **You cannot un-say something you signed. You can only stop honouring it — which requires
> checking something. Which is the lookup you were avoiding.**

That is not a flaw in JWTs. It is the definition of the property they provide
([E09](E09-should-you-use-jwts-for-sessions.md)).

---

## What must be revocable

Not everything, and knowing which is which saves effort:

| Event | Must revoke |
|---|---|
| User clicks logout | That session |
| User clicks "log out everywhere" | **All sessions** ([E13](E13-sessions-across-devices.md)) |
| Password changed or reset | **All sessions** ([D09](../track-d/D09-account-recovery.md)) |
| MFA added or removed | All sessions |
| Account disabled or deleted | **All sessions, all tokens, immediately** |
| Role or permission changed | Nothing structurally — but the cached claims are now wrong |
| Suspected compromise | **Everything, plus refresh families** ([I10](../track-i/I10-incident-response.md)) |
| User revokes a third-party app | That app's tokens ([F07](../track-f/F07-access-refresh-scopes.md)) |
| Refresh token reuse detected | **The whole family** ([E10](E10-token-lifetimes-and-rotation.md)) |
| Signing key compromised | **Every token signed with it** ([I06](../track-i/I06-key-rotation.md)) |

The row people underestimate is **role change**. It is not a security *revocation*, but a
demoted admin whose token still says `admin` is indistinguishable from one, for the token's
lifetime. This is the argument for keeping **permissions out of tokens** and looking them up
at the point of use ([H12](../track-h/H12-authz-in-microservices.md)).

---

## The five strategies

### 1. Server-side sessions — revocation by construction

```python
db.execute("DELETE FROM sessions WHERE id = %s", (session_hash,))
```

Instant, complete, no extra machinery. The lookup you were already doing *is* the revocation
check.

**This is why [E09](E09-should-you-use-jwts-for-sessions.md) recommends sessions for
first-party applications.** Revocation is not a feature you add; it is a consequence of the
design.

### 2. Short lifetimes — bound the window

If a token lives 5 minutes, the worst case is 5 minutes of unwanted access.

**This is the primary mechanism in OAuth**, and it is the same conclusion the web PKI
reached about certificates: revocation is unreliable, so **short lifetimes are the real
control** ([B15](../track-b/B15-certificates-and-pki.md)).

Combine with refresh tokens, which *are* revocable
([E10](E10-token-lifetimes-and-rotation.md)):

```
   Access token   5 min, unrevokable  ──> worst case: 5 minutes
   Refresh token  30 d, revocable     ──> DELETE stops all future access
```

**This is the answer for most token architectures.** Not "revoke the access token" — make
its life short enough that you do not need to.

### 3. A denylist — check the exceptions

Store revoked token IDs (`jti`) until they would have expired anyway.

```python
def is_revoked(claims) -> bool:
    return redis.exists(f"revoked:{claims['jti']}")

def revoke(claims):
    ttl = claims["exp"] - int(time.time())
    if ttl > 0:
        redis.setex(f"revoked:{claims['jti']}", ttl, "1")
```

The list stays small because entries expire with the tokens.

**But:** you now do a lookup on every request. If that lookup is against the same store your
session would have used, **you have built server-side sessions with extra steps and worse
properties** — the anti-pattern from [E08](E08-signed-cookies-vs-jwt-vs-opaque.md).

It is defensible when the lookup is much cheaper than a full session read (a bloom filter, a
replicated in-memory set) or only on high-value routes.

### 4. A version counter — revoke in bulk, cheaply

```python
# In the token:
{"sub": "4471", "tv": 7}         # token version

# On the user record:
users.token_version = 7

# On password change, "log out everywhere", role change:
UPDATE users SET token_version = token_version + 1 WHERE id = ...;

# At verification:
if claims["tv"] != user.token_version:
    raise Unauthorized()
```

One integer invalidates every token for that user at once. Cheap to store, cheap to bump.

The catch: **verifying it requires the user record.** If you are loading the user anyway —
which most applications are, for permissions — this is nearly free and genuinely useful. If
you are not, it reintroduces the lookup.

Best-of-both: put `token_version` in a small, highly-cached store keyed by user, separate
from the full user record.

### 5. Broadcast — push revocations to verifiers

Publish revocation events; verifiers keep a local set.

```
   Auth service ──> pub/sub ──> every service maintains a local denylist
```

Fast verification, no per-request lookup. The costs: eventual consistency (a service that
missed the message keeps accepting), state on every verifier, and a new distributed-systems
problem to operate.

Appropriate at large scale. Overkill below it.

---

## Choosing

| Architecture | Strategy |
|---|---|
| First-party web app | **Server-side sessions.** Free revocation. |
| SPA + your API | Session cookie, or short JWT + revocable refresh |
| Mobile + your API | Short access + rotating refresh with reuse detection |
| Microservices | **Short-lived JWTs (60 s–5 min) minted at the edge** — too short to need revocation |
| Third-party API | Short access + refresh + [RFC 7009](https://www.rfc-editor.org/rfc/rfc7009) revocation endpoint |
| Highest assurance | Sessions + introspection ([F12](../track-f/F12-introspection-vs-local-validation.md)) |

Read down that column: **most rows solve revocation by making the token's life short enough
that it does not matter.** That is the mature answer.

---

## The revocation endpoint (RFC 7009)

If you issue tokens to clients you do not control, give them a way to hand them back:

```http
POST /oauth/revoke
Content-Type: application/x-www-form-urlencoded
Authorization: Basic <client credentials>

token=8f14e45f...&token_type_hint=refresh_token
```

Three specification requirements that surprise people:

- **Always return `200`**, even for an unknown token. Otherwise the endpoint is an oracle
  for testing token validity.
- **Revoking a refresh token SHOULD revoke the access tokens issued from it** — which for
  self-contained tokens means the denylist or version counter above.
- **Authenticate the client.** Otherwise anyone can revoke anyone's tokens: a denial of
  service.

Related: [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) introspection lets a resource
server *ask* whether a token is still valid — trading local verification for a network call
and real revocation ([F12](../track-f/F12-introspection-vs-local-validation.md)).

---

## The lesson from certificates

The web PKI faced this exact problem twenty years earlier
([B15](../track-b/B15-certificates-and-pki.md)):

| Mechanism | Outcome |
|---|---|
| CRL — download a list of revoked certificates | Grew to megabytes. Abandoned. |
| OCSP — ask in real time | Latency, privacy leak, and **soft-fail**: unreachable responder → proceed |
| OCSP stapling | Better, still soft-fails without `Must-Staple` |
| Browser-pushed lists (CRLite) | Works — the vendor aggregates and pushes |
| **Short lifetimes** | **The actual answer.** 398 days → 47 days by 2029. |

An industry with enormous resources and twenty years of effort concluded that **revocation
does not work well, and short lifetimes are the reliable mechanism.**

Design your tokens with that in mind. If you find yourself building an elaborate revocation
system for long-lived tokens, consider making the tokens short instead.

---

## Terms defined in this chapter

`revocation`, `denylist`, `jti`

---

## What to remember

1. **You cannot un-sign a statement.** Revoking a self-contained token means checking
   something — the lookup you were avoiding.
2. **Server-side sessions get revocation for free.** It is a consequence, not a feature.
3. **Short lifetimes are the primary mechanism.** 5–15 minute access tokens plus a revocable
   refresh token.
4. **A denylist on every request is server-side sessions with worse properties.**
5. **A version counter** invalidates everything for one user with one integer — nearly free
   if you already load the user.
6. **Role changes are the underestimated case.** Keep permissions out of tokens.
7. RFC 7009: always `200`, revoke the descendants, authenticate the client.
8. **The web PKI concluded revocation does not work and shortened lifetimes instead.** Learn
   from it.

---

## Sources

- [RFC 7009 — OAuth 2.0 Token Revocation](https://www.rfc-editor.org/rfc/rfc7009)
- [RFC 7662 — OAuth 2.0 Token Introspection](https://www.rfc-editor.org/rfc/rfc7662)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §4.14
- [CA/Browser Forum — certificate lifetime reduction ballot SC-081](https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/)

---

**Next:** [E12 — Where to store a token in a browser: localStorage, cookie, memory](E12-where-to-store-a-token.md)
