# E08 — Signed cookies vs JWTs vs opaque tokens: pick one

**Part E · Sessions & tokens** · *Builds on [E04](E04-session-ids.md), [E06](E06-jwt-part-2-signature-jws-jwe.md)*
---

## The three options

```
  1. OPAQUE / REFERENCE                 2. SIGNED COOKIE                3. JWT
  ─────────────────────                 ─────────────────               ──────
  Cookie: session=8f14e45f              Cookie: s=user:4471|<hmac>       Cookie: s=eyJ...
             │                                     │                            │
             ▼ look it up                          ▼ verify HMAC                 ▼ verify sig
     ┌───────────────┐                     data is IN the cookie          claims are IN
     │ session store │                     (small, one party)             the token
     └───────────────┘                                                    (standard, portable)
```

They differ on exactly two axes:

**Does the credential *carry* data, or *point at* it?**
**Who can verify it?**

Everything else follows.

---

## The comparison

| | **Opaque** | **Signed cookie** | **JWT** |
|---|---|---|---|
| Client holds | A random 256-bit string | Data + HMAC tag | Claims + signature |
| Size | ~44 bytes | ~100–300 bytes | **500–1500 bytes** |
| Server lookup | **Every request** | None | None |
| Who can verify | Only you | Only key holders | **Anyone with the public key** |
| **Revocation** | ✅ **Instant — `DELETE`** | ❌ Hard | ❌ **Hard** ([E11](E11-revocation.md)) |
| Claims freshness | ✅ Always current | ❌ Stale until reissued | ❌ Stale until expiry |
| Change a role | ✅ Takes effect immediately | ❌ Wait for reissue | ❌ Wait for expiry |
| Readable by the user | ✅ Nothing to read | ⚠️ Yes | ⚠️ **Yes** ([E05](E05-jwt-part-1-three-parts.md)) |
| Cross-service | ❌ Needs your store | ❌ Needs the secret | ✅ **Public key only** |
| Cross-organisation | ❌ | ❌ | ✅ |
| Standardised | ❌ Yours | ❌ Framework-specific | ✅ RFC 7519 |
| Implementation risk | **Very low** | Low | **Moderate** ([E06](E06-jwt-part-2-signature-jws-jwe.md)) |
| Offline verification | ❌ | ✅ | ✅ |

Two rows carry the decision.

**Revocation.** Opaque wins outright. This is the property teams discover they need on the
day they need it urgently.

**Cross-boundary verification.** JWT wins outright. This is the property that justifies
every cost above it.

If you do not need the second, you are paying for it and getting nothing.

---

## Signed cookies, briefly

The forgotten middle option, and often the right one.

```python
import hmac, hashlib, base64, json, secrets

SECRET = os.environ["COOKIE_SECRET"].encode()

def sign(payload: dict) -> str:
    body = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=")
    tag  = hmac.new(SECRET, body, hashlib.sha256).digest()[:16]
    return f"{body.decode()}.{base64.urlsafe_b64encode(tag).rstrip(b'=').decode()}"

def unsign(value: str) -> dict | None:
    try:
        body, tag = value.rsplit(".", 1)
        expected = hmac.new(SECRET, body.encode(), hashlib.sha256).digest()[:16]
        got = base64.urlsafe_b64decode(tag + "=" * (-len(tag) % 4))
        if not hmac.compare_digest(expected, got):     # B16 — constant time
            return None
        return json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    except Exception:
        return None
```

This is what Django's `SECRET_KEY`, Rails' `secret_key_base`, and Flask's signed sessions
do. It is a JWT without the JOSE machinery: smaller, simpler, and with **no `alg` field to
attack**, because the algorithm is a constant in your code.

**Use it when:** one application, one secret, small data, and you want stateless sessions
without the JWT footguns.

**Do not use it when:** more than one party must verify — the shared HMAC secret means every
verifier can forge ([B13](../track-b/B13-message-authentication-hmac.md)).

---

## The decision tree

```
Does anything OUTSIDE your application need to verify this credential?
│
├── NO ──> Do you need instant revocation, or fresh claims?
│          │
│          ├── YES ──────────> ✅ OPAQUE + server-side session
│          │                      (the default for first-party web apps)
│          │
│          └── NO ───────────> ✅ SIGNED COOKIE
│                                 (rare; only when the store is a real cost)
│
└── YES ─> Are the verifiers inside your trust boundary?
           │
           ├── YES ──────────> ✅ JWT with ES256, short-lived (5–15 min)
           │                      + a refresh mechanism  (E10)
           │
           └── NO ───────────> ✅ JWT with ES256, published JWKS
              (other orgs)        + strict `aud`  (F08)
```

**The most common correct answer is the top branch: opaque tokens with server-side
sessions.** It is what most applications need and what most applications talk themselves out
of.

---

## The hybrid that most real systems land on

You do not have to pick once. The pattern that works at scale:

```
   Browser ──[opaque session cookie]──> Your BFF / gateway
                                              │
                                              │ look up the session (E03)
                                              │ mint a short-lived JWT (60s–5min)
                                              ▼
                                        Internal services
                                        verify the JWT locally,
                                        no store access needed
```

You get:

- **Instant revocation** at the edge — delete the session and the next request mints nothing.
- **No store lookups** in internal services.
- **A small cookie** in the browser.
- **Nothing readable** by the user.
- **Short-lived internal tokens**, so their staleness window is seconds.

The revocation problem disappears because the JWT's lifetime is shorter than any reasonable
revocation latency. This is the backend-for-frontend pattern
([F17](../track-f/F17-oauth-for-spas-and-bff.md)) and it is what most mature architectures
converge on.

---

## Cost you should actually count

The argument for JWTs is usually "avoid a database lookup." Measure both sides:

| Operation | Typical cost |
|---|---|
| Redis `GET` (same datacentre) | **0.2–0.5 ms** |
| Postgres primary-key lookup (warm) | 0.5–2 ms |
| **HS256 verify** | ~0.01 ms |
| **ES256 verify** | ~0.05–0.2 ms |
| **RS256 verify** | 0.1–0.5 ms |
| RS256 **sign** | 1–5 ms |

**An RS256 verification can cost more than a Redis lookup** — and it burns your
application's CPU, whereas the lookup is handled by a store built for it.

The real JWT advantage is not speed. It is **not needing to reach the store at all**: from
an edge function, another company's service, or a network partition. If your verifier is
already talking to your database on the same request, "avoiding the lookup" is not a
benefit you are receiving.

---

## Anti-patterns

**JWT + a revocation list on every request.** The worst of both worlds — you pay both costs.

**JWTs with a 24-hour lifetime.** A stolen token is valid for a day, and a fired employee
keeps access for a day. If you use JWTs, make them short (5–15 minutes) and refresh
([E10](E10-token-lifetimes-and-rotation.md)).

**Putting permissions in the JWT.** They go stale, they grow the token toward `431`, and
revoking a permission requires revoking the token. Put the **identity** in the token and
look up **permissions** at the point of use ([H12](../track-h/H12-authz-in-microservices.md)).

**Using an OAuth access token as your web session.** Different lifetime, different audience,
different revocation semantics. Exchange it for your own session at login
([G01](../track-g/G01-sign-in-with-google.md)).

**Storing a JWT in `localStorage` because "it's stateless."** Statelessness is about the
*server*. Where the client stores it is an independent decision, and `localStorage` is the
worse one ([E12](E12-where-to-store-a-token.md)).

---

## Terms defined in this chapter

`opaque token`, `reference token`, `self-contained token`, `signed cookie`

---

## What to remember

1. Two axes: **carry or point at data**, and **who can verify**. Everything else follows.
2. **Opaque wins on revocation and freshness. JWT wins on cross-boundary verification.**
   Pick the property you actually need.
3. **JWT + a per-request revocation check is server-side sessions, badly.**
4. **Signed cookies are the forgotten middle** — a JWT without the `alg` attack surface,
   for single-party use.
5. **Opaque + server-side session is the right default for first-party web applications.**
6. **The hybrid** — opaque at the edge, short-lived JWTs internally — is where mature
   systems land.
7. **RS256 verification can cost more than a Redis lookup.** The advantage is reach, not
   speed.
8. Identity in the token; **permissions looked up at the point of use.**

---

## Sources

- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [RFC 8725 — JWT Best Current Practices](https://www.rfc-editor.org/rfc/rfc8725)
- [RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens](https://www.rfc-editor.org/rfc/rfc9068)

---

**Next:** [E09 — Should you use JWTs for sessions?](E09-should-you-use-jwts-for-sessions.md)
