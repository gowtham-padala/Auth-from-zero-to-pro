# F06 — PKCE: what it fixes, and why it's mandatory now

**Part F · Delegated authorization — OAuth 2** · *Builds on [F04](F04-build-oauth-client-raw-http.md), [B04](../track-b/B04-what-a-hash-function-is.md)*
*Pronounced "pixie."*

---

## The attack it stops

A mobile app does OAuth. The authorization code comes back to the app via a custom URL
scheme:

```
myapp://callback?code=SplxlOBeZQQYbYS6WxSbIA
```

The problem: **any app on the phone can register `myapp://`**
([F18](F18-oauth-for-mobile.md)). A malicious app registers the same scheme, the OS delivers
the code to *both* apps, and the malicious one races to the token endpoint.

For a public client there is no client secret to stop it ([F09](F09-public-vs-confidential-clients.md)) —
the "secret" would be in the app binary, readable by anyone
([A07](../track-a/A07-client-vs-server.md)). So the attacker exchanges the stolen code and
gets the user's tokens.

**PKCE closes this in one move:** the code becomes useless to anyone who did not start the
flow. The malicious app has the code and cannot use it.

---

## The idea

**Proof Key for Code Exchange** ([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)): the
client proves, at the token exchange, that it is the same client that started the
authorization request — using a one-time secret it never sent over the front channel.

```
   START OF FLOW                          END OF FLOW
   ─────────────                          ───────────
   Make a secret:   code_verifier         Prove you have it:
   Send its HASH:   code_challenge   ─┐    send the verifier
   (front channel, exposed)           │    (back channel, private)
                                      │
                    AS remembers ─────┘    AS checks:
                    the challenge          SHA256(verifier) == challenge?
```

The **verifier** is a fresh random secret the client keeps. The **challenge** is its
SHA-256 hash ([B04](../track-b/B04-what-a-hash-function-is.md)), sent in the authorization
request. Because a hash is one-way, an attacker who intercepts the *challenge* on the front
channel cannot derive the *verifier* — so they cannot complete the exchange.

It is the same trick as a password hash ([D03](../track-d/D03-how-to-store-passwords.md)):
prove you know a secret by presenting it, having earlier committed to its hash.

---

## The whole thing

```python
import secrets, hashlib, base64

def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()   # B02

# ── At the START of the flow ───────────────────────────────────────────────
code_verifier = b64url(secrets.token_bytes(32))     # 43 chars, high entropy. B03
code_challenge = b64url(hashlib.sha256(code_verifier.encode()).digest())

# Store the VERIFIER server-side (or in secure app storage). Send the CHALLENGE.
session["code_verifier"] = code_verifier

# Authorization request:
params = {
    "response_type":         "code",
    "client_id":             CLIENT_ID,
    "redirect_uri":          REDIRECT_URI,
    "scope":                 SCOPE,
    "state":                 state,                  # F05
    "code_challenge":        code_challenge,         # the hash
    "code_challenge_method": "S256",                 # ← ALWAYS S256, never "plain"
}

# ── At the token EXCHANGE (back channel) ───────────────────────────────────
resp = requests.post(TOKEN_URL, data={
    "grant_type":    "authorization_code",
    "code":          code,
    "redirect_uri":  REDIRECT_URI,
    "code_verifier": session["code_verifier"],       # the secret itself
    "client_id":     CLIENT_ID,
})
# The AS computes SHA256(code_verifier) and checks it equals the code_challenge
# it stored with the code. Mismatch → the exchange fails.
```

That is PKCE. Two extra parameters going out, one coming back, one hash computed on each
side.

---

## The `code_verifier`

Requirements from the RFC, and why they are what they are:

- **43 to 128 characters** from the unreserved set `[A-Z a-z 0-9 - . _ ~]`.
- **High entropy** — at least 256 bits, from a CSPRNG ([B03](../track-b/B03-randomness.md)).
  `b64url(token_bytes(32))` gives exactly 43 characters of 256-bit entropy.
- **Fresh per flow.** Never reused. It is a one-time secret.

The entropy requirement is the point. If the verifier were guessable, an attacker who
intercepts the code could brute-force the verifier and complete the exchange. 256 bits makes
that impossible ([B01](../track-b/B01-bits-bytes-text-as-numbers.md)).

---

## S256 vs plain — the downgrade trap

The RFC defines two challenge methods:

| Method | `code_challenge` is | Secure? |
|---|---|---|
| **`S256`** | `BASE64URL(SHA256(verifier))` | ✅ **Use this** |
| `plain` | the verifier itself | ❌ No hashing — an intercepted challenge *is* the verifier |

`plain` exists only for clients that genuinely cannot compute SHA-256, which in 2026 is
essentially none. With `plain`, the challenge and verifier are identical, so intercepting
the front-channel challenge hands the attacker the verifier — PKCE provides nothing.

### The downgrade attack

The subtle danger: even if you send `S256`, a man-in-the-middle could try to *rewrite* your
request to `plain`, or strip PKCE entirely.

**Defences, layered:**

1. **The client always uses `S256`.** Never offer `plain`.
2. **The AS must reject `plain` if it advertised S256 support**, and must reject a token
   exchange with no verifier if the authorization request had a challenge — you cannot drop
   PKCE mid-flow.
3. **The AS binds the method to the code**, so the exchange is checked against the method the
   *request* used, not one the attacker substitutes.

This is a general pattern worth naming: a **downgrade attack** forces the weaker of two
options both parties support. The fix is always for each side to *pin* the strong option
rather than negotiate ([B12](../track-b/B12-key-exchange.md), [E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)).

---

## Why it is now mandatory for *everyone*

PKCE was designed in 2015 for public clients — mobile and SPA — which have no client secret.
The current guidance ([RFC 9700](https://www.rfc-editor.org/rfc/rfc9700), and OAuth 2.1)
requires it for **confidential clients too**. Two reasons:

**1. Defence in depth for the code.** Even a confidential client's authorization code can
leak — through a misconfigured proxy, a `Referer` header, a browser extension, a shared
device. The client secret protects the *exchange*, but PKCE additionally makes the *code
itself* useless to an interceptor. Two independent protections
([C04](../track-c/C04-threat-modeling.md)).

**2. It closes injection attacks.** Without PKCE, an attacker who obtains *any* valid code
for your client (from a different, less careful flow) can inject it into a victim's session.
PKCE binds each code to the specific verifier of the flow that produced it, so a code from
one flow cannot be used in another.

> **The rule as of 2026: use PKCE on every authorization code flow, public or confidential,
> web or mobile or SPA. No exceptions.**

If a provider or SDK does not support it, that is a signal about how current they are.

---

## PKCE vs `state` vs client secret

Three things that all touch the front channel, doing three different jobs
([F05](F05-the-state-parameter.md)):

| | Protects | Checked by | Even helps public clients? |
|---|---|---|---|
| **Client secret** | Proves *which app* exchanges the code | AS | ❌ they have none |
| **PKCE** | Proves *the same client instance* that started the flow | AS | ✅ **its whole reason** |
| **`state`** | Proves the callback belongs to *this browser* | Client | ✅ |

Notice PKCE and the client secret are complementary, not alternatives:

- **Confidential client:** secret (which app) **+** PKCE (same instance, defence in depth).
- **Public client:** PKCE **alone** — there is no secret, so PKCE is the only thing standing
  between an intercepted code and stolen tokens.

That is why mobile code interception is a PKCE problem specifically: the
malicious app cannot produce the verifier, so the code it stole is inert.

---

## The AS side

When you build an authorization server ([F14](F14-build-an-authorization-server.md)), PKCE
is straightforward:

```python
# At /authorize: store the challenge WITH the code.
codes[code] = {
    "client_id":       client_id,
    "redirect_uri":    redirect_uri,
    "code_challenge":  request.args["code_challenge"],
    "challenge_method": request.args.get("code_challenge_method", "plain"),
    "expires_at":      now() + 60,
    "used":            False,
}

# At /token: verify.
entry = codes.get(code)
verifier = request.form.get("code_verifier")

if entry["challenge_method"] == "S256":
    computed = b64url(hashlib.sha256(verifier.encode()).digest())
elif entry["challenge_method"] == "plain":
    computed = verifier
else:
    abort(400, "unsupported challenge method")

if not secrets.compare_digest(computed, entry["code_challenge"]):   # B16
    abort(400, "invalid_grant")     # PKCE verification failed
```

And the requirement that makes it robust: **if a challenge was present at `/authorize`, a
verifier MUST be present at `/token`** — otherwise an attacker downgrades by simply omitting
it.

---

## Terms defined in this chapter

`PKCE`, `code_verifier`, `code_challenge`, `S256`, `downgrade attack`

---

## What to remember

1. **PKCE makes an intercepted authorization code useless** to anyone who did not start the
   flow.
2. **Verifier = a fresh 256-bit secret. Challenge = its SHA-256.** Send the hash, prove with
   the secret.
3. **Always `S256`, never `plain`.** With `plain`, the challenge *is* the verifier.
4. **Mandatory for everyone now** — public *and* confidential, web and mobile and SPA. No
   exceptions.
5. For **public clients it is the only defence** for the code exchange; for confidential
   clients it is defence in depth.
6. **PKCE, `state`, and the client secret** defend three different things. Use all that
   apply.
7. The AS must **reject a missing verifier** when a challenge was sent, or the protection is
   downgradable.

---

## Sources

- [RFC 7636 — Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §2.1.1 (PKCE for all clients)
- [The OAuth 2.1 draft §4.1.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) — PKCE required
- Aaron Parecki, [oauth.com — PKCE](https://www.oauth.com/oauth2-servers/pkce/)

---

**Next:** [F07 — Access tokens, refresh tokens, and scopes](F07-access-refresh-scopes.md)
