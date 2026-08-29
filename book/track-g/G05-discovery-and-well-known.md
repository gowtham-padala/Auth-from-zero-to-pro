# G05 — Discovery and .well-known: how clients configure themselves

**Part G · Federated identity & SSO** · *Builds on [G04](G04-validate-an-id-token-by-hand.md)*
---

## Why it matters

A team integrates with an IdP by hardcoding its endpoints from the documentation:

```python
AUTHORIZE_URL = "https://auth.vendor.com/oauth/authorize"
TOKEN_URL     = "https://auth.vendor.com/oauth/token"
JWKS_URI      = "https://auth.vendor.com/oauth/keys"
```

Eighteen months later the vendor migrates infrastructure and moves the JWKS to a new host.
Every login breaks. The hardcoded URL points at a 404, so no key can be fetched, so no ID
token can be validated ([G04](G04-validate-an-id-token-by-hand.md)).

Had they used **discovery**, the client would have picked up the new endpoint automatically.
Discovery is how a client learns *everything* about a provider from one URL — and it is how
"log in with any OIDC provider" becomes a single code path instead of a per-vendor
integration.

---

## The discovery document

Every OIDC provider publishes its configuration at a standard URL:

```
https://accounts.google.com/.well-known/openid-configuration
```

The pattern is fixed: **`{issuer}/.well-known/openid-configuration`**. Fetch it, and you get
a JSON document describing the entire provider:

```json
{
  "issuer": "https://accounts.google.com",
  "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
  "token_endpoint": "https://oauth2.googleapis.com/token",
  "userinfo_endpoint": "https://openidconnect.googleapis.com/v1/userinfo",
  "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
  "response_types_supported": ["code", "token", "id_token", ...],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "scopes_supported": ["openid", "email", "profile"],
  "claims_supported": ["sub", "email", "email_verified", "name", ...],
  "code_challenge_methods_supported": ["S256"],
  "revocation_endpoint": "https://oauth2.googleapis.com/revoke",
  "end_session_endpoint": "https://.../logout"
}
```

Everything a client needs is here: where to send users, where to exchange codes, where to get
keys, what algorithms and scopes are supported, and how to log out. One fetch replaces a
dozen hardcoded values.

---

## `.well-known` — the convention

`.well-known/` ([RFC 8615](https://www.rfc-editor.org/rfc/rfc8615)) is a reserved path prefix
for machine-readable metadata, hosted at the root of a domain. You have met several already,
and will meet more:

| Path | Purpose | Chapter |
|---|---|---|
| `/.well-known/openid-configuration` | OIDC discovery | here |
| `/.well-known/oauth-authorization-server` | OAuth server metadata (RFC 8414) | [J08](../track-j/J08-mcp-and-oauth-21.md) |
| `/.well-known/oauth-protected-resource` | Resource server metadata (RFC 9728) | [J08](../track-j/J08-mcp-and-oauth-21.md) |
| `/.well-known/jwks.json` | Public signing keys | [E07](../track-e/E07-jose-family.md) |
| `/.well-known/assetlinks.json` | Android App Links | [F18](../track-f/F18-oauth-for-mobile.md) |
| `/.well-known/apple-app-site-association` | iOS Universal Links | [F18](../track-f/F18-oauth-for-mobile.md) |
| `/.well-known/security.txt` | Security contact | — |
| `/.well-known/webauthn` | WebAuthn Related Origins | [D14](../track-d/D14-webauthn-and-passkeys-concepts.md) |

The pattern is the same everywhere: a well-known URL, a JSON (or signed) document, fetched by
machines to self-configure. It is the mechanism that lets ecosystems interoperate without
per-partner setup.

---

## Using discovery

```python
import requests, time
from jwt import PyJWKClient

class OIDCProvider:
    def __init__(self, issuer: str):
        self.issuer = issuer
        self._config = None
        self._config_fetched = 0
        self._jwks = None

    def config(self) -> dict:
        # Cache, but refresh periodically — endpoints and keys can change.
        if not self._config or time.time() - self._config_fetched > 3600:
            url = f"{self.issuer.rstrip('/')}/.well-known/openid-configuration"
            self._config = requests.get(url, timeout=10).json()

            # ── Validate the document. It is a trust anchor. ──
            if self._config["issuer"] != self.issuer:            # ① iss must match
                raise SecurityError("issuer mismatch in discovery document")
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                if not self._config[key].startswith("https://"):  # ② HTTPS only
                    raise SecurityError(f"{key} is not HTTPS")

            self._config_fetched = time.time()
        return self._config

    def jwks_client(self) -> PyJWKClient:
        if self._jwks is None:
            self._jwks = PyJWKClient(self.config()["jwks_uri"],
                                     cache_keys=True, lifespan=3600)   # E07
        return self._jwks

google = OIDCProvider("https://accounts.google.com")
authorize_url = google.config()["authorization_endpoint"]
signing_key = google.jwks_client().get_signing_key_from_jwt(id_token)   # G04
```

Now a new provider is *three lines*:

```python
microsoft = OIDCProvider("https://login.microsoftonline.com/{tenant}/v2.0")
okta      = OIDCProvider("https://your-org.okta.com")
```

Same code, any compliant provider. That is the payoff.

---

## The security of discovery

The discovery document tells your client **where to send users to log in and where to get the
keys that validate their identity.** If an attacker controls it, they control your
authentication. Treat it as a trust anchor, not convenience data.

```
☐  Fetch over HTTPS, from the issuer you configured — never a URL from a token   G04
☐  Verify config["issuer"] EXACTLY matches the issuer you requested     ← ①
☐  Verify every endpoint is HTTPS                                        ← ②
☐  Pin the issuer in configuration; discovery fills in the details, not the identity
☐  Cache, but re-fetch periodically so key/endpoint rotation is picked up
☐  Handle fetch failure gracefully — a cached copy beats a broken login
```

The critical distinction: **you configure the *issuer*; discovery provides the *endpoints*.**
The issuer is the identity you trust ([G01](G01-sign-in-with-google.md)); the endpoints are
implementation details that may move. Never let a token or a redirect tell you which issuer to
trust — that is the mix-up attack ([F20](../track-f/F20-attack-your-own-oauth.md)).

The `issuer` field in the document *must* equal the URL you derived it from
(`{issuer}/.well-known/...`). A mismatch means either misconfiguration or an attack; reject
it either way. This is a real requirement in the OIDC discovery spec, and skipping it has
enabled impersonation attacks.

---

## Caching and rotation

Discovery interacts with key rotation ([I06](../track-i/I06-key-rotation.md)):

- **The JWKS is the volatile part.** Providers rotate signing keys regularly, publishing both
  old and new in the JWKS during the overlap ([E07](../track-e/E07-jose-family.md)). Your
  cache must respect the `Cache-Control` on the JWKS and refetch on an unknown `kid`.
- **The discovery document changes rarely** — endpoints are stable — so a longer cache (an
  hour) is fine, with periodic refresh.
- **Never cache forever.** The hardcoding example at the top of this chapter is what "cache
  forever" becomes. A provider migration should heal automatically within your cache TTL.

The balance: cache aggressively enough to avoid a network round trip per login, freshly enough
that a key or endpoint change is picked up before it breaks you.

---

## What you still configure by hand

Discovery gives you the *provider's* metadata. It does not give you *your* side:

- **Your `client_id` and `client_secret`** — from registering with the provider
  ([F09](../track-f/F09-public-vs-confidential-clients.md)). (Dynamic client registration
  can automate even this — [J08](../track-j/J08-mcp-and-oauth-21.md).)
- **Your `redirect_uri`(s)** — registered with the provider.
- **The scopes you request** — from `scopes_supported`, but you choose which
  ([F07](../track-f/F07-access-refresh-scopes.md)).
- **The issuer itself** — the one value you must configure and pin.

---

## Terms defined in this chapter

`discovery`, `.well-known`, `openid-configuration`

---

## What to remember

1. **`{issuer}/.well-known/openid-configuration`** returns everything a client needs —
   endpoints, keys, supported algorithms and scopes.
2. **Discovery turns "log in with any OIDC provider" into one code path.** A new provider is
   three lines.
3. `.well-known/` is a general convention — OIDC, OAuth metadata, JWKS, App Links, WebAuthn
   all use it.
4. **The discovery document is a trust anchor.** Fetch over HTTPS, verify `issuer` matches,
   verify endpoints are HTTPS.
5. **You configure the issuer; discovery provides the endpoints.** Never let a token choose
   the issuer.
6. **Cache, but re-fetch.** Hardcoding endpoints is how a provider migration breaks every
   login.
7. The JWKS is the volatile part — respect its cache headers and refetch on a `kid` miss.

---

## Sources

- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 8414 — OAuth 2.0 Authorization Server Metadata](https://www.rfc-editor.org/rfc/rfc8414)
- [RFC 8615 — Well-Known Uniform Resource Identifiers](https://www.rfc-editor.org/rfc/rfc8615)

---

**Next:** [G06 — Claims vs scopes, and the UserInfo endpoint](G06-claims-vs-scopes-userinfo.md)
