# F10 — Client credentials: machine-to-machine auth

**Part F · Delegated authorization — OAuth 2** · *Builds on [F09](F09-public-vs-confidential-clients.md)*
---

## The client credentials grant

> **A confidential client obtains a token for *itself*, with no user involved.**

The simplest grant in OAuth — one back-channel request, no redirects, no browser:

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=client_credentials
&scope=invoices:read invoices:write
&resource=https://api.example.com          ← F08 — audience the token is for
```

```json
{
  "access_token": "2YotnFZFEjr1zCsicMWpAA",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "invoices:read invoices:write"
}
```

Note what is **absent**:

- **No `redirect_uri`** — nothing to redirect; there is no browser.
- **No user login, no consent** — the service *is* the principal.
- **No refresh token** — when it expires, just ask again. Cheap, and it removes a long-lived
  credential to protect ([E10](../track-e/E10-token-lifetimes-and-rotation.md)).

The principal is the **client itself** ([C03](../track-c/C03-the-vocabulary.md)). There is
no `sub` pointing at a human — the machine identity is the subject, which is why Track J
distinguishes machine identity from user identity so carefully
([J01](../track-j/J01-machine-identity-is-not-user-identity.md)).

---

## The client side

```python
import time, requests, threading

class ServiceClient:
    def __init__(self, token_url, client_id, client_secret, resource, scope):
        self._token_url = token_url
        self._auth = (client_id, client_secret)
        self._resource = resource
        self._scope = scope
        self._token = None
        self._expires_at = 0
        self._lock = threading.Lock()

    def _fetch(self):
        r = requests.post(self._token_url, data={
            "grant_type": "client_credentials",
            "scope": self._scope,
            "resource": self._resource,          # F08
        }, auth=self._auth, timeout=10)
        r.raise_for_status()
        t = r.json()
        self._token = t["access_token"]
        # Refresh EARLY — before expiry, to absorb clock skew and latency.
        self._expires_at = time.time() + t["expires_in"] - 60

    def token(self) -> str:
        with self._lock:
            if not self._token or time.time() >= self._expires_at:
                self._fetch()
            return self._token

    def get(self, url, **kw):
        return requests.get(url, headers={"Authorization": f"Bearer {self.token()}"}, **kw)

billing = ServiceClient(
    token_url="https://auth.example.com/token",
    client_id="billing-service",
    client_secret=os.environ["BILLING_CLIENT_SECRET"],    # A10 / I05
    resource="https://api.example.com",
    scope="invoices:read invoices:write",
)

invoices = billing.get("https://api.example.com/v1/invoices").json()
```

Three things that make this production-grade:

**Cache the token; do not fetch per request.** A token endpoint call per API call is slow and
hammers the AS. Cache until shortly before expiry.

**Refresh early** (the `- 60`). Refreshing exactly at expiry means in-flight requests fail
during the gap. A 60-second buffer absorbs skew and network latency.

**Thread-safe fetch.** Under concurrency, a naive check-then-fetch has every thread fetching
at once when the token expires. The lock (or a single-flight, as in
[E10](../track-e/E10-token-lifetimes-and-rotation.md)) prevents the stampede.

---

## Client credentials vs a plain API key

Both authenticate a machine. Why prefer the grant?

| | **API key** | **Client credentials** |
|---|---|---|
| Lifetime | Forever, until rotated | Short-lived access tokens |
| Sent on every request | The long-lived secret itself | A short-lived token |
| Leak impact | Full access until noticed and rotated | Access until the token expires (minutes) |
| Scopes | Usually all-or-nothing | Per-token scopes ([F07](F07-access-refresh-scopes.md)) |
| Audience | Often none | `aud` per resource ([F08](F08-audience-and-resource-indicators.md)) |
| Rotation | Manual, disruptive | The client credential rotates; tokens rotate automatically |
| Central control | Per-service | The AS is one place to revoke, audit, and observe |

The core advantage: **the long-lived secret is presented only to the AS, never to the
resource servers.** The thing crossing the wire on every API call is a short-lived, scoped,
audience-bound token. A leaked *token* expires in minutes; a leaked *API key* is valid until
someone notices ([J02](../track-j/J02-api-keys.md) covers doing API keys well when you must).

That said — API keys persist for good reasons (simplicity, no AS to run), and Track J does
not dismiss them. Client credentials is the better answer *when you already have an
authorization server*.

---

## Where the client secret lives

This is a confidential client ([F09](F09-public-vs-confidential-clients.md)), so it has a
real secret, and the secret is the whole security of the system.

| Storage | Verdict |
|---|---|
| Hardcoded / committed | ❌ [A10](../track-a/A10-where-secrets-live.md) |
| Environment variable | ⚠️ Baseline; leaks into crash dumps and child processes |
| **Secret manager** (Vault, cloud KMS) | ✅ [I05](../track-i/I05-secrets-management.md) |
| **Workload identity** (no static secret at all) | ✅✅ Best — below |

### The better answer: no static secret

Modern platforms let a workload prove *what it is* from where it runs, and exchange that for
a token — no shared secret to store, leak, or rotate:

- **Cloud IAM** (AWS IAM roles, GCP service accounts, Azure managed identities) — the
  platform attests the workload's identity.
- **SPIFFE/SPIRE** — a workload gets a short-lived certificate based on platform attestation
  ([J05](../track-j/J05-workload-identity-spiffe.md)).
- **`private_key_jwt`** ([F09](F09-public-vs-confidential-clients.md)) — the client signs
  with a private key; the AS holds only the public key, so an AS breach exposes nothing.

Prefer these where the platform offers them. A static `client_secret` is the fallback, not
the goal — the same lesson as [I05](../track-i/I05-secrets-management.md): the best secret is
the one you never have to store.

---

## Authorization for machines

A token proves the *service* is who it says. It does not authorize the specific action — the
resource server still checks scope and, where relevant, which objects
([H12](../track-h/H12-authz-in-microservices.md)).

Two failure modes specific to M2M:

**Over-scoped service accounts.** A service that needs `invoices:read` requests
`invoices:*` "to be safe." Now a compromise of that service is a compromise of write access.
Least privilege applies to machines too ([J03](../track-j/J03-service-accounts.md)).

**No per-object checks between services.** "It came from the billing service, so it's
trusted" is the internal version of "they're logged in, so let them through"
([C02](../track-c/C02-authn-vs-authz-vs-session.md)). A compromised or buggy service can
request anything within its scope; the resource server must still enforce boundaries
([H12](../track-h/H12-authz-in-microservices.md)).

---

## Terms defined in this chapter

`client credentials grant`

---

## What to remember

1. **Client credentials is OAuth with no user.** The service is the principal.
2. **No redirect, no consent, no refresh token** — one back-channel request; re-request on
   expiry.
3. Only **confidential clients** can use it — it depends on a real client credential.
4. **Cache the token, refresh early, fetch under a lock.** Do not call the token endpoint
   per request.
5. Better than a plain API key because the **long-lived secret goes only to the AS**; the
   wire carries short-lived, scoped, audience-bound tokens.
6. **Prefer workload identity or `private_key_jwt`** over a static `client_secret`. The best
   secret is one you never store.
7. A machine token authenticates the service; the resource server still authorizes the
   action.

---

## Sources

- [RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4) — client credentials grant
- [RFC 7523 — JWT client authentication and grants](https://www.rfc-editor.org/rfc/rfc7523)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700)
- [SPIFFE](https://spiffe.io/) — workload identity without shared secrets

---

**Next:** [F11 — The device flow: how your TV logs in](F11-device-flow.md)
