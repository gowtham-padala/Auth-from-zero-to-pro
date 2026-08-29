# H12 — Authorization in microservices: who decides, and where?

**Part H · Authorization** · *Builds on [H02](H02-the-enforcement-point.md), [F08](../track-f/F08-audience-and-resource-indicators.md)*
---

## Why it matters

A microservices architecture. The API gateway authenticates the user and checks
authorization. The internal services, sitting behind the gateway, trust every request that
reaches them:

```python
# The `orders` service, internal:
@app.get("/orders/<id>")
def get_order(id):
    return db.get_order(id)      # no auth — "the gateway already checked"
```

Then: a bug in *another* service makes an internal call to `orders` with a manipulated user
ID. Or an attacker finds an SSRF ([A07](../track-a/A07-client-vs-server.md)) that lets them
reach the internal network. Or a compromised service pivots. In every case, `orders` hands over
data, because it assumed the perimeter did its job — and **"internal" is not a security
property** ([A07](../track-a/A07-client-vs-server.md)).

Distributing your application across services distributes the authorization problem too, and
"the gateway checked it" is the microservices version of "they're logged in, so let them
through" ([C02](../track-c/C02-authn-vs-authz-vs-session.md)).

---

## The core question: who decides, and where?

A request now crosses many services. At each hop, three questions
([H01](H01-where-does-authz-live.md)):

1. **Who is the caller?** — another service, and/or a user on whose behalf it acts.
2. **May this action happen?** — the authorization decision.
3. **Who makes that decision, and who enforces it?** — PDP and PEP, now spread across a
   network.

The example above answers #3 with "only the gateway," which leaves every internal service
defenceless the moment something reaches it another way.

---

## Rule 1: every service authenticates its callers (zero trust)

The perimeter is not the boundary. **Each service must verify who is calling it**, even for
internal traffic — this is **zero trust** applied to your own network
([C04](../track-c/C04-threat-modeling.md)).

Two identities travel on an internal call, and both matter
([F19](../track-f/F19-token-exchange.md)):

```
   ┌──────────────────────────────────────────────────────────┐
   │  WHO is calling?                                          │
   │    • the SERVICE   (which workload)  ──> mTLS / SPIFFE    │  J04 / J05
   │    • the USER      (on whose behalf) ──> a token          │  F07
   └──────────────────────────────────────────────────────────┘
```

- **Service identity** — prove *which workload* is calling. **mTLS** ([J04](../track-j/J04-mtls.md))
  or **SPIFFE/SPIRE** ([J05](../track-j/J05-workload-identity-spiffe.md)) give each service a
  cryptographic identity, so `orders` knows the call is genuinely from `checkout`, not an
  impostor on the network.
- **User context** — a token carrying *the user's* identity, so `orders` can authorize
  per-user, not just "some trusted service asked."

### Do NOT trust unsigned identity headers

The tempting shortcut is a header: `X-User-Id: 4471`. **This is an authentication bypass**
([A04](../track-a/A04-headers.md)) — any service (or anything that reaches the network) sets
the header to any value. If internal services trust `X-User-Id`, the whole mesh's security is
one forged header.

The fixes:

- **A signed token** (JWT) that each service *validates* ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md))
  — the user identity is authenticated, not asserted.
- **Or headers injected by a trusted mesh** that *strips inbound copies at the edge*
  ([A04](../track-a/A04-headers.md)) — so an attacker's `X-User-Id` never survives to an
  internal service.

---

## Rule 2: pass the right token, with the right audience

The token an internal service receives must be *for it* ([F08](../track-f/F08-audience-and-resource-indicators.md)).
The opening example's cousin: forwarding the user's original gateway token to every downstream
service — **token passthrough** — which either fails the `aud` check (if the downstream checks)
or succeeds insecurely (if it doesn't), the confused-deputy attack
([F08](../track-f/F08-audience-and-resource-indicators.md)).

The correct pattern is **token exchange** ([F19](../track-f/F19-token-exchange.md)): at each
hop, exchange the incoming token for one scoped and audienced for the next service, carrying
the user as `sub` (and, for accountability, the calling service as `act`):

```
   Gateway ──[token: aud=gateway]──> checkout
   checkout exchanges → [token: aud=orders, sub=user, act=checkout] ──> orders
   orders validates aud==orders, authorizes for the user
```

Each service validates `aud`, `iss`, `exp`, and the signature ([G04](../track-g/G04-validate-an-id-token-by-hand.md)),
then authorizes. No token is usable anywhere but where it was issued for.

---

## Rule 3: decide centrally, enforce locally (PDP/PEP, distributed)

Where does the *decision* live now? The [H01](H01-where-does-authz-live.md)/[H02](H02-the-enforcement-point.md)
split scales to microservices as **"centralise the decision, distribute the enforcement":**

```
   ┌────────────── central PDP (or its policy) ──────────────┐
   │  the RULES live in ONE place (a policy repo/engine)      │  H11
   └──────────────────────────┬──────────────────────────────┘
                              │ distributed to...
   ┌──────────┐   ┌──────────┐   ┌──────────┐
   │ orders   │   │ payments │   │ inventory│   each service = a PEP
   │ + sidecar│   │ + sidecar│   │ + sidecar│   asks the local PDP, enforces
   └──────────┘   └──────────┘   └──────────┘
```

The common architecture ([H11](H11-opa-cedar-or-sql.md)):

- **Policy lives centrally** — one repo, one source of truth, versioned and tested (the PAP,
  [H01](H01-where-does-authz-live.md)).
- **A local decision point** — an OPA/Cedar **sidecar** next to each service
  ([H11](H11-opa-cedar-or-sql.md)) evaluates policy *locally*, so there's no network hop per
  check and no single point of failure.
- **Each service enforces** — it calls its sidecar (PDP) and blocks (PEP), failing closed
  ([H02](H02-the-enforcement-point.md)).

This gives you central *governance* (change a policy once) with local *evaluation* (fast, no
per-request round trip to a distant PDP). It is why "who decides, and where?" has a two-part
answer: **the rules are decided centrally; the decision is *computed* and *enforced*
locally.**

The alternative — a central authorization *service* every request calls ([H08](../track-h/H08-model-drive-in-openfga.md))
— is right for ReBAC/relationship data (which is inherently central), but adds a network
dependency on the hot path. Many systems combine them: OPA sidecars for policy, a central
ReBAC service for relationship checks.

---

## The service mesh

A **service mesh** (Istio, Linkerd) provides much of rules 1–3 as infrastructure
([J04](../track-j/J04-mtls.md)):

- **Automatic mTLS** between services — service identity for free.
- **Policy enforcement** at the sidecar proxy — coarse authorization (which service may call
  which) without app code.
- **Identity propagation** — carrying user context safely.

The mesh handles *service-to-service* authentication and coarse routing well. It does **not**
know your objects — "may user 4471 read order 88?" is application-level and stays in your
service ([H02](H02-the-enforcement-point.md)). The mesh is the perimeter *between* services;
your code is still the object-level PEP.

---

## Don't put fine-grained permissions in the token

A tempting shortcut: stuff all the user's permissions into the JWT so services don't have to
look them up. Resist it ([E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md),
[E11](../track-e/E11-revocation.md)):

- **Stale claims** — revoke a permission and the token still grants it until expiry
  ([E11](../track-e/E11-revocation.md)).
- **Token bloat** — permissions grow the token toward header limits
  ([E05](../track-e/E05-jwt-part-1-three-parts.md)).
- **Coupling** — every service now depends on the token's permission format.

**Put *identity* in the token; look up *permissions* at the point of use**
([E08](../track-e/E08-signed-cookies-vs-jwt-vs-opaque.md)) — from the local PDP, which reads
current policy and current grants. Identity is stable; permissions change.

---

## Terms defined in this chapter

`service mesh`, `sidecar`

---

## What to remember

1. **Distributing the app distributes the authorization problem.** "The gateway checked it" is
   the microservices version of "they're logged in."
2. **Every service authenticates its callers** — zero trust. "Internal" is not a security
   property.
3. **Two identities travel:** the *service* (mTLS/SPIFFE — [J04](../track-j/J04-mtls.md),
   [J05](../track-j/J05-workload-identity-spiffe.md)) and the *user* (a validated token).
4. **Never trust unsigned identity headers** (`X-User-Id`) — a forged header is an auth bypass.
   Use signed tokens, or a mesh that strips inbound copies at the edge.
5. **Pass audience-scoped tokens via token exchange** ([F19](../track-f/F19-token-exchange.md)),
   not passthrough. Each service checks `aud` ([F08](../track-f/F08-audience-and-resource-indicators.md)).
6. **Decide centrally, enforce locally:** one policy source, local PDP sidecars, each service a
   PEP, failing closed.
7. **A service mesh handles service-to-service auth and coarse routing**, not object-level
   authorization — that stays in your code.
8. **Identity in the token; permissions looked up at use.** Avoids stale grants and bloat.

---

## Sources

- [OWASP: API Security — service-to-service auth](https://owasp.org/API-Security/)
- [OPA: Microservices authorization patterns](https://www.openpolicyagent.org/docs/latest/envoy-introduction/)
- [SPIFFE / SPIRE](https://spiffe.io/) ([J05](../track-j/J05-workload-identity-spiffe.md))
- [Istio security](https://istio.io/latest/docs/concepts/security/)

---

**Next:** [H13 — Audit logging: proving who did what](H13-audit-logging.md)
