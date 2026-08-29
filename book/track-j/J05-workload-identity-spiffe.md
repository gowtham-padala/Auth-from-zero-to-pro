# J05 — Workload identity: SPIFFE, SPIRE, and cloud federation

**Part J · Machine, workload & agent identity** · *Builds on [J04](J04-mtls.md)*
---

## The insight: attestation, not secrets

> **A workload proves its identity by what it *is* and *where it runs* — attested by the platform —
> rather than by a secret it holds.**

The platform already knows things about a workload that an attacker can't easily fake: which node
it's on, which Kubernetes service account it runs under, which container image it is, which cloud
instance with which IAM role. That knowledge is **attestation** — the platform *vouches* for the
workload's identity — and it's the root of trust that ends the regress:

```
   SECRET-BASED (the regress)            ATTESTATION-BASED (workload identity)
   ──────────────────────────            ────────────────────────────────────
   workload needs a secret               the PLATFORM attests what the workload is
   → to get it, needs another secret      → issues it a SHORT-LIVED credential
   → ...bottom turtle                     → no long-lived secret to bootstrap, store, or leak
```

There is no first secret to distribute, because identity is grounded in *facts about the workload*
the platform can verify. This is the ultimate expression of [I05](../track-i/I05-secrets-management.md)'s
principle — the best secret is one you never hold — and of [F10](../track-f/F10-client-credentials.md)'s
"prefer workload identity to a static client secret."

---

## SPIFFE and SPIRE

**SPIFFE** (Secure Production Identity Framework For Everyone) is the *standard* for workload
identity; **SPIRE** is its reference *implementation*.

Two core concepts:

**The SPIFFE ID** — a URI that names a workload:

```
   spiffe://trust-domain/path
   spiffe://example.com/ns/prod/sa/checkout      ← the checkout service, in prod
```

It's the workload's stable name, within a **trust domain** (an administrative boundary, like a
company or an environment).

**The SVID** (SPIFFE Verifiable Identity Document) — the workload's *credential*, carrying its
SPIFFE ID:

- **X.509-SVID** — a short-lived X.509 certificate ([B15](../track-b/B15-certificates-and-pki.md)),
  used directly for **mTLS** ([J04](J04-mtls.md)).
- **JWT-SVID** — a signed JWT ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)) for contexts
  where a certificate is awkward.

How SPIRE issues one, ending the regress:

```
   1. A workload starts and asks the local SPIRE agent: "who am I?"
   2. The agent ATTESTS the workload — checks platform facts:
        - node attestation:     is this really node N in our cluster?
        - workload attestation:  which K8s service account / process / image is this?
   3. If the attestation matches a registered identity, SPIRE issues a
      SHORT-LIVED SVID (minutes to an hour), auto-rotated before expiry.  I06
   4. The workload uses the SVID for mTLS / token auth. No static secret ever existed.
```

The attestation in step 2 is the whole trick: the workload proves *what it is* (facts the platform
already knows and can verify), and gets a credential *because* of it — no secret to bootstrap.

---

## Why short-lived and auto-rotated matters

SVIDs live minutes to an hour and rotate automatically ([I06](../track-i/I06-key-rotation.md)). This
isn't incidental — it's central to the security model:

- **A leaked SVID is worthless in an hour** — the blast radius ([I10](../track-i/I10-incident-response.md))
  of a stolen credential shrinks from "forever" to "minutes."
- **Rotation is automatic**, so the [J03](J03-service-accounts.md) failure ("who rotates the robot's
  password?") simply can't happen — there's no long-lived credential to forget to rotate.
- **Revocation is easy** — stop attesting the workload, and it can't renew; the current SVID expires
  in minutes ([E11](../track-e/E11-revocation.md)).

Compare the [J03](J03-service-accounts.md) service account: a static password, in a config file, for
years. Workload identity is its inverse on every axis — short-lived, auto-rotated, attested, with no
stored secret. This is the *good* version of machine identity the whole track builds toward.

---

## Cloud workload identity federation

You don't always need SPIRE. The major clouds provide workload identity natively, on the same
attestation principle:

| Platform | Mechanism |
|---|---|
| **AWS** | IAM roles — an EC2 instance / EKS pod / Lambda assumes a role; the platform attests it, issues short-lived credentials via the metadata service. No static key. |
| **GCP** | Service accounts with **Workload Identity Federation** — a K8s service account maps to a GCP identity, attested by the cluster. |
| **Azure** | **Managed identities** — the platform provides an identity to a VM/function, no stored secret. |

**Federation** ([Track G](../track-g/G02-oidc-on-top-of-oauth.md)'s idea, applied to workloads)
lets these cross boundaries: a Kubernetes workload can present its **service account token** (a
signed JWT the cluster issues), and a cloud provider — or your own auth server
([F10](../track-f/F10-client-credentials.md)) — *federates* that: trusts the cluster's attestation
and exchanges it for its own credential ([F19](../track-f/F19-token-exchange.md)). The workload
proves *what it is* to its own platform, and that proof is trusted across the boundary — no shared
secret between them.

This is why [F10](../track-f/F10-client-credentials.md) said the best client credential is *no static
credential*: a GitHub Actions job can authenticate to AWS with **no stored AWS key**, by presenting
its OIDC token, which AWS federates. The static secret — the thing that leaks
([A10](../track-a/A10-where-secrets-live.md), [I10](../track-i/I10-incident-response.md)) — is
eliminated entirely.

---

## The maturity ladder

Where this leaves machine identity, from worst to best ([J03](J03-service-accounts.md),
[J02](J02-api-keys.md), [F10](../track-f/F10-client-credentials.md)):

```
   ❌  Shared static password in config       J03 — the anti-pattern
   ⚠️  API key, hashed, rotated               J02 — fine for simple external cases
   ⚠️  Client-credentials with a static secret F10 — better, but the secret still exists
   ✅  Workload identity (attestation)         J05 — no static secret at all
   ✅✅ Federated workload identity             J05 — no secret, across boundaries
```

Move down the ladder as your platform allows. The direction is always toward *less stored secret*
and *more attestation*, because the secret you don't store is the one that can't leak.

---

## Terms defined in this chapter

`SPIFFE`, `SPIFFE ID`, `SVID`, `SPIRE`, `attestation (workload)`, `trust domain`

---

## What to remember

1. **The bottom-turtle problem:** every credential needs a credential to obtain it. Workload
   identity breaks the regress with **attestation** — proving *what you are*, not *what secret you
   hold*.
2. **The platform already knows facts about a workload** (node, service account, image) an attacker
   can't fake — that's the root of trust, and there's no first secret to distribute.
3. **SPIFFE** is the standard; **SPIRE** the implementation. A **SPIFFE ID** names the workload; an
   **SVID** (X.509 or JWT) is its short-lived, auto-rotated credential.
4. **Short-lived + auto-rotated** shrinks a leak's blast radius to minutes and makes the
   [J03](J03-service-accounts.md) "who rotates it?" failure impossible.
5. **Cloud workload identity** (AWS IAM roles, GCP WIF, Azure managed identities) does the same
   natively — no stored key.
6. **Federation** lets attestation cross boundaries — a K8s or GitHub Actions workload authenticates
   to a cloud with **no static secret** ([F10](../track-f/F10-client-credentials.md), [F19](../track-f/F19-token-exchange.md)).
7. **The maturity ladder points toward less stored secret** — the secret you don't hold can't leak.

---

## Sources

- [SPIFFE / SPIRE documentation](https://spiffe.io/docs/latest/spiffe-about/overview/)
- [AWS: IAM roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html) / [GCP Workload Identity Federation](https://cloud.google.com/iam/docs/workload-identity-federation) / [Azure managed identities](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview)
- [GitHub Actions: OIDC hardening (no stored cloud keys)](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)

---

**Next:** [J06 — Signing webhooks, and verifying them correctly](J06-signing-webhooks.md)
