# J04 — mTLS: mutual authentication at the transport layer

**Part J · Machine, workload & agent identity** · *Builds on [B15](../track-b/B15-certificates-and-pki.md), [F16](../track-f/F16-sender-constrained-tokens.md)*
---

## What mTLS is

Ordinary TLS ([B17](../track-b/B17-what-https-protects.md)) authenticates **one** side — the server
proves its identity to the client with a certificate ([B15](../track-b/B15-certificates-and-pki.md)),
and the client stays anonymous. That's right for the web: your browser verifies the bank, but the
bank identifies you *later*, with a login ([D06](../track-d/D06-build-login-part-2-login.md)).

**mTLS (mutual TLS)** authenticates **both** sides — the client *also* presents a certificate, and
the server verifies it:

```
   ORDINARY TLS                          mTLS
   ────────────                          ────
   Client ──"who are you?"──▶ Server     Client ◀──"who are you?"──▶ Server
   Server proves identity (cert)         BOTH prove identity (certs)
   Client is anonymous                   Client is authenticated cryptographically
   (auth happens later, at app layer)    (auth happens IN the handshake)
```

The client's proof is the same as the server's ([B14](../track-b/B14-digital-signatures.md),
[B12](../track-b/B12-key-exchange.md)): it holds a private key, presents the matching certificate,
and proves possession of the key during the handshake. You **cannot complete an mTLS handshake
without the private key** — so a forged header is impossible; there's nothing to forge.

---

## Why it fits machines (and not humans)

mTLS is a *machine-identity* tool ([J01](J01-machine-identity-is-not-user-identity.md)), and the
reason maps to Track J's whole theme:

- **No human, no problem.** mTLS needs no interactive login, no MFA, no browser — the certificate
  *is* the identity ([D11](../track-d/D11-sms-second-factor.md)). Perfect for service-to-service,
  where there's no human to prompt.
- **Strong, unforgeable identity** ([B14](../track-b/B14-digital-signatures.md)) — far better than a
  shared secret ([J03](J03-service-accounts.md)) or an unsigned header.
- **It also constrains tokens.** mTLS is the transport mechanism behind sender-constrained tokens
  ([F16](../track-f/F16-sender-constrained-tokens.md), RFC 8705) — a token can be *bound* to the
  client certificate, so a stolen bearer token is useless without the cert.

For *humans* it's awkward — managing client certificates in browsers is a poor experience — which is
why the web uses server-only TLS + application login, and DPoP ([F16](../track-f/F16-sender-constrained-tokens.md))
exists for browser proof-of-possession. mTLS shines exactly where the client is a *machine*.

---

## The private-PKI setup

mTLS needs a certificate for every client, which means a **certificate authority**
([B15](../track-b/B15-certificates-and-pki.md)) to issue and verify them. For internal
service-to-service, you run your **own private CA** — and here the calculus from
[B15](../track-b/B15-certificates-and-pki.md) *inverts* in your favour:

> **A private PKI is strictly better than the public one for internal use.** Only *your* CA is
> trusted in *your* services' trust stores, so no external CA — and no attacker who compromises one
> ([B15](../track-b/B15-certificates-and-pki.md) — DigiNotar) — can issue a certificate your
> services will accept. A smaller trust set is a smaller attack surface.

```
   Your internal CA (root)  ──issues──▶ cert for checkout service
                            ──issues──▶ cert for orders service
                            ──issues──▶ cert for payments service

   Each service's trust store: ONLY your CA.  ← nothing else is trusted
```

Conceptually, on the server side:

```python
# The orders service, requiring client certs:
ssl_context.verify_mode = ssl.CERT_REQUIRED           # demand a client cert
ssl_context.load_verify_locations("internal-ca.pem")  # trust ONLY our CA
# In the handshake, TLS verifies the client cert chains to our CA. B15.

# After the handshake, the app reads WHO the verified client is:
def handle_request(conn):
    client_cert = conn.getpeercert()
    caller = client_cert["subject"]["CN"]             # e.g. "checkout.internal"
    # This identity is CRYPTOGRAPHICALLY PROVEN — not a forgeable header. A04.
    authorize(caller, request)                        # H12 — still authorize the action
```

The identity (`caller`) is trustworthy because the handshake verified the certificate. Contrast a self-asserted
`X-Service` header any process could set. Now identity is proven by possession
of a CA-issued private key.

Note the last line: mTLS gives you **authentication** (who the caller is), not **authorization**
([C02](../track-c/C02-authn-vs-authz-vs-session.md)). You still check whether *this* verified service
may do *this* action ([H12](../track-h/H12-authz-in-microservices.md)).

---

## The hard part: certificate lifecycle at scale

mTLS's cryptography is easy; its **operations** are the challenge, and it's where naive setups fail
([B15](../track-b/B15-certificates-and-pki.md), [I06](../track-i/I06-key-rotation.md)):

- **Every workload needs a certificate** — and in a world of thousands of ephemeral container
  instances ([J01](J01-machine-identity-is-not-user-identity.md)), that's a lot of certificates,
  created and destroyed constantly.
- **Certificates expire and must rotate** ([B15](../track-b/B15-certificates-and-pki.md),
  [I06](../track-i/I06-key-rotation.md)) — and short lifetimes are *better* (a compromised cert is
  dangerous for hours, not years), which means rotating *often*, automatically.
- **Distributing private keys** to every workload is itself the secrets problem
  ([I05](../track-i/I05-secrets-management.md)) — you can't hand-place a key on ten thousand
  ephemeral pods.

Doing this by hand does not scale. The answer is automation, and it's exactly what the next chapter
is about: **SPIFFE/SPIRE** ([J05](J05-workload-identity-spiffe.md)) issues short-lived certificates
to workloads automatically, based on platform attestation, with no static keys to distribute — and a
**service mesh** ([H12](../track-h/H12-authz-in-microservices.md), Istio/Linkerd) can turn on mTLS
between all services transparently, handling issuance and rotation for you.

> **mTLS is the mechanism; workload identity ([J05](J05-workload-identity-spiffe.md)) and service
> meshes are what make it operable at scale.** Don't hand-manage service certificates — automate the
> issuance and rotation, or the lifecycle burden defeats you.

---

## Where mTLS fits

✅ **Service-to-service inside your infrastructure** — the canonical case; zero-trust internal
networking ([H12](../track-h/H12-authz-in-microservices.md), [J01](J01-machine-identity-is-not-user-identity.md)).
✅ **High-security / regulated M2M** — banking, FAPI ([F16](../track-f/F16-sender-constrained-tokens.md))
often mandate it.
✅ **Sender-constrained tokens** — binding OAuth tokens to a client cert ([F16](../track-f/F16-sender-constrained-tokens.md)).
✅ **Partner integrations** where both organisations exchange certificates.

⚠️ **Through CDNs / load balancers** that terminate TLS ([B17](../track-b/B17-what-https-protects.md))
— the client cert is lost at termination unless you propagate it deliberately; this is a common
operational snag.

❌ **Browsers / end users** — awkward client-cert management; use application login + DPoP
([F16](../track-f/F16-sender-constrained-tokens.md)) instead.

---

## Terms defined in this chapter

`mTLS` (deepened from F16), `client certificate`, `certificate binding`

---

## What to remember

1. **mTLS authenticates *both* sides** of a connection — the client also presents a certificate, so
   identity is proven *in the handshake*, cryptographically, not by a forgeable header.
2. It fixes the "internal, so trusted" failure ([J01](J01-machine-identity-is-not-user-identity.md),
   [H12](../track-h/H12-authz-in-microservices.md)) — you *cannot* complete the handshake without the
   private key.
3. **It's a machine-identity tool** — no human, no MFA, no browser; the certificate is the identity.
   Awkward for end users.
4. **Run a private CA** ([B15](../track-b/B15-certificates-and-pki.md)) — a smaller, tighter trust
   set than the public PKI; only your CA is trusted internally.
5. **mTLS gives authentication, not authorization** — still check what the verified caller may do
   ([H12](../track-h/H12-authz-in-microservices.md)).
6. **The hard part is certificate lifecycle at scale** — issuance, rotation, key distribution to
   ephemeral workloads.
7. **Automate it with SPIFFE/SPIRE** ([J05](J05-workload-identity-spiffe.md)) **and a service mesh** —
   the mechanism is easy; the operations are what defeat naive setups.

---

## Sources

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) (client authentication)
- [RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Tokens](https://www.rfc-editor.org/rfc/rfc8705) ([F16](../track-f/F16-sender-constrained-tokens.md))
- [Istio: Mutual TLS](https://istio.io/latest/docs/concepts/security/#mutual-tls-authentication)
- [SPIFFE / SPIRE](https://spiffe.io/) ([J05](J05-workload-identity-spiffe.md))

---

**Next:** [J05 — Workload identity: SPIFFE, SPIRE, and cloud federation](J05-workload-identity-spiffe.md)
