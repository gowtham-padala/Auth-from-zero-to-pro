# G08 — SAML vs OIDC: what to offer enterprise customers

**Part G · Federated identity & SSO** · *Builds on [G07](G07-saml-survival-guide.md), [G02](G02-oidc-on-top-of-oauth.md)*
---

## The honest comparison

| | **SAML 2.0** | **OIDC** |
|---|---|---|
| Age | 2005 | 2014 |
| Format | XML | JSON / JWT |
| Transport | Browser POST/redirect | HTTP + OAuth flows |
| Signing | XML-DSig (complex, XSW-prone) | JWS (flat string, simpler) |
| Mobile / native apps | ❌ Painful | ✅ Designed for it ([F18](../track-f/F18-oauth-for-mobile.md)) |
| API authorization | ❌ Not its job | ✅ It's OAuth underneath ([G02](G02-oidc-on-top-of-oauth.md)) |
| Discovery | Manual metadata exchange | `.well-known` auto-config ([G05](G05-discovery-and-well-known.md)) |
| Token size | Large XML | Compact JWT |
| Enterprise install base | **Enormous** | Growing, especially cloud-native |
| Attack surface | XSW, canonicalisation ([G14](G14-attack-your-own-sso.md)) | `alg` confusion, `aud` ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)) |
| New greenfield IdPs | Rare | The default |

On technical merits, OIDC wins for anything new: simpler, mobile-capable, API-native, with a
smaller and better-understood attack surface. But "technical merits" is not the axis that
decides enterprise deals.

---

## What actually decides it: the customer's IdP

You do not pick the protocol. **The customer's existing identity provider does**, and you
must speak what it speaks.

```
   Customer runs...                        You must support...
   ────────────────                        ──────────────────
   Okta, Entra ID, Ping (modern)     →     OIDC preferred, SAML available — either works
   Legacy AD FS on-premise           →     SAML (may not do OIDC well, or at all)
   Google Workspace                  →     OIDC (native) or SAML
   A homegrown/older IdP             →     SAML, usually
   No IdP (small customer)           →     Your own login + optional social  G01
```

The distribution matters: **a large share of enterprises still lead with SAML**, because it
is what their entrenched systems do and what their security teams have audited. Refusing SAML
does not make those customers adopt OIDC; it makes them adopt a different vendor.

---

## The recommendation

> **For B2B SaaS: support both. Prefer OIDC where the customer offers it; provide SAML because
> many customers require it.**

Concretely, in priority order:

1. **Your own auth** for small customers with no IdP — email/password, passkeys, social login
   ([G01](G01-sign-in-with-google.md)).
2. **OIDC SSO** for customers with a modern IdP — the better integration, easier to configure
   via discovery.
3. **SAML SSO** for customers who require it — and many will
   ([G07](G07-saml-survival-guide.md)).
4. **SCIM** for provisioning, on top of whichever SSO ([I02](../track-i/I02-provisioning-and-scim.md)).

This is the "Enterprise plan" of nearly every successful B2B product, and it is why "SSO tax"
(charging for SSO) is a common — if contentious — pricing pattern: SSO is genuinely
expensive to build and support, especially SAML.

---

## The build-vs-buy angle

Supporting both protocols, multi-tenant ([G09](G09-multi-tenant-sso.md)), with per-customer
configuration and certificate management, is **a lot of work** — and SAML specifically is
where the security stakes are highest ([G14](G14-attack-your-own-sso.md)).

This is the clearest case in the book for **buying the SSO layer**
([C05](../track-c/C05-build-vs-buy.md)):

- **SSO-specialist providers** (WorkOS, BoxyHQ, and similar) exist precisely for this: you
  integrate one API, and they handle the SAML/OIDC differences, the metadata exchange, the
  certificate rotation, and the signature-attack defences.
- **Full CIAM platforms** (Auth0, Okta CIC, Entra External ID) include it.
- **Self-hosted** (Keycloak, Zitadel) support both if you run the infrastructure.

The reasoning from [C05](../track-c/C05-build-vs-buy.md): you can **buy "who they are"** — and
multi-tenant SSO is the canonical example. What you cannot buy is your authorization model
([Track H](../track-h/H01-where-does-authz-live.md)), which stays yours regardless of how
login happens.

If you do build it, budget for **paid security review** of the SAML path specifically. XSW
and canonicalisation bugs cause breaches in other people's products, and this audience is
merciless about them.

---

## Keep your own session either way

Whichever protocol the customer uses, the ending is the same as every other federated login
([G01](G01-sign-in-with-google.md), [F04](../track-f/F04-build-oauth-client-raw-http.md)):

```
   SAML assertion  ─┐
                    ├─> validate ─> extract identity ─> create YOUR session  E03
   OIDC ID token   ─┘
```

Do not couple your session to the protocol. Own a local user table keyed on
`(issuer, subject)` ([G12](G12-account-linking.md)), issue your own session
([E03](../track-e/E03-build-server-side-sessions.md)), and keep authorization in your own
system ([H01](../track-h/H01-where-does-authz-live.md)). Then SAML vs OIDC is an
*integration* detail at the edge, not an architecture decision that reaches into your whole
app. This is exactly the "hide the provider behind an interface" pattern from
[C05](../track-c/C05-build-vs-buy.md), and it is what lets you support both without doubling
your codebase.

---

## Terms defined in this chapter

(No new glossary terms; this chapter is a decision built on G02 and G07.)

---

## What to remember

1. **You do not choose the protocol — the customer's IdP does.** Refusing SAML loses
   customers, not converts them.
2. On technical merits **OIDC wins** — JSON, mobile, API-native, smaller attack surface.
3. **For B2B SaaS: support both.** Prefer OIDC where offered; provide SAML because many
   enterprises require it.
4. Priority: own auth → OIDC SSO → SAML SSO → SCIM provisioning.
5. **This is the clearest buy case in the book.** SSO-specialist providers exist to absorb
   exactly this complexity — especially SAML's.
6. If you build SAML yourself, budget for **paid security review** of that path.
7. **Keep your own session and authorization**, keyed on `(iss, sub)`, so the protocol is an
   edge detail.

---

## Sources

- [OASIS SAML 2.0 Technical Overview](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- Yvonne Wilson & Abhishek Hingnikar, *Solving Identity Management in Modern Applications*, 2nd ed., Ch. 6–7
- [WorkOS / BoxyHQ documentation](https://workos.com/docs) — the "buy the SSO layer" model

---

**Next:** [G09 — Multi-tenant SSO for B2B SaaS: the IdP-per-customer problem](G09-multi-tenant-sso.md)
