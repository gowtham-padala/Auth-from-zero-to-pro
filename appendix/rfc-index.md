# RFC and spec index — what you need, and what you can ignore

Every normative source this book anchors to, grouped by what it does, with a one-line "why you care"
and the chapter that uses it. This is the reference behind [K05](../book/track-k/K05-the-decision-tree.md)'s
"which RFCs do I need?"

**How to read a spec:** [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) keywords — `MUST` is a
requirement, `SHOULD` a strong recommendation, `MAY` optional. The security is usually in the
`MUST`s, and the **Security Considerations** section is where the attacks live. **BCPs** (Best
Current Practice) distil years of vulnerabilities into requirements — often more useful than the
original spec.

---

## Tier 1 — read these if you do any auth at all

| Spec | What it is | Chapter |
|---|---|---|
| **[NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)** | Passwords, MFA, assurance levels. The authority. (Final July 2025.) | [D03](../book/track-d/D03-how-to-store-passwords.md), [D04](../book/track-d/D04-password-policies.md), [D18](../book/track-d/D18-step-up-auth-and-aal.md) |
| **[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700)** | OAuth 2.0 Security Best Current Practice. Every OAuth attack + mitigation. | [F01](../book/track-f/F01-the-problem-oauth-solves.md), [F20](../book/track-f/F20-attack-your-own-oauth.md) |
| **[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725)** | JWT Best Current Practices. Prevents most JWT vulnerabilities. | [E06](../book/track-e/E06-jwt-part-2-signature-jws-jwe.md), [E07](../book/track-e/E07-jose-family.md) |
| **[OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/)** | Testable auth requirements (V2 authn, V3 session, V7 access control). | [I07](../book/track-i/I07-testing-auth.md), [K01](../book/track-k/K01-architecture-review.md) |

---

## Core protocols

| Spec | What it is | Chapter |
|---|---|---|
| [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) | HTTP Semantics — methods, status codes, headers | [A03](../book/track-a/A03-methods-status-codes-401-vs-403.md), [A04](../book/track-a/A04-headers.md) |
| [RFC 6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis) | Cookies (the current draft) — SameSite, `__Host-` | [A06](../book/track-a/A06-cookies.md), [E02](../book/track-e/E02-cookie-attributes.md) |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | TLS 1.3 | [B12](../book/track-b/B12-key-exchange.md), [B17](../book/track-b/B17-what-https-protects.md) |
| [Fetch Standard](https://fetch.spec.whatwg.org/) | CORS (the normative source) | [A11](../book/track-a/A11-same-origin-and-cors.md) |

## Cryptographic primitives

| Spec | What it is | Chapter |
|---|---|---|
| [FIPS 180-4](https://csrc.nist.gov/pubs/fips/180-4/upd1/final) / [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final) | SHA-2 / SHA-3 | [B04](../book/track-b/B04-what-a-hash-function-is.md) |
| [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) | Argon2 password hashing | [B08](../book/track-b/B08-salts-peppers-slow-hashes.md), [D03](../book/track-d/D03-how-to-store-passwords.md) |
| [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) / [SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) | AES / GCM | [B09](../book/track-b/B09-symmetric-encryption.md) |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | EdDSA (Ed25519) | [B14](../book/track-b/B14-digital-signatures.md) |
| [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104) | HMAC | [B13](../book/track-b/B13-message-authentication-hmac.md) |
| [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) / [6962](https://www.rfc-editor.org/rfc/rfc6962) | X.509 certificates / Certificate Transparency | [B15](../book/track-b/B15-certificates-and-pki.md) |

## Sessions and tokens (JOSE)

| Spec | What it is | Chapter |
|---|---|---|
| [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) | JWT | [E05](../book/track-e/E05-jwt-part-1-three-parts.md) |
| [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515) / [7516](https://www.rfc-editor.org/rfc/rfc7516) | JWS (signed) / JWE (encrypted) | [E06](../book/track-e/E06-jwt-part-2-signature-jws-jwe.md) |
| [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517) / [7518](https://www.rfc-editor.org/rfc/rfc7518) | JWK/JWKS / JWA (algorithms) | [E07](../book/track-e/E07-jose-family.md) |
| [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068) | JWT profile for OAuth access tokens | [F12](../book/track-f/F12-introspection-vs-local-validation.md) |

## OAuth 2

| Spec | What it is | Chapter |
|---|---|---|
| [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) / [6750](https://www.rfc-editor.org/rfc/rfc6750) | OAuth 2.0 core / bearer tokens | [F02](../book/track-f/F02-four-roles-two-channels.md), [F03](../book/track-f/F03-authorization-code-flow.md) |
| [draft-ietf-oauth-v2-1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1) | **OAuth 2.1** — still a draft in 2026 | [F01](../book/track-f/F01-the-problem-oauth-solves.md) |
| **[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)** | **PKCE** — mandatory for everyone now | [F06](../book/track-f/F06-pkce.md) |
| [RFC 8707](https://www.rfc-editor.org/rfc/rfc8707) | Resource indicators (audience) | [F08](../book/track-f/F08-audience-and-resource-indicators.md) |
| [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628) | Device authorization grant (TVs, CLIs) | [F11](../book/track-f/F11-device-flow.md) |
| [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662) / [7009](https://www.rfc-editor.org/rfc/rfc7009) | Introspection / revocation | [F12](../book/track-f/F12-introspection-vs-local-validation.md), [E11](../book/track-e/E11-revocation.md) |
| [RFC 7523](https://www.rfc-editor.org/rfc/rfc7523) | JWT client authentication (`private_key_jwt`) | [F09](../book/track-f/F09-public-vs-confidential-clients.md) |
| [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693) | Token exchange (delegation, `act`) | [F19](../book/track-f/F19-token-exchange.md) |
| [RFC 9207](https://www.rfc-editor.org/rfc/rfc9207) | Issuer identification (mix-up defence) | [F20](../book/track-f/F20-attack-your-own-oauth.md) |
| [RFC 8252](https://www.rfc-editor.org/rfc/rfc8252) | OAuth for native apps | [F18](../book/track-f/F18-oauth-for-mobile.md) |
| [RFC 9470](https://www.rfc-editor.org/rfc/rfc9470) | Step-up authentication challenge | [D18](../book/track-d/D18-step-up-auth-and-aal.md) |
| [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) / [8705](https://www.rfc-editor.org/rfc/rfc8705) | DPoP / mTLS (sender-constrained tokens) | [F16](../book/track-f/F16-sender-constrained-tokens.md), [J04](../book/track-j/J04-mtls.md) |

## Federation

| Spec | What it is | Chapter |
|---|---|---|
| [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) | OIDC — the identity layer | [G02](../book/track-g/G02-oidc-on-top-of-oauth.md), [G04](../book/track-g/G04-validate-an-id-token-by-hand.md) |
| [OIDC Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) / [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414) | Discovery (`.well-known`) | [G05](../book/track-g/G05-discovery-and-well-known.md) |
| [NIST SP 800-63C-4](https://csrc.nist.gov/pubs/sp/800/63/c/4/final) | Federation assurance (FAL) | [G02](../book/track-g/G02-oidc-on-top-of-oauth.md) |
| [OASIS SAML 2.0](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html) | SAML | [G07](../book/track-g/G07-saml-survival-guide.md) |
| [OIDC Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html) | Single logout | [G11](../book/track-g/G11-federated-sessions-single-logout.md) |

## Lifecycle, machine, agent

| Spec | What it is | Chapter |
|---|---|---|
| [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) / [7644](https://www.rfc-editor.org/rfc/rfc7644) | SCIM (provisioning) | [I02](../book/track-i/I02-provisioning-and-scim.md) |
| [SPIFFE](https://spiffe.io/) | Workload identity | [J05](../book/track-j/J05-workload-identity-spiffe.md) |
| [RFC 6238](https://www.rfc-editor.org/rfc/rfc6238) / [4226](https://www.rfc-editor.org/rfc/rfc4226) | TOTP / HOTP | [D12](../book/track-d/D12-build-totp.md) |
| [W3C WebAuthn L3](https://www.w3.org/TR/webauthn-3/) | Passkeys | [D14](../book/track-d/D14-webauthn-and-passkeys-concepts.md), [D15](../book/track-d/D15-build-passkeys.md) |
| [MCP Authorization](https://modelcontextprotocol.io/specification/draft/basic/authorization) + [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728) / [7591](https://www.rfc-editor.org/rfc/rfc7591) | Agent auth; protected-resource metadata; dynamic client registration | [J08](../book/track-j/J08-mcp-and-oauth-21.md) |

---

## What you can ignore

| Spec / topic | Why | Chapter |
|---|---|---|
| **Implicit grant, ROPC** | Dead — removed from OAuth 2.1 | [F15](../book/track-f/F15-implicit-and-password-grants.md) |
| **OAuth 1.0a** | Obsolete | [F01](../book/track-f/F01-the-problem-oauth-solves.md) |
| **SAML** | If you have no enterprise customers | [G07](../book/track-g/G07-saml-survival-guide.md) |
| **DIDs / verifiable credentials** | A separate curriculum | [excluded.md](excluded.md) |
| **Post-quantum KEMs** | Moving too fast for evergreen material | [excluded.md](excluded.md) |
| **WS-Federation, SAML artifact binding** | Legacy enterprise edge cases | [excluded.md](excluded.md) |

---

**Back to:** [README](../README.md) · [decision tree](decision-tree.md) · [K05](../book/track-k/K05-the-decision-tree.md)
