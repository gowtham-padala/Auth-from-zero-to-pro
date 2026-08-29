# Auth, from Zero to Pro

**A complete concept book on authentication and authorization. No assumed knowledge.**

> **📖 Read it online → https://gowtham-padala.github.io/Auth-from-zero-to-pro/**  
> A single-page reader with the whole book, sidebar navigation, and search. Or browse the Markdown below — every chapter links to the next.

This is a book about how authentication and authorization actually work — written as a
**dependency graph, not a reading list**. It starts below the waterline (what a byte is, what a hash
is, what an HTTP header is) and builds up, one concept at a time, to federated identity, fine-grained
authorization, and machine- and AI-agent identity. Nothing in it assumes the thing it is about to
teach.

**140 chapters. Eleven parts. One running example** — a document-sharing app — threaded through the
whole book, because sharing forces genuinely hard authorization questions that a simpler example
never would.

---

## How to read it

It's a dependency graph, not a mandatory order — every chapter says what it builds on. Three ways in:

- **New to all of it.** Read A → B → C → D → E, in order. That is the spine; the rest attaches to it.
- **You write software and want to stop guessing.** Start at [C01](book/track-c/C01-auth-is-five-different-problems.md) —
  it splits "auth" into five separable problems, and you'll immediately know which one you have.
- **You need an answer now.** Jump to the [decision tree](appendix/decision-tree.md): six questions
  about your architecture, out comes your stack.

---

## How this book is written

Three principles, because they're the failure modes of most explanations of this subject:

1. **No undefined terms.** A term appears only after it's been defined. [GLOSSARY.md](GLOSSARY.md) is
   the ledger — every term, a plain definition, and where it's introduced.
2. **Every chapter opens with the problem, not the topic.** Here's what breaks, then here's the
   mechanism that fixes it.
3. **One example throughout.** A document-sharing app accumulates every layer, so each concept lands
   somewhere concrete.

Code appears where it clarifies a mechanism — short and illustrative, not a framework tour. The rule
behind the example: no library is used until the mechanism under it has been shown by hand, so you
know what the library is doing before you trust it.

---

## The eleven parts

### Part A — How the web actually works

*11 chapters. The prerequisites every auth tutorial assumes and never teaches.*

| # | Chapter | Builds on |
|---|---|---|
| A01 | [What happens when you type a URL and press enter](book/track-a/A01-what-happens-when-you-type-a-url.md) | — |
| A02 | [Reading HTTP requests and responses in your browser dev tools](book/track-a/A02-reading-http-in-dev-tools.md) | A01 |
| A03 | [HTTP methods, status codes, and why 401 is not 403](book/track-a/A03-methods-status-codes-401-vs-403.md) | A02 |
| A04 | [Headers: the metadata every request carries](book/track-a/A04-headers.md) | A02 |
| A05 | [What "stateless" means, and why HTTP forgets who you are](book/track-a/A05-stateless.md) | A03 |
| A06 | [Cookies: what they are, where they live, who sends them](book/track-a/A06-cookies.md) | A05 |
| A07 | [Client vs server: which of your code can an attacker read?](book/track-a/A07-client-vs-server.md) | A01 |
| A08 | [What an API is, and what "acting on someone's behalf" means](book/track-a/A08-what-an-api-is.md) | A03 |
| A09 | [Redirects, and why the address bar is a security boundary](book/track-a/A09-redirects.md) | A03 |
| A10 | [Where secrets live: env vars, and never in your frontend bundle](book/track-a/A10-where-secrets-live.md) | A07 |
| A11 | [Same-origin policy and CORS, explained without the panic](book/track-a/A11-same-origin-and-cors.md) | A06, A07 |

### Part B — Crypto foundations

*17 chapters. Why the rest of the book works — from bits to certificates.*

| # | Chapter | Builds on |
|---|---|---|
| B01 | [Bits, bytes, and how text becomes numbers](book/track-b/B01-bits-bytes-text-as-numbers.md) | — |
| B02 | [Encoding is not encryption: base64, hex, URL encoding](book/track-b/B02-encoding-is-not-encryption.md) | B01 |
| B03 | [Randomness, and why Math.random() will get you breached](book/track-b/B03-randomness.md) | B01 |
| B04 | [What a hash function is](book/track-b/B04-what-a-hash-function-is.md) | B01 |
| B05 | [Hashing vs encryption: one-way vs reversible](book/track-b/B05-hashing-vs-encryption.md) | B04 |
| B06 | [Collisions, and why MD5 and SHA-1 were retired](book/track-b/B06-collisions.md) | B04 |
| B07 | [Why fast hashes are the wrong tool for passwords](book/track-b/B07-fast-hashes-wrong-for-passwords.md) | B04 |
| B08 | [Salts, peppers, and slow hashes: bcrypt, scrypt, argon2id](book/track-b/B08-salts-peppers-slow-hashes.md) | B07 |
| B09 | [Symmetric encryption: XOR by hand, then AES](book/track-b/B09-symmetric-encryption.md) | B01, B05 |
| B10 | [The key distribution problem](book/track-b/B10-key-distribution-problem.md) | B09 |
| B11 | [Asymmetric encryption and one-way math](book/track-b/B11-asymmetric-encryption.md) | B10 |
| B12 | [Key exchange: agreeing on a secret in public](book/track-b/B12-key-exchange.md) | B11 |
| B13 | [Message authentication: hashing with a secret, and HMAC](book/track-b/B13-message-authentication-hmac.md) | B04, B09 |
| B14 | [Digital signatures: asymmetric encryption run backwards](book/track-b/B14-digital-signatures.md) | B11, B13 |
| B15 | [Certificates and PKI: why your browser trusts a stranger](book/track-b/B15-certificates-and-pki.md) | B14 |
| B16 | [Timing attacks and constant-time comparison](book/track-b/B16-timing-attacks.md) | B13 |
| B17 | [What HTTPS actually protects, and what it doesn't](book/track-b/B17-what-https-protects.md) | B12, B15 |

### Part C — The map

*5 chapters. Where "auth" stops being one word.*

| # | Chapter | Builds on |
|---|---|---|
| C01 | ["Auth" is five different problems](book/track-c/C01-auth-is-five-different-problems.md) | A06, B14 |
| C02 | [Authentication vs authorization vs session, once and for all](book/track-c/C02-authn-vs-authz-vs-session.md) | C01 |
| C03 | [The vocabulary: principal, subject, claim, scope, credential, token](book/track-c/C03-the-vocabulary.md) | C01 |
| C04 | [Threat modeling for normal people: who's attacking, with what?](book/track-c/C04-threat-modeling.md) | A07 |
| C05 | [Build vs buy: when to use a provider, and when not to](book/track-c/C05-build-vs-buy.md) | C01 |

### Part D — Authentication

*18 chapters. Proving who someone is.*

| # | Chapter | Builds on |
|---|---|---|
| D01 | [Identifiers: what should a user actually log in with?](book/track-d/D01-identifiers.md) | C03 |
| D02 | [Email as identity: verification, plus-addressing, homoglyphs](book/track-d/D02-email-as-identity.md) | D01 |
| D03 | [How to store passwords in 2026](book/track-d/D03-how-to-store-passwords.md) | B08 |
| D04 | [Password policies that help, and the ones NIST removed](book/track-d/D04-password-policies.md) | D03 |
| D05 | [Build a login, part 1: registration](book/track-d/D05-build-login-part-1-registration.md) | D03, A06 |
| D06 | [Build a login, part 2: login and error handling](book/track-d/D06-build-login-part-2-login.md) | D05 |
| D07 | [User enumeration: how your error messages leak your user list](book/track-d/D07-user-enumeration.md) | D06 |
| D08 | [Rate limiting, lockout, and credential stuffing defense](book/track-d/D08-rate-limiting-and-stuffing.md) | D06 |
| D09 | [Account recovery is your real weakest link](book/track-d/D09-account-recovery.md) | D06 |
| D10 | [Magic links and email OTP: how they work, when they're fine](book/track-d/D10-magic-links-and-email-otp.md) | D02 |
| D11 | [Why SMS is the worst second factor, and still the most common](book/track-d/D11-sms-second-factor.md) | D10 |
| D12 | [Build TOTP two-factor](book/track-d/D12-build-totp.md) | B13, D06 |
| D13 | [Recovery codes, and the 2FA lockout problem](book/track-d/D13-recovery-codes.md) | D12 |
| D14 | [WebAuthn and passkeys: the concepts](book/track-d/D14-webauthn-and-passkeys-concepts.md) | B14 |
| D15 | [Build passkey registration and login](book/track-d/D15-build-passkeys.md) | D14 |
| D16 | [Biometrics: what your fingerprint actually proves](book/track-d/D16-biometrics.md) | D14 |
| D17 | ["Remember this device" is harder than it looks](book/track-d/D17-remember-this-device.md) | D12 |
| D18 | [Step-up auth and assurance levels (NIST AAL)](book/track-d/D18-step-up-auth-and-aal.md) | D12, C04 |

### Part E — Sessions & tokens

*16 chapters. Keeping someone logged in.*

| # | Chapter | Builds on |
|---|---|---|
| E01 | [Why HTTP needs sessions at all](book/track-e/E01-why-http-needs-sessions.md) | A05 |
| E02 | [Cookie attributes that matter: HttpOnly, Secure, SameSite, `__Host-`](book/track-e/E02-cookie-attributes.md) | A06 |
| E03 | [Build server-side sessions](book/track-e/E03-build-server-side-sessions.md) | E01, B03 |
| E04 | [Session IDs: generation, entropy, storage, expiry](book/track-e/E04-session-ids.md) | E03, B03 |
| E05 | [What a JWT actually is, part 1: the three parts](book/track-e/E05-jwt-part-1-three-parts.md) | B02 |
| E06 | [What a JWT actually is, part 2: the signature, JWS vs JWE](book/track-e/E06-jwt-part-2-signature-jws-jwe.md) | E05, B13, B14 |
| E07 | [JOSE, JWK, JWKS, JWA: the acronym family, untangled](book/track-e/E07-jose-family.md) | E06 |
| E08 | [Signed cookies vs JWTs vs opaque tokens: pick one](book/track-e/E08-signed-cookies-vs-jwt-vs-opaque.md) | E04, E06 |
| E09 | [Should you use JWTs for sessions?](book/track-e/E09-should-you-use-jwts-for-sessions.md) | E08 |
| E10 | [Token lifetimes, refresh tokens, and rotation](book/track-e/E10-token-lifetimes-and-rotation.md) | E08 |
| E11 | [Revocation: the thing stateless tokens are bad at](book/track-e/E11-revocation.md) | E10 |
| E12 | [Where to store a token in a browser: localStorage, cookie, memory](book/track-e/E12-where-to-store-a-token.md) | E02, A07 |
| E13 | [Sessions across devices: listing, remote logout, "log out everywhere"](book/track-e/E13-sessions-across-devices.md) | E03 |
| E14 | [Why logging out is genuinely hard](book/track-e/E14-why-logout-is-hard.md) | E11, E13 |
| E15 | [CSRF: what it is, and why SameSite mostly killed it](book/track-e/E15-csrf.md) | E02 |
| E16 | [XSS is an auth vulnerability](book/track-e/E16-xss-is-an-auth-vulnerability.md) | A07, E12 |

### Part F — Delegated authorization — OAuth 2

*20 chapters. Letting app A call API B on a user's behalf.*

| # | Chapter | Builds on |
|---|---|---|
| F01 | [The problem OAuth was invented to solve](book/track-f/F01-the-problem-oauth-solves.md) | A08 |
| F02 | [Four roles and two channels](book/track-f/F02-four-roles-two-channels.md) | F01 |
| F03 | [The authorization code flow, drawn slowly](book/track-f/F03-authorization-code-flow.md) | F02, A09 |
| F04 | [Build an OAuth client with raw HTTP, no SDK](book/track-f/F04-build-oauth-client-raw-http.md) | F03 |
| F05 | [The state parameter: CSRF for OAuth](book/track-f/F05-the-state-parameter.md) | F04, E15 |
| F06 | [PKCE: what it fixes, and why it's mandatory now](book/track-f/F06-pkce.md) | F04, B04 |
| F07 | [Access tokens, refresh tokens, and scopes](book/track-f/F07-access-refresh-scopes.md) | F04, E10 |
| F08 | [Audience and resource indicators: the part everyone gets wrong](book/track-f/F08-audience-and-resource-indicators.md) | F07 |
| F09 | [Public vs confidential clients, and why it changes everything](book/track-f/F09-public-vs-confidential-clients.md) | F04 |
| F10 | [Client credentials: machine-to-machine auth](book/track-f/F10-client-credentials.md) | F09 |
| F11 | [The device flow: how your TV logs in](book/track-f/F11-device-flow.md) | F03 |
| F12 | [Token introspection vs local validation](book/track-f/F12-introspection-vs-local-validation.md) | F07, E06 |
| F13 | [Consent screens, and the UX that prevents phishing](book/track-f/F13-consent-screens.md) | F03 |
| F14 | [Build a minimal authorization server](book/track-f/F14-build-an-authorization-server.md) | F06, F12 |
| F15 | [Implicit and password grants: why they're dead](book/track-f/F15-implicit-and-password-grants.md) | F06 |
| F16 | [Sender-constrained tokens: mTLS and DPoP](book/track-f/F16-sender-constrained-tokens.md) | F07, B15 |
| F17 | [OAuth for SPAs, and the backend-for-frontend pattern](book/track-f/F17-oauth-for-spas-and-bff.md) | F06, E12 |
| F18 | [OAuth for mobile: deep links and app-claimed URLs](book/track-f/F18-oauth-for-mobile.md) | F06, A09 |
| F19 | [Token exchange, impersonation, and delegation](book/track-f/F19-token-exchange.md) | F07 |
| F20 | [OAuth's failure modes: redirect_uri smuggling, mix-up, token leakage](book/track-f/F20-attack-your-own-oauth.md) | F14, F05 |

### Part G — Federated identity & SSO

*14 chapters. "Log in with Google," and its enterprise cousins.*

| # | Chapter | Builds on |
|---|---|---|
| G01 | [What actually happens when you click "Sign in with Google"](book/track-g/G01-sign-in-with-google.md) | F03 |
| G02 | [OIDC on top of OAuth: what the openid scope changes](book/track-g/G02-oidc-on-top-of-oauth.md) | G01, F07 |
| G03 | [ID token vs access token: stop sending the wrong one](book/track-g/G03-id-token-vs-access-token.md) | G02, F08 |
| G04 | [Validate an ID token by hand: JWKS, iss, aud, nonce, exp](book/track-g/G04-validate-an-id-token-by-hand.md) | G03, E07 |
| G05 | [Discovery and .well-known: how clients configure themselves](book/track-g/G05-discovery-and-well-known.md) | G04 |
| G06 | [Claims vs scopes, and the UserInfo endpoint](book/track-g/G06-claims-vs-scopes-userinfo.md) | G02 |
| G07 | [SAML survival guide](book/track-g/G07-saml-survival-guide.md) | G01 |
| G08 | [SAML vs OIDC: what to offer enterprise customers](book/track-g/G08-saml-vs-oidc.md) | G07, G02 |
| G09 | [Multi-tenant SSO for B2B SaaS: the IdP-per-customer problem](book/track-g/G09-multi-tenant-sso.md) | G08 |
| G10 | [Home realm discovery: routing users by email domain](book/track-g/G10-home-realm-discovery.md) | G09 |
| G11 | [Federated sessions and single logout](book/track-g/G11-federated-sessions-single-logout.md) | G05, E14 |
| G12 | [Account linking: same human, three identity providers](book/track-g/G12-account-linking.md) | G06 |
| G13 | [Enterprise directories you'll meet: LDAP, Kerberos, Active Directory](book/track-g/G13-enterprise-directories.md) | G07 |
| G14 | [SSO's failure modes: signature wrapping, replay, and identity confusion](book/track-g/G14-attack-your-own-sso.md) | G04, F20 |

### Part H — Authorization

*14 chapters. What someone can do once they’re in.*

| # | Chapter | Builds on |
|---|---|---|
| H01 | [Where does authorization actually live in your app?](book/track-h/H01-where-does-authz-live.md) | C02 |
| H02 | [The enforcement point: middleware, service layer, or database?](book/track-h/H02-the-enforcement-point.md) | H01 |
| H03 | [Access control lists and direct permissions](book/track-h/H03-acls-and-direct-permissions.md) | H01 |
| H04 | [RBAC, and the exact moment it breaks](book/track-h/H04-rbac-and-when-it-breaks.md) | H03 |
| H05 | [Roles vs permissions vs scopes vs groups](book/track-h/H05-roles-permissions-scopes-groups.md) | H04, F07 |
| H06 | [ABAC and policy-based access control](book/track-h/H06-abac.md) | H04 |
| H07 | [ReBAC and the Zanzibar model](book/track-h/H07-rebac-and-zanzibar.md) | H04 |
| H08 | [Model Google Drive's sharing rules in OpenFGA](book/track-h/H08-model-drive-in-openfga.md) | H07 |
| H09 | [Multi-tenancy and the isolation problem](book/track-h/H09-multi-tenancy-isolation.md) | H04 |
| H10 | [Row-level security: authorization in the database](book/track-h/H10-row-level-security.md) | H02 |
| H11 | [OPA, Cedar, or just SQL?](book/track-h/H11-opa-cedar-or-sql.md) | H06, H08 |
| H12 | [Authorization in microservices: who decides, and where?](book/track-h/H12-authz-in-microservices.md) | H02, F08 |
| H13 | [Audit logging: proving who did what](book/track-h/H13-audit-logging.md) | H02 |
| H14 | [Broken access control: IDOR, privilege escalation, mass assignment](book/track-h/H14-attack-your-own-authorization.md) | H09, H04 |

### Part I — Identity lifecycle & operations

*12 chapters. The half of auth that only shows up in production.*

| # | Chapter | Builds on |
|---|---|---|
| I01 | [The identity lifecycle: joiner, mover, leaver](book/track-i/I01-identity-lifecycle.md) | C01 |
| I02 | [Provisioning: manual, just-in-time, and SCIM](book/track-i/I02-provisioning-and-scim.md) | I01, G09 |
| I03 | [Deprovisioning: the offboarding gap that fails audits](book/track-i/I03-deprovisioning.md) | I02 |
| I04 | [Admin impersonation: letting support log in as a user, safely](book/track-i/I04-admin-impersonation.md) | F19, H13 |
| I05 | [Secrets management: KMS, vaults, and never in git](book/track-i/I05-secrets-management.md) | A10 |
| I06 | [Key rotation without downtime: kid, JWKS, overlap windows](book/track-i/I06-key-rotation.md) | E07, I05 |
| I07 | [Testing auth: the tests everyone skips](book/track-i/I07-testing-auth.md) | E16 |
| I08 | [Observability for auth: what to log, and what never to log](book/track-i/I08-observability.md) | H13 |
| I09 | [Detecting account takeover: signals and risk scoring](book/track-i/I09-detecting-account-takeover.md) | D08 |
| I10 | [Incident response: your tokens leaked, now what?](book/track-i/I10-incident-response.md) | E11, I06 |
| I11 | [Compliance without a lawyer: SOC 2, GDPR, data minimization in tokens](book/track-i/I11-compliance.md) | I03, I08 |
| I12 | [Migrating auth: rehashing passwords, cutting over, not logging everyone out](book/track-i/I12-migrating-auth.md) | D03, E03 |

### Part J — Machine, workload & agent identity

*8 chapters. Auth when there’s no human at all.*

| # | Chapter | Builds on |
|---|---|---|
| J01 | [Machine identity is not user identity](book/track-j/J01-machine-identity-is-not-user-identity.md) | F10 |
| J02 | [API keys: why they persist, and how to do them properly](book/track-j/J02-api-keys.md) | B13, F10 |
| J03 | [Service accounts and their failure modes](book/track-j/J03-service-accounts.md) | J01 |
| J04 | [mTLS: mutual authentication at the transport layer](book/track-j/J04-mtls.md) | B15, F16 |
| J05 | [Workload identity: SPIFFE, SPIRE, and cloud federation](book/track-j/J05-workload-identity-spiffe.md) | J04 |
| J06 | [Signing webhooks, and verifying them correctly](book/track-j/J06-signing-webhooks.md) | B13, B16 |
| J07 | [Auth for AI agents: delegating to a non-human actor](book/track-j/J07-auth-for-ai-agents.md) | F19, F14 |
| J08 | [MCP and OAuth 2.1: dynamic client registration, resource-scoped tokens](book/track-j/J08-mcp-and-oauth-21.md) | J07, F14 |

### Part K — Capstone

*5 chapters. Assemble everything into one application.*

| # | Chapter | Builds on |
|---|---|---|
| K01 | [One app, all five layers: architecture review](book/track-k/K01-architecture-review.md) | — |
| K02 | [Build the capstone, part 1: authentication and sessions](book/track-k/K02-capstone-part-1.md) | — |
| K03 | [Build the capstone, part 2: OAuth, SSO, authorization](book/track-k/K03-capstone-part-2.md) | — |
| K05 | [What should you use? The decision tree](book/track-k/K05-the-decision-tree.md) | K03 |
| K06 | [Where to go next: specs, papers, and staying current](book/track-k/K06-where-to-go-next.md) | K05 |

---

## Appendices

- **[GLOSSARY.md](GLOSSARY.md)** — every term, defined, with where it's introduced.
- **[The decision tree](appendix/decision-tree.md)** — six questions, out comes your stack.
- **[RFC & spec index](appendix/rfc-index.md)** — which specs you need, which you can ignore.
- **[Sources by track](SOURCES.md)** — the reading list behind each part.
- **[Deliberately excluded](appendix/excluded.md)** — the boundary of scope, stated so it stops
  growing.

---

## Where to start reading

If you're picking one place to begin, start with **Part E — Sessions & tokens**. It's the material
most people are most confused about, and "what a JWT actually is" ([E05](book/track-e/E05-jwt-part-1-three-parts.md))
is the single highest-leverage concept in the book.

---

## A note on correctness

Parts A–E cover material that's stable and well-understood. Parts F, G, H, and J are where subtly
wrong advice causes real breaches — delegation, federation, authorization, and machine/agent
identity. Every normative claim in this book is anchored to a primary source (an RFC, a NIST
publication, a W3C recommendation, or a vendor's own documentation), and where the field is still
moving — OAuth 2.1, MCP authorization, WebAuthn Level 3 — the chapter says so and dates the claim.
If you build on those parts, get them reviewed.

*Last reviewed against primary sources: August 2026.*
