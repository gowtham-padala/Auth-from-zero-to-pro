# CURRICULUM.md — the chapter plan

Extracted from plan.md (the original video curriculum) on 2026-09-16 so the book has a
single chapter ledger. This file is the source of truth for chapter IDs, titles and
prerequisites from now on; plan.md is historical.

Format: `Concept`, `Build` (code from /app is included), `Attack` (the reader breaks
what was built). Status: `draft` means a migrated video script exists in /book and
awaits rewrite to the CLAUDE.md voice spec; `final` means rewritten and passing
`make check`; `missing` means no draft exists yet.

## Open decisions for the author

1. Hard rule 4 (every layer ends with an attack chapter) is unmet: D19, E17 and K04 are
   in the plan but not written, and tracks I and J have no attack chapter in the plan.
2. Several titles name products (G01, H08, H11, J08) or are rhetorical questions (A07,
   C04, D01, E09, H01, H02, H11, H12, I10). Rule 2 and the banned-heading rule apply to
   prose; decide whether titles are exempt or get renamed at rewrite time.
3. E05 and E06 are being merged into one calibration chapter, "What a JWT actually is",
   numbered E05. E06's remaining material (JWE, header key injection, rotation) moves to
   E06/E07 when those are rewritten.
4. Audit recommended deleting or merging 15 chapters (A10, B14, D11, D16, D17, E07, E09,
   F15, G08, G13, H05, I01, J01, J03, K05). Not applied; decide per chapter.

## Track A — How the web actually works

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| A01 | What happens when you type a URL and press enter | Concept | — | draft |
| A02 | Reading HTTP requests and responses in your browser dev tools | Build | A01 | draft |
| A03 | HTTP methods, status codes, and why 401 is not 403 | Concept | A02 | draft |
| A04 | Headers: the metadata every request carries | Concept | A02 | draft |
| A05 | What "stateless" means, and why HTTP forgets who you are | Concept | A03 | draft |
| A06 | Cookies: what they are, where they live, who sends them | Concept/Build | A05 | draft |
| A07 | Client vs server: which of your code can an attacker read? | Concept | A01 | draft |
| A08 | What an API is, and what "acting on someone's behalf" means | Concept | A03 | draft |
| A09 | Redirects, and why the address bar is a security boundary | Concept | A03 | draft |
| A10 | Where secrets live: env vars, and never in your frontend bundle | Concept/Build | A07 | draft |
| A11 | Same-origin policy and CORS, explained without the panic | Concept | A06, A07 | draft |

## Track B — Crypto foundations

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| B01 | Bits, bytes, and how text becomes numbers | Concept | — | draft |
| B02 | Encoding is not encryption: base64, hex, URL encoding | Concept/Build | B01 | draft |
| B03 | Randomness, and why `Math.random()` will get you breached | Concept/Build | B01 | draft |
| B04 | What a hash function is | Concept/Build | B01 | draft |
| B05 | Hashing vs encryption: one-way vs reversible | Concept | B04 | draft |
| B06 | Collisions, and why MD5 and SHA-1 were retired | Concept | B04 | draft |
| B07 | Why fast hashes are the wrong tool for passwords | Concept | B04 | draft |
| B08 | Salts, peppers, and slow hashes: bcrypt, scrypt, argon2id | Concept/Build | B07 | draft |
| B09 | Symmetric encryption: XOR by hand, then AES | Concept/Build | B01, B05 | draft |
| B10 | The key distribution problem | Concept | B09 | draft |
| B11 | Asymmetric encryption and one-way math | Concept | B10 | draft |
| B12 | Key exchange: agreeing on a secret in public | Concept | B11 | draft |
| B13 | Message authentication: hashing with a secret, and HMAC | Concept/Build | B04, B09 | draft |
| B14 | Digital signatures: asymmetric encryption run backwards | Concept/Build | B11, B13 | draft |
| B15 | Certificates and PKI: why your browser trusts a stranger | Concept | B14 | draft |
| B16 | Timing attacks and constant-time comparison | Concept/Attack/Build | B13 | draft |
| B17 | What HTTPS actually protects, and what it doesn't | Concept | B12, B15 | draft |

## Track C — The map

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| C01 | "Auth" is five different problems | Concept | A06, B14 | draft |
| C02 | Authentication vs authorization vs session, once and for all | Concept | C01 | draft |
| C03 | The vocabulary: principal, subject, claim, scope, credential, token | Concept | C01 | draft |
| C04 | Threat modeling for normal people: who's attacking, with what? | Concept | A07 | draft |
| C05 | Build vs buy: when to use a provider, and when not to | Concept | C01 | draft |

## Track D — Layer 1: Authentication

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| D01 | Identifiers: what should a user actually log in with? | Concept | C03 | draft |
| D02 | Email as identity: verification, plus-addressing, homoglyphs | Concept/Build | D01 | draft |
| D03 | How to store passwords in 2026 | Concept/Build | B08 | draft |
| D04 | Password policies that help, and the ones NIST removed | Concept | D03 | draft |
| D05 | Build a login from scratch, part 1: registration | Build | D03, A06 | draft |
| D06 | Build a login from scratch, part 2: login and error handling | Build | D05 | draft |
| D07 | User enumeration: how your error messages leak your user list | Attack | D06 | draft |
| D08 | Rate limiting, lockout, and credential stuffing defense | Concept/Build | D06 | draft |
| D09 | Account recovery is your real weakest link | Concept/Build | D06 | draft |
| D10 | Magic links and email OTP: how they work, when they're fine | Concept/Build | D02 | draft |
| D11 | Why SMS is the worst second factor, and still the most common | Concept | D10 | draft |
| D12 | Build TOTP two-factor from scratch | Build | B13, D06 | draft |
| D13 | Recovery codes, and the 2FA lockout problem | Concept/Build | D12 | draft |
| D14 | WebAuthn and passkeys: the concepts | Concept | B14 | draft |
| D15 | Build passkey registration and login | Build | D14 | draft |
| D16 | Biometrics: what your fingerprint actually proves | Concept | D14 | draft |
| D17 | "Remember this device" is harder than it looks | Concept/Build | D12 | draft |
| D18 | Step-up auth and assurance levels (NIST AAL) | Concept | D12, C04 | draft |
| D19 | Attack your own login: enumeration, timing, stuffing, reset abuse | Attack | D09, B16 | **missing** |

## Track E — Layer 2: Sessions and tokens

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| E01 | Why HTTP needs sessions at all | Concept | A05 | draft |
| E02 | Cookie attributes that matter: HttpOnly, Secure, SameSite, `__Host-` | Concept/Build | A06 | draft |
| E03 | Build server-side sessions | Build | E01, B03 | draft |
| E04 | Session IDs: generation, entropy, storage, expiry | Concept/Build | E03, B03 | draft |
| E05 | What a JWT actually is, part 1: the three parts | Concept/Build | B02 | draft |
| E06 | What a JWT actually is, part 2: the signature, JWS vs JWE | Concept/Build | E05, B13, B14 | draft |
| E07 | JOSE, JWK, JWKS, JWA: the acronym family, untangled | Concept | E06 | draft |
| E08 | Signed cookies vs JWTs vs opaque tokens: pick one | Concept | E04, E06 | draft |
| E09 | Should you use JWTs for sessions? | Concept | E08 | draft |
| E10 | Token lifetimes, refresh tokens, and rotation | Concept/Build | E08 | draft |
| E11 | Revocation: the thing stateless tokens are bad at | Concept | E10 | draft |
| E12 | Where to store a token in a browser: localStorage, cookie, memory | Concept | E02, A07 | draft |
| E13 | Sessions across devices: listing, remote logout, "log out everywhere" | Concept/Build | E03 | draft |
| E14 | Why logging out is genuinely hard | Concept | E11, E13 | draft |
| E15 | CSRF: what it is, and why SameSite mostly killed it | Concept/Attack/Build | E02 | draft |
| E16 | XSS is an auth vulnerability | Concept/Attack | A07, E12 | draft |
| E17 | Attack your own sessions: fixation, XSS theft, `alg: none`, tampering | Attack | E16, E06 | **missing** |

## Track F — Layer 3: Delegated authorization (OAuth 2)

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| F01 | The problem OAuth was invented to solve | Concept | A08 | draft |
| F02 | Four roles and two channels | Concept | F01 | draft |
| F03 | The authorization code flow, drawn slowly | Concept | F02, A09 | draft |
| F04 | Build an OAuth client with raw HTTP, no SDK | Build | F03 | draft |
| F05 | The `state` parameter: CSRF for OAuth | Concept/Build | F04, E15 | draft |
| F06 | PKCE: what it fixes, and why it's mandatory now | Concept/Build | F04, B04 | draft |
| F07 | Access tokens, refresh tokens, and scopes | Concept | F04, E10 | draft |
| F08 | Audience and resource indicators: the part everyone gets wrong | Concept | F07 | draft |
| F09 | Public vs confidential clients, and why it changes everything | Concept | F04 | draft |
| F10 | Client credentials: machine-to-machine auth | Concept/Build | F09 | draft |
| F11 | The device flow: how your TV logs in | Concept/Build | F03 | draft |
| F12 | Token introspection vs local validation | Concept/Build | F07, E06 | draft |
| F13 | Consent screens, and the UX that prevents phishing | Concept | F03 | draft |
| F14 | Build a minimal authorization server | Build | F06, F12 | draft |
| F15 | Implicit and password grants: why they're dead | Concept | F06 | draft |
| F16 | Sender-constrained tokens: mTLS and DPoP | Concept | F07, B15 | draft |
| F17 | OAuth for SPAs, and the backend-for-frontend pattern | Concept/Build | F06, E12 | draft |
| F18 | OAuth for mobile: deep links and app-claimed URLs | Concept/Build | F06, A09 | draft |
| F19 | Token exchange, impersonation, and delegation | Concept | F07 | draft |
| F20 | Attack your own OAuth: `redirect_uri` smuggling, missing state, mix-up | Attack | F14, F05 | draft |

## Track G — Layer 4: Federated identity and SSO

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| G01 | What actually happens when you click "Sign in with Google" | Concept | F03 | draft |
| G02 | OIDC on top of OAuth: what the `openid` scope changes | Concept | G01, F07 | draft |
| G03 | ID token vs access token: stop sending the wrong one | Concept | G02, F08 | draft |
| G04 | Validate an ID token by hand: JWKS, `iss`, `aud`, `nonce`, `exp` | Build | G03, E07 | draft |
| G05 | Discovery and `.well-known`: how clients configure themselves | Concept/Build | G04 | draft |
| G06 | Claims vs scopes, and the UserInfo endpoint | Concept | G02 | draft |
| G07 | SAML survival guide | Concept | G01 | draft |
| G08 | SAML vs OIDC: what to offer enterprise customers | Concept | G07, G02 | draft |
| G09 | Multi-tenant SSO for B2B SaaS: the IdP-per-customer problem | Concept/Build | G08 | draft |
| G10 | Home realm discovery: routing users by email domain | Concept/Build | G09 | draft |
| G11 | Federated sessions and single logout | Concept | G05, E14 | draft |
| G12 | Account linking: same human, three identity providers | Concept/Build | G06 | draft |
| G13 | Enterprise directories you'll meet: LDAP, Kerberos, Active Directory | Concept | G07 | draft |
| G14 | Attack your own SSO: signature wrapping, nonce replay, open redirects | Attack | G04, F20 | draft |

## Track H — Layer 5: Authorization

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| H01 | Where does authorization actually live in your app? | Concept | C02 | draft |
| H02 | The enforcement point: middleware, service layer, or database? | Concept | H01 | draft |
| H03 | Access control lists and direct permissions | Concept/Build | H01 | draft |
| H04 | RBAC, and the exact moment it breaks | Concept/Build | H03 | draft |
| H05 | Roles vs permissions vs scopes vs groups | Concept | H04, F07 | draft |
| H06 | ABAC and policy-based access control | Concept | H04 | draft |
| H07 | ReBAC and the Zanzibar model | Concept | H04 | draft |
| H08 | Model Google Drive's sharing rules in OpenFGA | Build | H07 | draft |
| H09 | Multi-tenancy and the isolation problem | Concept/Build | H04 | draft |
| H10 | Row-level security: authorization in the database | Concept/Build | H02 | draft |
| H11 | OPA, Cedar, or just SQL? | Concept | H06, H08 | draft |
| H12 | Authorization in microservices: who decides, and where? | Concept | H02, F08 | draft |
| H13 | Audit logging: proving who did what | Concept/Build | H02 | draft |
| H14 | Attack your own authorization: IDOR, privilege escalation, mass assignment | Attack | H09, H04 | draft |

## Track I — Identity lifecycle and operations

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| I01 | The identity lifecycle: joiner, mover, leaver | Concept | C01 | draft |
| I02 | Provisioning: manual, just-in-time, and SCIM | Concept/Build | I01, G09 | draft |
| I03 | Deprovisioning: the offboarding gap that fails audits | Concept/Build | I02 | draft |
| I04 | Admin impersonation: letting support log in as a user, safely | Concept/Build | F19, H13 | draft |
| I05 | Secrets management: KMS, vaults, and never in git | Concept/Build | A10 | draft |
| I06 | Key rotation without downtime: `kid`, JWKS, overlap windows | Concept/Build | E07, I05 | draft |
| I07 | Testing auth: the tests everyone skips | Concept/Build | E17 | draft |
| I08 | Observability for auth: what to log, and what never to log | Concept/Build | H13 | draft |
| I09 | Detecting account takeover: signals and risk scoring | Concept | D08 | draft |
| I10 | Incident response: your tokens leaked, now what? | Concept/Build | E11, I06 | draft |
| I11 | Compliance without a lawyer: SOC 2, GDPR, data minimization in tokens | Concept | I03, I08 | draft |
| I12 | Migrating auth: rehashing passwords, cutting over, not logging everyone out | Concept/Build | D03, E03 | draft |

## Track J — Machine, workload, and agent identity

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| J01 | Machine identity is not user identity | Concept | F10 | draft |
| J02 | API keys: why they persist, and how to do them properly | Concept/Build | B13, F10 | draft |
| J03 | Service accounts and their failure modes | Concept | J01 | draft |
| J04 | mTLS: mutual authentication at the transport layer | Concept/Build | B15, F16 | draft |
| J05 | Workload identity: SPIFFE, SPIRE, and cloud federation | Concept | J04 | draft |
| J06 | Signing webhooks, and verifying them correctly | Concept/Build | B13, B16 | draft |
| J07 | Auth for AI agents: delegating to a non-human actor | Concept | F19, F14 | draft |
| J08 | MCP and OAuth 2.1: dynamic client registration, resource-scoped tokens | Concept/Build | J07, F14 | draft |

## Track K — Capstone

| # | Title | Format | Needs | Status |
|---|---|---|---|---|
| K01 | One app, all five layers: architecture review | Concept | all | draft |
| K02 | Build the capstone, part 1: authentication and sessions | Build | D, E | draft |
| K03 | Build the capstone, part 2: OAuth, SSO, authorization | Build | F, G, H | draft |
| K04 | Now break it: a full attack pass | Attack | K03 | **missing** |
| K05 | What should *you* use? The decision tree | Concept | K04 | draft |
| K06 | Where to go next: specs, papers, and staying current | Concept | K05 | draft |
