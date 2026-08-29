# Auth, from zero to pro

A complete curriculum. No assumed knowledge.

---

## How to use this document

This is a **dependency graph**, not a playlist. Episodes are grouped into tracks
and numbered for reference, but the numbers are not a mandatory viewing order.
Each episode declares what it needs. A viewer who already knows hashing skips
straight to HMAC; a total beginner has a path from the absolute start.

Format tags:

- `[C]` **Concept.** Whiteboard or animation. No code on screen.
- `[B]` **Build.** Uncut screen recording. Code that runs.
- `[A]` **Attack.** Break the thing that was built two episodes ago.

Never mix `[C]` and `[B]` inside one episode. The visual whiplash loses people.

---

## The five non-negotiable rules

**1. No undefined terms.** A term may appear in an episode only if it was
defined in a prerequisite episode, or is defined on screen within thirty seconds
of first use. Maintain `GLOSSARY.md` in the repo as the ledger of defined terms.
If a script uses a term not on that list, the script is broken. Treat it as a
build failure, not a style note.

**2. Every layer ends with an attack episode.** Not optional. The attack
episodes are simultaneously the best teaching and the best growth engine.
"I broke my own login four ways" outperforms "understanding session management"
and teaches more.

**3. Every episode opens with the failure, not the topic.** Not "today we'll
learn about PKCE." Instead: here's an app, here's me stealing an authorization
code from it, here's the one parameter that stops me. Thirty seconds, then the
explanation.

**4. One repo, one git tag per episode.** Viewers check out `ep-E03-sessions`
and follow along. The repo will end up more valuable than the videos and is
what gets you cited.

**5. Titles are search queries.** "How to store passwords in 2026" not
"Module 4.2: Credential Storage." Every episode has to survive as a standalone
search result, because that is how almost everyone will arrive.

---

## The running project

One application, accumulating layers across the whole series.

**What it is:** a document-sharing app. Chosen deliberately, because sharing
semantics force genuinely hard authorization modeling in Track H, and nothing
else in a tutorial app does.

**Stack:** boring on purpose. A single language, a relational database, server-
rendered pages until Track E forces the SPA discussion. No framework that hides
the mechanism you're teaching. The whole point is that viewers see the HTTP.

**Rule:** libraries are banned until the mechanism has been built by hand. Build
HMAC verification manually in `B13`, then switch to the library in `E06` and
say why. Viewers need to know what the library is doing before they trust it.

---

# Track A — How the web actually works

11 episodes. The prerequisites every auth tutorial assumes and never teaches.

| # | Title | Fmt | Needs |
|---|---|---|---|
| A01 | What happens when you type a URL and press enter | C | — |
| A02 | Reading HTTP requests and responses in your browser dev tools | B | A01 |
| A03 | HTTP methods, status codes, and why 401 is not 403 | C | A02 |
| A04 | Headers: the metadata every request carries | C | A02 |
| A05 | What "stateless" means, and why HTTP forgets who you are | C | A03 |
| A06 | Cookies: what they are, where they live, who sends them | C/B | A05 |
| A07 | Client vs server: which of your code can an attacker read? | C | A01 |
| A08 | What an API is, and what "acting on someone's behalf" means | C | A03 |
| A09 | Redirects, and why the address bar is a security boundary | C | A03 |
| A10 | Where secrets live: env vars, and never in your frontend bundle | C/B | A07 |
| A11 | Same-origin policy and CORS, explained without the panic | C | A06, A07 |

`A07` is the highest-leverage episode in the track. Nearly every beginner auth
mistake is a misunderstanding of what the attacker can read.

---

# Track B — Crypto foundations

17 episodes, in strict dependency order. This track is why the rest works.

| # | Title | Fmt | Needs |
|---|---|---|---|
| B01 | Bits, bytes, and how text becomes numbers | C | — |
| B02 | Encoding is not encryption: base64, hex, URL encoding | C/B | B01 |
| B03 | Randomness, and why `Math.random()` will get you breached | C/B | B01 |
| B04 | What a hash function is | C/B | B01 |
| B05 | Hashing vs encryption: one-way vs reversible | C | B04 |
| B06 | Collisions, and why MD5 and SHA-1 were retired | C | B04 |
| B07 | Why fast hashes are the wrong tool for passwords | C | B04 |
| B08 | Salts, peppers, and slow hashes: bcrypt, scrypt, argon2id | C/B | B07 |
| B09 | Symmetric encryption: XOR by hand, then AES | C/B | B01, B05 |
| B10 | The key distribution problem | C | B09 |
| B11 | Asymmetric encryption and one-way math | C | B10 |
| B12 | Key exchange: agreeing on a secret in public | C | B11 |
| B13 | Message authentication: hashing with a secret, and HMAC | C/B | B04, B09 |
| B14 | Digital signatures: asymmetric encryption run backwards | C/B | B11, B13 |
| B15 | Certificates and PKI: why your browser trusts a stranger | C | B14 |
| B16 | Timing attacks and constant-time comparison | C/A/B | B13 |
| B17 | What HTTPS actually protects, and what it doesn't | C | B12, B15 |

Notes on the tricky ones:

- **B03** causes real breaches and is almost never taught. Demo: generate 1000
  session IDs with `Math.random()`, show the predictability, then predict one.
- **B09** does XOR by hand on paper first. Eight bits, one letter, encrypt and
  decrypt live. Then reveal that AES is the same idea with fourteen rounds.
- **B13** must show *why* `SHA256(secret + message)` is broken (length extension)
  before showing HMAC's two-pass construction. The naive version has to fail on
  screen or HMAC looks like arbitrary ceremony.
- **B16** is where `if (tag === expected)` gets replaced with a constant-time
  compare, and the viewer sees the timing difference on a graph.

---

# Track C — The map

5 episodes. Watch after A and B. This is where "auth" stops being one word.

| # | Title | Fmt | Needs |
|---|---|---|---|
| C01 | "Auth" is five different problems | C | A06, B14 |
| C02 | Authentication vs authorization vs session, once and for all | C | C01 |
| C03 | The vocabulary: principal, subject, claim, scope, credential, token | C | C01 |
| C04 | Threat modeling for normal people: who's attacking, with what? | C | A07 |
| C05 | Build vs buy: when to use a provider, and when not to | C | C01 |

`C01` is the flagship and the pinned video. `C04` belongs early because every
later design decision is downstream of "who is the attacker and what do they
already have."

---

# Track D — Layer 1: Authentication

19 episodes. Proving who someone is.

| # | Title | Fmt | Needs |
|---|---|---|---|
| D01 | Identifiers: what should a user actually log in with? | C | C03 |
| D02 | Email as identity: verification, plus-addressing, homoglyphs | C/B | D01 |
| D03 | How to store passwords in 2026 | C/B | B08 |
| D04 | Password policies that help, and the ones NIST removed | C | D03 |
| D05 | Build a login from scratch, part 1: registration | B | D03, A06 |
| D06 | Build a login from scratch, part 2: login and error handling | B | D05 |
| D07 | User enumeration: how your error messages leak your user list | A | D06 |
| D08 | Rate limiting, lockout, and credential stuffing defense | C/B | D06 |
| D09 | Account recovery is your real weakest link | C/B | D06 |
| D10 | Magic links and email OTP: how they work, when they're fine | C/B | D02 |
| D11 | Why SMS is the worst second factor, and still the most common | C | D10 |
| D12 | Build TOTP two-factor from scratch | B | B13, D06 |
| D13 | Recovery codes, and the 2FA lockout problem | C/B | D12 |
| D14 | WebAuthn and passkeys: the concepts | C | B14 |
| D15 | Build passkey registration and login | B | D14 |
| D16 | Biometrics: what your fingerprint actually proves | C | D14 |
| D17 | "Remember this device" is harder than it looks | C/B | D12 |
| D18 | Step-up auth and assurance levels (NIST AAL) | C | D12, C04 |
| D19 | Attack your own login: enumeration, timing, stuffing, reset abuse | A | D09, B16 |

Notes:

- **D12** is where `B13` pays off. TOTP is HMAC over a time counter, truncated to
  six digits. Viewers who watched `B13` will build it in twenty minutes and feel
  the concepts connect. This is the emotional high point of the early series.
- **D16** must land the distinction most people never learn: your fingerprint
  unlocks a private key held on the device. It is never transmitted, and the
  server never sees a biometric. Get this wrong and passkeys stay magic.
- **D09** deserves the full episode. More accounts are stolen through password
  reset than through password guessing.

---

# Track E — Layer 2: Sessions and tokens

17 episodes. Keeping someone logged in.

| # | Title | Fmt | Needs |
|---|---|---|---|
| E01 | Why HTTP needs sessions at all | C | A05 |
| E02 | Cookie attributes that matter: HttpOnly, Secure, SameSite, `__Host-` | C/B | A06 |
| E03 | Build server-side sessions | B | E01, B03 |
| E04 | Session IDs: generation, entropy, storage, expiry | C/B | E03, B03 |
| E05 | What a JWT actually is, part 1: the three parts | C/B | B02 |
| E06 | What a JWT actually is, part 2: the signature, JWS vs JWE | C/B | E05, B13, B14 |
| E07 | JOSE, JWK, JWKS, JWA: the acronym family, untangled | C | E06 |
| E08 | Signed cookies vs JWTs vs opaque tokens: pick one | C | E04, E06 |
| E09 | Should you use JWTs for sessions? | C | E08 |
| E10 | Token lifetimes, refresh tokens, and rotation | C/B | E08 |
| E11 | Revocation: the thing stateless tokens are bad at | C | E10 |
| E12 | Where to store a token in a browser: localStorage, cookie, memory | C | E02, A07 |
| E13 | Sessions across devices: listing, remote logout, "log out everywhere" | C/B | E03 |
| E14 | Why logging out is genuinely hard | C | E11, E13 |
| E15 | CSRF: what it is, and why SameSite mostly killed it | C/A/B | E02 |
| E16 | XSS is an auth vulnerability | C/A | A07, E12 |
| E17 | Attack your own sessions: fixation, XSS theft, `alg: none`, tampering | A | E16, E06 |

Notes:

- **E05** is the episode I'd most want to get right. Decode a JWT live. Show the
  payload is plain readable base64 and that anyone can read it. Then change one
  character and watch verification fail. That single demo is the whole lesson.
- **E09** is your opinionated episode and will be the highest-traffic video in
  the track. Take the position (sessions for first-party web apps), then link the
  dissent. Fence-sitting here is worse than being wrong.
- **E17** demonstrates `alg: none` by hand. It's a two-line forge, and seeing it
  work is what makes people take library choice seriously.

---

# Track F — Layer 3: Delegated authorization (OAuth 2)

20 episodes. Letting app A call API B on a user's behalf.

| # | Title | Fmt | Needs |
|---|---|---|---|
| F01 | The problem OAuth was invented to solve | C | A08 |
| F02 | Four roles and two channels | C | F01 |
| F03 | The authorization code flow, drawn slowly | C | F02, A09 |
| F04 | Build an OAuth client with raw HTTP, no SDK | B | F03 |
| F05 | The `state` parameter: CSRF for OAuth | C/B | F04, E15 |
| F06 | PKCE: what it fixes, and why it's mandatory now | C/B | F04, B04 |
| F07 | Access tokens, refresh tokens, and scopes | C | F04, E10 |
| F08 | Audience and resource indicators: the part everyone gets wrong | C | F07 |
| F09 | Public vs confidential clients, and why it changes everything | C | F04 |
| F10 | Client credentials: machine-to-machine auth | C/B | F09 |
| F11 | The device flow: how your TV logs in | C/B | F03 |
| F12 | Token introspection vs local validation | C/B | F07, E06 |
| F13 | Consent screens, and the UX that prevents phishing | C | F03 |
| F14 | Build a minimal authorization server | B | F06, F12 |
| F15 | Implicit and password grants: why they're dead | C | F06 |
| F16 | Sender-constrained tokens: mTLS and DPoP | C | F07, B15 |
| F17 | OAuth for SPAs, and the backend-for-frontend pattern | C/B | F06, E12 |
| F18 | OAuth for mobile: deep links and app-claimed URLs | C/B | F06, A09 |
| F19 | Token exchange, impersonation, and delegation | C | F07 |
| F20 | Attack your own OAuth: `redirect_uri` smuggling, missing state, mix-up | A | F14, F05 |

Notes:

- **F04** must use raw HTTP. The SDK hides exactly the parts that matter. Once
  the flow has been done by hand, switching to a library in `F17` is a relief
  rather than a mystery.
- **F15** exists because most tutorials on the internet still teach implicit.
  Viewers need the vocabulary to recognize stale advice, since they will find it.
- **F16** can be short. Bearer tokens are still fine in most contexts, but DPoP
  is part of the landscape now and shouldn't be a surprise later.

---

# Track G — Layer 4: Federated identity and SSO

14 episodes. "Log in with Google," and its enterprise cousins.

| # | Title | Fmt | Needs |
|---|---|---|---|
| G01 | What actually happens when you click "Sign in with Google" | C | F03 |
| G02 | OIDC on top of OAuth: what the `openid` scope changes | C | G01, F07 |
| G03 | ID token vs access token: stop sending the wrong one | C | G02, F08 |
| G04 | Validate an ID token by hand: JWKS, `iss`, `aud`, `nonce`, `exp` | B | G03, E07 |
| G05 | Discovery and `.well-known`: how clients configure themselves | C/B | G04 |
| G06 | Claims vs scopes, and the UserInfo endpoint | C | G02 |
| G07 | SAML survival guide | C | G01 |
| G08 | SAML vs OIDC: what to offer enterprise customers | C | G07, G02 |
| G09 | Multi-tenant SSO for B2B SaaS: the IdP-per-customer problem | C/B | G08 |
| G10 | Home realm discovery: routing users by email domain | C/B | G09 |
| G11 | Federated sessions and single logout | C | G05, E14 |
| G12 | Account linking: same human, three identity providers | C/B | G06 |
| G13 | Enterprise directories you'll meet: LDAP, Kerberos, Active Directory | C | G07 |
| G14 | Attack your own SSO: signature wrapping, nonce replay, open redirects | A | G04, F20 |

Notes:

- **G04** is the payoff episode for Track B. Fetch the JWKS, pick the key by
  `kid`, verify the signature, check every claim. All the crypto becomes concrete.
- **G07** gets exactly one episode. SAML deserves respect and not much airtime.
- **G12** is the unglamorous episode that saves viewers from a production
  disaster. Two accounts, one human, and no way to merge them.

---

# Track H — Layer 5: Authorization

14 episodes. What someone can do once they're in.

| # | Title | Fmt | Needs |
|---|---|---|---|
| H01 | Where does authorization actually live in your app? | C | C02 |
| H02 | The enforcement point: middleware, service layer, or database? | C | H01 |
| H03 | Access control lists and direct permissions | C/B | H01 |
| H04 | RBAC, and the exact moment it breaks | C/B | H03 |
| H05 | Roles vs permissions vs scopes vs groups | C | H04, F07 |
| H06 | ABAC and policy-based access control | C | H04 |
| H07 | ReBAC and the Zanzibar model | C | H04 |
| H08 | Model Google Drive's sharing rules in OpenFGA | B | H07 |
| H09 | Multi-tenancy and the isolation problem | C/B | H04 |
| H10 | Row-level security: authorization in the database | C/B | H02 |
| H11 | OPA, Cedar, or just SQL? | C | H06, H08 |
| H12 | Authorization in microservices: who decides, and where? | C | H02, F08 |
| H13 | Audit logging: proving who did what | C/B | H02 |
| H14 | Attack your own authorization: IDOR, privilege escalation, mass assignment | A | H09, H04 |

Notes:

- **H04** needs a concrete breaking point, not a hand-wave. Add "share this one
  document with one external person" to a role-based system and watch the role
  table explode. That failure motivates all of `H06`–`H08`.
- **H05** is pure vocabulary triage and unusually valuable. These four words get
  used interchangeably in every codebase and mean four different things.
- **H14** covers IDOR, which is statistically the most common serious
  vulnerability in real applications. It deserves the airtime.

---

# Track I — Identity lifecycle and operations

12 episodes. The half of auth that only shows up in production.

| # | Title | Fmt | Needs |
|---|---|---|---|
| I01 | The identity lifecycle: joiner, mover, leaver | C | C01 |
| I02 | Provisioning: manual, just-in-time, and SCIM | C/B | I01, G09 |
| I03 | Deprovisioning: the offboarding gap that fails audits | C/B | I02 |
| I04 | Admin impersonation: letting support log in as a user, safely | C/B | F19, H13 |
| I05 | Secrets management: KMS, vaults, and never in git | C/B | A10 |
| I06 | Key rotation without downtime: `kid`, JWKS, overlap windows | C/B | E07, I05 |
| I07 | Testing auth: the tests everyone skips | C/B | E17 |
| I08 | Observability for auth: what to log, and what never to log | C/B | H13 |
| I09 | Detecting account takeover: signals and risk scoring | C | D08 |
| I10 | Incident response: your tokens leaked, now what? | C/B | E11, I06 |
| I11 | Compliance without a lawyer: SOC 2, GDPR, data minimization in tokens | C | I03, I08 |
| I12 | Migrating auth: rehashing passwords, cutting over, not logging everyone out | C/B | D03, E03 |

Notes:

- **I06** is invisible until the day it isn't. Show the overlap window: publish
  the new key, wait for cache expiry, *then* start signing with it. Doing it in
  the wrong order logs out every user simultaneously.
- **I08** must cover what never to log. Tokens, session IDs, password reset
  links, and full authorization headers all end up in logs constantly, which
  turns your log aggregator into a credential store.
- **I12** is the episode nobody makes and everybody needs. Rehash-on-login is
  the technique, and it isn't obvious.

---

# Track J — Machine, workload, and agent identity

8 episodes. Auth when there's no human at all.

| # | Title | Fmt | Needs |
|---|---|---|---|
| J01 | Machine identity is not user identity | C | F10 |
| J02 | API keys: why they persist, and how to do them properly | C/B | B13, F10 |
| J03 | Service accounts and their failure modes | C | J01 |
| J04 | mTLS: mutual authentication at the transport layer | C/B | B15, F16 |
| J05 | Workload identity: SPIFFE, SPIRE, and cloud federation | C | J04 |
| J06 | Signing webhooks, and verifying them correctly | C/B | B13, B16 |
| J07 | Auth for AI agents: delegating to a non-human actor | C | F19, F14 |
| J08 | MCP and OAuth 2.1: dynamic client registration, resource-scoped tokens | C/B | J07, F14 |

Notes:

- **J02** covers hashed storage of keys, prefixes for scanning, and the
  `sk_live_` convention that lets GitHub secret-scanning find leaks. Practical
  and almost never taught.
- **J06** is the shortest path to making `B13` and `B16` feel urgent, because
  every viewer has integrated a webhook and most verified it wrong.
- **J07** and **J08** are your differentiator. Almost nobody has taught this yet,
  and it is the direction the whole field is currently moving.

---

# Track K — Capstone

6 episodes. Assemble everything, then break it.

| # | Title | Fmt | Needs |
|---|---|---|---|
| K01 | One app, all five layers: architecture review | C | all |
| K02 | Build the capstone, part 1: authentication and sessions | B | D, E |
| K03 | Build the capstone, part 2: OAuth, SSO, authorization | B | F, G, H |
| K04 | Now break it: a full attack pass | A | K03 |
| K05 | What should *you* use? The decision tree | C | K04 |
| K06 | Where to go next: specs, papers, and staying current | C | K05 |

`K05` should exist as an interactive tool on the site as well as a video. Six
questions about your architecture, and out comes the stack: session type, token
format, grant type, authorization model, plus the RFCs you need and the ones you
can ignore. That page will get more traffic than the rest of the site combined.

---

## Total: 143 episodes

That is not a series you can announce. At weekly cadence it's nearly three years.

**So change the unit of shipping.** Episodes are the curriculum unit. Uploads are
the marketing unit. They are not the same thing.

Bundle into roughly 30 long-form videos with chapter markers, each 40–120
minutes. A bundle is one commitment for a viewer and one production cycle for
you, and chapter markers preserve the granularity for anyone who wants to jump.
"Crypto for people who don't do math" gets watched on its own merits. "Episode 7
of the prerequisites season" does not.

Suggested bundles:

| Bundle | Episodes | Working title |
|---|---|---|
| 1 | A01–A11 | How the web actually works |
| 2 | B01–B08 | Hashing, and why passwords are special |
| 3 | B09–B17 | Crypto for people who don't do math |
| 4 | C01–C05 | "Auth" is five different problems |
| 5 | D01–D09 | Building a login you won't regret |
| 6 | D10–D19 | Two-factor, passkeys, and killing the password |
| 7 | E01–E09 | Sessions, cookies, and what a JWT really is |
| 8 | E10–E17 | Token lifetimes, logout, and session attacks |
| 9 | F01–F08 | OAuth 2 from first principles |
| 10 | F09–F20 | OAuth in the real world: SPAs, mobile, and attacks |
| 11 | G01–G07 | Sign in with Google, explained properly |
| 12 | G08–G14 | Enterprise SSO and multi-tenant identity |
| 13 | H01–H08 | Authorization: from RBAC to Zanzibar |
| 14 | H09–H14 | Multi-tenancy, enforcement, and IDOR |
| 15 | I01–I12 | The auth work nobody warns you about |
| 16 | J01–J08 | Machines, workloads, and AI agents |
| 17 | K01–K06 | The capstone |

Seventeen bundles is roughly fifteen months at one every three weeks. That is a
real commitment you can actually announce.

---

## Release order, which is not curriculum order

Publishing sequentially kills the project around bundle 2, because nobody knows
you exist yet and prerequisite content has no independent search demand.

**Phase 1, prove the format.** Ship the standalone episodes with the highest
search intent, as individual videos:

- `E05`/`E06` — what a JWT actually is
- `E09` — should you use JWTs for sessions
- `F06` — PKCE explained
- `G01` — what happens when you click "Sign in with Google"
- `H04` — RBAC and the moment it breaks
- `D03` — how to store passwords in 2026

**Phase 2, backfill the foundations.** Once traffic exists, ship bundles 1–3.
Now you have somewhere to send the commenters who say "you lost me at HMAC," and
that link becomes permanent infrastructure.

**Phase 3, fill the graph.** Remaining bundles in dependency order. Reorder the
playlists as you go; the playlist is the course, the upload date is not.

---

## Reference materials by track

| Track | Primary sources |
|---|---|
| A | MDN HTTP guide; *High Performance Browser Networking* (Grigorik, free) |
| B | *Real-World Cryptography* (Wong); *Serious Cryptography* (Aumasson); Cryptopals |
| C | *Solving Identity Management in Modern Applications* (Wilson & Hingnikar, 2nd ed) |
| D | The Copenhagen Book; NIST SP 800-63B-4; OWASP Authentication Cheat Sheet; passkeys.dev |
| E | The Copenhagen Book; RFC 7519 (JWT); RFC 7515 (JWS); OWASP Session Management Cheat Sheet |
| F | oauth.com (Parecki); RFC 6749; RFC 9700 (Security BCP); *OAuth 2 in Action* |
| G | OpenID Connect Core; NIST SP 800-63C-4; OASIS SAML 2.0 Technical Overview |
| H | Google Zanzibar paper; zanzibar.academy; OpenFGA docs; OPA and Cedar docs |
| I | RFC 7644 (SCIM); *Solving Identity Management*; cloud KMS docs |
| J | RFC 8705 (mTLS); RFC 9449 (DPoP); SPIFFE docs; MCP authorization spec |
| K | *API Security in Action* (Madden); RFC 9700; OWASP ASVS chapters 2, 3, 7 |

Two books carry disproportionate weight. *Solving Identity Management in Modern
Applications* is the only book whose table of contents maps onto all five layers,
so use it as the structural spine. *API Security in Action* is the best technical
writing in the field and should be the reference for anything in tracks E, F,
and H.

---

## The glossary ledger

`GLOSSARY.md` in the repo, one row per term, maintained as a hard gate:

```
term | plain-language definition | defined in | first used in
```

Terms that must be on this list before Track C begins, because I dropped every
one of them without explanation at some point in the conversation that produced
this document: hash, salt, HMAC, MAC, key, symmetric, asymmetric, public key,
private key, signature, certificate, nonce, entropy, base64, TOTP, JWT, JWS,
JWKS, `kid`, claim, scope, audience, bearer token, session, cookie, origin,
redirect, PKCE, IdP, SP, assertion, RBAC, ABAC, ReBAC, IDOR, CSRF, XSS.

Thirty-six terms. That count is the argument for Tracks A and B existing.

---

## Deliberately excluded

Stating the boundary keeps the scope from growing without limit.

- **Cryptographic implementation.** Viewers learn what AES does, never how to
  implement it. "Don't roll your own crypto" is taught by not teaching it.
- **Post-quantum migration.** Real, and moving too fast for evergreen video.
  Cover it in a dated blog post instead.
- **Blockchain and decentralized identity.** DIDs and verifiable credentials are
  a separate curriculum with a different audience. One "why this isn't covered"
  episode at most.
- **Specific vendor configuration.** No "how to set up Auth0" tutorials. They
  rot in months and the vendor already made them.
- **Physical and hardware security.** HSMs get a mention in `I05`. Secure
  enclaves get a mention in `D16`. No more.
- **Anything network-layer below TLS.** Referenced, never taught.

---

## The uncomfortable part

Tracks A, B, C, D, and E you can write correctly now.

Tracks F, G, H, and J you cannot yet, on your own account. Auth content that is
subtly wrong causes breaches in other people's products, and this audience is
merciless about it. Budget for paid technical review on every episode in those
tracks before publishing, and say in the description who reviewed it. That line
does more for credibility than production quality ever will.

Start with bundle 7 (JWTs and sessions). It's the highest search demand, it's
material you can teach accurately today, and it's where the most people are
currently confused.
