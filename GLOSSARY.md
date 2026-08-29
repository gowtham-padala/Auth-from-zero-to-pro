# GLOSSARY.md — the ledger

This file is a build gate, not a reference appendix.

**The rule:** a term may appear in a chapter only if it is already on this list with a
"defined in" chapter that precedes it in the dependency graph, or the chapter defines it
on the page within a paragraph of first use — in which case that chapter becomes its
"defined in" and this file gets a new row.

If a chapter uses a term with no row here, the chapter is broken. Fix the chapter or add
the row. Do not ship the chapter.

**Why this exists.** Thirty-six terms — hash, salt, HMAC, MAC, key, symmetric,
asymmetric, public key, private key, signature, certificate, nonce, entropy, base64,
TOTP, JWT, JWS, JWKS, kid, claim, scope, audience, bearer token, session, cookie, origin,
redirect, PKCE, IdP, SP, assertion, RBAC, ABAC, ReBAC, IDOR, CSRF, XSS — get dropped
without explanation in a typical hour of auth conversation. That count is the entire
argument for Tracks A and B existing.

Columns: **term** | **plain-language definition** | **defined in** | **first used in**

---

## A — Web and HTTP fundamentals

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| URL | The address of a thing on the web, made of scheme, host, port, path, query, and fragment. | A01 | A01 |
| scheme | The part of a URL before `://` that says which protocol to speak — `https`, `http`, `mailto`. | A01 | A01 |
| host | The machine name in a URL — `example.com`. Resolved to an IP address by DNS. | A01 | A01 |
| DNS | The phone book of the internet: turns a host name into an IP address. | A01 | A01 |
| port | A number that says which program on a machine should receive the connection. 443 for HTTPS. | A01 | A01 |
| TCP | The protocol that makes a reliable, ordered byte stream between two machines. | A01 | A01 |
| TLS | The layer that encrypts a TCP connection and proves the server's identity. The S in HTTPS. | A01 | A01 |
| HTTP | The request/response text protocol the web is written in. | A01 | A01 |
| request | A message from client to server: a method, a path, headers, and optionally a body. | A01 | A01 |
| response | A message from server to client: a status code, headers, and optionally a body. | A01 | A01 |
| client | The program making the request. Usually a browser, sometimes your own code. | A01 | A01 |
| server | The program answering the request. | A01 | A01 |
| user agent | Formal name for the client software. A browser is a user agent. | A02 | A02 |
| dev tools | The browser's built-in inspector, where you can read every request and response. | A02 | A02 |
| method | The verb of an HTTP request: GET, POST, PUT, PATCH, DELETE. | A03 | A03 |
| safe method | A method that is not supposed to change anything. GET and HEAD. | A03 | A03 |
| idempotent | An operation that has the same effect whether you do it once or five times. | A03 | A03 |
| status code | The three-digit result of a request. 200 OK, 401, 403, 404, 500. | A03 | A03 |
| 401 Unauthorized | "I do not know who you are." Misnamed: it means unauthenticated. | A03 | A03 |
| 403 Forbidden | "I know who you are, and you may not do this." | A03 | A03 |
| header | A name/value line of metadata attached to a request or response. | A04 | A04 |
| Authorization header | The request header that carries a credential, usually `Bearer <token>`. | A04 | A04 |
| Content-Type | The header that says what format the body is in. | A04 | A04 |
| stateless | A protocol where the server keeps no memory between requests. HTTP is stateless. | A05 | A05 |
| state | Any information about a client that outlives a single request. | A05 | A05 |
| cookie | A small named string a server asks a browser to store and send back on later requests. | A06 | A05 |
| Set-Cookie | The response header that creates or updates a cookie. | A06 | A06 |
| Cookie header | The request header the browser uses to send cookies back. | A06 | A06 |
| cookie attribute | A flag on a cookie controlling its scope and lifetime — Domain, Path, Expires, Secure, HttpOnly, SameSite. | A06 | A06 |
| Domain attribute | Which hosts a cookie is sent to. | A06 | A06 |
| Path attribute | Which URL paths a cookie is sent to. | A06 | A06 |
| session cookie | A cookie with no Expires/Max-Age; the browser drops it when it closes. | A06 | A06 |
| client-side | Code and data that live on the user's machine. The user can read and change all of it. | A07 | A07 |
| server-side | Code and data that live on your machine. The user sees only what you send. | A07 | A07 |
| trust boundary | The line where data stops being yours and starts being theirs. Everything crossing it is untrusted. | A07 | A07 |
| attacker | Anyone who sends you input you did not intend. Not necessarily a hacker. | A07 | A07 |
| API | An interface designed for programs rather than people to call. | A08 | A08 |
| endpoint | One callable URL of an API. | A08 | A08 |
| on behalf of | Acting with a user's permissions without being that user. The core idea of Track F. | A08 | A08 |
| redirect | A response that tells the browser to go somewhere else. Status 301, 302, 303, 307, 308. | A09 | A09 |
| Location header | The header on a redirect response naming where to go. | A09 | A09 |
| address bar | The only part of the browser a website cannot forge. A security boundary. | A09 | A09 |
| open redirect | A redirect endpoint that will send a user to any URL supplied in a parameter. A vulnerability. | A09 | A09 |
| environment variable | A named value handed to a process by whatever started it. Where server secrets live. | A10 | A10 |
| bundle | The compiled JavaScript file a browser downloads. Anything in it is public. | A10 | A10 |
| secret | A value whose security depends on nobody else having it. | A10 | A10 |
| origin | The triple (scheme, host, port). Two URLs are same-origin only if all three match. | A11 | A11 |
| same-origin policy | The browser rule that scripts on one origin cannot read responses from another. | A11 | A11 |
| CORS | The opt-in mechanism a server uses to relax the same-origin policy for specific origins. | A11 | A11 |
| preflight | An automatic `OPTIONS` request the browser sends before certain cross-origin requests. | A11 | A11 |
| credentialed request | A cross-origin request that carries cookies. Requires stricter CORS headers. | A11 | A11 |
| site | A coarser boundary than origin: roughly "the registrable domain." Used by SameSite. | A11 | A11 |

## B — Crypto foundations

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| bit | One binary digit: 0 or 1. | B01 | B01 |
| byte | Eight bits. Holds a number from 0 to 255. | B01 | B01 |
| binary | Base 2. How machines actually store numbers. | B01 | B01 |
| ASCII | A 1960s table mapping 128 characters to the numbers 0–127. | B01 | B01 |
| Unicode | The modern table mapping every character in every script to a number (a code point). | B01 | B01 |
| UTF-8 | The dominant way to turn Unicode code points into bytes. Variable width, 1–4 bytes. | B01 | B01 |
| code point | The number Unicode assigns to a character. | B01 | B01 |
| encoding | A reversible, keyless transformation of data from one representation to another. | B02 | B02 |
| base64 | An encoding that represents arbitrary bytes using 64 safe ASCII characters. Not encryption. | B02 | B02 |
| base64url | Base64 with `+/` replaced by `-_` and padding usually dropped, so it survives a URL. | B02 | B02 |
| hex | Base 16. Two characters per byte. Human-readable byte dumps. | B02 | B02 |
| percent-encoding | URL encoding: `%20` for a space. Makes arbitrary bytes safe inside a URL. | B02 | B02 |
| randomness | Unpredictability. In security, the only kind that counts is cryptographic. | B03 | B03 |
| PRNG | Pseudo-random number generator. Deterministic; produces a repeatable stream from a seed. | B03 | B03 |
| CSPRNG | Cryptographically secure PRNG. Unpredictable even to someone who has seen the previous output. | B03 | B03 |
| seed | The starting state of a PRNG. Know the seed, know the whole stream. | B03 | B03 |
| entropy | A measure of how much genuine unpredictability a value contains, in bits. | B03 | B03 |
| bits of entropy | The log base 2 of the number of equally likely possibilities. 128 bits ≈ unguessable. | B03 | B03 |
| hash function | A function that turns any input into a fixed-size output, deterministically and one-way. | B04 | B04 |
| digest | The output of a hash function. | B04 | B04 |
| preimage resistance | Given a digest, you cannot find an input that produces it. | B04 | B04 |
| second preimage resistance | Given one input, you cannot find a different input with the same digest. | B04 | B04 |
| collision resistance | You cannot find *any* two different inputs with the same digest. | B04 | B06 |
| avalanche effect | Change one input bit, and about half the output bits flip. | B04 | B04 |
| SHA-256 | The current default general-purpose hash. 256-bit digest. | B04 | B04 |
| one-way | Easy to compute forwards, infeasible to reverse. | B05 | B05 |
| encryption | A reversible transformation controlled by a key. Confidentiality. | B05 | B05 |
| plaintext | The data before encryption. | B05 | B05 |
| ciphertext | The data after encryption. | B05 | B05 |
| key | A secret value that parameterises a cryptographic operation. | B05 | B05 |
| collision | Two different inputs producing the same digest. | B06 | B06 |
| birthday bound | Collisions become likely after roughly 2^(n/2) tries on an n-bit hash, not 2^n. | B06 | B06 |
| MD5 | A retired 128-bit hash. Collisions are trivially findable. Never use for security. | B06 | B06 |
| SHA-1 | A retired 160-bit hash. Practically broken since SHAttered (2017). | B06 | B06 |
| chosen-prefix collision | A collision where the attacker controls the meaningful start of both inputs. The dangerous kind. | B06 | B06 |
| rainbow table | A precomputed lookup from digests back to inputs. Defeated by salting. | B07 | B07 |
| offline attack | Attacking stolen hashes on your own hardware, at your own speed, with no rate limit. | B07 | B07 |
| work factor | A tunable cost parameter that makes a password hash deliberately slow. | B07 | B08 |
| salt | A unique, non-secret random value mixed into each password hash so identical passwords hash differently. | B08 | B07 |
| pepper | A secret value mixed into every password hash, stored outside the database. | B08 | B08 |
| key derivation function | A function that stretches a low-entropy secret into a key, slowly and deliberately. | B08 | B08 |
| bcrypt | A 1999 password hash with a single cost parameter. Still acceptable. 72-byte input limit. | B08 | B08 |
| scrypt | A password hash that is deliberately memory-hard as well as slow. | B08 | B08 |
| Argon2id | The current recommended password hash. Memory-hard, side-channel resistant, tunable. | B08 | B08 |
| memory-hard | A function that needs a lot of RAM, which makes custom cracking hardware expensive. | B08 | B08 |
| PHC string | The self-describing `$argon2id$v=19$m=...$salt$hash` format that stores algorithm and parameters alongside the digest. | B08 | B08 |
| symmetric encryption | Encryption where the same key both encrypts and decrypts. | B09 | B09 |
| XOR | Exclusive or. The bit operation at the heart of every stream cipher. | B09 | B09 |
| block cipher | A cipher that transforms fixed-size blocks (AES: 16 bytes) under a key. | B09 | B09 |
| AES | The standard block cipher. 128/192/256-bit keys, 10/12/14 rounds. | B09 | B09 |
| mode of operation | How a block cipher is applied to data longer than one block. CBC, CTR, GCM. | B09 | B09 |
| IV | Initialisation vector. A per-message value that keeps identical plaintexts from encrypting identically. | B09 | B09 |
| AEAD | Authenticated encryption with associated data. Encrypts and authenticates in one step. AES-GCM, ChaCha20-Poly1305. | B09 | B09 |
| nonce | A number used once. Reusing one under the same key breaks most AEAD schemes catastrophically. | B09 | B09 |
| key distribution problem | Symmetric crypto needs both parties to already share a key. Getting it there is the hard part. | B10 | B10 |
| n² problem | n parties needing pairwise symmetric keys need n(n−1)/2 keys. Does not scale. | B10 | B10 |
| asymmetric encryption | Encryption with a key pair: one key encrypts, the other decrypts. Also called public-key. | B11 | B11 |
| public key | The half of a key pair you publish. | B11 | B11 |
| private key | The half of a key pair you never share. Everything depends on this. | B11 | B11 |
| trapdoor function | Easy one way, infeasible backwards — unless you hold the trapdoor (the private key). | B11 | B11 |
| RSA | The classic asymmetric algorithm, based on the difficulty of factoring large numbers. | B11 | B11 |
| elliptic curve | The modern basis for asymmetric crypto. Much smaller keys for the same strength. | B11 | B11 |
| ECDSA | Elliptic-curve digital signature algorithm. | B11 | B14 |
| Ed25519 | A modern, fast, misuse-resistant signature scheme on Curve25519. | B11 | B14 |
| key exchange | A protocol for two parties to agree on a shared secret over a channel anyone can read. | B12 | B12 |
| Diffie–Hellman | The original key exchange. Both sides mix a private value with a public one and arrive at the same secret. | B12 | B12 |
| ECDH | Diffie–Hellman over an elliptic curve. What TLS actually uses. | B12 | B12 |
| forward secrecy | Using an ephemeral key per session, so stealing the long-term key later does not decrypt past traffic. | B12 | B12 |
| MAC | Message authentication code. A tag proving a message came from someone holding the key and was not modified. | B13 | B13 |
| integrity | The property that a message has not been changed. | B13 | B13 |
| authenticity | The property that a message really came from who it claims. | B13 | B13 |
| length extension attack | The flaw that lets an attacker append to a message authenticated by `SHA256(secret ‖ message)` without the key. | B13 | B13 |
| HMAC | Hash-based MAC. A two-pass construction, immune to length extension. `H((K⊕opad) ‖ H((K⊕ipad) ‖ m))`. | B13 | B13 |
| ipad / opad | The two fixed padding constants (0x36, 0x5c) HMAC XORs the key with. | B13 | B13 |
| tag | The output of a MAC. | B13 | B13 |
| digital signature | A MAC where verification uses a *public* key, so anyone can verify and only one party can produce. | B14 | B14 |
| non-repudiation | The signer cannot later deny signing, because only they hold the private key. | B14 | B14 |
| sign | Produce a signature over a digest using a private key. | B14 | B14 |
| verify | Check a signature against a digest using the public key. | B14 | B14 |
| certificate | A public key plus identity information, signed by someone else. | B15 | B15 |
| X.509 | The certificate format the web uses. | B15 | B15 |
| CA | Certificate authority. An organisation whose signature browsers already trust. | B15 | B15 |
| root store | The list of CAs your browser or OS trusts, shipped with the software. | B15 | B15 |
| chain of trust | Leaf certificate signed by intermediate, signed by root, which is already trusted. | B15 | B15 |
| SAN | Subject Alternative Name. The certificate field that actually lists which hostnames it covers. | B15 | B15 |
| revocation (certificates) | Declaring a certificate invalid before it expires. CRL, OCSP, short lifetimes. | B15 | B15 |
| certificate pinning | Trusting only one specific key rather than any CA-signed one. | B15 | B15 |
| Certificate Transparency | Public append-only logs of every issued certificate, so misissuance is detectable. | B15 | B15 |
| timing attack | Learning a secret from how long an operation takes. | B16 | B16 |
| side channel | Any leak through a physical or observable property rather than the output — time, power, cache, sound. | B16 | B16 |
| constant-time comparison | Comparing two values in time independent of where they first differ. | B16 | B16 |
| early return | Bailing out of a loop on first mismatch. The bug that creates a timing oracle. | B16 | B16 |
| oracle | Anything that answers a question an attacker should not be able to ask. | B16 | B16 |
| man in the middle | An attacker positioned between two parties, able to read and modify traffic. | B17 | B17 |
| HTTPS | HTTP carried inside TLS. | B17 | B17 |
| HSTS | A header telling browsers to only ever reach this host over HTTPS. | B17 | B17 |
| SNI | Server Name Indication. The hostname sent in the clear during TLS handshake. | B17 | B17 |
| traffic analysis | Learning from sizes and timings of encrypted traffic without decrypting it. | B17 | B17 |

## C — The map

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| authentication | Proving who someone is. Layer 1. Abbreviated authn. | C01 | C01 |
| session management | Remembering that proof across later requests. Layer 2. | C01 | C01 |
| delegated authorization | Letting one application act on a user's behalf against another. Layer 3. OAuth. | C01 | C01 |
| federated identity | Trusting another system's authentication. Layer 4. OIDC, SAML. | C01 | C01 |
| authorization | Deciding what a known principal may do. Layer 5. Abbreviated authz. | C01 | C01 |
| identity lifecycle | Creating, changing, and removing accounts over time. | C01 | I01 |
| principal | The entity a system is making decisions about. A user, a service, an agent. | C03 | C03 |
| subject | The principal a token or assertion is *about*. The `sub` claim. | C03 | C03 |
| actor | The principal actually performing the action, when it differs from the subject. | C03 | F19 |
| identity | The set of attributes a system associates with a principal. | C03 | C03 |
| identifier | The value used to look a principal up. Email, username, `sub`. | C03 | D01 |
| credential | Something a principal presents to prove identity. A password, a key, a signature. | C03 | C03 |
| authenticator | The thing that holds a credential and performs the proof. A phone, a security key. | C03 | D12 |
| factor | A category of credential: something you know, have, or are. | C03 | D11 |
| claim | A single assertion about a subject, as a name/value pair. `email: a@b.com`. | C03 | C03 |
| token | A string that stands in for a credential or a decision. | C03 | C03 |
| bearer token | A token where possession alone is sufficient. Whoever holds it can use it. | C03 | C03 |
| scope | A coarse label bounding what a token may be used for. Requested by the client. | C03 | C03 |
| audience | Who a token is *for*. The `aud` claim. Checking it is not optional. | C03 | C03 |
| issuer | Who minted a token. The `iss` claim. | C03 | C03 |
| assertion | A signed statement about a subject, made by one system for another. SAML's word for it. | C03 | G07 |
| threat model | A written answer to: who is attacking, what do they already have, and what do they want? | C04 | C04 |
| attack surface | Every place untrusted input can reach your system. | C04 | C04 |
| STRIDE | A six-category checklist for finding threats: spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege. | C04 | C04 |
| threat actor | A named category of attacker with defined capabilities and motives. | C04 | C04 |
| defence in depth | Assuming each control will fail, and having another behind it. | C04 | C04 |
| identity provider | The system that authenticates users and vouches for them. Abbreviated IdP. | C05 | C05 |
| CIAM | Customer identity and access management — auth for your product's end users. | C05 | C05 |
| workforce identity | Auth for your own employees. A different product category from CIAM. | C05 | C05 |

## D — Authentication

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| username | A human-chosen identifier, unique within one system. | D01 | D01 |
| account | The record a system keeps about one principal. | D01 | D01 |
| canonicalisation | Reducing a value to one standard form before comparing or storing it. | D02 | D02 |
| plus-addressing | `user+tag@example.com` — the same mailbox, a different string. | D02 | D02 |
| homoglyph | A character that looks like another. `аpple` with a Cyrillic а is not `apple`. | D02 | D02 |
| Punycode | The ASCII encoding of internationalised domain names. `xn--` prefixes. | D02 | D02 |
| double-submit verification | Confirming an email by sending a token to it and requiring it back. | D02 | D02 |
| password | A secret string a user memorises. The worst credential still in wide use. | D03 | D03 |
| password hash | The stored, slow, salted one-way transformation of a password. Never the password. | D03 | D03 |
| credential stuffing | Replaying username/password pairs breached elsewhere against your login. | D03 | D08 |
| password spraying | Trying one common password against many accounts, to stay under per-account rate limits. | D04 | D08 |
| blocklist (passwords) | A list of known-breached or trivially-guessed passwords to reject at registration. | D04 | D04 |
| composition rules | Requirements like "one uppercase, one symbol." NIST removed these in SP 800-63B-4. | D04 | D04 |
| registration | Creating an account. | D05 | D05 |
| login | Presenting a credential and receiving a session. | D06 | D06 |
| user enumeration | Learning which accounts exist from differences in responses. | D07 | D07 |
| response oracle | Any observable difference — message, status, timing — that answers an attacker's question. | D07 | D07 |
| rate limiting | Capping how often an operation can be attempted, per key. | D08 | D08 |
| account lockout | Disabling login after N failures. A denial-of-service risk if done naively. | D08 | D08 |
| exponential backoff | Doubling the delay after each failure. | D08 | D08 |
| account recovery | Regaining access without the primary credential. Statistically your weakest link. | D09 | D09 |
| reset token | A single-use, short-lived, high-entropy secret sent to a verified channel. | D09 | D09 |
| single-use token | A token invalidated the moment it is redeemed. | D09 | D09 |
| magic link | A login link containing a single-use token, sent by email. | D10 | D10 |
| OTP | One-time password. A short code valid once, or briefly. | D10 | D10 |
| MFA | Multi-factor authentication. Two or more *different* factor categories. | D11 | D11 |
| 2FA | Two-factor authentication. A specific case of MFA. | D11 | D11 |
| SIM swap | Persuading a carrier to move a phone number to an attacker's SIM. Defeats SMS 2FA. | D11 | D11 |
| SS7 | The legacy telephone signalling network, which allows SMS interception. | D11 | D11 |
| phishing-resistant | An authenticator that cannot be relayed by a fake site, because it is bound to the origin. | D11 | D14 |
| TOTP | Time-based one-time password. HMAC over a 30-second counter, truncated to six digits. RFC 6238. | D12 | D12 |
| HOTP | Counter-based one-time password. RFC 4226. TOTP's parent. | D12 | D12 |
| shared secret | A key both sides hold. TOTP's seed. | D12 | D12 |
| base32 | The encoding used for TOTP secrets in `otpauth://` URIs. | D12 | D12 |
| dynamic truncation | The HOTP step that turns a 20-byte HMAC into a 6-digit number. | D12 | D12 |
| drift window | Accepting the adjacent time steps to tolerate clock skew. | D12 | D12 |
| replay | Reusing a captured credential or code a second time. | D12 | D12 |
| recovery code | A pre-generated single-use code that substitutes for a second factor. | D13 | D13 |
| WebAuthn | The browser API for public-key authentication. W3C. Level 3 as of 2026. | D14 | D14 |
| FIDO2 | The umbrella: WebAuthn (browser side) plus CTAP (authenticator side). | D14 | D14 |
| CTAP | Client to Authenticator Protocol. How a browser talks to a security key. | D14 | D14 |
| passkey | A discoverable WebAuthn credential, usually synced across a user's devices. | D14 | D14 |
| relying party | The site a WebAuthn credential is bound to. Abbreviated RP. | D14 | D14 |
| RP ID | The domain a passkey is scoped to. The anti-phishing binding. | D14 | D14 |
| challenge | A fresh random value the server sends so the response cannot be replayed. | D14 | D14 |
| attestation | Optional cryptographic evidence about what kind of authenticator was used. | D14 | D14 |
| authenticator data | The structured bytes a WebAuthn authenticator signs, including RP ID hash and flags. | D15 | D15 |
| client data JSON | The browser-assembled JSON containing challenge, origin, and type, hashed into the signature. | D15 | D15 |
| user verification | Proof the right human is present — PIN, fingerprint, face. The `UV` flag. | D15 | D15 |
| user presence | Proof a human touched the authenticator. The `UP` flag. | D15 | D15 |
| discoverable credential | A credential the authenticator can find without being told the user's ID. Enables usernameless login. | D15 | D15 |
| signature counter | An incrementing counter some authenticators return, used to detect cloning. | D15 | D15 |
| biometric | A measurement of the body used to unlock a local secret. Never transmitted to a server. | D16 | D16 |
| secure enclave | Isolated hardware that holds keys the main OS cannot read. | D16 | D16 |
| false accept rate | How often a biometric admits the wrong person. | D16 | D16 |
| device binding | Tying a trust decision to one specific device. | D17 | D17 |
| step-up authentication | Demanding a stronger proof for a more sensitive action, mid-session. | D18 | D18 |
| AAL | Authenticator Assurance Level. NIST's 1–3 scale for how strongly identity was proven. | D18 | D18 |
| assurance level | How confident you are in a claim of identity. | D18 | D18 |
| `amr` | Authentication Methods References. The claim listing how the user authenticated. | D18 | D18 |
| `acr` | Authentication Context Class Reference. The claim naming the assurance level achieved. | D18 | D18 |
| auth_time | The claim recording when the user last actually authenticated. | D18 | D18 |

## E — Sessions and tokens

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| session | Server-remembered state tying a series of requests to one authenticated principal. | E01 | A05 |
| session ID | The opaque high-entropy string that names a session. | E01 | E01 |
| HttpOnly | Cookie attribute that hides a cookie from JavaScript. | E02 | E02 |
| Secure | Cookie attribute that stops a cookie being sent over plain HTTP. | E02 | E02 |
| SameSite | Cookie attribute controlling whether a cookie is sent on cross-site requests. Lax, Strict, None. | E02 | E02 |
| `__Host-` prefix | A cookie name prefix browsers enforce: Secure, path `/`, no Domain. The strongest binding available. | E02 | E02 |
| cookie jar | The browser's per-origin store of cookies. | E02 | E02 |
| session store | Where the server keeps session records. Memory, Redis, a table. | E03 | E03 |
| sticky sessions | Routing a user to the same server so in-memory sessions work. A design smell. | E03 | E03 |
| idle timeout | Expiring a session after inactivity. | E04 | E04 |
| absolute timeout | Expiring a session a fixed time after creation regardless of activity. | E04 | E04 |
| session fixation | Making a victim use a session ID the attacker already knows. | E04 | E04 |
| JWT | JSON Web Token. A compact, self-contained, signed set of claims. RFC 7519. | E05 | E05 |
| JWS | JSON Web Signature. The signed structure a JWT normally uses. RFC 7515. | E06 | E05 |
| JWE | JSON Web Encryption. The encrypted variant. RFC 7516. Rare. | E06 | E06 |
| compact serialization | The `header.payload.signature` dotted base64url form. | E05 | E05 |
| JOSE | The umbrella spec family: JWS, JWE, JWK, JWA, JWT. | E07 | E07 |
| JWA | JSON Web Algorithms. The registry of `alg` values. RFC 7518. | E07 | E07 |
| JWK | JSON Web Key. A key expressed as JSON. RFC 7517. | E07 | E07 |
| JWKS | JSON Web Key Set. A JSON document listing public keys, fetched over HTTPS. | E07 | E07 |
| kid | Key ID. The header field naming which key in a JWKS signed this token. | E07 | E07 |
| alg | The header field naming the signing algorithm. Never trust it blindly. | E06 | E06 |
| `alg: none` | The unsigned JWT type. Accepting it is a two-line total compromise. | E06 | E06 |
| algorithm confusion | Tricking a verifier into using an RSA public key as an HMAC secret. | E06 | E06 |
| opaque token | A token with no meaning to the client; the server looks it up. | E08 | E08 |
| reference token | Another name for an opaque token. Points at server state. | E08 | E08 |
| self-contained token | A token that carries its own claims and needs no lookup. A JWT. | E08 | E08 |
| signed cookie | A cookie whose value carries a MAC so the server can detect tampering. | E08 | E08 |
| access token | The credential presented to an API. Short-lived. | E10 | C03 |
| refresh token | A longer-lived credential used only to obtain new access tokens. | E10 | E10 |
| rotation | Issuing a new refresh token on every use and invalidating the old one. | E10 | E10 |
| reuse detection | Noticing a rotated refresh token being presented twice, and killing the whole family. | E10 | E10 |
| token family | The chain of refresh tokens descending from one authorization. | E10 | E10 |
| revocation | Making a still-unexpired credential stop working. | E11 | E11 |
| denylist | A list of revoked token identifiers checked on every request. | E11 | E11 |
| jti | JWT ID. The unique identifier claim, used for denylists and replay detection. | E11 | E11 |
| introspection | Asking the issuer whether a token is currently valid. RFC 7662. | E11 | F12 |
| localStorage | Browser storage readable by any script on the origin. Survives XSS badly. | E12 | E12 |
| in-memory storage | Holding a token in a JavaScript variable. Gone on refresh, still XSS-readable. | E12 | E12 |
| device session | One session record per device, so they can be listed and killed individually. | E13 | E13 |
| global logout | Ending every session for a user at once. | E13 | E13 |
| CSRF | Cross-site request forgery. Making a victim's browser send an authenticated request they did not intend. | E15 | E15 |
| CSRF token | An unpredictable per-session value required on state-changing requests. | E15 | E15 |
| double-submit cookie | A stateless CSRF defence: same random value in a cookie and in the request. | E15 | E15 |
| XSS | Cross-site scripting. Getting your JavaScript to run on someone else's origin. | E16 | E16 |
| stored XSS | Injected script persisted server-side and served to every visitor. | E16 | E16 |
| reflected XSS | Injected script echoed back from a request parameter. | E16 | E16 |
| DOM XSS | Injection that never touches the server — client-side code writes attacker input into the DOM. | E16 | E16 |
| CSP | Content Security Policy. A header restricting which scripts may run. | E16 | E16 |
| output encoding | Escaping data for the context it lands in. The actual fix for XSS. | E16 | E16 |

## F — Delegated authorization (OAuth 2)

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| OAuth 2.0 | The delegated-authorization framework. RFC 6749 plus a large family. | F01 | F01 |
| OAuth 2.1 | The consolidation draft: authorization code + PKCE only, no implicit, no password grant. Still a draft in 2026. | F01 | F01 |
| password anti-pattern | Giving app A your password for service B. The thing OAuth exists to kill. | F01 | F01 |
| resource owner | The user who owns the data. One of OAuth's four roles. | F02 | F02 |
| client (OAuth) | The application requesting access. Not the browser. | F02 | F02 |
| authorization server | The system that authenticates the user, gets consent, and issues tokens. Abbreviated AS. | F02 | F02 |
| resource server | The API that accepts the token and serves the data. Abbreviated RS. | F02 | F02 |
| front channel | The browser. Visible to the user, visible in logs, cannot keep a secret. | F02 | F02 |
| back channel | A direct server-to-server HTTPS call. Nothing in it touches the browser. | F02 | F02 |
| grant type | The particular flow used to obtain a token. | F03 | F03 |
| authorization code | A short-lived single-use code exchanged for tokens over the back channel. | F03 | F03 |
| authorization endpoint | The AS URL the browser is sent to. Front channel. | F03 | F03 |
| token endpoint | The AS URL the client POSTs to. Back channel. | F03 | F03 |
| redirect_uri | Where the AS returns the browser after authorization. Must be pre-registered and exactly matched. | F03 | F03 |
| authorization request | The front-channel request that starts a flow. | F03 | F03 |
| code exchange | Trading the authorization code plus client credentials for tokens. | F04 | F04 |
| state | An opaque client value round-tripped through the AS, binding response to request. CSRF defence. | F05 | F05 |
| PKCE | Proof Key for Code Exchange. RFC 7636. Binds the code to the client that started the flow. | F06 | F06 |
| code_verifier | A high-entropy random string the client keeps. | F06 | F06 |
| code_challenge | `BASE64URL(SHA256(code_verifier))`. Sent in the authorization request. | F06 | F06 |
| S256 | The only code challenge method you should use. `plain` is a downgrade. | F06 | F06 |
| downgrade attack | Forcing a weaker option that both sides technically support. | F06 | F06 |
| scope (OAuth) | A space-separated list of permission labels requested by the client and consented by the user. | F07 | C03 |
| incremental authorization | Requesting more scopes later, when they are actually needed. | F07 | F07 |
| `aud` | Audience claim. Which resource server may accept this token. | F08 | C03 |
| resource indicator | The `resource` parameter naming the API a token is for. RFC 8707. | F08 | F08 |
| confused deputy | Tricking a privileged component into misusing its authority on your behalf. | F08 | F08 |
| token passthrough | Forwarding a token you received to a different API. Almost always a vulnerability. | F08 | J08 |
| public client | A client that cannot keep a secret — SPA, mobile app, CLI. | F09 | F09 |
| confidential client | A client running on a server that can hold a secret. | F09 | F09 |
| client authentication | How a confidential client proves its identity at the token endpoint. | F09 | F09 |
| client secret | A password for an application. | F09 | F09 |
| private_key_jwt | Client authentication by signing a JWT with the client's private key. Better than a shared secret. | F09 | F09 |
| client credentials grant | Machine-to-machine: a client gets a token for itself, with no user involved. | F10 | F10 |
| device authorization grant | The flow for input-constrained devices. RFC 8628. User code plus a verification URL. | F11 | F11 |
| user code | The short code shown on a TV screen for the user to type on their phone. | F11 | F11 |
| polling | The device repeatedly asking the token endpoint whether authorization completed. | F11 | F11 |
| local validation | Verifying a token's signature and claims without calling the issuer. | F12 | F12 |
| consent | The user's explicit approval of what an application may do. | F13 | F13 |
| consent phishing | A real OAuth consent screen used by a malicious app with a trustworthy-looking name. | F13 | F13 |
| implicit grant | The dead flow that returned tokens in the URL fragment. Removed in OAuth 2.1. | F15 | F15 |
| ROPC | Resource owner password credentials grant. The client collects the password. Dead. | F15 | F15 |
| fragment | The part of a URL after `#`. Never sent to the server. Where implicit put tokens. | F15 | A01 |
| sender-constrained token | A token usable only by the client that obtained it, proven by a key. | F16 | F16 |
| mTLS | Mutual TLS. Both sides present certificates. RFC 8705 binds tokens to the client cert. | F16 | F16 |
| DPoP | Demonstrating Proof of Possession. RFC 9449. A per-request signed JWT binds the token to a key. | F16 | F16 |
| proof of possession | Demonstrating you hold a key, rather than merely holding a token. | F16 | F16 |
| BFF | Backend-for-frontend. A server component that holds tokens so the browser never does. | F17 | F17 |
| app-claimed URL | A verified HTTPS link a mobile OS routes to your app only. Universal Links, App Links. | F18 | F18 |
| custom URI scheme | `myapp://` — routable to your app, but claimable by other apps. Weaker than app-claimed. | F18 | F18 |
| token exchange | RFC 8693. Trading one token for another, with different audience, scope, or subject. | F19 | F19 |
| impersonation | Acting *as* a user, with no trace of who is really acting. | F19 | F19 |
| delegation | Acting *for* a user, with the real actor recorded in the `act` claim. | F19 | F19 |
| `act` claim | The token claim naming the actual actor in a delegation. | F19 | F19 |
| redirect_uri smuggling | Getting an AS to send the code to an attacker-controlled URL. | F20 | F20 |
| mix-up attack | Confusing a multi-IdP client about which AS a response came from. | F20 | F20 |
| `iss` in response | RFC 9207. The AS names itself in the authorization response, defeating mix-up. | F20 | F20 |

## G — Federated identity and SSO

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| SSO | Single sign-on. Authenticate once, reach many applications. | G01 | G01 |
| social login | Federated identity using a consumer IdP — Google, Apple, GitHub. | G01 | G01 |
| OIDC | OpenID Connect. An identity layer on top of OAuth 2. | G02 | G02 |
| `openid` scope | The scope that turns an OAuth flow into an OIDC flow and produces an ID token. | G02 | G02 |
| ID token | A JWT about the authentication event, for the client. Never sent to an API. | G03 | G03 |
| nonce | (OIDC) A client value echoed into the ID token, binding it to this authentication request. | G03 | B09 |
| `at_hash` | A claim binding an ID token to the access token issued with it. | G03 | G04 |
| hybrid flow | An OIDC flow returning some artifacts on the front channel and some on the back. | G03 | G03 |
| clock skew | Small differences between machine clocks, which token expiry checks must tolerate. | G04 | G04 |
| discovery | Fetching an IdP's configuration from a well-known URL. | G05 | G05 |
| `.well-known` | The standard URL prefix for machine-readable metadata. | G05 | G05 |
| openid-configuration | The OIDC discovery document listing endpoints, keys, and supported features. | G05 | G05 |
| UserInfo endpoint | The OIDC API returning claims about the user, called with the access token. | G06 | G06 |
| standard claims | The OIDC-defined claim names: `name`, `email`, `picture`, and so on. | G06 | G06 |
| SAML | Security Assertion Markup Language. The XML-based enterprise SSO standard. | G07 | G07 |
| service provider | The application in SAML. Abbreviated SP. Equivalent to an OIDC relying party. | G07 | G07 |
| SAML assertion | The signed XML statement about an authenticated user. | G07 | G07 |
| SP-initiated | SSO that starts at the application. | G07 | G07 |
| IdP-initiated | SSO that starts at the identity provider. Unsolicited, and harder to secure. | G07 | G07 |
| metadata (SAML) | The XML document exchanging entity IDs, endpoints, and certificates. | G07 | G07 |
| XML canonicalisation | Normalising XML before signing. The source of signature-wrapping bugs. | G07 | G14 |
| tenant | One customer's isolated slice of a multi-customer system. | G09 | G09 |
| multi-tenant | One deployment serving many customers with enforced isolation. | G09 | G09 |
| IdP-per-tenant | Each enterprise customer bringing their own identity provider. | G09 | G09 |
| home realm discovery | Deciding which IdP to send a user to, usually from their email domain. | G10 | G10 |
| domain verification | Proving a customer controls an email domain before routing it to their IdP. | G10 | G10 |
| SP-initiated logout | Ending both local and IdP sessions from the application. | G11 | G11 |
| front-channel logout | Logging out other applications via hidden iframes. Fragile. | G11 | G11 |
| back-channel logout | The IdP calling each application's logout endpoint directly with a logout token. | G11 | G11 |
| account linking | Connecting several IdP identities to one local account. | G12 | G12 |
| pre-account-takeover | Registering an account with a victim's email before they federate in. | G12 | G12 |
| LDAP | The protocol for querying enterprise directories. | G13 | G13 |
| Active Directory | Microsoft's directory service. LDAP plus Kerberos plus policy. | G13 | G13 |
| Kerberos | The ticket-based authentication protocol behind Windows domain login. | G13 | G13 |
| signature wrapping | Moving signed XML so the signature still verifies but a different element is read. | G14 | G14 |

## H — Authorization

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| policy | The rules describing who may do what. | H01 | H01 |
| policy decision point | The component that answers "may this principal do this?" Abbreviated PDP. | H01 | H01 |
| policy enforcement point | The component that actually blocks or allows the request. Abbreviated PEP. | H01 | H01 |
| policy information point | Where the decision point fetches the facts it needs. Abbreviated PIP. | H01 | H01 |
| deny by default | Refusing anything not explicitly permitted. | H01 | H01 |
| fail closed | On error, deny. The correct default for authorization. | H02 | H02 |
| middleware | Code that runs before your handler, per request. | H02 | H02 |
| ACL | Access control list. Explicit per-object list of who may do what. | H03 | H03 |
| capability | A token that *is* the permission, rather than pointing at a permission check. | H03 | H03 |
| RBAC | Role-based access control. Permissions attach to roles; users get roles. | H04 | H04 |
| role | A named bundle of permissions. | H04 | H04 |
| permission | An atomic allowed operation. `document:delete`. | H04 | H04 |
| role explosion | The failure mode where exceptions force one role per situation. | H04 | H04 |
| group | A named set of principals. Not a role, though everyone conflates them. | H05 | H05 |
| ABAC | Attribute-based access control. Decisions from attributes of subject, resource, action, and environment. | H06 | H06 |
| attribute | A fact used in a policy decision. | H06 | H06 |
| PBAC | Policy-based access control. ABAC with the rules in a policy language. | H06 | H06 |
| ReBAC | Relationship-based access control. Decisions from a graph of relationships. | H07 | H07 |
| Zanzibar | Google's global authorization system, and the paper that made ReBAC mainstream. | H07 | H07 |
| relation tuple | `object#relation@subject` — the atomic fact of a Zanzibar-style system. | H07 | H07 |
| userset | A set of users named indirectly, e.g. "the editors of folder X." | H07 | H07 |
| userset rewrite | Rules deriving relations from others — "viewer includes editor." | H07 | H07 |
| computed userset | A relation derived from another relation on the same object. | H07 | H08 |
| tuple-to-userset | A relation derived through another object. How folder inheritance works. | H07 | H08 |
| check API | The single question a ReBAC system answers: may subject S do relation R on object O? | H07 | H08 |
| list-objects | The reverse query: which objects may this subject act on? Harder than check. | H08 | H08 |
| OpenFGA | The open-source Zanzibar implementation. | H08 | H08 |
| authorization model | The schema declaring types, relations, and rewrite rules. | H08 | H08 |
| tenant isolation | Guaranteeing one customer cannot reach another's data. | H09 | H09 |
| noisy neighbour | One tenant's load affecting another. An availability, not authorization, concern. | H09 | H09 |
| RLS | Row-level security. The database filters rows by policy, per session. | H10 | H10 |
| session variable | A per-connection value the database policy can read. How RLS learns the current user. | H10 | H10 |
| OPA | Open Policy Agent. A general policy engine using the Rego language. | H11 | H11 |
| Rego | OPA's declarative policy language. | H11 | H11 |
| Cedar | AWS's authorization policy language. Analysable, typed, verifiable. | H11 | H11 |
| policy as code | Keeping authorization rules in version control, tested and reviewed like code. | H11 | H11 |
| service mesh | Infrastructure that intercepts service-to-service traffic and can enforce policy. | H12 | H12 |
| sidecar | A helper process next to a service, often the local policy decision point. | H12 | H12 |
| audit log | An append-only record of who did what, when, and whether it was allowed. | H13 | H13 |
| tamper-evident log | A log where modification is detectable, usually by hash chaining. | H13 | H13 |
| IDOR | Insecure direct object reference. Changing an ID in a request and getting someone else's data. | H14 | H14 |
| BOLA | Broken object level authorization. The API-specific name for IDOR. | H14 | H14 |
| privilege escalation | Gaining permissions you were not granted. Vertical or horizontal. | H14 | H14 |
| mass assignment | Letting request fields bind directly to model attributes, including `is_admin`. | H14 | H14 |
| forced browsing | Reaching an unlinked URL directly to see whether it is protected. | H14 | H14 |

## I — Lifecycle and operations

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| joiner-mover-leaver | The three lifecycle events every identity system must handle. | I01 | I01 |
| provisioning | Creating accounts and entitlements in a downstream system. | I02 | I02 |
| JIT provisioning | Creating the account on first successful SSO login. | I02 | I02 |
| SCIM | System for Cross-domain Identity Management. RFC 7643/7644. The provisioning API standard. | I02 | I02 |
| deprovisioning | Removing access when someone leaves. The step that fails audits. | I03 | I03 |
| orphaned account | An account whose owner is gone but which still works. | I03 | I03 |
| impersonation (admin) | Support staff acting as a user to reproduce a problem. | I04 | I04 |
| break-glass | An emergency access path, heavily logged and time-limited. | I04 | I04 |
| KMS | Key management service. Holds keys and performs operations without releasing them. | I05 | I05 |
| vault | A system for storing and distributing secrets with access control and audit. | I05 | I05 |
| envelope encryption | Encrypting data with a data key, and the data key with a master key. | I05 | I05 |
| HSM | Hardware security module. Tamper-resistant hardware holding keys. | I05 | I05 |
| secret sprawl | Copies of the same secret accumulating in code, CI, laptops, and chat. | I05 | I05 |
| key rotation | Replacing a signing or encryption key on a schedule, without downtime. | I06 | I06 |
| overlap window | The period where both the old and new key are trusted for verification. | I06 | I06 |
| cache TTL | How long a client may reuse a fetched JWKS before refetching. | I06 | I06 |
| observability | Being able to answer new questions about a running system without shipping code. | I08 | I08 |
| PII | Personally identifiable information. | I08 | I11 |
| redaction | Removing sensitive values before they reach a log. | I08 | I08 |
| account takeover | An attacker gaining control of a legitimate account. Abbreviated ATO. | I09 | I09 |
| risk score | A number combining signals to decide whether to challenge a login. | I09 | I09 |
| impossible travel | Two logins from locations too far apart for the time between them. | I09 | I09 |
| device fingerprint | A probabilistic identifier derived from browser and device characteristics. | I09 | I09 |
| blast radius | How much an attacker can reach once one credential is compromised. | I10 | I10 |
| SOC 2 | An audit framework covering security, availability, confidentiality, and privacy controls. | I11 | I11 |
| GDPR | The EU data protection regulation. Lawful basis, minimisation, erasure. | I11 | I11 |
| data minimisation | Collecting and carrying only the data you actually need. | I11 | I11 |
| rehash on login | Upgrading a password hash to a stronger algorithm the next time the user logs in. | I12 | I12 |
| shadow write | Writing to both old and new systems during a migration to keep them in sync. | I12 | I12 |

## J — Machine, workload, and agent identity

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| machine identity | An identity belonging to software rather than a person. | J01 | J01 |
| workload | A running instance of software that needs an identity. | J01 | J01 |
| API key | A long-lived bearer secret identifying a caller. Simple, and usually done badly. | J02 | J02 |
| key prefix | A recognisable start like `sk_live_` that lets secret scanners find leaked keys. | J02 | J02 |
| secret scanning | Automated searching of public code for credential patterns. | J02 | J02 |
| service account | A non-human account in a system built for humans. | J03 | J03 |
| client certificate | A certificate presented by the client during a TLS handshake. | J04 | J04 |
| certificate binding | Tying a token to the client certificate that requested it. | J04 | F16 |
| SPIFFE | A standard for workload identity: a URI name and a short-lived certificate. | J05 | J05 |
| SPIFFE ID | `spiffe://trust-domain/path` — a workload's name. | J05 | J05 |
| SVID | SPIFFE Verifiable Identity Document. The workload's credential. | J05 | J05 |
| SPIRE | The reference implementation of SPIFFE. | J05 | J05 |
| attestation (workload) | Proving what a workload is from platform evidence, not a shared secret. | J05 | J05 |
| trust domain | The administrative boundary within which SPIFFE identities are issued. | J05 | J05 |
| webhook | An HTTP callback one system makes into another when something happens. | J06 | J06 |
| signature header | The header carrying a MAC over a webhook body. | J06 | J06 |
| raw body | The exact bytes received, before parsing. What you must verify over. | J06 | J06 |
| replay window | The time period within which a signed timestamp is accepted. | J06 | J06 |
| agent | Software that pursues a goal with some autonomy, taking actions on a user's behalf. | J07 | J07 |
| human in the loop | Requiring explicit human approval for specific agent actions. | J07 | J07 |
| MCP | Model Context Protocol. The standard for connecting AI applications to tools and data. | J08 | J08 |
| protected resource metadata | RFC 9728. How a resource server advertises its authorization server. | J08 | J08 |
| dynamic client registration | RFC 7591. Clients registering themselves at an AS at runtime. | J08 | J08 |
| client ID metadata document | A URL used as a client_id, which the AS fetches for the client's metadata. | J08 | J08 |
| WWW-Authenticate | The response header a 401 uses to say how to authenticate. Carries discovery hints. | J08 | J08 |

## K — Capstone

| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| ASVS | OWASP Application Security Verification Standard. A testable requirements checklist. | K01 | K01 |
| security boundary | A line across which trust changes and checks are mandatory. | K01 | K01 |
| decision tree | A structured set of questions leading to a concrete architecture recommendation. | K05 | K05 |

---

## Terms this book deliberately never defines

Because it never uses them, and because a term you do not need is a term you should not
carry. If you meet these elsewhere, that is a different curriculum:

`DID`, `verifiable credential`, `zero-knowledge proof`, `homomorphic encryption`,
`post-quantum KEM`, `Feistel network`, `S-box`, `HSM partition`, `SAML artifact binding`,
`WS-Federation`, `OAuth 1.0a signature base string`.

See [appendix/excluded.md](appendix/excluded.md) for why.
