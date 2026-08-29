# Sources by track

The reading list behind each track. Where the book makes a normative claim, it's anchored to one of
these. Two books carry disproportionate weight, and it's worth saying why up front.

---

## The two that carry disproportionate weight

**Yvonne Wilson & Abhishek Hingnikar — *Solving Identity Management in Modern Applications* (2nd ed).**
The only book whose table of contents maps onto all five layers ([C01](book/track-c/C01-auth-is-five-different-problems.md)).
Used as the **structural spine** of this book — if you read one companion volume, this is it.

**Neil Madden — *API Security in Action*.** The best technical writing in the field. The reference
for the technical work in Tracks E, F, and H — sessions, OAuth, and authorization. Precise, correct,
and unusually clear about *why*, not just *what*.

---

## Track A — How the web actually works

- [MDN HTTP guide](https://developer.mozilla.org/en-US/docs/Web/HTTP) — the practical reference
- Ilya Grigorik, [*High Performance Browser Networking*](https://hpbn.co/) (free online) — what actually happens on the wire
- [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110) (HTTP Semantics), [RFC 6265bis](https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis) (cookies), [Fetch Standard](https://fetch.spec.whatwg.org/) (CORS)
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)

## Track B — Crypto foundations

- David Wong, *Real-World Cryptography* — the modern, practical treatment
- Jean-Philippe Aumasson, *Serious Cryptography* (2nd ed) — deeper, still readable
- [Cryptopals](https://cryptopals.com/) — learn by breaking
- [NIST FIPS 180-4/202](https://csrc.nist.gov/publications/fips) (hashes), [FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) (AES), [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) (Argon2), [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (EdDSA)

## Track C — The map

- Wilson & Hingnikar, *Solving Identity Management in Modern Applications* (2nd ed) — the spine
- [OWASP Top 10](https://owasp.org/Top10/) — the threat landscape
- Adam Shostack, *Threat Modeling: Designing for Security* ([C04](book/track-c/C04-threat-modeling.md))

## Track D — Authentication

- [The Copenhagen Book](https://thecopenhagenbook.com/) — the practical first-party auth reference
- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) — passwords, MFA, assurance (final July 2025)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html) and the Password Storage, Forgot Password, and MFA cheat sheets
- [passkeys.dev](https://passkeys.dev/) and [W3C WebAuthn L3](https://www.w3.org/TR/webauthn-3/)

## Track E — Sessions and tokens

- The Copenhagen Book — [Sessions](https://thecopenhagenbook.com/sessions)
- [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519) (JWT), [7515](https://www.rfc-editor.org/rfc/rfc7515) (JWS), **[8725](https://www.rfc-editor.org/rfc/rfc8725) (JWT BCP)**
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- Madden, *API Security in Action*, Ch. 4–6

## Track F — OAuth 2

- Aaron Parecki, [oauth.net](https://oauth.net/) and [oauth.com](https://www.oauth.com/) — the clearest OAuth explanations anywhere
- [RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) (core), **[RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) (Security BCP)**, [RFC 7636](https://www.rfc-editor.org/rfc/rfc7636) (PKCE)
- Justin Richer & Antonio Sanso, *OAuth 2 in Action*
- Madden, *API Security in Action*, Ch. 7

## Track G — Federated identity and SSO

- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) and [Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [NIST SP 800-63C-4](https://csrc.nist.gov/pubs/sp/800/63/c/4/final) — federation assurance
- [OASIS SAML 2.0 Technical Overview](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- Somorovsky et al., [*On Breaking SAML*](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky) (the XSW paper)

## Track H — Authorization

- [Google Zanzibar paper](https://research.google/pubs/pub48190/) — the foundational ReBAC work
- [zanzibar.academy](https://zanzibar.academy/) — an approachable walkthrough
- [OpenFGA](https://openfga.dev/docs) / [SpiceDB](https://authzed.com/docs) docs
- [OPA/Rego](https://www.openpolicyagent.org/docs/) and [Cedar](https://www.cedarpolicy.com/) docs
- [OWASP Top 10 A01: Broken Access Control](https://owasp.org/Top10/A01_2021-Broken_Access_Control/) and the [API Security Top 10](https://owasp.org/API-Security/)
- Madden, *API Security in Action*, Ch. 8–9

## Track I — Lifecycle and operations

- [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643)/[7644](https://www.rfc-editor.org/rfc/rfc7644) (SCIM)
- Wilson & Hingnikar, *Solving Identity Management*, Ch. 10 (provisioning)
- Cloud KMS docs ([AWS](https://docs.aws.amazon.com/kms/), [GCP](https://cloud.google.com/kms/docs)), [HashiCorp Vault](https://developer.hashicorp.com/vault/docs)
- [NIST SP 800-61r3](https://csrc.nist.gov/pubs/sp/800/61/r3/final) (incident response), [SP 800-92](https://csrc.nist.gov/pubs/sp/800/92/final) (logging)
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html)

## Track J — Machine, workload, and agent identity

- [RFC 8705](https://www.rfc-editor.org/rfc/rfc8705) (mTLS), [RFC 9449](https://www.rfc-editor.org/rfc/rfc9449) (DPoP)
- [SPIFFE/SPIRE docs](https://spiffe.io/docs/)
- [Standard Webhooks](https://www.standardwebhooks.com/), [Stripe webhook signing](https://docs.stripe.com/webhooks)
- [MCP Authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization) and [RFC 9728](https://www.rfc-editor.org/rfc/rfc9728)/[7591](https://www.rfc-editor.org/rfc/rfc7591)
- [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## Track K — Capstone

- Neil Madden, *API Security in Action* — the technical reference
- [RFC 9700](https://www.rfc-editor.org/rfc/rfc9700) (OAuth Security BCP)
- [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) — chapters 2 (authentication), 3 (session), 7 (access control)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — free labs for every attack chapter

---

## A note on primary sources

Every normative claim in this book is anchored to one of the above — an RFC, a NIST publication, a
W3C recommendation, or a vendor's own documentation ([K06](book/track-k/K06-where-to-go-next.md)).
Where the field is still moving — OAuth 2.1, MCP authorization, WebAuthn Level 3, certificate
lifetimes — the relevant chapter says so and dates the claim. When something matters in your own
work, **read the primary source, not a summary of it** ([K06](book/track-k/K06-where-to-go-next.md)).

*Last reviewed against primary sources: August 2026.*

---

**Back to:** [README](README.md) · [rfc-index.md](appendix/rfc-index.md)
