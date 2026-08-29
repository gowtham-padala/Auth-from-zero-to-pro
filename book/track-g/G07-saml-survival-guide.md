# G07 — SAML survival guide

**Part G · Federated identity & SSO** · *Builds on [G01](G01-sign-in-with-google.md)*
> SAML gets exactly one chapter. It deserves respect and not much airtime. This is enough to
> integrate it, recognise its shape, and know where the sharp edges are — no more.

---

## Why you cannot avoid it

You would not choose SAML today. But if you sell to enterprises, **your customers already run
it**, and "we only support OIDC" loses deals. SAML 2.0 is a 2005 OASIS standard, entrenched
in Active Directory Federation Services, Okta, Ping, and every corporate identity stack. It
is XML where OIDC is JSON, and it predates the mobile/API world OIDC was built for — but it
works, it is deployed everywhere, and it is not going away.

The good news: **structurally it is the same idea as OIDC.** An identity provider
authenticates the user and sends your app a signed statement vouching for them
([G01](G01-sign-in-with-google.md)). Only the encoding and the vocabulary differ.

---

## The vocabulary map

Same roles, different names ([G01](G01-sign-in-with-google.md)):

| Concept | OIDC term | SAML term |
|---|---|---|
| The app | Relying Party (RP) / client | **Service Provider (SP)** |
| The identity source | Identity Provider (IdP) | **Identity Provider (IdP)** |
| The signed identity statement | ID token (JWT) | **Assertion** (XML) |
| Configuration exchange | Discovery (`.well-known`) | **Metadata** (XML) |
| The user identifier | `sub` | **NameID** |
| Format | JSON / JWT | **XML** |
| Signing | JWS ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)) | **XML Signature (XML-DSig)** |

If you know OIDC, you know SAML's *shape*. What is different — and dangerous — is XML
signing, which is where SAML's security failures live.

---

## The flow

The most common variant, **SP-initiated SSO with the HTTP-POST binding**:

```
 USER          BROWSER              YOUR APP (SP)              IdP (Okta/AD FS)
  │              │                     │                          │
  │ visits ─────>│─── GET /login ─────>│                          │
  │              │                     │ build a SAML AuthnRequest │
  │              │<── 302 to IdP (with the request) ──────────────│
  │              │───────── GET /sso?SAMLRequest=... ────────────>│
  │              │                     │                    authenticates YOU
  │              │                     │                    builds a signed ASSERTION
  │              │<── HTML form that auto-POSTs to your ACS ───────│
  │              │─── POST /saml/acs (SAMLResponse=<signed XML>) ─>│
  │              │                     │ ① VALIDATE the assertion  │  ← the whole game
  │              │                     │    (signature, conditions,│
  │              │                     │     audience, timing)     │
  │              │                     │ ② extract NameID + attrs  │
  │              │                     │ ③ create YOUR session     │  E03
  │  logged in ◄─│◄────────────────────│                          │
```

**ACS** = Assertion Consumer Service — your endpoint that receives the POSTed assertion. It is
the SAML equivalent of your OIDC callback ([G04](G04-validate-an-id-token-by-hand.md)), and
validating the assertion there is the entire security of the login.

Two ways a flow can start:

- **SP-initiated** (above) — the user starts at your app; you send them to the IdP. Preferred.
- **IdP-initiated** — the user clicks your app's tile in their Okta dashboard, and the IdP
  POSTs an *unsolicited* assertion to your ACS. Convenient, and **harder to secure** — there
  is no request you initiated to correlate the response against, which removes a CSRF-style
  defence ([F05](../track-f/F05-the-state-parameter.md)). Support it only if a customer
  requires it, and be extra strict on validation.

---

## Validating an assertion

The SAML equivalent of the ten ID-token checks ([G04](G04-validate-an-id-token-by-hand.md)),
and just as non-negotiable:

```
① Signature       — verify the XML-DSig against the IdP's certificate from metadata
② What is signed  — the ASSERTION must be signed (not just the response envelope)  ← critical
③ Audience        — <AudienceRestriction> names YOUR entity ID       F08
④ Conditions      — NotBefore / NotOnOrAfter within tolerance         G04
⑤ Recipient       — the assertion's Recipient == your ACS URL
⑥ InResponseTo    — matches the request YOU sent (SP-initiated)       F05
⑦ Replay          — the assertion ID has not been seen before
⑧ Issuer          — from the IdP you expect
```

Every one maps to something you already know from OIDC. The two SAML-specific dangers:

**② What is signed.** SAML lets you sign the *response envelope*, the *assertion*, or both.
**The assertion itself must be signed**, and your validator must confirm *that specific
element* is what the signature covers. Getting this wrong is the door to signature wrapping
(below).

**⑥ InResponseTo / ⑦ Replay.** Assertions are bearer tokens with a validity window. Without
replay protection (tracking seen assertion IDs until they expire) and `InResponseTo`
correlation, a captured assertion can be reused ([G14](G14-attack-your-own-sso.md)).

---

## The one you must know about: signature wrapping (XSW)

SAML's signature attacks are its defining hazard, and **XML Signature Wrapping** is the
canonical one. It has broken SAML implementations at major companies repeatedly.

The attack exploits a gap between *what is signed* and *what is read*:

```
1. Attacker obtains any validly-signed assertion (e.g. their own login).
2. They MOVE the signed assertion to a different part of the XML tree,
   and inject a NEW, unsigned assertion where the parser will read it.
3. The signature still verifies — it covers the (relocated) original element.
4. The application READS the injected assertion — the attacker's forged one.
5. Signature "valid," identity forged.
```

The root cause: XML is a tree, signatures reference elements by ID or XPath, and the
*verifier* and the *consumer* can end up looking at different nodes. XML canonicalisation
([B06](../track-b/B06-collisions.md) territory — normalising before signing) is subtle, and
implementations disagree.

**Defences:**

- **Use a mature, maintained SAML library.** Do **not** parse and validate SAML XML yourself
  — this is the strongest single piece of advice in the chapter. The failure modes are a
  research field.
- **Verify that the signature covers the exact element you read**, and reject documents with
  multiple assertions or unexpected structure.
- **Schema-validate** and reject anything that does not match the expected shape.
- **Prefer OIDC for new integrations.** JWS signs a flat, dot-delimited string
  ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)) — there is no tree to wrap.

Full attack treatment is [G14](G14-attack-your-own-sso.md).

---

## Metadata

Instead of `.well-known` discovery ([G05](G05-discovery-and-well-known.md)), SAML exchanges
**metadata XML** between SP and IdP:

```xml
<EntityDescriptor entityID="https://yourapp.example.com/saml/metadata">
  <SPSSODescriptor>
    <AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://yourapp.example.com/saml/acs"/>
    <KeyDescriptor use="signing"><!-- your cert --></KeyDescriptor>
  </SPSSODescriptor>
</EntityDescriptor>
```

The exchange establishes:

- **Entity IDs** — the SP's and IdP's identifiers (used in `Audience`).
- **Endpoints** — your ACS, the IdP's SSO URL.
- **Certificates** — the IdP's signing cert (you verify assertions against it) and yours.

Setup is a manual exchange of these documents — one reason multi-tenant SAML is so much work
([G09](G09-multi-tenant-sso.md)): every enterprise customer is a separate metadata exchange
and certificate to manage.

---

## SAML vs OIDC, in one line each

Full comparison is [G08](G08-saml-vs-oidc.md). The headline:

- **SAML:** XML, browser-based, entrenched in enterprise, signature-attack-prone, no good
  mobile/API story.
- **OIDC:** JSON/JWT, works for web/mobile/API, simpler signing, the modern default.

**Offer both to enterprise customers, prefer OIDC where the customer supports it, and never
hand-roll SAML XML.**

---

## Terms defined in this chapter

`SAML`, `service provider` (SP), `SAML assertion`, `SP-initiated`, `IdP-initiated`,
`metadata (SAML)`, `assertion` (from C03), `XML canonicalisation`

---

## What to remember

1. **SAML is structurally OIDC in XML** — an IdP sends your SP a signed *assertion*. Same
   idea, older encoding.
2. You support it because **enterprise customers already run it**, not because it is good.
3. Vocabulary: SP = RP, assertion = ID token, metadata = discovery, NameID = `sub`.
4. **Validate the assertion** like an ID token: signature, audience, conditions, recipient,
   `InResponseTo`, replay — and confirm the **assertion itself** is what is signed.
5. **Signature wrapping (XSW)** is SAML's defining attack: signed and consumed elements
   diverge. **Never parse SAML XML yourself** — use a maintained library.
6. **IdP-initiated flows are harder to secure** — no request to correlate. Support only if
   required.
7. **Prefer OIDC** for new integrations; there is no XML tree to wrap.

---

## Sources

- [OASIS SAML 2.0 Technical Overview](https://docs.oasis-open.org/security/saml/Post2.0/sstc-saml-tech-overview-2.0.html)
- [SAML 2.0 Core](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- Somorovsky et al., [*On Breaking SAML: Be Whoever You Want to Be*](https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/somorovsky) (USENIX 2012) — the XSW paper
- [OWASP SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)

---

**Next:** [G08 — SAML vs OIDC: what to offer enterprise customers](G08-saml-vs-oidc.md)
