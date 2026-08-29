# B15 — Certificates and PKI: why your browser trusts a stranger

**Part B · Crypto foundations** · *Builds on [B14](B14-digital-signatures.md)*
---

## The problem certificates solve

From [B11](B11-asymmetric-encryption.md) and [B14](B14-digital-signatures.md): a public key
is a number. It arrives with no name attached.

```
   Browser connects to example.com
   Server: "Hi, my public key is 3F8A2B..."
   Browser: "...is it, though?"
```

An attacker in the middle sends *their* public key and claims it is example.com's. The
mathematics is satisfied. The identity is not.

You need a way to bind **a public key** to **a name**. But binding requires a statement, and
a statement requires a source you already trust — so the question becomes: *whom do you
already trust, and why?*

---

## A certificate is a signed statement

> **A certificate is a public key plus identity information, signed by someone else.**

An X.509 certificate contains, essentially:

```
┌──────────────────────────────────────────────────────┐
│ Subject:      CN=example.com                          │
│ SAN:          example.com, www.example.com            │  ← what it actually covers
│ Public Key:   3F8A2B...                               │
│ Issuer:       CN=R11, O=Let's Encrypt                 │
│ Valid:        2026-06-01 → 2026-08-30                 │
│ Serial:       04:A3:...                               │
│ Key Usage:    Digital Signature, Key Encipherment     │
│ Extended KU:  TLS Web Server Authentication           │
│ SCTs:         [certificate transparency proofs]       │
├──────────────────────────────────────────────────────┤
│ Signature by the issuer's private key: 9C2F...        │
└──────────────────────────────────────────────────────┘
```

The **SAN** (Subject Alternative Name) row is the one that matters operationally. The
`Subject`/`CN` field is legacy — browsers have ignored it for hostname matching since about
2017. **Only SAN entries count.** A certificate with the right CN and a missing SAN is
rejected, which surprises people migrating old configurations.

The signature means: *the issuer asserts that this public key belongs to these names.*

---

## The chain of trust

Your browser does not trust `example.com`. It trusts a small set of **root CAs**, whose
certificates ship inside the browser or the operating system — the **root store**.

```
   ┌──────────────────────────────────────┐
   │  ROOT CA                             │  Self-signed. Trusted because it
   │  "ISRG Root X1"                      │  is IN YOUR ROOT STORE. That is
   │  (in your browser's root store)      │  the only reason. Kept offline.
   └────────────────┬─────────────────────┘
                    │ signs
                    ▼
   ┌──────────────────────────────────────┐
   │  INTERMEDIATE CA                     │  Signed by the root. Online,
   │  "Let's Encrypt R11"                 │  does the day-to-day issuing.
   └────────────────┬─────────────────────┘  Revocable without killing the root.
                    │ signs
                    ▼
   ┌──────────────────────────────────────┐
   │  LEAF CERTIFICATE                    │  Your server's actual certificate.
   │  "example.com"                       │
   └──────────────────────────────────────┘
```

Verification walks up:

1. Does the leaf cover the hostname I typed? (**SAN check.**)
2. Is it within its validity period?
3. Is its signature valid under the intermediate's public key?
4. Repeat for the intermediate under the root.
5. **Is that root in my trust store?**
6. Is anything in the chain revoked?

Step 5 is where trust actually terminates. The root is trusted **because it is in the
list** — not because of any cryptographic property. Everything else is arithmetic; this
step is policy.

### Why intermediates exist

The root's private key is kept offline, in a safe, in a facility with cameras, used a
handful of times a year in ceremonies with witnesses. It is a catastrophic single point of
failure — if it leaks, every certificate it ever signed is suspect, and the fix requires
updating every browser on Earth.

Intermediates are the operational layer. They are online, they issue millions of
certificates, and if one is compromised it can be revoked without touching the root.

---

## Who decides what is in the root store?

Browser and OS vendors: Mozilla, Apple, Microsoft, Google, and the Chrome Root Program.

To get in, a CA must pass **WebTrust** audits, comply with the **CA/Browser Forum Baseline
Requirements**, and demonstrate operational controls. It is a genuine bar.

It is also a **structural weakness**, and naming it precisely matters:

> **Any CA in your root store can issue a valid certificate for any domain.**
>
> Not just domains they have a relationship with. **Any domain.** Your bank's certificate
> is protected not only by your bank's CA but by every one of the ~150 CAs your browser
> trusts, and any government that can compel one of them.

That is DigiNotar. And Comodo (2011). And TÜRKTRUST (2013). And ANSSI (2013). And WoSign
(2016). And Symantec, which was progressively distrusted in 2017–18 for systematic
misissuance despite being one of the largest CAs in the world.

The system is not "trust one authority." It is "trust the *union* of a hundred and fifty
authorities," and the union is only as strong as its weakest member.

---

## The mitigations

### Certificate Transparency — the one that worked

Every certificate must be published to public, append-only, cryptographically verifiable
logs. Chrome has required this since 2018; Safari too.

The logs are Merkle trees, so a log operator cannot retroactively remove or alter an entry
without detection.

The effect is a genuine change in the threat model:

- **Misissuance becomes detectable.** Google can monitor for certificates issued for
  `google.com` by any CA on Earth. So can you — [crt.sh](https://crt.sh) is free, and CT
  monitoring services will email you.
- **Silent attacks become impossible.** DigiNotar went undetected for weeks. Today the
  fraudulent certificate would appear in a public log within hours, because a certificate
  without valid **SCTs** (signed certificate timestamps) is rejected by the browser.

CT converted an unauditable trust system into an auditable one, without changing who is
trusted. It is the most successful security intervention in the history of the web PKI.

**Do this today:** set up CT monitoring for your domains. It is free, it takes ten minutes,
and it is how you find out someone issued a certificate for your domain.

### Short lifetimes

Certificate maximum lifetimes have been steadily cut — 5 years, then 2, then 398 days, and
the CA/Browser Forum has agreed a schedule taking them to **47 days by 2029**.

The logic: revocation does not really work (below), so a short lifetime is the reliable
mechanism. A compromised key is dangerous for weeks, not years.

The consequence: **manual certificate management is no longer viable.** Automation — ACME,
Let's Encrypt, cert-manager, your cloud provider's managed certificates — is now mandatory
infrastructure, not a convenience. If your renewal process involves a human and a calendar
reminder, it will fail.

### Revocation, which mostly does not work

Three mechanisms, in order of how well they work:

- **CRL** — a list of revoked serials. Grew to megabytes. Effectively abandoned for the web
  PKI.
- **OCSP** — ask the CA in real time. Adds latency, leaks browsing history to the CA, and —
  fatally — browsers **soft-fail**: if the OCSP responder is unreachable, they proceed
  anyway. An attacker who can present a revoked certificate can also block the OCSP
  request. Chrome disabled it by default years ago, and the CA/Browser Forum made OCSP
  optional for CAs in 2025.
- **OCSP stapling** — the *server* fetches its own OCSP response and includes it in the
  handshake. Fixes latency and privacy. Still soft-fails without `Must-Staple`.
- **Browser-pushed lists** — CRLite, CRLSets. The vendor aggregates revocations and pushes
  a compressed set to browsers. This actually works, and is where the ecosystem landed.

**The honest summary: revocation on the web is weak, and short lifetimes are the real
answer.** Keep that in mind when you design your own token revocation
([E11](../track-e/E11-revocation.md)) — the industry with the most resources and the
longest experience concluded that short expiry beats a revocation list, and the same
reasoning usually applies to you.

---

## Certificate validation levels

| Type | Validates | Time | Worth it? |
|---|---|---|---|
| **DV** (Domain Validated) | You control the domain | Seconds | **Yes.** Free via Let's Encrypt. |
| **OV** (Organization Validated) | Plus company identity | Days | Rarely. |
| **EV** (Extended Validation) | Plus deeper legal checks | Weeks | **No.** |

EV certificates used to produce a green company name in the address bar. **Browsers removed
that indicator in 2019**, after research showed users did not notice it, and that
lookalike company names could be registered legitimately. EV now costs more and displays
identically.

The security value of a certificate is in the *encryption and the name binding*, both of
which DV provides completely. Anything above DV is procurement theatre.

---

## Private PKI

Inside your own infrastructure the calculus inverts.

Running your own CA for internal services means **your** root, in **your** trust stores,
issuing certificates only for **your** names. No third party can issue for your internal
domains, because nobody else's root is trusted there.

This is how **mTLS** works ([J04](../track-j/J04-mtls.md)) and how **SPIFFE/SPIRE** issues
workload identities ([J05](../track-j/J05-workload-identity-spiffe.md)). It is also
strictly better than the public PKI for internal use — a smaller trust set is a smaller
attack surface.

Tools: `cfssl`, `step-ca`, HashiCorp Vault's PKI engine, or your cloud's private CA.

---

## Look at a real chain

```bash
# The full chain, as served
openssl s_client -connect example.com:443 -servername example.com -showcerts </dev/null

# The fields that matter
openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName

# Every certificate ever issued for a domain — Certificate Transparency, free
curl -s 'https://crt.sh/?q=example.com&output=json' | head -c 2000
```

That last command is the one to remember. Run it against your own domain. If there is a
certificate you did not issue, you have found something important.

---

## Terms defined in this chapter

`certificate`, `X.509`, `CA`, `root store`, `chain of trust`, `SAN`,
`revocation (certificates)`, `certificate pinning`, `Certificate Transparency`

---

## What to remember

1. A certificate binds a **public key** to a **name**, asserted by a signature you already
   trust.
2. Trust terminates at the **root store** — a list shipped with your software. That step is
   policy, not mathematics.
3. **Any trusted CA can issue for any domain.** Security is the weakest of ~150 CAs.
4. **Certificate Transparency made misissuance detectable.** Monitor your domains on
   crt.sh. Free, ten minutes.
5. **Revocation mostly does not work.** Short lifetimes are the real mechanism — heading
   for 47 days. Automate renewal or it will break.
6. **Only SAN entries count** for hostname matching. CN is legacy.
7. EV certificates buy nothing. DV is complete.
8. Private PKI for internal services is smaller, tighter, and better.

---

## Sources

- [RFC 5280 — Internet X.509 Public Key Infrastructure Certificate and CRL Profile](https://www.rfc-editor.org/rfc/rfc5280)
- [RFC 6962 — Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962)
- [CA/Browser Forum Baseline Requirements](https://cabforum.org/working-groups/server/baseline-requirements/documents/)
- [Chrome Root Program Policy](https://googlechrome.github.io/chromerootprogram/)
- [ENISA / Fox-IT: Black Tulip — Report of the investigation into the DigiNotar Certificate Authority breach](https://www.rijksoverheid.nl/documenten/rapporten/2012/08/13/black-tulip-update)

---

**Next:** [B16 — Timing attacks and constant-time comparison](B16-timing-attacks.md)
