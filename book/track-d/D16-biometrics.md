# D16 — Biometrics: what your fingerprint actually proves

**Part D · Authentication** · *Builds on [D14](D14-webauthn-and-passkeys-concepts.md)*
---

## What actually happens

```
   ┌────────────────────────────────────────────────────────────────┐
   │  THE DEVICE                                                    │
   │                                                                │
   │   👆 fingerprint sensor                                        │
   │        │                                                       │
   │        ▼                                                       │
   │   ┌──────────────────────────────────────┐                     │
   │   │  SECURE ENCLAVE / TEE / TPM          │                     │
   │   │                                      │                     │
   │   │  • Stores a mathematical template    │                     │
   │   │    (not an image, not reversible)    │                     │
   │   │  • Compares the new scan to it       │                     │
   │   │  • Answers ONE bit: match / no match │                     │
   │   │  • On match: unlocks the private key │                     │
   │   │    and signs, inside the chip        │                     │
   │   └──────────────┬───────────────────────┘                     │
   │                  │                                             │
   │                  ▼  a 64-byte signature                        │
   └──────────────────┼─────────────────────────────────────────────┘
                      │
                      ▼
   ┌────────────────────────────────────────────────────────────────┐
   │  YOUR SERVER                                                   │
   │    Receives: a signature. Verifies it with a public key.       │
   │    Receives: nothing biometric. Ever.                          │
   └────────────────────────────────────────────────────────────────┘
```

> **The biometric unlocks a private key held on the device. It is never transmitted, and the
> server never sees it.**
>
> The fingerprint is a **local gate**, not a credential. What crosses the network is a
> signature — the same signature you would get from a PIN, or a swipe pattern, or a security
> key's button.

Concretely: on the wire, "signed in with Face ID" and "signed in with a device PIN" are
**identical**. Both set the `UV` flag ([D15](D15-build-passkeys.md)). Your server cannot
distinguish them and does not need to.

---

## So what does the biometric prove?

It proves **the right person is holding the unlocked device right now**.

That is genuinely valuable and precisely bounded. It converts "something you have" — the
device — into "something you have, and the right person is using it."

What it does **not** prove:

- **Not identity to your server.** Your server learns "the key was used," not "a fingerprint
  matched."
- **Not liveness, always.** Quality varies enormously by device. Some sensors are defeated
  by a photograph or a lifted print; modern ones with depth sensing and liveness detection
  are much harder.
- **Not uniqueness.** Face recognition confuses relatives. Fingerprint sensors have
  measurable false-accept rates.
- **Not consent.** A sleeping or unconscious person's finger works. Courts in several
  jurisdictions have treated compelled biometric unlock differently from compelled password
  disclosure, precisely because of this.

---

## Why "you can't change your fingerprint" is the wrong objection

It is a correct fact and the wrong conclusion, and the reason is architectural.

If a system stored fingerprints centrally and compared them server-side, the objection would
be devastating: a breach would leak an unchangeable identifier, permanently, for everyone.

**That is not how WebAuthn works.** The biometric is local. The key is per-site
([D14](D14-webauthn-and-passkeys-concepts.md)). A breach of your database leaks public keys.

And the biometric *is* effectively revocable at the level that matters: the user deletes the
passkey, or resets the device's biometric enrolment, and every key it protected is
invalidated. The finger is unchanged; the credential is gone.

The objection is fatal to **server-side biometric matching**, and that architecture is what
you should refuse to build.

---

## The rule for your own systems

> **Never send a biometric to your server. Never store one. Never compare one.**

If a vendor proposes server-side biometric matching — "upload a selfie, we'll compare it to
the one on file" — understand what you are taking on:

- **Irrevocable identifiers** in your database, for every user, forever.
- **Biometric-specific regulation.** Illinois BIPA carries statutory damages *per
  violation* and has produced settlements in the hundreds of millions. GDPR treats
  biometrics as special-category data requiring explicit consent and a heightened lawful
  basis. Texas, Washington, and a growing list of states have their own regimes.
- **A breach you cannot remediate.** You cannot issue everyone a new face.

There is one legitimate category: **identity proofing** — a one-time check that a person
matches their government ID, at onboarding, for a regulated purpose. Even there, use a
specialist provider, and **delete the biometric data as soon as the check completes.** Do
not retain it "in case."

That is a fundamentally different operation from *authentication*, and NIST separates them:
**SP 800-63A** covers identity proofing; **SP 800-63B** covers authentication. Conflating
them is how companies end up storing faces.

---

## Where the key actually lives

The security of the whole arrangement rests on hardware that isolates the key from the
operating system.

| Platform | Hardware | Notes |
|---|---|---|
| Apple | **Secure Enclave** | Separate coprocessor, its own boot ROM and memory. Keys are non-exportable. |
| Android | **TEE / StrongBox** | TrustZone; StrongBox is a discrete secure element. |
| Windows | **TPM** | Discrete or firmware. Windows Hello keys live here. |
| Security keys | **Secure element** | Purpose-built; the key has no exportable form at all. |

The property that matters is the same in all four: **the private key has no exportable
form.** Even a fully compromised operating system can *ask* the enclave to sign — while the
attacker has control — but cannot *extract* the key and use it later, elsewhere.

That distinction is exactly the one from [A10](../track-a/A10-where-secrets-live.md): a key
in a KMS can be *used* by an attacker inside your system, but not *taken*. It bounds a
catastrophe into an incident.

### Synced passkeys change the picture

A synced passkey ([D14](D14-webauthn-and-passkeys-concepts.md)) is, by definition,
exportable from one device and importable to another — that is what sync means. The private
key is encrypted with a key derived from the user's platform account, and Apple and Google
both design so that they cannot read it themselves.

The security therefore rests on the user's iCloud or Google account rather than on hardware
isolation. That is a real difference:

- **Usability:** dramatically better. Losing a device does not lose the account.
- **Assurance:** lower. This is why synced passkeys generally sit at **AAL2**, and
  device-bound hardware credentials are what reach **AAL3**
  ([D18](D18-step-up-auth-and-aal.md)).

If you are building for a regulated context that requires AAL3, require device-bound
credentials and check the `backed_up` flag you stored in
[D15](D15-build-passkeys.md).

---

## Accessibility and inclusion

Biometrics fail for real people, systematically:

- **Fingerprints** are unreadable for some users — manual labour, certain medical
  conditions, age, some medications.
- **Face recognition** has documented accuracy disparities across demographic groups.
- **Any biometric** may be unusable after an injury.
- **Some users decline** on privacy or religious grounds, and that is a legitimate choice.

**Always offer a non-biometric path.** In WebAuthn this is free: the device PIN produces the
same `UV` flag and the same signature. Users choose their local gate; your server sees the
same thing either way.

This is worth stating in your UI. "Use your fingerprint, face, or device PIN" tells users
the choice exists and removes the assumption that they must hand over a biometric.

---

## Terms defined in this chapter

`biometric`, `secure enclave`, `false accept rate`

---

## What to remember

1. **The biometric unlocks a local private key. It never leaves the device. Your server
   never sees it.**
2. It proves *the right person is holding the unlocked device*. Not identity, not consent,
   not liveness.
3. "You can't change your fingerprint" is fatal to **server-side matching** — which is why
   WebAuthn does not do it.
4. **Never store, send, or compare biometrics.** BIPA, GDPR special-category data, and a
   breach you cannot remediate.
5. Identity proofing (SP 800-63A) is a different operation from authentication
   (SP 800-63B). Delete the data afterwards.
6. Hardware isolation means the key can be *used* under compromise but not *taken*.
7. **Synced passkeys trade hardware isolation for recoverability** — AAL2, not AAL3.
8. **Always offer a PIN.** Same flag, same signature, and biometrics exclude real people.

---

## Sources

- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.2.3 (biometrics as an activation factor only)
- [NIST SP 800-63A-4](https://csrc.nist.gov/pubs/sp/800/63/a/4/final) — identity proofing, the separate problem
- [Apple Platform Security Guide — Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)
- [Android: Hardware-backed Keystore and StrongBox](https://source.android.com/docs/security/features/keystore)
- [Illinois Biometric Information Privacy Act (BIPA)](https://www.ilga.gov/legislation/ilcs/ilcs3.asp?ActID=3004)

---

**Next:** [D17 — "Remember this device" is harder than it looks](D17-remember-this-device.md)
