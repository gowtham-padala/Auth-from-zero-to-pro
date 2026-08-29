# D11 — Why SMS is the worst second factor, and still the most common

**Part D · Authentication** · *Builds on [D10](D10-magic-links-and-email-otp.md)*
---

## Every way SMS fails

### 1. SIM swap

Above. The carrier is a third party in your security model whose staff you do not train,
whose incentives are customer satisfaction, and whose verification is knowledge-based
([D09](D09-account-recovery.md) explains why that is worthless).

Some carriers now offer port-freeze or a SIM-swap PIN. Adoption is low and the protections
are inconsistent.

### 2. SS7 and the signalling network

**SS7** is the protocol suite that routes calls and messages between carriers. It was
designed in the 1970s for a small club of state monopolies, and it has **no
authentication**. Any party with network access — hundreds of carriers, resellers,
lawful-interception vendors, and anyone who buys access — can request that messages for a
number be delivered elsewhere.

Demonstrated publicly since 2014. Used to drain bank accounts in Germany in 2017. Still
present, because replacing it requires global coordination.

### 3. Malware and notification previews

An Android app with SMS permission reads every message. Codes appear in lock-screen
previews on both platforms, visible to anyone holding the phone.

### 4. Real-time phishing

The attacker's fake page asks for the code and relays it within the validity window. This
defeats **every** code-based factor — SMS, email OTP, and TOTP alike
([D12](D12-build-totp.md)). Only origin-bound cryptography stops it
([D14](D14-webauthn-and-passkeys-concepts.md)).

### 5. Number recycling

Carriers reassign disconnected numbers within months. A 2021 Princeton study found a large
fraction of sampled recycled numbers were still attached to online accounts. The new owner
receives the old owner's codes and can take over accounts without trying.

### 6. Delivery failure

International delivery is unreliable, and there is no way to distinguish "not delivered"
from "user did not enter it." Login failures caused by carrier routing are indistinguishable
from user error, which makes support impossible.

### 7. SMS pumping fraud

An attacker triggers millions of SMS sends to premium-rate numbers they control, and takes
a share of the termination fees. This is **your** bill — six-figure incidents are
documented. Rate limit SMS sends per number, per IP, and globally, and block high-risk
country codes you do not serve.

---

## NIST's position

**SP 800-63B-4** (final, July 2025) classifies SMS as an **out-of-band authenticator using
the public switched telephone network**, and restricts it:

- It is permitted, but the verifier **SHALL** consider the risk of SIM swap and number
  porting.
- The verifier **SHOULD** verify that the number is associated with a specific physical
  device, not a VoIP number.
- Out-of-band authentication over PSTN is explicitly **not phishing-resistant**, and cannot
  be used to reach the highest assurance level (AAL3), which requires a hardware
  cryptographic authenticator ([D18](D18-step-up-auth-and-aal.md)).

The direction of travel across revisions has been consistently downward. It has not been
banned, because the alternative for a large part of the world's population is *no* second
factor at all.

---

## So why is it still everywhere?

Because on the axis that determines adoption, it wins comprehensively:

| | SMS | TOTP | Passkey |
|---|---|---|---|
| Works on any phone | ✅ | ❌ needs an app | ❌ needs a modern device |
| Nothing to install | ✅ | ❌ | ⚠️ mostly built in now |
| No enrolment ceremony | ✅ | ❌ QR scan | ❌ |
| Nothing to lose | ✅ number survives a lost phone | ❌ | ⚠️ synced ones survive |
| Users already understand it | ✅ | ❌ | ❌ |
| **Enrolment completion** | **~90%** | **~30–50%** | **rising, still lower** |

That last row is the whole argument.

> **A second factor that 90% of users enrol in beats a better one that 30% enrol in.**

Google's own published data showed SMS 2FA blocking 100% of automated bots, 96% of bulk
phishing, and 76% of targeted attacks. Not perfect — dramatically better than nothing, which
is the realistic alternative.

**SMS is not "insecure." It is the weakest of the good options, and vastly better than
none.** Anyone who tells a general-consumer product to remove SMS 2FA without a plan for the
users who will end up with no second factor is optimising the wrong number.

---

## What to do

### The ranking

```
  BEST   ┌─────────────────────────────────────────────────────┐
         │ Passkey / security key   phishing-resistant, no      │
         │                          shared secret               │
         ├─────────────────────────────────────────────────────┤
         │ Push with number match   good UX; needs an app       │
         ├─────────────────────────────────────────────────────┤
         │ TOTP                     no network dependency;      │
         │                          phishable                   │
         ├─────────────────────────────────────────────────────┤
         │ Email OTP                as strong as the mailbox    │
         ├─────────────────────────────────────────────────────┤
         │ SMS                      SIM swap, SS7, relay        │
         ├─────────────────────────────────────────────────────┤
  WORST  │ Security questions       actively harmful — D09      │
         └─────────────────────────────────────────────────────┘
```

### The policy

1. **Offer passkeys first**, prominently, as the default.
2. **Offer TOTP** as the standard alternative.
3. **Offer SMS** as the fallback — but never as the *only* option, and never as the default
   presented first.
4. **For high-value accounts and admin roles: do not accept SMS.** Require a
   phishing-resistant factor ([D18](D18-step-up-auth-and-aal.md)).
5. **Never allow SMS to reset a stronger factor.** If a user has a passkey, an SMS code must
   not be sufficient to remove it — otherwise the account's real strength is SMS.
6. **Record which factor was used** in the session (`amr`), and gate sensitive actions on it.

Point 5 is the one that quietly undoes MFA programmes. Your security is the weakest path to
the account, not the strongest one you offer.

### If you must use SMS

- **Reject VoIP numbers** at enrolment (carrier lookup APIs do this).
- **Never send the code to a number changed in the last 72 hours.** This alone defeats most
  SIM swap attacks, because the attacker's move is immediately followed by a login attempt.
- **Alert on number change**, to email and to the old number.
- **Include context in the message:** *"Your code is 483920. We will never ask you for this.
  Signing in from Chrome, London."*
- **Rate limit sends** — per number, per account, per IP, and globally
  ([D08](D08-rate-limiting-and-stuffing.md)). SMS pumping is a real financial attack.
- **Six digits, five attempts, five-minute expiry, single use.**
- **Use `autocomplete="one-time-code"`** so iOS and Android autofill it, which is both a UX
  and a security improvement — autofill only offers the code to the page the message
  references when you use the [origin-bound SMS format](https://wicg.github.io/sms-one-time-codes/):
  ```
  Your code is 483920.

  @app.example.com #483920
  ```

---

## Terms defined in this chapter

`MFA`, `2FA`, `SIM swap`, `SS7`, `phishing-resistant`

---

## What to remember

1. **SIM swap needs no technical skill.** A phone call, public information, and a helpful
   representative.
2. **SS7 has no authentication.** Demonstrated for over a decade; still deployed.
3. Number recycling hands accounts to strangers who did not even attack you.
4. **SMS pumping is a financial attack on your bill.** Rate limit sends.
5. **NIST permits SMS but restricts it**, and it can never reach AAL3.
6. **~90% enrolment beats a better factor at 30%.** SMS blocks the vast majority of real
   attacks.
7. Offer passkey → TOTP → SMS, in that order. **Never let SMS reset a stronger factor.**
8. If you use it: block VoIP, freeze on recent number change, alert, rate limit, and use the
   origin-bound message format.

---

## Sources

- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.2.5 (out-of-band), §3.3 (AAL)
- Lee & Narayanan, [*Security and Privacy Risks of Number Recycling at Mobile Carriers in the US*](https://recyclednumbers.cs.princeton.edu/) (Princeton, 2021)
- Google Security Blog, [*New research: How effective is basic account hygiene at preventing hijacking*](https://security.googleblog.com/2019/05/new-research-how-effective-is-basic.html)
- [WICG: Origin-bound one-time codes delivered via SMS](https://wicg.github.io/sms-one-time-codes/)

---

**Next:** [D12 — Build TOTP two-factor](D12-build-totp.md)
