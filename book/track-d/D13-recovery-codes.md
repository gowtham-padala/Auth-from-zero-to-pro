# D13 — Recovery codes, and the 2FA lockout problem

**Part D · Authentication** · *Builds on [D12](D12-build-totp.md)*
---

## What a recovery code is

A pre-generated, single-use secret that substitutes for the second factor.

```
  a4f9-2c1e-8b3d
  7e2a-9f4c-1d8b
  3c8e-1a5f-9b2d
  ...
```

Generated at enrolment, shown **once**, stored by the user somewhere offline. Ten of them,
each usable once.

The design goal is precise: **a factor the user can store outside every device they own.**
Printed, in a safe, in a password manager, in a filing cabinet. It survives a river.

---

## Generating and storing them

```python
import secrets, hashlib, hmac

ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"   # no i/l/o/0/1 — transcription-safe
GROUPS, GROUP_LEN, COUNT = 3, 4, 10

def generate_recovery_codes(user_id: str) -> list[str]:
    codes = []
    rows = []
    for _ in range(COUNT):
        raw = "".join(secrets.choice(ALPHABET) for _ in range(GROUPS * GROUP_LEN))
        pretty = "-".join(raw[i:i + GROUP_LEN] for i in range(0, len(raw), GROUP_LEN))
        codes.append(pretty)
        rows.append(hashlib.sha256(raw.encode()).digest())   # store the HASH

    with db.transaction():
        db.delete_recovery_codes_for(user_id)      # regenerating invalidates the old set
        db.insert_recovery_codes(user_id, rows)

    return codes          # shown ONCE, never retrievable again
```

### Entropy

31 characters × 12 positions = 31¹² ≈ 7.9 × 10¹⁷ ≈ **2⁵⁹**.

That is not 128 bits, and that is a deliberate trade — the code has to be typed by a human
under stress. 59 bits is unguessable *provided you rate limit*, which for an online-only
credential is sufficient. There is no offline attack here: the codes are hashed, and an
attacker with the database has already won by other means.

If you want more, use 4 groups (2⁷⁹) or a base32 string. Do not go below 3 groups.

### Hash them — with SHA-256, not Argon2id

The distinction from [B07](../track-b/B07-fast-hashes-wrong-for-passwords.md):

| Secret | Entropy | Hash |
|---|---|---|
| Password | ~25 bits | **Argon2id** — guessable, must be expensive |
| Recovery code | **~59 bits** | **SHA-256** — a fast hash is fine |

A 59-bit random value cannot be brute-forced offline, so there is nothing to slow down.
Argon2id here would add 300 ms of latency to defend against nothing.

(If you generate *short* codes — say 6 digits — that reasoning inverts and you need a slow
hash. Do not generate short codes.)

---

## Redeeming one

```python
@app.post("/login/recovery-code")
@rate_limit(key=lambda: request.form["t"], limit="5/hour")     # tighter than TOTP
def use_recovery_code():
    pending = load_pending_mfa_session(request.form["t"])
    if pending is None or pending.expired():
        return redirect("/login")

    submitted = request.form.get("code", "").strip().lower().replace("-", "").replace(" ", "")
    code_hash = hashlib.sha256(submitted.encode()).digest()

    with db.transaction():
        # Atomic single-use, and a constant-time lookup by exact hash.
        row = db.delete_recovery_code_returning(pending.user_id, code_hash)

        if row is None:
            record_failed_attempt(pending.user_id, client_ip())
            return render("recovery.html", t=pending.id,
                          error="That code isn't valid."), 401

        remaining = db.count_recovery_codes(pending.user_id)
        consume_pending_mfa_session(pending.id)
        session_id = create_session(pending.user_id, request, amr=["pwd", "rc"])

    # ── The notification is the security control. ──
    notify_user(
        pending.user_id,
        subject="A recovery code was used on your account",
        body=f"A recovery code was used to sign in from {client_ip()} at {now()}. "
             f"{remaining} codes remain. If this wasn't you, secure your account now.",
    )
    audit_log("2fa.recovery_code_used", user_id=pending.user_id, remaining=remaining)

    if remaining <= 2:
        flash("You have few recovery codes left. Generate a new set.")

    return redirect("/")
```

### The five properties

| Property | Why |
|---|---|
| **Single-use, atomically** | `DELETE ... RETURNING` inside a transaction. Two simultaneous submissions must not both succeed. |
| **Hashed at rest** | A database read must not yield working credentials. |
| **Rate limited, hard** | Tighter than TOTP — legitimate use is rare and deliberate. |
| **Notify on use** | If the user did not use it, this is an active compromise. |
| **Track remaining** | Prompt regeneration before they run out. |

The notification is genuinely the most important line in that handler. Recovery code use is
*rare* and *high-signal*: a legitimate user knows they did it, and an attacker's use is one
of the clearest takeover signals you will ever get
([I09](../track-i/I09-detecting-account-takeover.md)).

---

## Showing them once

```
┌──────────────────────────────────────────────────────────────────┐
│  Save your recovery codes                                        │
│                                                                  │
│  These are the ONLY way to get in if you lose your phone.        │
│  Each works once. We cannot show them to you again.              │
│                                                                  │
│      a4f9-2c1e-8b3d        7e2a-9f4c-1d8b                        │
│      3c8e-1a5f-9b2d        6b1d-4e8a-2f7c                        │
│      ...                                                         │
│                                                                  │
│   [ Download ]  [ Copy ]  [ Print ]                              │
│                                                                  │
│   ☐  I have saved these codes somewhere safe                     │
│                                        [ Continue ]              │
└──────────────────────────────────────────────────────────────────┘
```

Design notes that measurably improve completion:

- **Force an explicit acknowledgement.** A checkbox that gates the button. Friction is the
  point.
- **Offer download, copy, and print.** Different users store differently, and the ones who
  print are the ones who will still have them in three years.
- **Never email them.** The mailbox is a channel an attacker may already control, and it is
  frequently the *same* channel used for account recovery
  ([D09](D09-account-recovery.md)). Emailing recovery codes collapses two independent
  factors into one.
- **Show them at enrolment**, not on a settings page the user will never visit
  ([D12](D12-build-totp.md)).

---

## The whole lockout ladder

Recovery codes are one rung. Design the ladder, and know which rung is your real security
level.

```
1. Second passkey / second security key      ★★★★★  best — enrol two at signup
2. Synced passkeys (iCloud / Google)         ★★★★☆  platform handles recovery
3. Recovery codes                            ★★★★☆  offline, survives everything
4. A second enrolled TOTP device             ★★★☆☆  same QR on two phones
5. Approval from an already-trusted device   ★★★☆☆  good UX, needs one live device
6. Email verification + delay + notification ★★☆☆☆  as strong as the mailbox
7. Identity documents                        ★★★★☆  high friction, high value
8. Support ticket                            ★☆☆☆☆  the weakest link — D09
```

> **Your account security is rung 8, unless you have removed it.** An attacker takes the
> cheapest path. If support can disable 2FA with a convincing phone call, that *is* your
> 2FA.

The realistic policy for most products:

- **Rungs 1–3 as the standard offering.** Two authenticators plus recovery codes at
  enrolment.
- **Rung 6 with a 72-hour delay and notification** as the self-service fallback.
- **Rung 8 only with written procedure, two-person approval, and a delay**
  ([D09](D09-account-recovery.md)).

The delay is what makes the weak rungs tolerable: it gives the real owner a window to
object, which turns a silent takeover into a detected attempt.

---

## Regeneration and hygiene

```python
@app.post("/settings/2fa/recovery-codes/regenerate")
@require_recent_authentication(max_age_seconds=300)     # D18 — step-up
def regenerate_recovery_codes():
    codes = generate_recovery_codes(current_user.id)    # invalidates the whole old set
    audit_log("2fa.recovery_codes_regenerated", user_id=current_user.id)
    notify_user(current_user.id, "Your recovery codes were regenerated.")
    return render("recovery-codes.html", codes=codes)
```

- **Regenerating replaces the whole set.** Never mix generations.
- **Require recent authentication.** An attacker with a hijacked session must not be able
  to mint themselves a permanent backdoor
  ([D18](D18-step-up-auth-and-aal.md)) — this is exactly the kind of action step-up exists
  for.
- **Prompt at ≤2 remaining.**
- **Regenerate after any use**, ideally, and definitely after a suspected compromise
  ([I10](../track-i/I10-incident-response.md)).
- **Delete them when 2FA is disabled**, and regenerate when it is re-enabled.

---

## Terms defined in this chapter

`recovery code`

---

## What to remember

1. Recovery codes exist so **"lost phone"** never becomes **"convince support to disable
   2FA."**
2. ~59 bits is enough **because they are rate-limited and hashed**. SHA-256, not Argon2id —
   there is no offline attack.
3. **Single-use, atomically.** `DELETE ... RETURNING` in a transaction.
4. **Notify on every use.** Rare, deliberate, and one of the highest-signal takeover
   indicators you will get.
5. **Show once, at enrolment**, with an acknowledgement checkbox and download/print.
6. **Never email them.** It collapses two factors into one channel.
7. **Your security is the weakest rung of the recovery ladder** — usually the support desk.
8. Require step-up authentication to regenerate.

---

## Sources

- [OWASP Multifactor Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.2.1 (look-up secrets)
- [The Copenhagen Book — MFA and recovery codes](https://thecopenhagenbook.com/mfa)

---

**Next:** [D14 — WebAuthn and passkeys: the concepts](D14-webauthn-and-passkeys-concepts.md)
