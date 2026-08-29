# D09 — Account recovery is your real weakest link

**Part D · Authentication** · *Builds on [D06](D06-build-login-part-2-login.md)*
---

## Why it matters

You have done everything right. Argon2id. A breach blocklist. Rate limiting. TOTP
two-factor, mandatory.

Then:

```
POST /password-reset  { "email": "ceo@company.com" }
```

The attacker, who controls a compromised mailbox — or who has SIM-swapped a phone, or who
called support and was convincing — clicks the link, sets a new password, and is in.

**Your 2FA did not apply**, because the reset flow was built as a way *around* login rather
than as a form *of* login.

> **Account recovery is a parallel authentication path with none of the controls.** More
> accounts are stolen through password reset than through password guessing, and it is
> almost never given the attention login gets.

---

## The fundamental tension

Recovery is unavoidable. People lose passwords, phones, laptops, and access to email
accounts. A system with no recovery loses users permanently, and support pressure will
eventually force a manual override — which is worse, because it is undocumented and
unaudited.

But every recovery mechanism is, by construction, **a way to gain access without the normal
credential**.

```
                     Security
                        ▲
    No recovery ────────┤ Users are permanently locked out.
                        │ Support invents an unofficial process.
                        │
    Strong recovery ────┤ Identity documents, in-person, delays
                        │ ← where high-value accounts should sit
                        │
    Email reset ────────┤ ← where most of the web sits
                        │
    Security questions ─┤ ← actively harmful
                        │
    "Call support" ─────┤ Social engineering. The weakest link
                        ▼   in most large organisations.
                     Usability
```

The design goal is not to eliminate the trade-off. It is to make sure your recovery path is
**no weaker than your login path** — because an attacker will always take the weaker one.

---

## Password reset, done properly

```python
import secrets, hashlib
from datetime import datetime, timedelta, timezone

RESET_TTL = timedelta(minutes=15)

@app.post("/password-reset/request")
@rate_limit(key=lambda: canonicalize(request.form["email"]), limit="3/hour")
@rate_limit(key=lambda: client_ip(),                          limit="10/hour")
def request_reset():
    email = canonicalize(request.form.get("email", ""))
    user  = db.find_user_by_canonical_email(email)

    if user:
        # Invalidate any outstanding tokens: one live reset at a time.
        db.delete_reset_tokens_for(user.id)

        token = secrets.token_urlsafe(32)                       # B03: 256 bits
        db.insert_reset_token(
            token_hash=hashlib.sha256(token.encode()).digest(), # B05: hashed
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + RESET_TTL,
            requested_ip=client_ip(),
        )
        enqueue_email(user.email, "reset", token=token)         # async — D07
        audit_log("password_reset.requested", user_id=user.id, ip=client_ip())

    # Identical response, identical timing, whether or not the account exists.
    return render("reset-requested.html"), 200

@app.post("/password-reset/confirm")
@rate_limit(key=lambda: request.form.get("token", "")[:8], limit="5/hour")
def confirm_reset():
    token        = request.form.get("token", "")
    new_password = request.form.get("password", "")

    errors = validate_password(new_password, "", "")            # D04
    if errors:
        return render("reset-form.html", token=token, errors=errors), 400

    token_hash = hashlib.sha256(token.encode()).digest()

    with db.transaction():
        # Atomic single-use: DELETE ... RETURNING.
        row = db.delete_reset_token_returning(token_hash)
        if row is None or row.expires_at < datetime.now(timezone.utc):
            return render("reset-invalid.html"), 400

        user = db.get_user_for_update(row.user_id)

        db.update_password_hash(user.id, ph.hash(normalize(new_password)))   # D03

        # ── The steps everyone forgets ──────────────────────────────────
        db.delete_all_sessions_for(user.id)          # E13: kill every session
        db.delete_all_reset_tokens_for(user.id)      # no siblings survive
        db.mark_email_verified(user.id)              # they proved mailbox control

    send_password_changed_notification(user.email)   # to the OLD address too
    audit_log("password_reset.completed", user_id=user.id, ip=client_ip())

    return redirect("/login?reset=success")
```

---

## The properties, and what breaks without each

| Property | Missing it means |
|---|---|
| **256-bit random token** | Guessable. A 6-digit reset code is 10⁶ and brute-forceable. |
| **Hashed at rest** | A read-only SQL injection is a live account-takeover kit. |
| **Short expiry (15 min)** | A forwarded or archived email works months later. |
| **Atomically single-use** | Two clicks, two resets. Mail prefetchers cause this. |
| **Bound to one account** | A token for A resets B. Never take a `user_id` from the form. |
| **Constant-time compare** | Timing recovers the token byte by byte ([B16](../track-b/B16-timing-attacks.md)). |
| **Invalidate all sessions** | The attacker who *caused* the reset stays logged in. |
| **Notify the user** | The owner never learns it happened. |
| **Rate limited** | Mail bombing, and token brute force. |
| **Identical responses** | Enumeration ([D07](D07-user-enumeration.md)). |

Two of those deserve expansion.

### Invalidating sessions is not optional

The scenario: an attacker gains a session (XSS, a stolen cookie, a shared computer). The
user notices something odd and changes their password. If the reset does not kill sessions,
**the attacker's session survives** and the user believes they have recovered the account.

Kill every session, including the one performing the reset, and require a fresh login. If
you want to be kind, keep the *current* session and kill all others — but be explicit about
that choice.

### Notify, always, on both channels

Send to the address being changed **and** the previous one
([D01](D01-identifiers.md)). Include the time, the approximate location, and a "this wasn't
me" link that locks the account.

For many users this notification is the only signal they will ever get.

---

## The `Referer` leak

A reset link in a URL is a live credential in a URL
([A01](../track-a/A01-what-happens-when-you-type-a-url.md),
[A04](../track-a/A04-headers.md)):

```
https://app.example.com/reset?token=abc123
```

The reset page loads an analytics script, and that script's request carries
`Referer: https://app.example.com/reset?token=abc123`. Your token is now in a third
party's logs.

**Fixes, in order:**

1. **`Referrer-Policy: no-referrer`** on the reset page specifically.
2. **Load nothing third-party** on that page. No analytics, no fonts, no tag manager.
3. **Better: get the token out of the URL.** Land on the page, read the token from the
   query string in JavaScript, immediately `history.replaceState` it away, and submit it in
   a `POST` body.
4. `Cache-Control: no-store` on the page.

---

## Security questions: do not

> *"Verifiers SHALL NOT prompt subscribers to use knowledge-based authentication."*
> — NIST SP 800-63B-4

Mother's maiden name, first school, first pet, street you grew up on. All of these are:

- **Findable** on social media, in public records, in genealogy sites.
- **Low entropy.** A few hundred common answers cover most users.
- **Unchangeable.** You cannot rotate your mother's maiden name after a breach.
- **Leaked already.** They have appeared, in plaintext, in dozens of breaches.
- **Shared across sites.** The same answers work everywhere.

They are a second, weaker password that the user cannot change and the internet already
knows.

If a legacy system forces you to keep them: let users enter **random strings** stored in a
password manager, and hash the answers like passwords. That converts them into what they
should have been — a second secret — at the cost of the "memorable" property that made them
attractive in the first place.

---

## Recovery when there is no password

Passkey-first accounts ([D14](D14-webauthn-and-passkeys-concepts.md)) have no password to
reset. Recovery has to be designed, not inherited.

| Mechanism | Strength | Notes |
|---|---|---|
| **Multiple passkeys** | ★★★★★ | Enrol two at registration. The best answer. |
| **Synced passkeys** | ★★★★☆ | iCloud Keychain, Google Password Manager. Recovery is the platform's problem. |
| **Recovery codes** | ★★★★☆ | Printed, single-use ([D13](D13-recovery-codes.md)) |
| **A second device** | ★★★★☆ | Approve from an already-trusted device |
| **Email magic link** | ★★★☆☆ | Only as strong as the mailbox ([D10](D10-magic-links-and-email-otp.md)) |
| **Social recovery** | ★★★☆☆ | N-of-M trusted contacts. Rare outside crypto. |
| **Identity documents** | ★★★★☆ | High friction; right for high value |
| **Support ticket** | ★☆☆☆☆ | **Social engineering target.** See below. |

**The strongest practical design: enrol two authenticators at registration.** "Add a second
passkey" or "save these recovery codes" at the moment of sign-up, when the user is engaged.
Retrofitting it later has terrible completion rates.

---

## The human path

Every recovery mechanism eventually falls back to a person, and **the human path is the
weakest link in most large organisations**. A confident phone call has defeated the security
of companies that spend millions on technical controls — this is how a large share of
high-profile account compromises actually happen.

If support can restore access, they need:

| Control | Why |
|---|---|
| **A written, mandatory procedure** | Improvisation under social pressure is the vulnerability |
| **Verification that is not public knowledge** | Not name, address, or date of birth — recent account activity, last invoice amount |
| **Two-person approval** for high-value accounts | One person cannot be talked into it alone |
| **A mandatory delay** (24–72 h) with notification | The real owner gets a chance to object |
| **Full audit logging** ([H13](../track-h/H13-audit-logging.md)) | Reconstruct what happened |
| **Escalation being a signal, not a shortcut** | Urgency and anger are the standard pressure tactics; train for them |

That fourth row is the most effective single control. A delay costs a legitimate user
inconvenience and costs an attacker their entire window — because the real owner is
notified and can cancel.

---

## The rule

> **Recovery must be at least as strong as login, or it is your authentication mechanism —
> and the one you designed is decorative.**

Concretely, if you require MFA to log in, you should require **something beyond email** to
reset. Otherwise anyone who controls the mailbox has bypassed the second factor entirely.

Options that preserve the strength:

- Require a **recovery code** in addition to the emailed link.
- Require the **existing second factor** during reset, and treat losing it as a separate,
  higher-friction flow.
- Apply a **delay plus notification** for resets on MFA-enabled accounts.
- **Re-enrol MFA after reset**, and tell the user prominently.

---

## Terms defined in this chapter

`account recovery`, `reset token`, `single-use token`

---

## What to remember

1. **Recovery is a parallel authentication path with none of the controls.** More accounts
   are stolen this way than by guessing.
2. Reset tokens: 256-bit, **hashed at rest**, 15 minutes, **atomically single-use**, bound
   to one account, constant-time compared.
3. **Invalidate every session** on reset, or the attacker who caused it stays in.
4. **Notify both the new and old addresses.** Often the only signal the owner gets.
5. Get the token **out of the URL**, or `Referer` hands it to a third party.
6. **Security questions are prohibited by NIST.** They are a weaker password you cannot
   change.
7. **Enrol two authenticators at registration.** Retrofitting fails.
8. **The support desk is the weakest link.** Written procedure, non-public verification,
   two-person approval, mandatory delay, full audit.
9. If login requires MFA, reset must require more than email.

---

## Sources

- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.1 (no KBA), §5.1
- [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html)
- [The Copenhagen Book — Password reset](https://thecopenhagenbook.com/password-reset)
- [passkeys.dev — Account recovery](https://passkeys.dev/docs/use-cases/bootstrapping/)

---

**Next:** [D10 — Magic links and email OTP: how they work, when they're fine](D10-magic-links-and-email-otp.md)
