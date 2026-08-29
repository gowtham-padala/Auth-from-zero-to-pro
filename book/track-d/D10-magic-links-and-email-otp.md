# D10 — Magic links and email OTP: how they work, when they're fine

**Part D · Authentication** · *Builds on [D02](D02-email-as-identity.md)*
---

## What a magic link is

```
1. User enters their email
2. Server generates a high-entropy single-use token
3. Server emails https://app.example.com/auth/<token>
4. User clicks
5. Server validates the token and creates a session
```

Structurally **identical to a password reset** ([D09](D09-account-recovery.md)) — with the
password step removed. Which means it inherits every property of password reset, including
the security ceiling.

> **A magic link makes your email account the credential for everything.** That is not
> automatically wrong — password reset already did — but it should be a decision, not a
> side effect.

**Email OTP** is the same mechanism with a different delivery format: a 6–8 digit code the
user types instead of a link they click. Same trust model, different trade-offs (below).

---

## Implementation

```python
import secrets, hashlib
from datetime import datetime, timedelta, timezone

MAGIC_LINK_TTL = timedelta(minutes=10)

@app.post("/auth/magic-link")
@rate_limit(key=lambda: canonicalize(request.form["email"]), limit="3/hour")
@rate_limit(key=lambda: client_ip(),                          limit="10/hour")
def request_magic_link():
    email = canonicalize(request.form.get("email", ""))
    user  = db.find_user_by_canonical_email(email)

    if user:
        db.delete_magic_links_for(user.id)          # one live link at a time

        token = secrets.token_urlsafe(32)           # B03
        db.insert_magic_link(
            token_hash=hashlib.sha256(token.encode()).digest(),   # B05
            user_id=user.id,
            expires_at=datetime.now(timezone.utc) + MAGIC_LINK_TTL,
            requested_ip=client_ip(),
            requested_ua=request.headers.get("User-Agent", ""),
        )
        enqueue_email(user.email, "magic-link", token=token)      # async — D07

    return render("check-your-email.html"), 200     # identical either way

@app.get("/auth/verify/<token>")
def verify_magic_link_page(token: str):
    # Deliberately does NOT consume the token. Mail scanners follow GETs.
    return render("confirm-login.html", token=token)

@app.post("/auth/verify")
@rate_limit(key=lambda: request.form.get("token", "")[:8], limit="5/hour")
def verify_magic_link():
    token_hash = hashlib.sha256(request.form["token"].encode()).digest()

    with db.transaction():
        row = db.delete_magic_link_returning(token_hash)     # atomic single-use
        if row is None or row.expires_at < datetime.now(timezone.utc):
            return render("link-invalid.html"), 400

        # Same-device check: warn if the browser differs from the requester.
        if row.requested_ua and row.requested_ua != request.headers.get("User-Agent", ""):
            audit_log("magic_link.different_device", user_id=row.user_id)
            # For higher-value products, require a code confirmation here.

        session_id = create_session(row.user_id, request, amr=["email"])   # D18

    resp = redirect("/")
    resp.set_cookie("__Host-session", session_id, httponly=True, secure=True,
                    samesite="Lax", path="/", max_age=60*60*24*14)
    return resp
```

The `GET` page that does **not** consume the token is the single most important detail. A
scanner or a mail client prefetching the link renders a confirmation page and changes
nothing. The user clicks a button; the `POST` consumes it.

---

## Magic link vs email OTP

Same security model, meaningfully different in practice.

| | **Magic link** | **Email OTP (code)** |
|---|---|---|
| User action | Click | Read and type |
| Cross-device | ❌ Opens on the email device | ✅ Type it on any device |
| Mail scanner prefetch | ❌ A problem (mitigable) | ✅ Not affected |
| Link preview leakage | ❌ Slack, Teams, previews | ✅ A code is useless without the session |
| Phishability | Moderate | **Higher** — relayed in real time |
| Session continuity | Breaks: requested in Safari, opens in Gmail's browser | **Preserved** — same tab throughout |
| Brute force | Not feasible (256-bit) | **Feasible** — must rate limit hard |

**The session continuity problem is the one that ruins magic links in practice.** A user
requests a link in Chrome, opens it in the Gmail app's in-app browser, and gets logged in
*there* — a different browser, with a different cookie jar, where they cannot continue what
they were doing.

**Email OTP avoids it entirely.** The user stays in the original tab and types six digits.
For that reason alone, most products that started with magic links have moved to codes.

If you use OTP codes:

- **8 digits, not 6**, for email (there is no 30-second window bounding the attack as with
  TOTP).
- **Maximum 5 attempts**, then invalidate.
- **10-minute expiry.**
- **Bind the code to the originating session** — store the session ID with the code and
  refuse it from a different one. This defeats the relay attack, because the phisher's
  browser is not the one that requested it.

That last control is the strongest available for email OTP and it is rarely implemented.

---

## When magic links / email OTP are fine

✅ **Low-to-medium value consumer products.** The account is worth roughly what the email
account is worth.

✅ **Products where users log in rarely.** Nobody remembers a password they use twice a
year. They will use "forgot password" every time — which *is* a magic link, with extra
steps and worse UX.

✅ **As one option among several.** Alongside passkeys and SSO.

✅ **B2B where email is already the corporate identity**, and the mailbox is protected by
the company's own MFA. You are inheriting their controls, which are often better than
yours.

## When they are not

❌ **High-value accounts.** Financial, healthcare, admin, anything with irreversible
actions. Email is a moderately-trusted channel, not a strong one
([D02](D02-email-as-identity.md)).

❌ **When you need real MFA.** A magic link is one factor. "Magic link + email OTP" is the
same factor twice, over the same channel — not two factors
([C03](../track-c/C03-the-vocabulary.md)).

❌ **When email delivery is unreliable for your users.** Corporate filters, unusual
providers, and international deliverability problems become login outages. A password
always works.

❌ **When latency matters.** Ten to sixty seconds per login, every time, is real friction.

❌ **Where phishing is a serious concern.** Both are relayable in real time. Passkeys are
not ([D14](D14-webauthn-and-passkeys-concepts.md)).

---

## The phishing problem

A phishing site asks for your email, forwards it to the *real* service, and the real
service emails you a genuine code. You type it into the phishing site. The attacker relays
it and is in.

The email is authentic. The code is genuine. Nothing looks wrong.

Mitigations, in order of effectiveness:

1. **Bind the code to the requesting session.** The attacker's request came from their
   browser, not yours, so your code will not work in their session. Strongest available
   defence.
2. **Show context in the email.** *"You're signing in from Chrome on macOS in London.
   If this wasn't you, do not enter this code."*
3. **Include a number-matching challenge.** Display a two-digit number on the login page
   and require the user to pick it in the email. Awkward, effective.
4. **Never send a code the user did not request** — and if you do, say prominently that
   nobody should ever ask them for it.

None of these reach the phishing resistance of WebAuthn, where the browser performs the
origin check mechanically ([A09](../track-a/A09-redirects.md)).

---

## Deliverability is a security property

If the email does not arrive, the user cannot log in. Login availability is now bound to
your email infrastructure.

- **SPF, DKIM, DMARC.** Without them, your mail lands in spam, *and* anyone can forge a
  login email that appears to come from you.
- **A dedicated sending domain or subdomain** for transactional mail, separate from
  marketing. A marketing send that triggers spam complaints must not take down login.
- **Monitor delivery and open rates** as an availability metric, with alerting.
- **Always offer a fallback** — a password, a passkey, SSO. A single-channel login is a
  single point of failure.

---

## Terms defined in this chapter

`magic link`, `OTP`

---

## What to remember

1. A magic link is a password reset without the password. It makes the **mailbox** the
   credential.
2. **Land on a page; consume on `POST`.** Mail scanners follow `GET`s.
3. Token: 256-bit, **hashed at rest**, 10 minutes, **atomically single-use**, rate limited.
4. **Email OTP beats magic links on session continuity** — the reason most products
   switched.
5. **Bind the code to the requesting session.** Best available anti-phishing control.
6. Magic link + email OTP is **one factor, twice.** Not MFA.
7. Deliverability is availability. SPF/DKIM/DMARC, a dedicated domain, monitoring, and a
   fallback.

---

## Sources

- [The Copenhagen Book — Email verification and OTP](https://thecopenhagenbook.com/email-verification)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.2 (out-of-band authenticators)

---

**Next:** [D11 — Why SMS is the worst second factor, and still the most common](D11-sms-second-factor.md)
