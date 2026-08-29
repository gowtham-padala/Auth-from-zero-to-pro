# D12 — Build TOTP two-factor

**Part D · Authentication** · *Builds on [B13](../track-b/B13-message-authentication-hmac.md), [D06](D06-build-login-part-2-login.md)*
---

## The algorithm

```
                shared secret (20 bytes, exchanged once at enrolment)
                            │
   current unix time ──┐    │
                       ▼    ▼
              T = floor(now / 30)          ← the same number on both sides
                       │
                       ▼
        HMAC-SHA1(secret, T as 8 big-endian bytes)      ← B13
                       │
                       ▼
              20 bytes of output
                       │
                       ▼  dynamic truncation
              a 31-bit integer
                       │
                       ▼  mod 10^6
                   483920
```

Both sides compute it independently. Nothing is transmitted except the six digits the
user types. The secret was exchanged **once**, at enrolment, and never again.

Two specifications:

- **[RFC 4226 — HOTP](https://www.rfc-editor.org/rfc/rfc4226)**: HMAC over an incrementing
  *counter*.
- **[RFC 6238 — TOTP](https://www.rfc-editor.org/rfc/rfc6238)**: HOTP where the counter is
  *the current time divided by 30*.

TOTP is one line of difference from HOTP. That line — using a shared clock instead of a
shared counter — is what removes the synchronisation problem and made it universal.

---

## The whole thing

```python
import hmac, hashlib, struct, time, base64, secrets, urllib.parse

DIGITS = 6
PERIOD = 30

def totp(secret: bytes, at: int | None = None, digits: int = DIGITS,
         period: int = PERIOD) -> str:
    """RFC 6238. This is the complete algorithm."""
    counter = int((at if at is not None else time.time()) // period)

    # 1. HMAC over the counter as 8 big-endian bytes.  B13.
    mac = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()

    # 2. Dynamic truncation (RFC 4226 §5.3).
    #    The low 4 bits of the last byte choose where to read from.
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFF_FFFF
    #                                                     ^ mask the sign bit,
    #                                                       so it is the same
    #                                                       on every platform

    # 3. Take the last `digits` decimal digits.
    return str(code % (10 ** digits)).zfill(digits)

def verify_totp(secret: bytes, code: str, at: int | None = None,
                window: int = 1) -> bool:
    """Accept the current step and `window` steps either side (clock skew)."""
    now = int(at if at is not None else time.time())
    ok = False
    for drift in range(-window, window + 1):
        candidate = totp(secret, at=now + drift * PERIOD)
        # Constant-time, and do NOT break early — B16.
        ok |= hmac.compare_digest(candidate, code)
    return ok
```

**That is TOTP.** Twenty lines, standard library only, interoperable with Google
Authenticator, 1Password, Authy, Aegis, and every other app ever written.

### The three details that look arbitrary and are not

**`struct.pack(">Q", counter)`** — 8 bytes, big-endian. Both sides must serialise the
counter identically or the HMACs differ ([B01](../track-b/B01-bits-bytes-text-as-numbers.md)).
This is the single most common interoperability bug.

**`& 0x7FFF_FFFF`** — masks the high bit. Without it, languages that treat the 32-bit value
as signed produce a negative number and a different result. The RFC mandates it explicitly
so implementations agree across platforms.

**`ok |= compare_digest(...)`** rather than an early `return True` — the loop runs the same
number of iterations regardless of which step matched, so the timing does not reveal the
clock drift ([B16](../track-b/B16-timing-attacks.md)).

---

## Enrolment

```python
def generate_secret() -> bytes:
    return secrets.token_bytes(20)          # 160 bits — RFC 4226 §4 R6.  B03.

def provisioning_uri(secret: bytes, account: str, issuer: str) -> str:
    """The otpauth:// URI that becomes a QR code."""
    b32 = base64.b32encode(secret).decode().rstrip("=")   # base32 — B02
    label = urllib.parse.quote(f"{issuer}:{account}")
    params = urllib.parse.urlencode({
        "secret": b32,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": DIGITS,
        "period": PERIOD,
    })
    return f"otpauth://totp/{label}?{params}"
```

```
otpauth://totp/Acme%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Acme&algorithm=SHA1&digits=6&period=30
```

**Why base32** ([B02](../track-b/B02-encoding-is-not-encryption.md)): a human sometimes has
to read the secret off a screen and type it into a phone. Base32 uses `A–Z` and `2–7` — no
lowercase, no `0`/`O`, no `1`/`l`. Less efficient than base64, far fewer transcription
errors. Encodings are chosen for their channel.

### The enrolment flow

```python
@app.post("/settings/2fa/start")
def start_2fa_enrollment():
    secret = generate_secret()
    # Do NOT save to the user yet — only after they prove it works.
    pending = create_pending_enrollment(current_user.id, secret, ttl_seconds=600)
    return render("2fa-setup.html",
                  qr=qr_code_png(provisioning_uri(secret, current_user.email, "Acme")),
                  manual_key=base64.b32encode(secret).decode(),   # for manual entry
                  pending_id=pending.id)

@app.post("/settings/2fa/confirm")
@rate_limit(key=lambda: request.form["pending_id"], limit="5/10min")
def confirm_2fa_enrollment():
    pending = load_pending_enrollment(request.form["pending_id"])
    if pending is None or pending.user_id != current_user.id:
        return error("Setup expired. Start again."), 400

    if not verify_totp(pending.secret, request.form.get("code", "")):
        return render("2fa-setup.html", error="That code didn't work. Try again."), 400

    with db.transaction():
        db.save_totp_secret(current_user.id, encrypt(pending.secret))   # B09
        codes = generate_recovery_codes(current_user.id)                # D13
        consume_pending_enrollment(pending.id)

    audit_log("2fa.enrolled", user_id=current_user.id)      # H13
    notify_user("Two-factor authentication was enabled on your account.")

    # Show recovery codes ONCE, prominently, before the user leaves.
    return render("recovery-codes.html", codes=codes)
```

**Confirm before saving.** If you store the secret before the user proves their app has it,
a mis-scanned QR code locks them out permanently — and their only route back is account
recovery ([D09](D09-account-recovery.md)), which is the weakest path.

**Show recovery codes immediately.** This is the moment the user is engaged. Retrofitting
recovery codes later has terrible completion rates
([D13](D13-recovery-codes.md)).

---

## Verification at login

```python
@app.post("/login/mfa")
@rate_limit(key=lambda: request.form["t"], limit="5/5min")     # D08 — critical
def login_mfa():
    pending = load_pending_mfa_session(request.form["t"])
    if pending is None or pending.expired():
        return redirect("/login")

    user   = db.get_user(pending.user_id)
    secret = decrypt(user.totp_secret)
    code   = request.form.get("code", "").strip().replace(" ", "")

    # ── Replay prevention: this exact code, for this user, once only. ──
    if db.totp_code_already_used(user.id, code):
        audit_log("2fa.replay_attempt", user_id=user.id)
        return render("mfa.html", t=pending.id, error="Incorrect code."), 401

    if not verify_totp(secret, code):
        record_failed_attempt(user.email, client_ip())
        return render("mfa.html", t=pending.id, error="Incorrect code."), 401

    db.record_used_totp_code(user.id, code, ttl_seconds=90)   # cover the drift window
    consume_pending_mfa_session(pending.id)

    session_id = create_session(user.id, request, amr=["pwd", "otp"])   # D18
    ...
```

### The two controls that make TOTP actually strong

**Rate limiting.** Six digits is 1,000,000 possibilities and a code is valid for 30–90
seconds. Without a limit, an attacker who has the password brute-forces it in minutes. Five
attempts, then invalidate the pending session entirely. **This is not optional, and it is
the most commonly missing control in TOTP implementations.**

**Replay prevention.** A code is valid for the whole time step. If an attacker observes it —
over the shoulder, in a phishing relay, in a log — they can reuse it within the window. Store
used codes for 90 seconds and reject repeats.

---

## The drift window

Clocks disagree. Phones drift; servers drift; users take time to type.

| Window | Accepts | Codes valid at once |
|---|---|---|
| 0 | current step only | 1 |
| **1** | ±30 s | **3** ← RFC 6238's recommendation |
| 2 | ±60 s | 5 |
| 3+ | ±90 s+ | 7+ — too wide |

**Use 1.** Each extra step multiplies the attacker's guessing surface. If users routinely
fail, their clocks are wrong — fix that with a hint in the UI ("check your phone's time is
set automatically"), not by widening the window.

---

## Storing the secret

The TOTP secret is a **symmetric shared secret**. Anyone holding it generates valid codes
forever.

```python
# ❌ plaintext — a database read defeats every user's 2FA
db.save(user_id, secret)

# ✅ encrypted with a key from a KMS.  B09 / I05.
db.save(user_id, aead.encrypt(nonce, secret, aad=str(user_id).encode()))
```

You **cannot hash it** — you need the value to compute codes
([B05](../track-b/B05-hashing-vs-encryption.md)). So encryption is required, and the key
must live somewhere the database does not.

Note the `aad=user_id`: associated data binds the ciphertext to one user, so an attacker
with database write access cannot move Alice's encrypted secret onto Bob's row
([B09](../track-b/B09-symmetric-encryption.md)).

---

## What TOTP does and does not defend against

| Attack | Defended? |
|---|---|
| Credential stuffing | ✅ The password alone is not enough |
| Password breach elsewhere | ✅ |
| Brute force | ✅ **if rate limited** |
| Database breach (your hashes) | ✅ The password hash is not enough |
| **Real-time phishing** | ❌ Relayed within the window |
| **Malware on the device** | ❌ Reads the secret from the app |
| **Your database breach (secrets)** | ❌ **if stored in plaintext** |
| Man-in-the-middle after login | ❌ The session cookie is the target now |

**The phishing row is why passkeys exist.** A phishing site collects the password and the
code and relays both inside thirty seconds. TOTP raises the cost; it does not eliminate the
attack. Only origin-bound cryptography does
([D14](D14-webauthn-and-passkeys-concepts.md), [A09](../track-a/A09-redirects.md)).

TOTP remains a large improvement over passwords alone, works offline, has no carrier
dependency, and costs nothing to run. It is the right default second factor for most
products in 2026 — with passkeys offered above it.

---

## Terms defined in this chapter

`TOTP`, `HOTP`, `shared secret`, `base32`, `dynamic truncation`, `drift window`, `replay`

---

## What to remember

1. **TOTP is HMAC-SHA1 over `floor(time/30)`, truncated to six digits.** Twenty lines.
2. **HMAC-SHA1 here is fine.** HMAC's security does not rest on collision resistance
   ([B06](../track-b/B06-collisions.md)). Be able to explain that to an auditor.
3. Big-endian 8-byte counter, and mask the sign bit. Both are interoperability
   requirements.
4. **Confirm a code before saving the secret**, or a bad scan locks the user out.
5. **Rate limit code submission.** Six digits is a million. This is the most-missed control.
6. **Prevent replay** within the drift window.
7. Window = 1. Wider multiplies the guessing surface.
8. **Encrypt the secret at rest** with a KMS key, bound to the user via associated data.
9. TOTP does not stop real-time phishing. Passkeys do.

---

## Sources

- [RFC 6238 — TOTP: Time-Based One-Time Password Algorithm](https://www.rfc-editor.org/rfc/rfc6238)
- [RFC 4226 — HOTP: An HMAC-Based One-Time Password Algorithm](https://www.rfc-editor.org/rfc/rfc4226) (§5.3 is dynamic truncation)
- [Key URI format (`otpauth://`)](https://github.com/google/google-authenticator/wiki/Key-Uri-Format)
- [The Copenhagen Book — TOTP](https://thecopenhagenbook.com/mfa#totp)

---

**Next:** [D13 — Recovery codes, and the 2FA lockout problem](D13-recovery-codes.md)
