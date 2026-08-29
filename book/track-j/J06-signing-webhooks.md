# J06 — Signing webhooks, and verifying them correctly

**Part J · Machine, workload & agent identity** · *Builds on [B13](../track-b/B13-message-authentication-hmac.md), [B16](../track-b/B16-timing-attacks.md)*
> The shortest path to making B13 and B16 feel urgent — because every reader has integrated a
> webhook, and most verified it wrong.

---

## Why it matters

Your app receives webhooks from a payment provider — `payment.succeeded` events that credit a
customer's account. The handler:

```python
@app.post("/webhooks/payments")
def handle_webhook():
    event = request.get_json()
    if event["type"] == "payment.succeeded":
        credit_account(event["customer"], event["amount"])   # ← no verification
    return "ok"
```

An attacker who knows your webhook URL — it's not secret; it's in your provider dashboard, maybe in
a leaked config — simply POSTs their own JSON:

```bash
curl -X POST https://yourapp.com/webhooks/payments \
  -d '{"type":"payment.succeeded","customer":"attacker","amount":1000000}'
```

Your app credits them a million. **A webhook endpoint is a publicly-reachable API that performs
privileged actions, and this one authenticated nothing.** The direction of the call is reversed —
*they* call *you* ([A08](../track-a/A08-what-an-api-is.md)) — so you must verify *their* identity,
and the mechanism is a signature you check.

Almost every webhook integration gets this wrong in one of a handful of specific ways. This chapter
is those ways.

---

## The mechanism: HMAC over the raw body

Webhook signing is [B13](../track-b/B13-message-authentication-hmac.md) applied directly. The
provider and you share a secret ([B10](../track-b/B10-key-distribution-problem.md) — exchanged
out-of-band via the dashboard, [J02](J02-api-keys.md)). The provider signs each request; you verify:

```
   Provider:  signature = HMAC-SHA256(secret, timestamp + "." + raw_body)   B13
              sends the body + a header:  X-Signature: t=<ts>,v1=<signature>

   You:       recompute HMAC over what you RECEIVED, compare to the header.
              Match → it's genuinely from the provider, unmodified.  B13
```

The signature proves two things ([B13](../track-b/B13-message-authentication-hmac.md)):
**authenticity** (only someone with the shared secret could produce it — so it's really the
provider) and **integrity** (the body wasn't changed in transit). The opening example fails because
the attacker doesn't have the secret and can't produce a valid signature.

---

## Verifying correctly — every trap

```python
import hmac, hashlib, time

WEBHOOK_SECRET = os.environ["WEBHOOK_SECRET"].encode()   # I05
TOLERANCE = 300   # 5 minutes

@app.post("/webhooks/payments")
def handle_webhook():
    # ★ TRAP 1: get the RAW bytes, before any parsing.
    raw_body = request.get_data()                        # NOT request.get_json()!

    sig_header = request.headers.get("X-Signature", "")
    timestamp, signature = parse_sig_header(sig_header)   # "t=..., v1=..."

    # ★ TRAP 2: verify over timestamp + raw body, exactly as the provider signed.
    signed_payload = f"{timestamp}.".encode() + raw_body
    expected = hmac.new(WEBHOOK_SECRET, signed_payload, hashlib.sha256).hexdigest()

    # ★ TRAP 3: constant-time comparison. NEVER ==.  B16
    if not hmac.compare_digest(expected, signature):
        abort(400, "invalid signature")

    # ★ TRAP 4: reject old timestamps — replay protection.
    if abs(time.time() - int(timestamp)) > TOLERANCE:
        abort(400, "timestamp outside tolerance")

    # ★ TRAP 5: idempotency — the SAME valid event may arrive twice.
    event = json.loads(raw_body)                         # NOW it's safe to parse
    if already_processed(event["id"]):
        return "ok"                                      # dedupe by event id
    mark_processed(event["id"])

    process(event)
    return "ok"
```

Five traps, and each is a real, common bug:

### Trap 1 & 2 — verify the RAW bytes, not a re-serialised parse

**The single most common webhook bug** ([B13](../track-b/B13-message-authentication-hmac.md)):

```python
# ❌ Parse, then re-serialise, then verify — the bytes CHANGED.
body = json.dumps(request.get_json())    # whitespace, key order, unicode all differ
verify(secret, body, signature)          # will NOT match

# ✅ Verify the EXACT bytes you received.
verify(secret, request.get_data(), signature)
```

`json.dumps(json.loads(x))` is not `x` — key order, whitespace, and number/unicode formatting all
change ([B13](../track-b/B13-message-authentication-hmac.md), [B01](../track-b/B01-bits-bytes-text-as-numbers.md)).
The provider signed the *exact bytes on the wire*, so you must verify those exact bytes. Grab the
raw body *before* any middleware parses it. This is why [B13](../track-b/B13-message-authentication-hmac.md)
insists: verify over the bytes you received, never a regenerated form.

### Trap 3 — constant-time comparison

```python
if expected == signature:          # ❌ leaks the signature byte-by-byte via timing  B16
if hmac.compare_digest(expected, signature):   # ✅
```

The signature is a secret-derived value being compared against attacker-supplied input — exactly the
[B16](../track-b/B16-timing-attacks.md) scenario. `==` returns early on the first mismatched byte,
so an attacker can recover the valid signature one byte at a time. `compare_digest` runs in constant
time. This is [B16](../track-b/B16-timing-attacks.md)'s webhook example, made real.

### Trap 4 — replay protection via timestamp

A signature is valid *forever* ([B14](../track-b/B14-digital-signatures.md) — signatures don't
expire). Without a timestamp, an attacker who captures one valid webhook (from a log, a proxy) can
**replay** it indefinitely — resending a genuine `payment.succeeded` a thousand times. Signing the
**timestamp** into the payload and rejecting old ones bounds the replay window
([D12](../track-d/D12-build-totp.md) — freshness, [F16](../track-f/F16-sender-constrained-tokens.md)).

### Trap 5 — idempotency

Webhooks are delivered *at-least-once*: providers retry on timeout, so the *same valid event* may
arrive multiple times legitimately. Process it twice and you credit the account twice. **Dedupe by
event ID** — process each event exactly once, even under legitimate retries. This isn't security per
se, but it's the bug that turns "verified webhook" into "double charge."

---

## Why webhooks make B13 and B16 urgent

This chapter is deliberately placed to make the crypto foundations feel *necessary* rather than
academic. Every trap maps to an earlier chapter, and every one bites in production:

| Trap | Foundation | The production symptom |
|---|---|---|
| Raw body | [B13](../track-b/B13-message-authentication-hmac.md) | "The signature never matches" |
| HMAC over the right payload | [B13](../track-b/B13-message-authentication-hmac.md) | Same |
| Constant-time compare | [B16](../track-b/B16-timing-attacks.md) | A subtle, exploitable timing leak |
| Timestamp / replay | [B14](../track-b/B14-digital-signatures.md), [D12](../track-d/D12-build-totp.md) | Replayed events |
| Idempotency | — | Double-processing |

If [B13](../track-b/B13-message-authentication-hmac.md) and [B16](../track-b/B16-timing-attacks.md)
felt abstract, this is where they cash out: a webhook you verified wrong is either forgeable
(no signature check), timing-leaky (`==`), or replayable (no timestamp) — and you *have* integrated
a webhook.

---

## The other direction: signing webhooks you send

If *you* are the provider sending webhooks, do unto others
([B13](../track-b/B13-message-authentication-hmac.md)):

- **Sign every webhook** — HMAC over `timestamp.body`, per receiver's shared secret.
- **Include a timestamp** in the signed payload, so receivers can do replay protection.
- **Include an event ID**, so receivers can dedupe.
- **Support secret rotation** — publish *two* active signing secrets during a rotation window so
  receivers can roll without missing events ([I06](../track-i/I06-key-rotation.md)) — the same
  overlap principle as key rotation.
- **Document the exact signing scheme** — which bytes, which header format — so receivers can verify
  the *raw* body correctly (trap 1).
- **Consider mTLS or asymmetric signatures** ([J04](J04-mtls.md), [B14](../track-b/B14-digital-signatures.md))
  for higher-assurance webhooks — with an asymmetric signature, receivers verify with your *public*
  key and you never share a secret ([B10](../track-b/B10-key-distribution-problem.md)).

The asymmetric option is worth noting: an HMAC secret shared with every receiver means any receiver
*could* forge webhooks to any other ([B10](../track-b/B10-key-distribution-problem.md),
[B14](../track-b/B14-digital-signatures.md)). A signature (you sign with a private key, they verify
with your public key) avoids that — the same reasoning as choosing RS256/ES256 over HS256 for
multi-party JWTs ([E06](../track-e/E06-jwt-part-2-signature-jws-jwe.md)).

---

## Terms defined in this chapter

`webhook`, `signature header`, `raw body`, `replay window`

---

## What to remember

1. **A webhook endpoint is a public API that does privileged actions** — verify the sender's
   identity, or an attacker just POSTs forged events.
2. **The mechanism is HMAC** ([B13](../track-b/B13-message-authentication-hmac.md)) over the request,
   with a shared secret — proving authenticity and integrity.
3. **Verify the RAW bytes, never a re-serialised parse** — `json.dumps(json.loads(x)) != x`. This is
   *the* most common webhook bug.
4. **Constant-time comparison** ([B16](../track-b/B16-timing-attacks.md)), never `==` — the signature
   is secret-derived and compared against attacker input.
5. **Sign and check a timestamp** — signatures don't expire, so without it, valid events are
   replayable forever.
6. **Dedupe by event ID** — at-least-once delivery means the same valid event arrives twice.
7. **Sending webhooks:** sign them, timestamp them, ID them, support secret rotation
   ([I06](../track-i/I06-key-rotation.md)), and consider asymmetric signatures so receivers can't
   forge to each other.

---

## Sources

- [Stripe: Verifying webhook signatures](https://docs.stripe.com/webhooks#verify-manually) — the reference implementation of everything here
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104) ([B13](../track-b/B13-message-authentication-hmac.md))
- [Standard Webhooks specification](https://www.standardwebhooks.com/) — a cross-provider signing standard
- [OWASP: Webhook security](https://cheatsheetseries.owasp.org/)

---

**Next:** [J07 — Auth for AI agents: delegating to a non-human actor](J07-auth-for-ai-agents.md)
