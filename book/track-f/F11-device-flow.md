# F11 — The device flow: how your TV logs in

**Part F · Delegated authorization — OAuth 2** · *Builds on [F03](F03-authorization-code-flow.md)*
---

## Why it matters

You set up a streaming app on a new TV. It shows:

```
   Go to  example.com/activate
   and enter code:  WDJB-MJHT
```

You type that on your phone, approve, and the TV logs in. No keyboard on the TV. No browser
on the TV. No password typed on the TV.

How? The authorization code flow needs a browser on the device to receive the redirect
([F03](F03-authorization-code-flow.md)). A TV, a CLI, a game console, a smart speaker, an
IoT sensor — these have **no browser, or no good way to type**. The redirect has nowhere to
land.

The **device authorization grant** ([RFC 8628](https://www.rfc-editor.org/rfc/rfc8628))
solves it by moving the authorization to a *different device* — the phone in your pocket.

---

## The flow

```
   INPUT-CONSTRAINED DEVICE (TV)         SECOND DEVICE (phone)         AUTH SERVER
          │                                    │                          │
          │─① POST /device_authorization ──────┼─────────────────────────>│
          │<─ device_code, user_code,          │                          │
          │   verification_uri, interval ──────┼──────────────────────────│
          │                                    │                          │
          │  Displays: "go to example.com/activate, enter WDJB-MJHT"      │
          │                                    │                          │
          │                          user goes │─② GET verification_uri ──>│
          │                          there ────│  logs in, enters code,   │
          │                                    │  consents ──────────────>│
          │                                    │                          │
          │─③ POLL POST /token (device_code) ──┼─────────────────────────>│
          │<─ authorization_pending ───────────┼──────────────────────────│
          │  (wait `interval` seconds)         │                          │
          │─③ POLL again ──────────────────────┼─────────────────────────>│
          │<─ access_token (+ refresh_token) ──┼──────────────────────────│  ← approved
          │                                    │                          │
          │  Now logged in.                    │                          │
```

Two channels, one screen apart. The TV never sees a credential; the phone does all the
authenticating, on its own trusted browser.

---

## The device side

### Step 1 — request codes

```python
import requests, time

resp = requests.post("https://auth.example.com/device_authorization", data={
    "client_id": "tv-app-12345",
    "scope": "openid profile streaming:read",
}).json()

# {
#   "device_code":      "GmRhmhcxhwEzkoEqiMEg_DnyEysNkuNhszIySk9eS",  ← secret, for the TV
#   "user_code":        "WDJB-MJHT",                                  ← shown to the user
#   "verification_uri": "https://example.com/activate",
#   "verification_uri_complete": "https://example.com/activate?user_code=WDJB-MJHT",
#   "expires_in":       1800,
#   "interval":         5
# }

display(f"Go to {resp['verification_uri']} and enter: {resp['user_code']}")
show_qr(resp["verification_uri_complete"])       # a QR the phone camera can open directly
```

Two codes, two purposes:

- **`device_code`** — a long, secret value the TV keeps and uses to poll. Never shown.
- **`user_code`** — short, human-readable, typed by the user. Deliberately low-entropy so it
  is typeable, which is why it needs its own protections (below).

### Step 2 — the user authorizes, elsewhere

On the phone: open the URL (or scan the QR), log in with full MFA on a real browser
([A09](../track-a/A09-redirects.md)), enter `WDJB-MJHT`, and **consent** — the consent screen
must clearly say *which device* is being authorized ([F13](F13-consent-screens.md)).

### Step 3 — the device polls

```python
deadline = time.time() + resp["expires_in"]
interval = resp["interval"]

while time.time() < deadline:
    time.sleep(interval)
    r = requests.post("https://auth.example.com/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "device_code": resp["device_code"],
        "client_id": "tv-app-12345",
    })
    body = r.json()

    if r.status_code == 200:
        save_tokens(body); break                 # ✅ approved
    elif body.get("error") == "authorization_pending":
        continue                                 # user hasn't finished yet
    elif body.get("error") == "slow_down":
        interval += 5                            # ← you MUST honour this
    elif body.get("error") in ("access_denied", "expired_token"):
        show("Authorization failed. Please try again."); break
```

The four token-endpoint responses are the whole protocol on the device side:

| Response | Meaning | Do |
|---|---|---|
| `200` + tokens | Approved | Save and proceed |
| `authorization_pending` | User not done yet | Keep polling at `interval` |
| **`slow_down`** | Polling too fast | **Increase `interval` by 5s** |
| `access_denied` / `expired_token` | Denied or timed out | Stop, restart the flow |

**Honour `slow_down`.** Ignoring it gets your client rate-limited or blocked. And never poll
faster than `interval` — the AS is telling you its capacity.

---

## The security concerns particular to this flow

The device flow trades browser presence for a short, typeable code, and that trade creates
risks the code flow does not have.

### The `user_code` is low-entropy — protect it

`WDJB-MJHT` is a handful of characters so a human can type it. That is guessable compared to
a 256-bit code ([B03](../track-b/B03-randomness.md)). Mitigations, all required:

- **Short expiry** — 15–30 minutes, then dead.
- **Rate-limit the verification endpoint** hard — a few attempts per session, then a CAPTCHA
  ([D08](../track-d/D08-rate-limiting-and-stuffing.md)). Otherwise an attacker brute-forces
  the space of active codes.
- **One `user_code` active per `device_code`** at a time.

### The device phishing attack

The dangerous one, and it is subtle:

```
1. Attacker starts a device flow for THEIR malicious client, gets a user_code.
2. Attacker sends YOU: "Your account needs re-verification —
   go to accounts.google.com/device and enter ABCD-1234."
   The link is the REAL provider. The code is the attacker's.
3. You go to the real, trusted page and enter the code.
4. You have just authorized the ATTACKER'S device to access YOUR account.
```

Everything the user sees is genuine — the real domain, the real login, the real consent
screen. The attack is that *the user was told which code to enter by the attacker.*

Defences, layered:

- **The consent screen must show what is being authorized, unmissably** — the app name, the
  scopes, ideally a location or device description. A user re-reading "Smart TV wants access
  to your photos" when they expected "re-verify your email" is the catch
  ([F13](F13-consent-screens.md)).
- **Warn on unsolicited codes.** "Only enter a code shown on a device *you* are setting up."
- **Bind the code to a fresh, deliberate action**, and expire it fast.
- **Consider not offering device flow at all for high-value scopes.** It is inherently
  weaker against social engineering than a flow where the user initiates on their own device.

This is a known, exploited attack class (used in real phishing campaigns against enterprise
accounts). Treat the device flow as *convenient but socially engineerable*, and scope what
it can grant accordingly.

---

## When to use it

✅ **Smart TVs and streaming devices** — the canonical case.
✅ **CLI tools** — `gh auth login`, `aws sso login`, `az login` all use it. Better than
pasting a token, because the login happens in a real browser with full MFA.
✅ **Game consoles, smart speakers, IoT** — no keyboard, or no browser.
✅ **Any headless or input-constrained device.**

❌ **Anything with a usable browser** — use the authorization code flow
([F03](F03-authorization-code-flow.md)); it is stronger.
❌ **High-value scopes on consumer devices**, given the phishing risk above — or gate them
behind additional confirmation.

The CLI case is worth highlighting: `aws sso login` opening your browser and showing a code
is the device flow, and it is strictly better than the old world of long-lived access keys
pasted into `~/.aws/credentials` ([J02](../track-j/J02-api-keys.md)).

---

## Terms defined in this chapter

`device authorization grant`, `user code`, `polling`

---

## What to remember

1. **The device flow moves authorization to a second device** — a phone — because the first
   has no browser or keyboard.
2. Two codes: **`device_code`** (secret, for the device to poll) and **`user_code`** (short,
   typed by the human).
3. The device **polls** the token endpoint; the four responses are `pending`, `slow_down`,
   `access_denied`/`expired`, and success. **Honour `slow_down`.**
4. The **`user_code` is low-entropy** — short expiry and hard rate limiting are mandatory.
5. **Device phishing is real:** an attacker's code entered on the real provider authorizes
   the attacker's device. The consent screen is the defence.
6. Use it for TVs, consoles, IoT, and **CLIs**. Never where a proper browser is available.

---

## Sources

- [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://www.rfc-editor.org/rfc/rfc8628)
- [RFC 9700 — OAuth 2.0 Security BCP](https://www.rfc-editor.org/rfc/rfc9700) §4.13 (device grant)
- Aaron Parecki, [oauth.com — Device Flow](https://www.oauth.com/oauth2-servers/device-flow/)
- [Microsoft: Device code phishing](https://learn.microsoft.com/en-us/security/) — the attack in the wild

---

**Next:** [F12 — Token introspection vs local validation](F12-introspection-vs-local-validation.md)
