# I09 — Detecting account takeover: signals and risk scoring

**Part I · Identity lifecycle & operations** · *Builds on [D08](../track-d/D08-rate-limiting-and-stuffing.md)*
---

## Why prevention isn't enough

Everything so far *prevents* unauthorized access. But prevention assumes the credential is in the
right hands. ATO is what happens when it isn't:

```
   Tracks D–H:  "Is this a valid credential?"        → yes → allow
   ATO defence: "Does this login look like THIS       → no  → challenge / block / alert
                 user's normal behaviour?"
```

Detection is probabilistic where prevention is binary. It won't have a definitive "this is an
attacker" signal — it has *signals* that this login is *unusual*, combined into a *risk score*,
which drives a *proportional response*. This is defence in depth ([C04](../track-c/C04-threat-modeling.md))
for the case where the front-line control (the credential) has already been defeated.

---

## The signals

What makes a login look *unlike* the user:

| Signal | Why it's suspicious |
|---|---|
| **Impossible travel** | Login from London, then Tokyo 20 minutes later — physically impossible |
| **New device / fingerprint** | Never-seen device ([D17](../track-d/D17-remember-this-device.md)) |
| **New location / country** | First login from a new country |
| **Datacentre / VPN / Tor IP** | Legitimate users rarely log in from an AWS IP |
| **Known-bad IP** | On a threat-intel blocklist |
| **Credential-stuffing pattern** | This IP just failed against 500 other accounts ([D08](../track-d/D08-rate-limiting-and-stuffing.md)) |
| **Breached password** | The password just appeared in a new breach corpus ([D04](../track-d/D04-password-policies.md)) |
| **Unusual time** | 3am for a 9-to-5 user |
| **Rapid sensitive actions** | Immediately changes email + password + MFA — the takeover-lockout sequence |
| **Behavioural anomaly** | Bulk-downloads data they've never accessed before ([H14](../track-h/H14-attack-your-own-authorization.md)) |

**Impossible travel** is the highest-signal and most-cited: it requires two data points (previous
login location + this one) and simple arithmetic, and a positive is a near-certain compromise or
shared account. **The rapid-sensitive-actions sequence** is the one that matters most to catch,
because it's the attacker making their access *permanent* ([D09](../track-d/D09-account-recovery.md)) —
detecting it in real time is the difference between a scare and a lockout.

---

## Risk scoring: combine, don't gate individually

No single signal is decisive — a real user *does* travel, *does* get a new phone, *does* use a
VPN. Gating on any one produces false positives that train users to hate you
([D08](../track-d/D08-rate-limiting-and-stuffing.md)). Instead, **combine signals into a score**:

```python
def login_risk(user, request) -> str:
    score = 0
    if impossible_travel(user, request):          score += 60   # near-certain
    if new_device(user, request):                 score += 20
    if new_country(user, request):                score += 15
    if is_datacenter_ip(request.ip):              score += 15
    if ip_recently_stuffed_others(request.ip):    score += 40   # D08
    if password_in_recent_breach(user):           score += 30   # D04
    if unusual_hour(user, request):               score += 10

    if score >= 70:   return "high"
    if score >= 30:   return "elevated"
    return "normal"
```

The response is **proportional to the score** — escalate friction, don't slam a door
([D18](../track-d/D18-step-up-auth-and-aal.md)):

| Risk | Response |
|---|---|
| Normal | Proceed |
| Elevated | **Step up** — require MFA / re-auth for this login or the next sensitive action ([D18](../track-d/D18-step-up-auth-and-aal.md)) |
| High | Step up now + **notify the user** ("new login from Tokyo — was this you?") |
| Critical (during session) | **Terminate the session** ([E13](../track-e/E13-sessions-across-devices.md)), force full re-auth, alert |

The principle from [D18](../track-d/D18-step-up-auth-and-aal.md): **escalate, don't block.** A
legitimate user on a business trip gets an MFA prompt (mild friction); an attacker gets a wall
they can't pass (they don't have the second factor). Blocking outright punishes the traveller and
generates support tickets; step-up catches the attacker while letting the real user through.

---

## Detection continues *after* login

ATO detection is not only at the login gate. A session can be hijacked mid-flight
([E16](../track-e/E16-xss-is-an-auth-vulnerability.md)), so continuous signals matter
([D18](../track-d/D18-step-up-auth-and-aal.md)):

- **The IP/location changing mid-session** — the cookie moved to a different machine.
- **The rapid-sensitive-actions sequence** — email + password + MFA changes in quick succession.
- **Behavioural drift** — a support agent's account suddenly bulk-exporting customer data
  ([H14](../track-h/H14-attack-your-own-authorization.md)).

These feed the same score, driving a step-up ([D18](../track-d/D18-step-up-auth-and-aal.md)) or a
session kill ([E13](../track-e/E13-sessions-across-devices.md)) during the session — the
continuous-assurance model, not a one-time check at login.

---

## The user is your best detector

The most effective ATO control is often the cheapest: **tell the user, and let them react.**
Throughout this book, notification is a recurring control ([D09](../track-d/D09-account-recovery.md),
[E13](../track-e/E13-sessions-across-devices.md), [D13](../track-d/D13-recovery-codes.md)):

- **"New login from [location/device] — was this you?"** with a one-click "secure my account"
  that kills sessions and forces a reset.
- **Alert on sensitive changes** — email change, MFA removal, recovery code use — to the *old*
  contact channel, so the real owner learns of a takeover in progress and can stop it
  ([D09](../track-d/D09-account-recovery.md)).
- **A visible login/activity history** the user can review ([E13](../track-e/E13-sessions-across-devices.md)) —
  the user recognising an entry they didn't make is frequently how ATO is discovered at all.

The user knows their own behaviour better than any model. A well-placed notification turns them
into a real-time detector with zero false-positive cost to you — they simply ignore the ones that
were them.

---

## Build vs buy

Sophisticated ATO detection — device fingerprinting, IP reputation, behavioural baselines,
impossible-travel at scale — is genuinely hard, and it's a place where specialist providers add
real value ([C05](../track-c/C05-build-vs-buy.md)): they see attack patterns across many customers
that you can't see alone, and maintain threat-intel feeds you can't.

But the *fundamentals* are cheap and high-value, and you should build them regardless of any
vendor:

- **Impossible travel** — you have login locations; the arithmetic is trivial.
- **Log and alert on failed-login spikes** ([D08](../track-d/D08-rate-limiting-and-stuffing.md),
  [I08](I08-observability.md)).
- **Notify users of new-device logins and sensitive changes.**
- **Check passwords against breach corpora** ([D04](../track-d/D04-password-policies.md)).

Start with those — they catch the common attacks. Add a vendor when the volume and sophistication
of attacks against you justify it.

---

## Terms defined in this chapter

`account takeover` (ATO), `risk score`, `impossible travel`, `device fingerprint`

---

## What to remember

1. **ATO defeats authentication rather than breaking it** — a valid credential in the wrong hands
   is invisible to every prevention control. The answer is *detection*.
2. **Signals, not certainties:** impossible travel, new device/location, datacentre IPs,
   stuffing patterns, breached passwords, rapid sensitive changes.
3. **Combine signals into a risk score** — no single signal gates, because real users travel and
   change devices.
4. **Respond proportionally: escalate, don't block.** Step up on elevated risk, notify on high,
   kill the session on critical ([D18](../track-d/D18-step-up-auth-and-aal.md)).
5. **Detection continues after login** — mid-session IP changes and the takeover-lockout sequence
   are the highest-value catches.
6. **The user is your best detector** — "was this you?" notifications turn every user into a
   real-time, zero-false-positive-cost sensor.
7. **Build the fundamentals** (impossible travel, failed-login alerts, breach checks,
   notifications) regardless; **buy** sophisticated detection when attack volume justifies it.

---

## Sources

- [OWASP: Credential Stuffing / Account Takeover](https://owasp.org/www-community/attacks/Credential_stuffing)
- [NIST SP 800-63B-4 §5.2 — reauthentication and risk signals](https://csrc.nist.gov/pubs/sp/800/63/b/4/final)
- Google Security Blog, [account-hijacking prevention research](https://security.googleblog.com/2019/05/new-research-how-effective-is-basic.html)

---

**Next:** [I10 — Incident response: your tokens leaked, now what?](I10-incident-response.md)
