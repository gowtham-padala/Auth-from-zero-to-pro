# B02 — Encoding is not encryption: base64, hex, URL encoding

**Part B · Crypto foundations** · *Builds on [B01](B01-bits-bytes-text-as-numbers.md)*
---

## Why it matters

A code review comment, seen in the wild more than once:

> "We encrypt the password before sending it — see, it's `cGFzc3dvcmQxMjM=`."

```bash
$ echo 'cGFzc3dvcmQxMjM=' | base64 -d
password123
```

No key. No secret. One command available on every machine ever made.

This is not a beginner's mistake alone. It appears in production systems, in vendor
documentation, and in compliance evidence. It appears because base64 output *looks*
scrambled, and looking scrambled is what people think encryption is.

---

## The distinction, once

| | **Encoding** | **Encryption** |
|---|---|---|
| Purpose | Represent data safely in some medium | Keep data confidential |
| Key? | **No** | **Yes** |
| Reversible by anyone? | **Yes** | Only with the key |
| Security value | **Zero** | The whole point |

> **Encoding changes the representation. Encryption changes who can read it.**

If a transformation has no key, it provides no confidentiality. That is not a rule of
thumb — it is definitional. Base64, hex, URL encoding, ROT13, and "we reversed the string"
are all in the same category: **public, reversible, and useless for secrecy.**

---

## Base64

**Base64** represents arbitrary bytes using 64 characters that survive text-only channels:
`A–Z`, `a–z`, `0–9`, `+`, `/`, with `=` for padding.

### How it works

Take 3 bytes (24 bits). Split into 4 groups of 6 bits. Each 6-bit group (0–63) indexes the
alphabet.

```
Input:   M         a         n
ASCII:   77        97        110
Binary:  01001101  01100001  01101110
Regroup: 010011 010110 000101 101110
Value:   19     22     5      46
Base64:  T      W      F      u
                                        → "TWFu"
```

3 bytes → 4 characters, always. **Base64 makes data ~33% larger.** That is the cost of
using only 6 of every 8 bits.

### Padding

When the input is not a multiple of 3:

```
"Ma"  (2 bytes) → "TWE="     one =
"M"   (1 byte)  → "TQ=="     two =
```

The `=` characters carry no data. They exist so the length is always a multiple of 4.

### base64url — the variant you will actually use

`+` and `/` are hostile in a URL. `+` means space in a query string; `/` is a path
separator. `=` needs percent-encoding.

**base64url** fixes it:

| Standard | base64url |
|---|---|
| `+` | `-` |
| `/` | `_` |
| `=` padding | usually **omitted** |

This is what JWTs use ([E05](../track-e/E05-jwt-part-1-three-parts.md)), what PKCE uses
([F06](../track-f/F06-pkce.md)), and what WebAuthn uses
([D15](../track-d/D15-build-passkeys.md)). Every JOSE specification mandates base64url
without padding.

> **The most common JWT bug in the world:** decoding with a standard base64 decoder that
> requires padding. Two-thirds of tokens fail, seemingly at random, depending on payload
> length mod 3. Use a base64url decoder, or re-pad with `'=' * (-len(s) % 4)` before
> decoding.

---

## Hex

Base 16. Two characters per byte, `0`–`9` and `a`–`f`.

```
Byte 72 = 0x48 = "48"
"Hello" → 48 65 6c 6c 6f
```

Doubles the size — worse than base64's 33% — but is trivially readable and always aligned:
byte *n* is always at string position 2*n*. That property makes hex the default for
displaying digests, fingerprints, and anything you might need to eyeball or diff.

You will see hashes in hex almost everywhere ([B04](B04-what-a-hash-function-is.md)).

---

## URL encoding (percent-encoding)

Some characters have structural meaning in a URL. To include them as *data*, replace each
byte with `%` and its two hex digits:

```
space  → %20   (or + in a query string, confusingly)
/      → %2F
?      → %3F
&      → %26
=      → %3D
%      → %25
é      → %C3%A9    ← UTF-8 bytes, percent-encoded individually
```

### Where this becomes a security problem

**Double encoding.** `%252F` decodes once to `%2F`, twice to `/`. If a filter checks
before one decode and a consumer decodes twice, the filter is bypassed. This is a classic
path-traversal and access-control bypass — and it is exactly why
[A09](../track-a/A09-redirects.md) insists on parsing URLs rather than string-matching them.

**Decode order.** Decode-then-validate and validate-then-decode give different answers.
Pick decode-then-validate, always, and decode exactly once.

**Inconsistent normalisation between components.** Your router, your framework, your proxy,
and your CDN may each normalise differently. An authorization rule on `/admin` that a
proxy sees as `/admin` but the app sees as `/Admin/` or `/admin/../admin` is bypassable.
Enforce authorization on a **canonical, post-routing** representation, not on a raw path
string ([H02](../track-h/H02-the-enforcement-point.md)).

---

## Encodings you will meet in auth

| Encoding | Where | Why that one |
|---|---|---|
| **base64url** | JWT, PKCE, WebAuthn, JWK | URL- and header-safe |
| **base64** | HTTP Basic, PEM keys, email attachments | Historical; text-safe |
| **hex** | Digests, fingerprints, HMAC signatures in webhook headers | Readable, aligned |
| **base32** | TOTP secrets, `otpauth://` URIs | Case-insensitive, no ambiguous chars — a human can type it ([D12](../track-d/D12-build-totp.md)) |
| **percent** | Everything in a URL | Required by the URL grammar |
| **PEM** | Certificates, keys | base64 of DER, plus `-----BEGIN ...-----` markers |
| **DER** | The binary form underneath PEM | Compact ASN.1 |

Base32's presence is worth a note. It is *less* efficient than base64 (5 bits per
character), and it is used for TOTP secrets precisely because a human sometimes has to
read one off a screen and type it into a phone. `A–Z` and `2–7` — no lowercase, no `0`/`O`
confusion, no `1`/`l`. Efficiency lost, transcription errors avoided. Encodings are chosen
for their *channel*.

---

## The demonstration that ends the argument

Run this. It takes ten seconds and settles the question permanently.

```python
import base64, hashlib, os
from cryptography.fernet import Fernet     # pip install cryptography

secret = b"my-password-123"

# ENCODING — no key. Anyone reverses it.
encoded = base64.b64encode(secret)
print("encoded :", encoded.decode())
print("reversed:", base64.b64decode(encoded).decode())     # ← no key needed

# ENCRYPTION — needs the key.
key = Fernet.generate_key()
encrypted = Fernet(key).encrypt(secret)
print("encrypted:", encrypted[:40].decode(), "...")
try:
    Fernet(Fernet.generate_key()).decrypt(encrypted)       # wrong key
except Exception as e:
    print("wrong key:", type(e).__name__)                  # ← InvalidToken

# HASHING — one-way. Nobody reverses it, including you.
print("hashed   :", hashlib.sha256(secret).hexdigest())
```

```
encoded : bXktcGFzc3dvcmQtMTIz
reversed: my-password-123
encrypted: gAAAAABm3xK9... ...
wrong key: InvalidToken
hashed   : 4d5f3e9c8a1b... (64 hex chars, and there is no way back)
```

Three transformations. One is public. One is reversible with a secret. One is not
reversible at all. Confusing them is the origin of a large fraction of real-world
cryptographic failures.

---

## Where this bites in authentication

**HTTP Basic auth** is `base64(username:password)`. Not encryption. Safe only inside TLS,
and even then the raw password crosses the wire on every request
([A04](../track-a/A04-headers.md)).

**A JWT payload is readable.** `eyJzdWIiOiJhbGljZSJ9` is base64url for `{"sub":"alice"}`.
Anyone holding the token reads every claim. Signing protects **integrity**, not
**confidentiality**. Put nothing in a JWT you would not put on a postcard —
[E05](../track-e/E05-jwt-part-1-three-parts.md) is built around making people see this.

**"Encrypted at rest" in a vendor questionnaire** sometimes means base64. Ask which
algorithm, which key, and where the key lives.

**PKCE's `code_challenge` is `BASE64URL(SHA256(verifier))`** — an encoding wrapped around a
hash. The encoding makes it URL-safe; the hash makes it one-way. Two different jobs,
composed. ([F06](../track-f/F06-pkce.md).)

---

## Terms defined in this chapter

`encoding`, `base64`, `base64url`, `hex`, `percent-encoding`

---

## What to remember

1. **No key means no confidentiality.** Encoding is a representation change, nothing more.
2. Base64 is 3 bytes → 4 chars, ~33% larger. base64url swaps `+/` for `-_` and drops
   padding.
3. **JWTs, PKCE, and WebAuthn all use base64url without padding.** Using a standard
   decoder is the classic bug.
4. Percent-encoding is where double-decoding bypasses live. Decode once, then validate.
5. base32 for TOTP because humans type it. Encodings are chosen for their channel.
6. A signed JWT is readable by anyone. Signing is integrity, not secrecy.

---

## Sources

- [RFC 4648 — The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648) (§5 is base64url)
- [RFC 3986 — URI Generic Syntax](https://www.rfc-editor.org/rfc/rfc3986) §2.1 (percent-encoding)
- [RFC 7515 — JSON Web Signature](https://www.rfc-editor.org/rfc/rfc7515) §2 ("base64url encoding … without padding")

---

**Next:** [B03 — Randomness, and why Math.random() will get you breached](B03-randomness.md)
