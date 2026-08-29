# B01 — Bits, bytes, and how text becomes numbers

**Part B · Crypto foundations**
---

## Bits

A **bit** is one binary digit: `0` or `1`. That is the entire concept.

With *n* bits you can represent 2ⁿ distinct values:

| Bits | Values | Feels like |
|---|---|---|
| 1 | 2 | a coin |
| 8 | 256 | one byte |
| 16 | 65,536 | a small lookup table |
| 32 | ~4.3 billion | IPv4 address space |
| 64 | ~1.8 × 10¹⁹ | a very big number |
| 128 | ~3.4 × 10³⁸ | **unguessable, forever** |
| 256 | ~1.2 × 10⁷⁷ | more than atoms in the observable universe |

That table is the foundation of every "is this secure?" argument in this book. When
[B03](B03-randomness.md) says a session ID needs 128 bits of entropy, this row is why.
Nobody brute-forces 2¹²⁸ — not with all the computers, not with all the time.

The intuition worth building: **each extra bit doubles the work.** 128 bits is not twice
as hard as 64. It is 18 quintillion times as hard.

---

## Bytes

A **byte** is eight bits, so it holds a number from 0 to 255.

```
  binary:  0 1 0 0 1 0 0 0
  place:  128 64 32 16 8 4 2 1
  value:      64    + 8       = 72
```

72 is the byte. What it *means* depends entirely on how you interpret it — the number 72,
the letter `H`, a shade of grey, a machine instruction. **The byte does not know.**
Interpretation lives in the code, never in the data.

This is not philosophy. It is the reason "encoding is not encryption"
([B02](B02-encoding-is-not-encryption.md)), the reason type confusion bugs exist, and the
reason a hash function can hash a photograph and a password with the same code.

---

## Text becomes numbers

### ASCII: the 1960s answer

A table mapping 128 characters to the numbers 0–127.

```
  65 → A      97 → a       48 → 0      32 → (space)
  66 → B      98 → b       49 → 1      33 → !
```

Three things fall out of that layout, all of which you will use:

- **Uppercase and lowercase differ by exactly 32** (one bit — the 6th). `A` is `0100 0001`,
  `a` is `0110 0001`. That is why `c ^ 32` toggles case, and why case-insensitive
  comparison used to be a bit mask.
- **Digits start at 48**, so `'7' - '0' = 7`.
- **128 characters is nowhere near enough.** No `é`, no `日`, no emoji.

`HELLO` in ASCII:

```
 H     E     L     L     O
 72    69    76    76    79
 0x48  0x45  0x4C  0x4C  0x4F
```

### Unicode: the number for every character

**Unicode** assigns every character in every writing system a number called a **code
point**, written `U+XXXX`:

```
U+0041  A
U+00E9  é
U+65E5  日
U+1F600 😀
```

About 150,000 assigned, with room for 1.1 million. Unicode says *which number*. It does
not say *how to store it*. That is a separate decision, and a consequential one.

### UTF-8: how code points become bytes

**UTF-8** is the encoding the web settled on, and it won for a good reason: ASCII text is
byte-identical in UTF-8. Every existing ASCII file was already a valid UTF-8 file.

It is variable-width — 1 to 4 bytes per code point:

| Code point range | Bytes | Pattern |
|---|---|---|
| U+0000 – U+007F | 1 | `0xxxxxxx` |
| U+0080 – U+07FF | 2 | `110xxxxx 10xxxxxx` |
| U+0800 – U+FFFF | 3 | `1110xxxx 10xxxxxx 10xxxxxx` |
| U+10000 – U+10FFFF | 4 | `11110xxx 10xxxxxx 10xxxxxx 10xxxxxx` |

```
 A   U+0041   → 41                 1 byte
 é   U+00E9   → C3 A9              2 bytes
 日  U+65E5   → E6 97 A5           3 bytes
 😀  U+1F600  → F0 9F 98 80        4 bytes
```

Note that the leading byte announces the length, and continuation bytes all start `10`.
That self-synchronising design means you can find a character boundary from anywhere in
the stream — which is why UTF-8 is robust to truncation in a way UTF-16 is not.

### The consequence: a "character" is not a byte

```python
>>> s = "café"
>>> len(s)                    # 4 characters
4
>>> len(s.encode("utf-8"))    # 5 bytes
5
```

Four sharp edges follow, and every one of them shows up in authentication:

**1. Length limits are ambiguous.** "Maximum 72 characters" and "maximum 72 bytes" are
different rules. **bcrypt truncates at 72 *bytes*** ([B08](B08-salts-peppers-slow-hashes.md)).
A password of 40 emoji is 160 bytes; bcrypt silently ignores everything past 72, and the
user has a much weaker password than they think.

**2. Truncation can produce invalid data.** Cutting a UTF-8 string at a byte boundary can
split a character in half. Databases with byte-limited columns do this silently.

**3. Comparison depends on normalisation.** The `café` bug at the top. Unicode defines
normalisation forms — **NFC** (composed) and **NFD** (decomposed) — and you must pick one
and apply it consistently before hashing or comparing.

> **The rule:** normalise to **NFC** at the boundary — on registration, on login, on any
> comparison. Store normalised. NIST SP 800-63B explicitly requires normalisation of
> Unicode passwords ([D04](../track-d/D04-password-policies.md)).

**4. Different characters can look identical.** `а` (U+0430, Cyrillic) renders the same as
`a` (U+0061, Latin) in most fonts. `аdmin@example.com` is not `admin@example.com`. These
are **homoglyphs**, and they are an account-takeover technique
([D02](../track-d/D02-email-as-identity.md)).

---

## Why cryptography only sees bytes

Every function in Track B takes bytes and returns bytes. Not strings. Not "text."

```
"password"  ──encode UTF-8──>  [70 61 73 73 77 6F 72 64]  ──SHA-256──>  [32 bytes]
```

The encode step is not a formality. It is a **decision that changes the output**. Hash the
UTF-8 bytes of `café` and the UTF-16 bytes of `café`, and you get two unrelated digests.

Which produces the most common category of "why doesn't my HMAC match?" bug — where two
systems agree on the algorithm, agree on the key, and disagree on how a string became
bytes. You will meet this for real in [B13](B13-message-authentication-hmac.md) and
[J06](../track-j/J06-signing-webhooks.md), where the fix is: **verify over the raw bytes
you received, never over a re-serialised parse.**

### The checklist

Whenever you feed data to a cryptographic function:

1. **What encoding?** UTF-8 unless you have a specific reason.
2. **What normalisation?** NFC for anything a human typed.
3. **Are both sides doing the same thing?** This is where interoperability dies.
4. **Am I hashing the bytes I received, or bytes I regenerated?** For signature
   verification the answer must always be *received*.

---

## Small exercise: see the bytes

```python
for s in ["A", "café", "café", "日本", "😀"]:   # note: two different "café"s
    b = s.encode("utf-8")
    print(f"{s!r:12} chars={len(s):2}  bytes={len(b):2}  {b.hex(' ')}")
```

```
'A'          chars= 1  bytes= 1  41
'café'       chars= 4  bytes= 5  63 61 66 c3 a9        ← NFC: é is one code point
'café'       chars= 5  bytes= 6  63 61 66 65 cc 81     ← NFD: e + combining accent
'日本'        chars= 2  bytes= 6  e6 97 a5 e6 9c ac
'😀'          chars= 1  bytes= 4  f0 9f 98 80
```

Rows two and three are the bug from the top of the chapter, made visible. They render
identically. `s1 == s2` is `False`. Their SHA-256 digests share nothing.

Now fix it:

```python
import unicodedata
a = unicodedata.normalize("NFC", "café")   # composed
b = unicodedata.normalize("NFC", "café")   # decomposed input, composed output
assert a == b                              # ✅ now they match
```

One line. Add it wherever a human-typed string meets a cryptographic function.

---

## Terms defined in this chapter

`bit`, `byte`, `binary`, `ASCII`, `Unicode`, `UTF-8`, `code point`

---

## What to remember

1. **Everything is bytes.** Meaning lives in the interpretation, never in the data.
2. Each bit doubles the search space. 128 bits is the practical line for "unguessable."
3. A character is not a byte. UTF-8 is 1–4 bytes per code point, and ASCII is a subset.
4. **Normalise to NFC** before hashing or comparing anything a human typed.
5. bcrypt's 72-*byte* limit is a real trap for non-ASCII passwords.
6. Two systems that agree on the algorithm and disagree on the encoding will never
   interoperate. Most "signature mismatch" bugs are this.

---

## Sources

- [The Unicode Standard](https://www.unicode.org/versions/latest/) — Ch. 2 (general structure), Ch. 3 (conformance, normalisation)
- Joel Spolsky, [*The Absolute Minimum Every Software Developer Must Know About Unicode*](https://www.joelonsoftware.com/2003/10/08/the-absolute-minimum-every-software-developer-absolutely-positively-must-know-about-unicode-and-character-sets-no-excuses/)
- [NIST SP 800-63B-4](https://csrc.nist.gov/pubs/sp/800/63/b/4/final) §3.1.1 (Unicode normalisation for passwords)

---

**Next:** [B02 — Encoding is not encryption: base64, hex, URL encoding](B02-encoding-is-not-encryption.md)
