# Auth: From Zero to Pro

## What this project is

A technical handbook on authentication and authorization, written to the
standard of *Designing Data-Intensive Applications* or *Release It!*. Not a
tutorial site, not a blog, not a docs portal. A book.

It also publishes as a website, from the same source.

Existing draft content lives in this repo and is being converted. Treat all
existing content as a rough draft to be rewritten to the voice spec below, not
as finished prose to preserve.

## The reader

Assumed knowledge: they can write code. That is all.

They do not know what a hash is, what a cookie is, what encryption is, what
HMAC is, or what a JWT is. Every one of those is taught from zero, in order,
before it is used.

## Hard rules

These are build failures, not preferences.

1. **No undefined terms.** A term may appear only if defined in an earlier
   chapter, or defined in-line at first use. `GLOSSARY.md` is the ledger.
   `scripts/check-glossary.py` enforces it in CI.

2. **Mechanism and recommendation are physically separate.** Mechanism prose
   contains no version numbers, no product names, no parameter values, no
   "currently recommended". Recommendations go in tagged, dated blocks that
   generate into a dated appendix. This is what keeps the book from rotting.

3. **No code pasted into prose.** All code lives in `/app` and is pulled in with
   tagged includes. CI runs the app's tests. If the code breaks, the book does
   not build.

4. **Every layer ends with an attack chapter** where the reader breaks the thing
   they built two chapters earlier.

5. **Never state a security claim without a verifiable source.** Cite the RFC
   section, the NIST publication, or the paper. If you cannot cite it, flag it
   `TODO(verify)` and move on. Do not write it confidently.

## Voice specification

This is the most important section. Default LLM technical prose reads like a
blog post. This book must not.

**Structure of every chapter:**

1. **The problem.** Open with a concrete scenario that breaks. Never open with
   a definition. Never "X is a protocol that...". The reader should feel the
   need before they learn the name.
2. **The mechanism.** Build it up incrementally. Show the naive version failing
   before showing the correct version.
3. **Getting it wrong.** The real failure mode, with a named attack.
4. **Getting it right.** The recommendation, in a dated block.
5. **Tradeoffs and when not to.** Every design decision has a cost. State it.
6. **Summary.** What was established, in prose. Not a bullet recap.
7. **References.** RFCs, papers, specs, with section numbers.

**Prose rules:**

- Concrete numbers, never adjectives. Not "hashing is slow" but "argon2id at
  these parameters takes roughly 250ms per verification".
- Name every tradeoff explicitly. A chapter with no stated cost is incomplete.
- Historical context only where it explains a design. Why OAuth looks the way it
  does is worth a paragraph. Trivia is not.
- Cross-reference constantly, in both directions. "As we saw in Chapter 4" and
  "we return to this in Chapter 17". This is what makes a book feel like a book
  rather than a stack of posts.
- Sidebars for tangents, so the main line stays clean.
- Short sentences. Plain words. A knowledgeable person talking, not a document
  performing authority.

**Banned:**

- Em-dash asides used as a rhetorical tic.
- "Not just X, but Y" constructions.
- Colon-then-reveal sentences.
- The words: leverage, utilize, robust, powerful, seamless, delve, crucial,
  essential, landscape, realm, journey, unlock, empower.
- Emoji, exclamation marks, rhetorical questions as headings.
- "In this chapter we will learn..." Just start.
- Bullet lists where prose would carry the argument better. Default to prose.
  Lists are for genuinely enumerable things.
- Any sentence that could appear in a vendor's marketing page.

## Toolchain

- **AsciiDoc**, built with Asciidoctor. One file per chapter in `/book`.
- `asciidoctor-pdf` and `asciidoctor-epub3` for output.
- **Mermaid** for diagram source, in `/diagrams`, rendered at build.
- **Vale** for prose linting, with the banned-word list above as a custom rule.
- Conditional attributes (`ifdef::book[]` / `ifdef::web[]`) so one source
  produces the print book and the website.
- Make targets: `make book`, `make web`, `make check`, `make all`.

## Repo layout

```
/book          chapter .adoc files, numbered by track
/app           the running document-sharing application
/diagrams      mermaid source
/scripts       glossary checker, build helpers
/site          web output
GLOSSARY.md    the term ledger
CURRICULUM.md  the full chapter plan
```

## Workflow

- Work on one chapter at a time. Never batch-generate chapters.
- Every chapter starts as an outline for the author to approve before prose.
- Commit per chapter, conventional commit messages.
- Open a PR for each chapter so reviewers can comment inline.

## What you do not decide

Security recommendations. Surface the options and the sources; the author
chooses. If you believe a draft claim is wrong, say so and cite why. Do not
silently correct it.
