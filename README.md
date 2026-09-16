# Auth: From Zero to Pro

A technical handbook on authentication and authorization, written for people who can
write code and know nothing else about the subject. It teaches from bytes and hashes up
to federated identity, fine-grained authorization, and machine and agent identity, in
dependency order, with one document-sharing application running through the whole book.

The book is being rewritten chapter by chapter from an earlier draft. `CURRICULUM.md`
lists every chapter and its status. `CLAUDE.md` holds the voice specification and the
hard rules that the build enforces. A chapter marked `final` has been rewritten to that
standard; a chapter marked `draft` is the old text, converted but not yet rewritten.

## Building

Requires Ruby with Bundler, Node 20 (for diagram rendering), Python 3, and
[Vale](https://vale.sh).

```
bundle install
npm install
make check     # tests, glossary gate, prose lint, generated files
make web       # site/index.html
make book      # build/auth-from-zero-to-pro.pdf and .epub
make all
```

One source, two outputs. `ifdef::web[]` and `ifdef::book[]` blocks in the AsciiDoc
select edition-specific text.

## Layout

```
book/           one .adoc per chapter, in book/track-a … track-k; book.adoc is the master
book/preface.adoc
book/appendix-recommendations.adoc   generated: every dated recommendation, by date
diagrams/       Mermaid sources, rendered at build
scripts/        check-glossary.py (the no-undefined-terms gate), build-recommendations.py, chapters.py
tests/          tests for the scripts
app/            the running application (not yet created)
GLOSSARY.md     the term ledger: term, definition, defined in, first used in
CURRICULUM.md   the chapter plan and status
SOURCES.md, appendix/   reading list, RFC index, decision tree, scope boundary
```

## The rules the build enforces

- No term appears before the chapter that defines it. `scripts/check-glossary.py` reads
  `GLOSSARY.md`, walks the final chapters in order, and fails the build on a violation.
- Mechanism prose carries no version numbers, product names or parameter values. Those
  live in dated recommendation blocks, collected into an appendix by
  `scripts/build-recommendations.py`.
- Prose is linted by Vale against the banned-word list in `CLAUDE.md`.
- Code is not pasted into chapters. It lives in `/app`, is included by tag, and its tests
  run as part of `make check`.

## Reading the old draft

The previous single-page reader (`index.html`, built by `tools/build-reader.py`) is
kept until the web build replaces it on GitHub Pages. It renders the pre-rewrite draft.
