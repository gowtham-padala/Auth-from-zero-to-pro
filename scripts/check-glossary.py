#!/usr/bin/env python3
"""Enforce the no-undefined-terms rule.

GLOSSARY.md is a ledger of rows `| term | definition | defined in | first used in |`.
Chapters live in book/track-*/<ID>-<slug>.adoc and are ordered by ID (track letter,
then number). A term may appear in a chapter only if the chapter that defines it comes
at or before that chapter in the order.

By default only chapters whose header carries `:status: final` are checked, so the
migrated drafts do not fail the build while they wait to be rewritten. Pass --all to
check every chapter.

Exit status: 0 clean, 1 violations or ledger errors, 2 usage error.
"""
from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

CHAPTER_ID = re.compile(r"^([A-K])(\d{2})(?:-|$)")
ROW = re.compile(r"^\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*([A-K]\d{2}|—|-)\s*\|\s*([A-K]\d{2}|—|-)\s*\|\s*$")
STATUS = re.compile(r"^:status:\s*(\w+)\s*$", re.M)
IGNORE = re.compile(r"^:glossary-ignore:\s*(.+?)\s*$", re.M)


@dataclass
class Term:
    name: str
    defined_in: str
    first_used_in: str
    line: int


@dataclass
class Chapter:
    id: str
    path: Path
    status: str
    ignore: set[str] = field(default_factory=set)


def order_key(chapter_id: str) -> tuple[str, int]:
    m = CHAPTER_ID.match(chapter_id)
    if not m:
        raise ValueError(f"not a chapter id: {chapter_id!r}")
    return (m.group(1), int(m.group(2)))


def parse_glossary(path: Path) -> tuple[list[Term], list[str]]:
    terms: list[Term] = []
    errors: list[str] = []
    seen: dict[str, int] = {}
    for n, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        m = ROW.match(raw)
        if not m:
            continue
        name = m.group(1).strip().strip("`").strip()
        if name.lower() in ("term",) or set(name) <= set("-: "):
            continue
        defined_in, first_used = m.group(3), m.group(4)
        if defined_in in ("—", "-"):
            continue
        key = name.lower()
        if key in seen:
            errors.append(f"{path}:{n}: duplicate headword {name!r} (also line {seen[key]})")
            continue
        seen[key] = n
        if first_used not in ("—", "-") and order_key(first_used) < order_key(defined_in):
            errors.append(
                f"{path}:{n}: {name!r} is first used in {first_used} but defined in "
                f"{defined_in}, which comes later"
            )
        terms.append(Term(name, defined_in, first_used, n))
    return terms, errors


def find_chapters(book: Path) -> list[Chapter]:
    chapters = []
    for p in sorted(book.glob("track-*/*.adoc")):
        m = CHAPTER_ID.match(p.name)
        if not m:
            continue
        text = p.read_text(encoding="utf-8")
        s = STATUS.search(text)
        ig = IGNORE.search(text)
        ignore = {t.strip().lower() for t in ig.group(1).split(",")} if ig else set()
        chapters.append(Chapter(m.group(1) + m.group(2), p, s.group(1) if s else "draft", ignore))
    chapters.sort(key=lambda c: order_key(c.id))
    return chapters


def prose_lines(text: str) -> list[tuple[int, str]]:
    """Return (line_number, text) for lines that count as prose.

    Drops listing/literal/comment blocks, single-line comments, attribute entries,
    include and image macros, block attribute lines and anchors. Keeps example and
    sidebar blocks, because those are prose. Inline code spans are kept, since a term
    in backticks is still a use of the term.
    """
    out: list[tuple[int, str]] = []
    fence: str | None = None
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if fence:
            if stripped == fence:
                fence = None
            continue
        if stripped in ("----", "....", "////", "++++", "```"):
            fence = stripped
            continue
        if stripped.startswith(("//", ":", "include::", "image::", "mermaid::", "[[", "[")):
            if stripped.startswith("[") and not stripped.endswith("]"):
                pass  # a line that merely starts with a bracket is prose
            else:
                continue
        # xref targets and link URLs are not prose; keep their display text.
        line = re.sub(r"<<([^,>]+),([^>]*)>>", r"\2", line)
        line = re.sub(r"<<([^>]+)>>", "", line)
        line = re.sub(r"(?:link|xref|https?):[^\[\s]+\[([^\]]*)\]", r"\1", line)
        out.append((n, line))
    return out


def term_pattern(name: str) -> re.Pattern[str]:
    escaped = re.escape(name).replace(r"\ ", r"[\s-]+")
    body = rf"(?<![\w-]){escaped}(?:e?s)?(?![\w-])"
    acronym = name.isupper() and len(name) <= 8
    return re.compile(body if acronym else body, 0 if acronym else re.I)


def check(glossary: Path, book: Path, include_all: bool, only: list[Path] | None = None) -> list[str]:
    terms, errors = parse_glossary(glossary)
    chapters = find_chapters(book)
    ids = {c.id for c in chapters}
    for t in terms:
        if t.defined_in not in ids:
            errors.append(f"{glossary}:{t.line}: {t.name!r} is defined in {t.defined_in}, which has no chapter file")
    selected = [c for c in chapters if include_all or c.status == "final"]
    if only:
        wanted = {p.resolve() for p in only}
        selected = [c for c in selected if c.path.resolve() in wanted]
    patterns = [(t, term_pattern(t.name)) for t in terms]
    for ch in selected:
        text = ch.path.read_text(encoding="utf-8")
        here = order_key(ch.id)
        later = [
            (t, pat)
            for t, pat in patterns
            if order_key(t.defined_in) > here and t.name.lower() not in ch.ignore
        ]
        if not later:
            continue
        for n, line in prose_lines(text):
            for t, pat in later:
                if pat.search(line):
                    errors.append(
                        f"{ch.path}:{n}: {t.name!r} used before it is defined (defined in {t.defined_in})"
                    )
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--glossary", default="GLOSSARY.md", type=Path)
    ap.add_argument("--book", default="book", type=Path)
    ap.add_argument("--all", action="store_true", help="check drafts too, not only :status: final")
    ap.add_argument("files", nargs="*", type=Path, help="restrict to these chapter files")
    args = ap.parse_args(argv)
    if not args.glossary.exists() or not args.book.is_dir():
        print("glossary or book directory not found", file=sys.stderr)
        return 2
    errors = check(args.glossary, args.book, args.all, args.files or None)
    for e in errors:
        print(e)
    if errors:
        print(f"\n{len(errors)} glossary violation(s)", file=sys.stderr)
        return 1
    print("glossary check: clean")
    return 0


if __name__ == "__main__":
    sys.exit(main())
