#!/usr/bin/env python3
"""One-time migration: convert book/track-*/*.md drafts to AsciiDoc.

Converted, not rewritten. Each chapter gets a stable anchor, an ID-prefixed title,
`:status: draft`, and `:builds-on:` extracted from the draft's subtitle line. Links to
other chapters become <<ID,label>> xrefs. The markdown originals are removed with
`git rm` so history keeps them.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ID_RE = re.compile(r"^([A-K]\d{2})-")
CHAPTER_LINK = re.compile(r"xref:(?:\.\./track-[a-k]/)?([A-K]\d{2})-[^\[\]/]*?\.adoc\[([^\]]*)\]")
OTHER_ADOC_LINK = re.compile(r"xref:((?:\.\./)*(?:[\w-]+/)*[\w-]+)\.adoc\[")
BUILDS_ON = re.compile(r"^== \*Part [A-K][^*]*\*(?: · _Builds on (.*)_)?\s*$")
TITLE = re.compile(r"^= ([A-K]\d{2}) -- (.*)$")


def convert(md: Path) -> Path:
    cid = ID_RE.match(md.name).group(1)
    out = md.with_suffix(".adoc")
    subprocess.run(["bundle", "exec", "kramdoc", "-o", str(out), str(md)], check=True, cwd=ROOT)
    lines = out.read_text(encoding="utf-8").splitlines()

    title = None
    builds_on = ""
    body: list[str] = []
    for line in lines:
        m = TITLE.match(line)
        if m and title is None:
            title = m.group(2).strip()
            continue
        m = BUILDS_ON.match(line)
        if m:
            builds_on = ", ".join(re.findall(r"\[([A-K]\d{2})\]", m.group(1) or ""))
            continue
        if line.startswith("*Next:*"):
            continue
        body.append(line)
    if title is None:
        title = lines[0].lstrip("= ").strip()

    text = "\n".join(body)
    text = CHAPTER_LINK.sub(lambda m: f"<<{m.group(1)},{m.group(2)}>>", text)
    text = OTHER_ADOC_LINK.sub(lambda m: f"link:{m.group(1)}.md[", text)
    text = re.sub(r"\n{3,}", "\n\n", text).strip() + "\n"

    header = [f"[[{cid}]]", f"= {cid}. {title}", ":status: draft", f":chapter-id: {cid}"]
    if builds_on:
        header.append(f":builds-on: {builds_on}")
    out.write_text("\n".join(header) + "\n\n" + text, encoding="utf-8")
    return out


def main() -> int:
    mds = sorted((ROOT / "book").glob("track-*/*.md"))
    if not mds:
        print("nothing to migrate")
        return 0
    for md in mds:
        convert(md)
        print(f"{md.relative_to(ROOT)} -> .adoc")
    subprocess.run(["git", "rm", "-q", *[str(m) for m in mds]], check=True, cwd=ROOT)
    print(f"migrated {len(mds)} chapters")
    return 0


if __name__ == "__main__":
    sys.exit(main())
