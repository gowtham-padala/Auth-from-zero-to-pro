#!/usr/bin/env python3
"""List chapter files, optionally filtered by :status:. Used by the Makefile."""
import argparse, re, sys
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("--status", help="only chapters with this :status: (draft is the default when unset)")
ap.add_argument("--book", default="book", type=Path)
a = ap.parse_args()
for p in sorted(a.book.glob("track-*/*.adoc")):
    m = re.search(r"^:status:\s*(\w+)", p.read_text(encoding="utf-8"), re.M)
    status = m.group(1) if m else "draft"
    if a.status is None or status == a.status:
        print(p)
