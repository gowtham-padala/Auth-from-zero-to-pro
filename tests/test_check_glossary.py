import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_glossary", ROOT / "scripts" / "check-glossary.py")
cg = importlib.util.module_from_spec(spec)
sys.modules["check_glossary"] = cg  # dataclasses resolve annotations via sys.modules
spec.loader.exec_module(cg)

GLOSSARY = """# ledger
| Term | Plain-language definition | Defined in | First used in |
|---|---|---|---|
| cookie | A small string. | A06 | A06 |
| `HMAC` | Keyed hash. | B13 | B13 |
| JWT | A token. | E05 | E05 |
| key | A secret value. | B05 | B05 |
"""


def write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def chapter(cid: str, body: str, status: str = "final", ignore: str | None = None) -> str:
    extra = f":glossary-ignore: {ignore}\n" if ignore else ""
    return f"[[{cid}]]\n= {cid}. Title\n:status: {status}\n{extra}\n{body}\n"


class CheckGlossaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        write(self.root, "GLOSSARY.md", GLOSSARY)
        # every defined_in chapter must exist
        for cid in ("A05", "A06", "B05", "B13", "E05"):
            write(self.root, f"book/track-{cid[0].lower()}/{cid}-x.adoc", chapter(cid, "Plain prose.", "draft"))

    def tearDown(self):
        self.tmp.cleanup()

    def run_check(self, include_all=False):
        return cg.check(self.root / "GLOSSARY.md", self.root / "book", include_all)

    def test_term_used_before_definition_fails(self):
        write(self.root, "book/track-a/A05-x.adoc", chapter("A05", "The server sets a cookie here."))
        errs = self.run_check()
        self.assertEqual(len(errs), 1)
        self.assertIn("'cookie' used before it is defined (defined in A06)", errs[0])
        self.assertIn("A05-x.adoc:5", errs[0])

    def test_term_used_in_defining_or_later_chapter_passes(self):
        write(self.root, "book/track-a/A06-x.adoc", chapter("A06", "A cookie is a small string."))
        write(self.root, "book/track-e/E05-x.adoc", chapter("E05", "A JWT rides in a cookie, protected by an HMAC."))
        self.assertEqual(self.run_check(), [])

    def test_drafts_are_skipped_unless_all(self):
        write(self.root, "book/track-a/A05-x.adoc", chapter("A05", "Set a cookie.", status="draft"))
        self.assertEqual(self.run_check(), [])
        self.assertEqual(len(self.run_check(include_all=True)), 1)

    def test_code_blocks_and_comments_are_ignored(self):
        body = "Prose.\n\n[source,python]\n----\ncookie = 1\n----\n\n// a cookie in a comment\n\n....\ncookie\n....\n"
        write(self.root, "book/track-a/A05-x.adoc", chapter("A05", body))
        self.assertEqual(self.run_check(), [])

    def test_inline_code_counts_as_use(self):
        write(self.root, "book/track-a/A05-x.adoc", chapter("A05", "Read the `cookie` header."))
        self.assertEqual(len(self.run_check()), 1)

    def test_plural_matches(self):
        write(self.root, "book/track-a/A05-x.adoc", chapter("A05", "Browsers store cookies."))
        self.assertEqual(len(self.run_check()), 1)

    def test_acronyms_are_case_sensitive(self):
        write(self.root, "book/track-b/B05-x.adoc", chapter("B05", "Use hmac, the lower-case word, freely here."))
        self.assertEqual(self.run_check(), [])
        write(self.root, "book/track-b/B05-x.adoc", chapter("B05", "An HMAC tag."))
        self.assertEqual(len(self.run_check()), 1)

    def test_ignore_attribute_suppresses_false_positive(self):
        write(self.root, "book/track-a/A05-x.adoc", chapter("A05", "The key point is speed.", ignore="key"))
        self.assertEqual(self.run_check(), [])

    def test_duplicate_headword_is_a_ledger_error(self):
        write(self.root, "GLOSSARY.md", GLOSSARY + "| Cookie | again | A06 | A06 |\n")
        errs = self.run_check()
        self.assertTrue(any("duplicate headword" in e for e in errs))

    def test_first_used_before_defined_is_a_ledger_error(self):
        write(self.root, "GLOSSARY.md", GLOSSARY + "| nonce | A number. | B13 | A05 |\n")
        errs = self.run_check()
        self.assertTrue(any("first used in A05 but defined in B13" in e for e in errs))

    def test_defined_in_missing_chapter_is_an_error(self):
        write(self.root, "GLOSSARY.md", GLOSSARY + "| ghost | Boo. | K09 | K09 |\n")
        errs = self.run_check()
        self.assertTrue(any("has no chapter file" in e for e in errs))

    def test_xref_targets_are_not_prose(self):
        write(self.root, "book/track-a/A05-x.adoc", chapter("A05", "See <<E05,later>> and xref:E05-x.adoc[later]."))
        self.assertEqual(self.run_check(), [])

    def test_order_key(self):
        self.assertLess(cg.order_key("B13"), cg.order_key("E05"))
        self.assertLess(cg.order_key("A09"), cg.order_key("A10"))


if __name__ == "__main__":
    unittest.main()
