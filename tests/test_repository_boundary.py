"""Exercise actual publication failures, including force-added indexed files."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("boundary", Path(__file__).resolve().parents[1] / "scripts/check_repository.py")
boundary = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(boundary)


class PathTests(unittest.TestCase):
    def test_allowed_roles(self):
        for name in ("src/aegis/metrics.py", "tests/test_metrics.py", "tests/fixtures/case.json",
                     "config/run.example.toml", "rules/example.yar", "docs/TESTING.md"):
            with self.subTest(name=name):
                self.assertTrue(boundary.allowed_path(name))

    def test_local_and_unapproved_material(self):
        for name in ("private/note.md", "Kursinis/main.tex", "docs/meeting.md", "docs/draft.pdf",
                     "tests/fixtures/sample.exe", "config/run.toml", "src/data/item.py",
                     "src/.env", "src/__pycache__/item.py", "src/../README.md", "src\\a.py"):
            with self.subTest(name=name):
                self.assertFalse(boundary.allowed_path(name))


class ContentTests(unittest.TestCase):
    def test_ordinary_code(self):
        self.assertEqual([], boundary.inspect_content("src/metrics.py", b"def rate(a, b):\n    return a / b\n"))

    def test_secret_patterns(self):
        cases = [b"gh" + b"p_" + b"a" * 36,
                 b"-----BEGIN " + b"PRIVATE KEY-----\n",
                 b"api_key = '" + b"a" * 32 + b"'",
                 b"person" + b"@gmail.com",
                 ("/" + "Users" + "/someone/project").encode()]
        for content in cases:
            with self.subTest(content_length=len(content)):
                self.assertTrue(boundary.inspect_content("src/code.py", content))

    def test_binary_and_oversized_content(self):
        for content in (b"M" + b"Zpayload", b"data\x00data", b"\xff", b"x" * (boundary.MAX_BYTES + 1)):
            self.assertTrue(boundary.inspect_content("tests/fixtures/case.txt", content))


class GitIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.original_root = boundary.ROOT
        boundary.ROOT = self.root
        self.run_git("init", "-q")
        ignore = Path(__file__).resolve().parents[1] / ".gitignore"
        (self.root / ".gitignore").write_text(ignore.read_text())

    def tearDown(self):
        boundary.ROOT = self.original_root
        self.temp.cleanup()

    def run_git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.root), *args], stderr=subprocess.PIPE)

    def stage(self, name, content):
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(content)
        self.run_git("add", "-f", "--", name)

    def check(self):
        return boundary.check_entries(boundary.index_entries(), {})[0]

    def test_force_added_note_is_rejected(self):
        self.stage("private/note.md", b"local note\n")
        self.assertTrue(self.check())

    def test_gitignore_blocks_unapproved_files(self):
        for name in ("private/note.md", "docs/draft.md", "src/private/code.py",
                     "config/local.toml", "tests/fixtures/sample.exe", "unexpected.txt"):
            with self.subTest(name=name):
                self.assertEqual(name, self.run_git("check-ignore", "--no-index", name).decode().strip())

    def test_gitignore_admits_expected_code_and_examples(self):
        for name in ("src/aegis/main.py", "tests/test_case.py", "tests/fixtures/case.json",
                     "config/run.example.toml", "docs/TESTING.md", "rules/test.yar"):
            result = subprocess.run(["git", "-C", str(self.root), "check-ignore", "--no-index", name],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            with self.subTest(name=name):
                self.assertEqual(1, result.returncode)

    def test_staged_blob_is_checked_instead_of_clean_working_copy(self):
        self.stage("src/code.py", b"gh" + b"p_" + b"x" * 36)
        (self.root / "src/code.py").write_text("print('clean')\n")
        self.assertTrue(self.check())

    def test_symlink_is_rejected(self):
        (self.root / "source.txt").write_text("synthetic\n")
        (self.root / "src").mkdir()
        (self.root / "src/link.py").symlink_to("../source.txt")
        self.run_git("add", "src/link.py")
        self.assertTrue(self.check())

    def test_historical_disallowed_file_remains_detectable(self):
        self.stage("private/note.md", b"local note\n")
        self.run_git("-c", "user.name=Test", "-c", "user.email=test@example.org", "commit", "-qm", "fixture")
        self.run_git("rm", "-q", "private/note.md")
        self.stage("README.md", b"synthetic fixture\n")
        self.run_git("-c", "user.name=Test", "-c", "user.email=test@example.org", "commit", "-qm", "remove fixture")
        errors, _ = boundary.check_entries(boundary.tree_entries("HEAD~1"), {})
        self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
