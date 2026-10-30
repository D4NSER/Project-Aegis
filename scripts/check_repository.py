"""Validate the exact Git index and, optionally, every committed tree."""
import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 256 * 1024
EXACT_PATHS = {
    ".gitignore", ".gitattributes", "README.md", "pyproject.toml",
    "requirements.txt", "docs/TESTING.md", ".githooks/pre-commit", ".githooks/pre-push",
    ".github/workflows/repository-checks.yml", "src/.gitkeep",
    "src/mac_app.m", "src/desktop_ui/index.html", "src/desktop_ui/app.css", "src/desktop_ui/app.js",
    "config/.gitkeep", "rules/.gitkeep", "tests/fixtures/.gitkeep",
}
BLOCKED_PARTS = {
    "private", "internal", "notes", "archive", "archives", "backups",
    "literature", "thesis", "data", "datasets", "samples", "payloads",
    "results", "logs", "reports", "prompts", "transcripts", "tmp",
    "__pycache__", "node_modules", "venv",
}
SECRET_PATTERNS = (
    (re.compile(rb"(?m)^-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"), "private key"),
    (re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b"), "GitHub credential"),
    (re.compile(rb"\bgithub_pat_[A-Za-z0-9_]{50,}\b"), "GitHub credential"),
    (re.compile(rb"\bAKIA[A-Z0-9]{16}\b"), "cloud credential"),
    (re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{24,}\b"), "API credential"),
    (re.compile(rb"(?i)\b(?:api[_-]?key|access[_-]?token|password|secret)\s*[:=]\s*[\"'][A-Za-z0-9_+/=-]{16,}[\"']"), "literal credential assignment"),
    (re.compile(re.escape(("/" + "Users" + "/").encode()) + rb"[^/\s\"'<>]+/"), "personal machine path"),
    (re.compile(re.escape(("C:" + "\\" + "Users" + "\\").encode()) + rb"[^\\\s\"'<>]+\\"), "personal machine path"),
    (re.compile(rb"(?i)\b[A-Z0-9._%+-]+@(?:gmail|outlook|hotmail|icloud|yahoo)\.[A-Z]{2,}\b"), "personal email address"),
)


def allowed_path(name):
    if name.startswith("/") or "\\" in name or any(p in {"", ".", ".."} for p in name.split("/")):
        return False
    if name in EXACT_PATHS:
        return True
    parts = PurePosixPath(name).parts
    if any(p.startswith(".") or p.casefold() in BLOCKED_PARTS for p in parts):
        return False
    suffix = PurePosixPath(name).suffix
    if parts[0] in {"src", "tests", "scripts"} and suffix == ".py":
        return True
    if name.startswith("tests/fixtures/") and suffix in {".json", ".csv", ".txt"}:
        return True
    if parts[0] == "config" and name.endswith((".example.toml", ".example.json")):
        return True
    return parts[0] == "rules" and suffix in {".yar", ".yara"}


def inspect_content(name, content):
    errors = []
    if len(content) > MAX_BYTES:
        return ["file exceeds 256 KiB"]
    if b"\x00" in content or content.startswith((b"MZ", b"\x7fELF")):
        return ["binary or executable content"]
    try:
        content.decode("utf-8")
    except UnicodeDecodeError:
        return ["file is not UTF-8 text"]
    for pattern, reason in SECRET_PATTERNS:
        if pattern.search(content):
            errors.append(reason)
    return errors


def git(*args):
    return subprocess.check_output(["git", "-C", str(ROOT), *args], stderr=subprocess.PIPE)


def index_entries():
    for entry in git("ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        metadata, path = entry.split(b"\t", 1)
        mode, oid, stage = metadata.decode("ascii").split()
        yield mode, oid, path.decode("utf-8"), stage


def tree_entries(commit):
    for entry in git("ls-tree", "-r", "-z", commit).split(b"\0"):
        if not entry:
            continue
        metadata, path = entry.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        yield mode, oid, path.decode("utf-8"), "0" if kind == "blob" else "unsupported"


def check_entries(entries, cache):
    errors = []
    count = 0
    for mode, oid, name, stage in entries:
        count += 1
        if not allowed_path(name):
            errors.append(name + ": path is outside the publication allowlist")
            continue
        if mode not in {"100644", "100755"} or stage != "0":
            errors.append(name + ": unsupported file type or unresolved index entry")
            continue
        if oid not in cache:
            size = int(git("cat-file", "-s", oid))
            cache[oid] = (["file exceeds 256 KiB"] if size > MAX_BYTES
                          else inspect_content(name, git("cat-file", "blob", oid)))
        errors.extend(name + ": " + reason for reason in cache[oid])
    if not count:
        errors.append("No files in the Git index/tree to validate")
    return errors, count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--history", action="store_true", help="also inspect all reachable committed trees")
    args = parser.parse_args(argv)
    try:
        cache = {}
        errors, count = check_entries(index_entries(), cache)
        commits = git("rev-list", "--all").decode("ascii").split() if args.history else []
        for commit in commits:
            past_errors, _ = check_entries(tree_entries(commit), cache)
            errors.extend(commit[:12] + ": " + error for error in past_errors)
    except (subprocess.CalledProcessError, UnicodeError, ValueError) as exc:
        print("Repository check could not complete: " + type(exc).__name__, file=sys.stderr)
        return 2
    if errors:
        for error in sorted(set(errors)):
            print(error, file=sys.stderr)
        return 1
    print("Repository boundary passed: {} indexed files, {} committed trees.".format(count, len(commits)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
