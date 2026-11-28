"""The generation attempts log: every started attempt stays, whatever its outcome.

One record per attempt (one candidate of one original, or one rule for one
target), written once when the attempt ends. A record names the fixed setup
(template and settings hashes), its session, every turn with request and
response hashes and durations, the number of repairs (at most three), any
build-setting changes the researcher made, and the outcome:

code variants: REFUSED, COMPILE_FAIL, FUNC_FAIL, FUNC_INCONCLUSIVE, DUPLICATE,
               ACCEPTED (a session awaiting a manual response writes nothing
               until it ends and is then replayed from the stored answers);
rules:         REFUSED or a rule-acceptance decision status.

A variant is new only if its source differs from the original once comments
and whitespace are removed, and its file is a duplicate if its SHA-256 equals
the original's or an accepted variant's. The summary gives the per-outcome
counts, the share of usable variants and the cost figures (requests,
durations, failures) that the cost table is built from.
"""
from datetime import datetime, timezone
import difflib
import hashlib
import json
import math
from pathlib import Path
import re
import uuid

import aegis

MAX_REPAIRS = 3
CODE_OUTCOMES = {"REFUSED", "COMPILE_FAIL", "FUNC_FAIL", "FUNC_INCONCLUSIVE", "DUPLICATE", "ACCEPTED"}
TASKS = {"code_variant", "rule", "code_control", "rule_control"}
RECORD_FIELDS = {"schema", "kind", "attempt_id", "task", "subject", "candidate", "session_id", "setup_id",
                 "template_sha256", "settings_sha256", "model_id", "mode", "turns", "repairs",
                 "researcher_changes", "outcome", "reasons", "artifacts", "started_at_utc", "finished_at_utc"}
TURN_FIELDS = {"turn", "kind", "request_sha256", "response_sha256", "refused", "elapsed_seconds"}


def now():
    return datetime.now(timezone.utc).isoformat()


def strip_c(source):
    """C/C++ source without comments and whitespace; string and character literals are kept intact."""
    out, i, n = [], 0, len(source)
    while i < n:
        c = source[i]
        if c in "\"'":
            j = i + 1
            while j < n and source[j] != c:
                j += 2 if source[j] == "\\" else 1
            out.append(source[i:j + 1])
            i = j + 1
        elif source.startswith("//", i):
            while i < n and source[i] != "\n":
                i += 1
        elif source.startswith("/*", i):
            end = source.find("*/", i + 2)
            i = n if end < 0 else end + 2
        elif c.isspace():
            i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def changed_lines(original, variant):
    """Lines removed plus lines added between the two sources."""
    diff = difflib.ndiff(original.splitlines(), variant.splitlines())
    return sum(1 for line in diff if line[:2] in {"- ", "+ "})


def duplicate_reason(*, variant_source, original_source, binary_sha256, original_sha256, accepted_sha256s):
    """Why a candidate is not a new variant, or None."""
    if strip_c(variant_source) == strip_c(original_source):
        return "SOURCE_SAME_AS_ORIGINAL"
    if binary_sha256 == original_sha256:
        return "FILE_SAME_AS_ORIGINAL"
    if binary_sha256 in accepted_sha256s:
        return "FILE_SAME_AS_ACCEPTED_VARIANT"
    return None


class Attempt:
    """One attempt in progress; `finish` writes its record once."""

    def __init__(self, log, task, subject, candidate, setup, template_name):
        if task not in TASKS:
            raise ValueError("Unknown generation task: " + str(task))
        self.log = log
        self.record = {"schema": 1, "kind": "generation_attempt",
                       "attempt_id": "attempt-" + uuid.uuid4().hex[:12], "task": task, "subject": subject,
                       "candidate": candidate, "session_id": "session-" + uuid.uuid4().hex[:12],
                       "setup_id": setup["setup_id"], "template_sha256": setup["templates"][template_name],
                       "settings_sha256": setup["settings_sha256"], "model_id": setup["model_id"],
                       "mode": setup["mode"], "turns": [], "repairs": 0, "researcher_changes": [],
                       "outcome": None, "reasons": [], "artifacts": {}, "started_at_utc": now(),
                       "finished_at_utc": None}

    @property
    def session_id(self):
        return self.record["session_id"]

    def turn(self, kind, request_sha256, response, response_sha256):
        if kind == "repair":
            if self.record["repairs"] >= MAX_REPAIRS:
                raise ValueError("At most three repair requests per candidate")
            self.record["repairs"] += 1
        self.record["turns"].append({"turn": len(self.record["turns"]), "kind": kind,
                                     "request_sha256": request_sha256, "response_sha256": response_sha256,
                                     "refused": response["refused"], "elapsed_seconds": response["elapsed_seconds"]})

    def researcher_change(self, description):
        """Only build settings applied equally to the original and all its variants may change."""
        self.record["researcher_changes"].append({"at_utc": now(), "change": str(description)[:300]})

    def finish(self, outcome, reasons=(), **artifacts):
        if self.record["finished_at_utc"] is not None:
            raise ValueError("This attempt is already finished: " + self.record["attempt_id"])
        if self.record["task"] in {"code_variant", "code_control"} and outcome not in CODE_OUTCOMES:
            raise ValueError("Unknown code-variant outcome: " + str(outcome))
        self.record.update(outcome=outcome, reasons=list(reasons), artifacts=artifacts, finished_at_utc=now())
        return self.log.write(self.record)


class GenerationLog:
    def __init__(self, root, *, create=True):
        """`create=False` opens an existing log for reading; a missing folder is an error, not an empty log."""
        self.root = aegis.external_path(root)
        if create:
            self.root.mkdir(parents=True, exist_ok=True)
        elif not self.root.is_dir():
            raise ValueError("Attempts log not found: " + str(self.root))

    def start(self, task, subject, candidate, setup, template_name):
        return Attempt(self, task, subject, candidate, setup, template_name)

    def write(self, record):
        validate(record)
        # One record per attempt: a second record with the same attempt ID is refused.
        if list(self.root.glob("*-" + record["attempt_id"] + ".json")):
            raise ValueError("The attempt is already logged: " + record["attempt_id"])
        number = len(list(self.root.glob("*-attempt-*.json"))) + 1
        path = self.root / ("%03d-%s.json" % (number, record["attempt_id"]))
        with path.open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
        return record

    def records(self):
        values = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(self.root.glob("*-attempt-*.json"))]
        for value in values:
            validate(value)
        ids = [value["attempt_id"] for value in values]
        if len(ids) != len(set(ids)):
            raise ValueError("An attempt appears more than once in the log")
        return values

    def accepted_sha256s(self, subject):
        return {r["artifacts"].get("binary_sha256") for r in self.records()
                if r["task"] == "code_variant" and r["subject"] == subject and r["outcome"] == "ACCEPTED"}

    def candidates_used(self, task, subject):
        return {r["candidate"] for r in self.records() if r["task"] == task and r["subject"] == subject}


def validate(record):
    if (not isinstance(record, dict) or set(record) != RECORD_FIELDS or record["kind"] != "generation_attempt"
            or record["task"] not in TASKS or not isinstance(record["turns"], list) or not record["turns"]
            or type(record["repairs"]) is not int or not 0 <= record["repairs"] <= MAX_REPAIRS
            or not isinstance(record["outcome"], str) or not record["outcome"]):
        raise ValueError("Invalid generation attempt record")
    for turn in record["turns"]:
        if (set(turn) != TURN_FIELDS or not aegis.SHA256.fullmatch(str(turn["request_sha256"]))
                or (turn["response_sha256"] is not None and not aegis.SHA256.fullmatch(str(turn["response_sha256"])))
                or type(turn["refused"]) is not bool
                or type(turn["elapsed_seconds"]) not in (int, float) or not math.isfinite(turn["elapsed_seconds"])
                or turn["elapsed_seconds"] < 0):
            raise ValueError("Invalid turn in attempt " + str(record.get("attempt_id"))
                             + " (durations must be finite, non-negative numbers)")
    if sum(1 for t in record["turns"] if t["kind"] == "repair") != record["repairs"]:
        raise ValueError("Repair count differs from the recorded turns")
    if any(t["refused"] for t in record["turns"]) != (record["outcome"] == "REFUSED"):
        raise ValueError("A refusal must end its attempt as REFUSED, and only a refusal may")
    return record


def summary(records):
    """Per task: outcome counts, usable share and the cost figures."""
    result = {}
    for record in records:
        item = result.setdefault(record["task"], {"attempts": 0, "outcomes": {}, "requests": 0, "repairs": 0,
                                                  "refusals": 0, "model_seconds": 0.0, "manual_wait_seconds": 0.0,
                                                  "failures": 0,
                                                  "researcher_changes": 0})
        item["attempts"] += 1
        item["outcomes"][record["outcome"]] = item["outcomes"].get(record["outcome"], 0) + 1
        item["requests"] += len(record["turns"])
        item["repairs"] += record["repairs"]
        item["refusals"] += record["outcome"] == "REFUSED"
        # A manual response's duration is the researcher's wait, not model time.
        field = "manual_wait_seconds" if record["mode"] == "manual" else "model_seconds"
        item[field] = round(item[field] + sum(t["elapsed_seconds"] for t in record["turns"]), 3)
        item["failures"] += record["outcome"] not in {"ACCEPTED", "DUPLICATE"}
        item["researcher_changes"] += len(record["researcher_changes"])
    for item in result.values():
        accepted = item["outcomes"].get("ACCEPTED", 0)
        item["usable_share"] = {"numerator": accepted, "denominator": item["attempts"],
                                "rate": accepted / item["attempts"] if item["attempts"] else None}
    return result
