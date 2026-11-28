"""Functionality cards as data, and the card evaluator. Nothing here executes a file.

A card is written before generation and fixed by its SHA-256. The same card
judges an original and all its variants. The evaluator reads what the
laboratory recorded about one run (process outcome, owned files, Process
Monitor rows) and returns the protocol's outcome:

* NOT_RUN       - the program was not launched (e.g. an earlier step failed);
* INCONCLUSIVE  - the outcome cannot be established: the launch could not be
                  confirmed, monitoring was incomplete or recorded nothing for
                  the process, or another technical fault occurred;
* FAIL          - monitoring was complete and at least one card condition is
                  not met, including a confirmed run past the time limit;
* PASS          - every condition is met, with the required monitored actions.

The functionality record binds the file hash, the card hash and the outcome,
in the form `aegis.py` validates; the evaluation details are kept beside it.
"""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
from pathlib import Path, PurePosixPath
import sys
import uuid

import aegis

CARD_FIELDS = {"schema", "kind", "card_id", "original_id", "created_at_utc", "input", "time_limit_seconds",
               "expected", "evidence"}
EXPECTED_FIELDS = {"exit_code", "stdout", "stderr_empty", "files"}
RUN_FIELDS = {"launch", "sample_sha256", "arguments", "pid", "exit_code", "timed_out", "elapsed_seconds",
              "stdout", "stderr", "workdir", "token", "files", "monitor", "technical_error"}


def _number(value):
    """A finite real number (not a boolean)."""
    return type(value) in (int, float) and math.isfinite(value)
LAUNCH = {"NOT_ATTEMPTED", "STARTED", "FAILED_TO_START"}


def _relative(name):
    path = PurePosixPath(name)
    if (not name or path.is_absolute() or "\\" in name or ":" in name
            or any(part in {"", ".", ".."} for part in name.split("/"))):
        raise ValueError("Card paths are relative to the run's work directory: " + str(name))
    return name


def validate_card(card):
    if not isinstance(card, dict) or set(card) != CARD_FIELDS or card["schema"] != 1 \
            or card["kind"] != "functionality_card":
        raise ValueError("Invalid functionality card")
    for key in ("card_id", "original_id"):
        if not isinstance(card[key], str) or not card[key].strip():
            raise ValueError("Card needs " + key)
    if datetime.fromisoformat(str(card["created_at_utc"]).replace("Z", "+00:00")).utcoffset() is None:
        raise ValueError("Card time must include a time zone")
    arguments = card["input"].get("arguments") if isinstance(card["input"], dict) else None
    if not isinstance(arguments, list) or not all(isinstance(a, str) for a in arguments):
        raise ValueError("Card input needs a list of argument templates")
    limit = card["time_limit_seconds"]
    if not _number(limit) or limit <= 0:
        raise ValueError("Card needs a finite positive time limit")
    expected = card["expected"]
    if not isinstance(expected, dict) or set(expected) != EXPECTED_FIELDS:
        raise ValueError("Card expectations need exit_code, stdout, stderr_empty and files")
    if expected["exit_code"] is not None and type(expected["exit_code"]) is not int:
        raise ValueError("Expected exit code must be an integer or null")
    if expected["stdout"] is not None and not isinstance(expected["stdout"], str):
        raise ValueError("Expected stdout must be text or null")
    if type(expected["stderr_empty"]) is not bool or not isinstance(expected["files"], list):
        raise ValueError("Invalid card expectations")
    for item in expected["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "content"} or not isinstance(item["content"], str):
            raise ValueError("Expected files need path and exact content")
        _relative(item["path"])
    evidence = card["evidence"]
    if (not isinstance(evidence, dict) or set(evidence) != {"monitor", "operations"}
            or evidence["monitor"] != "process_monitor" or not isinstance(evidence["operations"], list)):
        raise ValueError("Card evidence must name Process Monitor operations")
    for item in evidence["operations"]:
        if not isinstance(item, dict) or set(item) != {"operation", "path", "result"}:
            raise ValueError("Each required operation needs operation, path and result")
        _relative(item["path"])
    if not expected["files"] and not evidence["operations"] and expected["stdout"] is None:
        raise ValueError("A card must check an observable action")
    return card


def card_sha256(card):
    """The hash recorded in the manifest: canonical JSON of a validated card."""
    validate_card(card)
    return hashlib.sha256(json.dumps(card, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


def _fill(template, token):
    return template.replace("{token}", token)


def _windows_join(workdir, relative):
    return (str(workdir).rstrip("\\/") + "\\" + relative.replace("/", "\\")).casefold()


def card_arguments(card, run):
    """The card's argument templates filled with this run's work directory and token."""
    return [a.replace("{workdir}", str(run["workdir"])).replace("{token}", str(run["token"]))
            for a in card["input"]["arguments"]]


def evaluate(card, run, monitor_rows, sample_sha256, *, monitor_sha256, synthetic=False):
    """(functionality record, details) for one recorded run of one file under one card.

    The run record must name the hash of the file it launched and the hash of
    the Process Monitor export it was traced in; evidence from another file or
    another trace is refused rather than judged.
    """
    validate_card(card)
    if not isinstance(run, dict) or set(run) != RUN_FIELDS or run["launch"] not in LAUNCH:
        raise ValueError("Invalid run record")
    if not aegis.SHA256.fullmatch(str(sample_sha256)):
        raise ValueError("Invalid sample hash")
    if run["sample_sha256"] != sample_sha256:
        raise ValueError("Run record belongs to a different file")
    monitor = run["monitor"] if isinstance(run["monitor"], dict) else {}
    # A captured trace must be the one supplied; without a capture the outcome is unknown anyway.
    if monitor.get("captured") is True and not (
            aegis.SHA256.fullmatch(str(monitor.get("csv_sha256"))) and monitor["csv_sha256"] == monitor_sha256):
        raise ValueError("Process Monitor export does not belong to this run")
    reasons, technical = [], []
    if run["launch"] == "NOT_ATTEMPTED":
        status, reasons = "NOT_RUN", ["PROGRAM_NOT_LAUNCHED"]
    else:
        if run["launch"] == "FAILED_TO_START":
            technical.append("LAUNCH_NOT_CONFIRMED")
        if run["technical_error"]:
            technical.append("TECHNICAL_ERROR:" + str(run["technical_error"]))
        if monitor.get("captured") is not True or monitor.get("complete") is not True:
            technical.append("MONITORING_INCOMPLETE")
        if type(run["pid"]) is not int:
            technical.append("PROCESS_ID_UNKNOWN")
        if not isinstance(run["arguments"], list) or run["arguments"] != card_arguments(card, run):
            # The card was not applied as written, so its conditions cannot be judged.
            technical.append("INPUT_DIFFERS_FROM_CARD")
        if type(run["timed_out"]) is not bool:
            technical.append("TIMEOUT_FLAG_UNRECORDED")
        if not _number(run["elapsed_seconds"]) or run["elapsed_seconds"] < 0:
            technical.append("ELAPSED_TIME_UNRECORDED")
        # Outputs must be recorded values; a missing value is not a met or unmet condition.
        killed = run["timed_out"] is True
        if not (type(run["exit_code"]) is int or (killed and run["exit_code"] is None)):
            technical.append("EXIT_CODE_UNRECORDED")
        if not isinstance(run["stdout"], str) or not isinstance(run["stderr"], str):
            technical.append("OUTPUT_UNRECORDED")
        if not isinstance(run["files"], dict) or not all(
                isinstance(k, str) and (v is None or aegis.SHA256.fullmatch(str(v))) for k, v in run["files"].items()):
            technical.append("FILES_UNRECORDED")
        owned = [row for row in monitor_rows if str(row.get("PID", "")).strip() == str(run["pid"])]
        if not technical and not owned:
            technical.append("MONITOR_HAS_NO_EVENTS_FOR_PROCESS")
        if technical:
            status, reasons = "INCONCLUSIVE", technical
        else:
            expected, token = card["expected"], str(run["token"])
            limit = card["time_limit_seconds"]
            elapsed = run["elapsed_seconds"]
            if run["timed_out"] or elapsed > limit:
                reasons.append("TIME_LIMIT_EXCEEDED")
            if expected["exit_code"] is not None and run["exit_code"] != expected["exit_code"]:
                reasons.append("EXIT_CODE")
            if expected["stdout"] is not None and run["stdout"].strip() != _fill(expected["stdout"], token):
                reasons.append("STDOUT")
            if expected["stderr_empty"] and run["stderr"]:
                reasons.append("STDERR_NOT_EMPTY")
            recorded = run["files"]
            for item in expected["files"]:
                want = hashlib.sha256(_fill(item["content"], token).encode("utf-8")).hexdigest()
                if recorded.get(item["path"]) != want:
                    reasons.append("FILE:" + item["path"])
            for item in card["evidence"]["operations"]:
                target = _windows_join(run["workdir"], item["path"])
                if not any(row.get("Operation") == item["operation"] and row.get("Result") == item["result"]
                           and str(row.get("Path", "")).casefold() == target for row in owned):
                    reasons.append("NOT_OBSERVED:" + item["operation"] + ":" + item["path"])
            status = "FAIL" if reasons else "PASS"
    record_id = "card-eval-" + uuid.uuid4().hex
    record = {"schema": 1, "kind": "functionality_record", "record_id": record_id,
              "sample_sha256": sample_sha256, "card_sha256": card_sha256(card), "status": status,
              "synthetic": synthetic}
    details = {"schema": 1, "kind": "functionality_details", "record_id": record_id, "status": status,
               "reasons": reasons, "card_id": card["card_id"],
               "monitored_events_for_process": len([r for r in monitor_rows
                                                   if str(r.get("PID", "")).strip() == str(run["pid"])]),
               "evaluated_at_utc": datetime.now(timezone.utc).isoformat()}
    return record, details


def read_monitor_csv(path):
    """Process Monitor CSV export (UTF-16 or UTF-8) as rows with PID, Operation, Path, Result."""
    content = Path(path).read_bytes()
    encoding = "utf-16" if content[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    reader = csv.DictReader(io.StringIO(content.decode(encoding, errors="replace"), newline=""))
    if not {"PID", "Operation", "Path", "Result"} <= set(reader.fieldnames or []):
        raise ValueError("Unrecognized Process Monitor CSV columns")
    return [{key: row.get(key, "") for key in ("PID", "Operation", "Path", "Result")} for row in reader]


BUILD_FIELDS = {"source_sha256", "compiler", "settings", "output_sha256"}


def check_control_build(original, copy):
    """A control copy must come from the same source, compiler and settings as its original."""
    for name, value in (("original", original), ("copy", copy)):
        compiler = value.get("compiler") if isinstance(value, dict) else None
        if (not isinstance(value, dict) or set(value) != BUILD_FIELDS
                or not all(aegis.SHA256.fullmatch(str(value[k])) for k in ("source_sha256", "output_sha256"))
                or not isinstance(compiler, dict) or set(compiler) != {"name", "version", "sha256"}
                or not all(isinstance(compiler[k], str) and compiler[k].strip() for k in ("name", "version"))
                or not aegis.SHA256.fullmatch(str(compiler["sha256"]))
                or not isinstance(value["settings"], list) or not all(isinstance(x, str) for x in value["settings"])):
            raise ValueError("Invalid build record (the compiler needs name, version and SHA-256): " + name)
    for key in ("source_sha256", "compiler", "settings"):
        if original[key] != copy[key]:
            raise ValueError("Control copy was not built under the same conditions: " + key)
    return {"same_conditions": True,
            "reproducible": "IDENTICAL" if original["output_sha256"] == copy["output_sha256"] else "DIFFERENT"}


def _write_new(path, value):
    with aegis.external_path(path).open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("card-hash")
    command.add_argument("--card", required=True)
    command = commands.add_parser("evaluate")
    for name in ("--card", "--run", "--monitor-csv", "--sample-sha256", "--record", "--details"):
        command.add_argument(name, required=True)
    args = parser.parse_args(argv)
    try:
        card = json.loads(aegis.external_path(args.card).read_text(encoding="utf-8"))
        if args.command == "card-hash":
            print(card_sha256(card))
            return 0
        run = json.loads(aegis.external_path(args.run).read_text(encoding="utf-8"))
        monitor = aegis.external_path(args.monitor_csv)
        rows = read_monitor_csv(monitor)
        record, details = evaluate(card, run, rows, args.sample_sha256, monitor_sha256=aegis.digest(monitor))
        _write_new(args.record, record)
        _write_new(args.details, details)
    except (ValueError, OSError, KeyError) as exc:
        print("Functionality evaluation failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
