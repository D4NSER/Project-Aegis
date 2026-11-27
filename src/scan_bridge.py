"""Host bridge: validated guest detector reports -> accounting observation rows.

Each AV report covers one file; each YARA report covers a batch. Reports are
stored in the external workspace and referenced as evidence. Statuses map
without reinterpretation: MATCHED/NOT_MATCHED become DETECTED/NOT_DETECTED,
ERROR and NOT_RUN stay unknown. Tool-state IDs are derived from the recorded
versions; a series whose state changes is refused so that the run can be split.
"""
import argparse
import csv
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path
import sys

import aegis
from guest_research_scan import YARA_VERSION, source_check, state_matches, versions_stable

AV_FIELDS = {"schema", "kind", "run_id", "scan_id", "sample_id", "sha256", "expected_state", "wait_seconds",
             "started_at_utc", "finished_at_utc", "defender_before", "defender_after", "realtime", "custom_scan",
             "file_unchanged", "status", "detected_by", "reasons", "platform", "architecture", "code_sha256"}
YARA_FIELDS = {"schema", "kind", "run_id", "scan_id", "expected_state", "defender_state", "yara_version",
               "yara_sha256", "ruleset_sha256", "started_at_utc", "finished_at_utc", "files",
               "platform", "architecture", "code_sha256"}
YARA_STATUS = {"MATCHED": "DETECTED", "NOT_MATCHED": "NOT_DETECTED", "ERROR": "ERROR", "NOT_RUN": "NOT_RUN"}


def _time(value):
    moment = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if moment.utcoffset() is None:
        raise ValueError("Report time must include a time zone")
    return value


def _state_id(prefix, value):
    return prefix + "-" + hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:16]


def av_state_id(report):
    before = report["defender_before"] or {}
    return _state_id("defender", {key: before.get(key) for key in
                                  ("AMProductVersion", "AMEngineVersion", "AntivirusSignatureVersion")})


def yara_state_id(report):
    return _state_id("yara", {"version": report["yara_version"], "executable": report["yara_sha256"],
                              "ruleset": report["ruleset_sha256"]})


def validate_av(report):
    if (not isinstance(report, dict) or set(report) != AV_FIELDS or report["schema"] != 1
            or report["kind"] != "av_check" or report["expected_state"] != "A"
            or report["status"] not in aegis.STATUSES or not aegis.SHA256.fullmatch(str(report["sha256"]))
            or not str(report["scan_id"]).startswith("av-") or report["platform"] != "Windows"):
        raise ValueError("Invalid AV report")
    status, detected_by = report["status"], report["detected_by"]
    if (status == "DETECTED") != (detected_by in aegis.DETECTED_BY) or (status != "DETECTED" and detected_by != ""):
        raise ValueError("An AV detection must name REALTIME or CUSTOM_SCAN, and only a detection may")
    if status in {"DETECTED", "NOT_DETECTED"}:
        # A valid response must agree with the evidence recorded beside it.
        if not (state_matches(report["defender_before"], "A") and state_matches(report["defender_after"], "A")
                and versions_stable(report["defender_before"], report["defender_after"])):
            raise ValueError("A valid AV response needs state A and unchanged tool versions before and after")
        realtime = report["realtime"] if isinstance(report["realtime"], dict) else {}
        custom = report["custom_scan"] if isinstance(report["custom_scan"], dict) else {}
        lookup = custom.get("lookup") if isinstance(custom.get("lookup"), dict) else {}
        def recorded(value):
            return (isinstance(value.get("events"), list) and isinstance(value.get("threats"), list)
                    and bool(value["events"] or value["threats"]))
        if detected_by == "REALTIME" and not (
                realtime.get("known") is True and realtime.get("detected") is True and recorded(realtime)
                and source_check(realtime, "REALTIME") == "SUPPORTED"):
            raise ValueError("A REALTIME detection needs a real-time detection record with a real-time source")
        if detected_by == "CUSTOM_SCAN" and not (
                realtime.get("known") is True and realtime.get("detected") is False
                and lookup.get("known") is True and lookup.get("detected") is True and recorded(lookup)
                and source_check(lookup, "CUSTOM_SCAN") == "SUPPORTED"):
            raise ValueError("A CUSTOM_SCAN detection needs a clean real-time lookup and a custom-scan record")
        if status == "NOT_DETECTED" and not (
                report["file_unchanged"] is True and custom.get("exit_code") == 0 and custom.get("timed_out") is False
                and realtime.get("known") is True and realtime.get("detected") is False
                and lookup.get("known") is True and lookup.get("detected") is False):
            raise ValueError("An AV negative needs a completed custom scan of unchanged bytes and readable history")
    _time(report["finished_at_utc"])
    return report


def validate_yara(report):
    if (not isinstance(report, dict) or set(report) != YARA_FIELDS or report["schema"] != 1
            or report["kind"] != "yara_check" or report["expected_state"] != "F"
            or not aegis.SHA256.fullmatch(str(report["ruleset_sha256"]))
            or not str(report["scan_id"]).startswith("yara-") or report["platform"] != "Windows"
            or not isinstance(report["files"], list)):
        raise ValueError("Invalid YARA report")
    ready = state_matches(report["defender_state"], "F") and isinstance(report["yara_version"], str) \
        and bool(YARA_VERSION.fullmatch(report["yara_version"]))
    for item in report["files"]:
        if (not isinstance(item, dict) or set(item) != {"sample_id", "sha256", "status", "rules", "reason"}
                or item["status"] not in YARA_STATUS or (item["status"] == "MATCHED") != bool(item["rules"])):
            raise ValueError("Invalid YARA file result")
        if item["status"] in {"MATCHED", "NOT_MATCHED"}:
            if not ready or item["reason"] is not None:
                raise ValueError("A valid YARA response needs state F and a recorded YARA version")
        elif not isinstance(item["reason"], str) or not item["reason"]:
            raise ValueError("An incomplete YARA response needs its reason")
    _time(report["finished_at_utc"])
    return report


def observations(report_paths, samples, run_id, workspace):
    """Observation rows for aegis.py and the tool-state IDs its configuration must name."""
    workspace = aegis.external_path(workspace)
    rows, seen, states = [], set(), {"av": set(), "yara": set()}

    def add(sample_id, sha, tool, status, state, scan_id, observed_at, evidence, detected_by=""):
        sample = samples.get(sample_id)
        if sample is None or sample["sha256"] != sha:
            raise ValueError("Report names an unknown file or a stale hash: " + str(sample_id))
        if (sample_id, tool) in seen:
            raise ValueError("More than one " + tool + " report for one file: " + sample_id)
        seen.add((sample_id, tool))
        states[tool].add(state)
        rows.append(dict(zip(aegis.OBSERVATION_FIELDS, [run_id, sample_id, sha, tool, status, state, scan_id,
                                                        observed_at, evidence, detected_by])))

    for relative in report_paths:
        path = aegis.local_file(workspace, relative)
        if path.stat().st_size > 1024 * 1024:
            raise ValueError("Report exceeds limit: " + relative)
        report = json.loads(path.read_text(encoding="utf-8"))
        if report.get("run_id") != run_id:
            raise ValueError("Report belongs to a different run: " + relative)
        if report.get("kind") == "av_check":
            validate_av(report)
            add(report["sample_id"], report["sha256"], "av", report["status"], av_state_id(report),
                report["scan_id"], report["finished_at_utc"], relative, report["detected_by"])
        elif report.get("kind") == "yara_check":
            validate_yara(report)
            for item in report["files"]:
                add(item["sample_id"], item["sha256"], "yara", YARA_STATUS[item["status"]], yara_state_id(report),
                    report["scan_id"], report["finished_at_utc"], relative)
        else:
            raise ValueError("Unknown report kind: " + relative)
    for tool, values in states.items():
        if len(values) > 1:
            raise ValueError("The " + tool + " tool state changed within the series; split it into separate runs")
    return rows, {tool: next(iter(values)) if values else None for tool, values in states.items()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--collection")
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--reports", nargs="+", required=True, help="workspace-relative report paths")
    parser.add_argument("--output", required=True, help="new observations CSV outside the repository")
    args = parser.parse_args(argv)
    try:
        workspace = aegis.external_path(args.workspace)
        collection = aegis.external_path(args.collection) if args.collection else None
        samples = aegis.validate_samples(aegis.read_csv(aegis.external_path(args.manifest), aegis.SAMPLE_FIELDS),
                                         workspace, collection)
        rows, states = observations(args.reports, samples, args.run_id, workspace)
        stream = io.StringIO()
        writer = csv.DictWriter(stream, fieldnames=aegis.OBSERVATION_FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
        with aegis.external_path(args.output).open("x", encoding="utf-8", newline="") as handle:
            handle.write(stream.getvalue())
        print(json.dumps({"state_ids": states, "rows": len(rows)}))
    except (ValueError, OSError, KeyError) as exc:
        print("Scan bridge failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
