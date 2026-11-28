"""Costs and failures (A14) and the generation table, from the checked attempts log.

Every figure is counted from attempt records that pass validation
(`GenerationLog.records`: record shape, repair counts, refusals, finite
non-negative durations) and are unique by attempt ID; an invalid or repeated
record stops the table. Shape checks cannot detect every edit of a record. A
missing log, an empty log or an accounting file that is not a report is
refused before any output is written. The tables report, per task:

* attempts and their outcomes, and the usable share (accepted / attempts)
  with numerator and denominator;
* requests (initial plus repairs), repairs, refusals, attempts without a
  usable result (all but ACCEPTED) and, of those, failures (not counting
  duplicates);
* model time (adapter-reported response durations; prepared durations in
  simulated mode) and, separately, the researcher's wait for manual
  responses;
* researcher build-setting changes.

The generation table repeats the outcome counts per original or target. An
optional accounting report adds the detector checks that ended without a
valid response (ERROR, INCONCLUSIVE, NOT_RUN), per tool.
"""
import argparse
import csv
import io
import json
import sys

import aegis
from generation_log import CODE_OUTCOMES, GenerationLog

INCOMPLETE = ("ERROR", "INCONCLUSIVE", "NOT_RUN")
TASK_NAMES = {"code_variant": "Kodo variantai", "rule": "Taisyklės", "code_control": "Kodo kontrolė",
              "rule_control": "Taisyklės kontrolė"}


def _fraction(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "rate": numerator / denominator if denominator else None}


def costs(records):
    """Per-task cost and failure figures from validated records."""
    result = {}
    for record in records:
        item = result.setdefault(record["task"], {
            "attempts": 0, "outcomes": {}, "requests": 0, "repairs": 0, "refusals": 0, "unusable": 0,
            "failures": 0, "model_seconds": 0.0, "manual_wait_seconds": 0.0, "researcher_changes": 0})
        item["attempts"] += 1
        item["outcomes"][record["outcome"]] = item["outcomes"].get(record["outcome"], 0) + 1
        item["requests"] += len(record["turns"])
        item["repairs"] += record["repairs"]
        item["refusals"] += record["outcome"] == "REFUSED"
        item["unusable"] += record["outcome"] != "ACCEPTED"
        item["failures"] += record["outcome"] not in {"ACCEPTED", "DUPLICATE"}
        seconds = sum(turn["elapsed_seconds"] for turn in record["turns"])
        field = "manual_wait_seconds" if record["mode"] == "manual" else "model_seconds"
        item[field] = round(item[field] + seconds, 3)
        item["researcher_changes"] += len(record["researcher_changes"])
    for item in result.values():
        item["usable_share"] = _fraction(item["outcomes"].get("ACCEPTED", 0), item["attempts"])
    return result


def by_subject(records):
    """Outcome counts per task and original (or rule target)."""
    table = {}
    for record in records:
        key = (record["task"], record["subject"])
        item = table.setdefault(key, {"attempts": 0, "outcomes": {}})
        item["attempts"] += 1
        item["outcomes"][record["outcome"]] = item["outcomes"].get(record["outcome"], 0) + 1
    return table


def check_report(report):
    """An accounting report as `aegis.run` writes it; anything else is refused, never read as zeros."""
    counts = report.get("status_counts") if isinstance(report, dict) else None
    if (not isinstance(report, dict) or not report.get("run_id") or report.get("mode") not in {
            "control", "rehearsal", "research"} or not isinstance(counts, dict) or not counts
            or not all(isinstance(k, str) and k.split(":", 1)[0] in {"av", "yara"} and ":" in k
                       and type(v) is int and v >= 0 for k, v in counts.items())):
        raise ValueError("Not an accounting report with status counts")
    return report


def incomplete_checks(report):
    """Detector checks without a valid response, from an accounting report's status counts."""
    counts = check_report(report)["status_counts"]
    return {tool: {status: counts.get(tool + ":" + status, 0) for status in INCOMPLETE}
            for tool in ("av", "yara")}


def _csv(header, rows):
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(header)
    writer.writerows(rows)
    return stream.getvalue()


def _seconds(value):
    return ("%.1f" % value).replace(".", ",")


def tables(records, report=None):
    if not records:
        raise ValueError("The attempts log holds no records; an empty table would look like a result")
    if report is not None:
        check_report(report)
    figures = costs(records)
    outcomes = sorted(CODE_OUTCOMES | {o for item in figures.values() for o in item["outcomes"]})
    out = {}
    rows = []
    for (task, subject), item in sorted(by_subject(records).items()):
        accepted = item["outcomes"].get("ACCEPTED", 0)
        rows.append([task, subject, item["attempts"]] + [item["outcomes"].get(o, 0) for o in outcomes]
                    + [accepted, item["attempts"]])
    out["generation.csv"] = _csv(["task", "subject", "attempts", *outcomes, "usable", "usable_of"], rows)
    columns = ("attempts", "requests", "repairs", "refusals", "unusable", "failures", "model_seconds",
               "manual_wait_seconds", "researcher_changes")
    out["costs.csv"] = _csv(["task", *columns, "usable", "usable_of"],
                            [[task, *(item[c] for c in columns), item["usable_share"]["numerator"],
                              item["usable_share"]["denominator"]] for task, item in sorted(figures.items())])
    lines = []
    for task, item in sorted(figures.items()):
        lines.append(" & ".join([TASK_NAMES.get(task, task), str(item["attempts"]), str(item["requests"]),
                                 str(item["repairs"]), str(item["refusals"]), str(item["failures"]),
                                 aegis._rate_text(item["usable_share"]), _seconds(item["model_seconds"]),
                                 _seconds(item["manual_wait_seconds"]), str(item["researcher_changes"])]) + " \\\\")
    out["costs.tex"] = ("% Generated by Project Aegis from the checked attempts log.\n"
                        "Užduotis & Bandymai & Užklausos & Taisymai & Atsisakymai & Nesėkmės & Tinkami & "
                        "Modelio laikas, s & Rankinis laukimas, s & Nustatymų keitimai \\\\\n\\midrule\n"
                        + "\n".join(lines) + "\n")
    if report is not None:
        checks = incomplete_checks(report)
        out["incomplete_checks.csv"] = _csv(["tool", *INCOMPLETE],
                                            [[tool, *(checks[tool][s] for s in INCOMPLETE)] for tool in ("av", "yara")])
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", required=True, help="attempts log folder (outside the repository)")
    parser.add_argument("--tables", required=True, help="new folder for the CSV and LaTeX tables")
    parser.add_argument("--accounting", help="optional accounting report JSON for incomplete checks")
    args = parser.parse_args(argv)
    try:
        # Every input is read and checked before the output folder exists.
        records = GenerationLog(args.log, create=False).records()
        report = json.loads(aegis.external_path(args.accounting).read_text(encoding="utf-8")) if args.accounting else None
        content_by_name = tables(records, report)
        folder = aegis.external_path(args.tables)
        folder.mkdir(parents=True, exist_ok=False)
        for name, content in content_by_name.items():
            with (folder / name).open("x", encoding="utf-8", newline="") as stream:
                stream.write(content)
    except (ValueError, OSError, KeyError) as exc:
        print("Cost table failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
