"""Control-stage manifest validation and detection-result accounting; no execution.

The metric definitions follow the evaluation protocol: AV and combined
responses are compared only where both AV and YARA responses are valid,
incomplete checks never become negatives, and detection loss counts only
functional variants whose original and control copy were detected.
"""
import argparse
from collections import Counter, defaultdict
import csv
from datetime import datetime
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FIELDS = (
    "sample_id", "project_id", "family_id", "split", "kind", "parent_id",
    "generation_order", "holdout", "sha256", "path", "functionality",
    "card_sha256", "functionality_evidence", "source", "source_version",
    "label_basis", "format", "architecture",
)
OBSERVATION_FIELDS = (
    "run_id", "sample_id", "sha256", "tool", "status", "state_id",
    "scan_id", "observed_at", "evidence", "detected_by",
)
STATUSES = {"DETECTED", "NOT_DETECTED", "ERROR", "INCONCLUSIVE", "NOT_RUN"}
KINDS = {"original", "variant", "control_copy", "benign"}
FUNCTIONALITY = {"PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN", "NOT_APPLICABLE"}
TESTED_FUNCTIONALITY = {"PASS", "FAIL", "INCONCLUSIVE"}
RULESET_STATUSES = {"FROZEN", "EMPTY", "FAILED"}
DETECTED_BY = {"REALTIME", "CUSTOM_SCAN"}
SPLITS = ("calibration", "evaluation")
SHA256 = re.compile(r"[0-9a-f]{64}")
COLLECTION_PREFIX = "collection:"


def external_path(path):
    path = Path(path).resolve()
    if path == ROOT or ROOT in path.parents:
        raise ValueError("Working data and reports must be outside the public repository")
    return path


def local_file(root, name):
    relative = PurePosixPath(name)
    if (not name or relative.is_absolute() or "\\" in name or ":" in name
            or any(p in {"", ".", ".."} for p in name.split("/"))):
        raise ValueError("Expected a relative, contained file path: " + name)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("Symlink in working data: " + name)
    if not current.is_file():
        raise ValueError("Missing working file: " + name)
    return current


def sample_file(name, workspace, collection=None):
    """Workspace-relative path, or `collection:<relative>` inside a read-only collection."""
    if name.startswith(COLLECTION_PREFIX):
        if collection is None:
            raise ValueError("A collection path needs a configured collection root: " + name)
        return local_file(collection, name[len(COLLECTION_PREFIX):])
    return local_file(workspace, name)


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def read_csv(path, fields):
    with Path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(fields):
            raise ValueError("Unexpected CSV columns: " + str(path))
        rows = list(reader)
    if any(None in row or any(value is None for value in row.values()) for row in rows):
        raise ValueError("Malformed CSV row: " + str(path))
    return rows


def functionality_record(path, row):
    """A card evaluator record binds one file hash, one card hash and one outcome."""
    if path.stat().st_size > 65536:
        raise ValueError("Functionality record exceeds limit: " + row["sample_id"])
    value = json.loads(path.read_text(encoding="utf-8"))
    expected = {"schema", "kind", "record_id", "sample_sha256", "card_sha256", "status", "synthetic"}
    if (not isinstance(value, dict) or set(value) != expected or value["schema"] != 1
            or value["kind"] != "functionality_record" or not isinstance(value["record_id"], str)
            or not value["record_id"].strip() or type(value["synthetic"]) is not bool):
        raise ValueError("Invalid functionality record: " + row["sample_id"])
    if (value["sample_sha256"] != row["sha256"] or value["card_sha256"] != row["card_sha256"]
            or value["status"] != row["functionality"]):
        raise ValueError("Functionality record does not match its sample, card or status: " + row["sample_id"])
    return value


def eligible(row, samples):
    if row["kind"] == "benign":
        return True
    if row["kind"] == "control_copy" or row["functionality"] != "PASS":
        return False
    return row["kind"] != "variant" or samples[row["parent_id"]]["functionality"] == "PASS"


def expected_holdouts(samples):
    """Per calibration project group: the last eligible variant, if at least two are eligible."""
    groups = defaultdict(list)
    for row in samples.values():
        if row["kind"] == "variant" and row["split"] == "calibration" and eligible(row, samples):
            groups[row["project_id"]].append(row)
    return {max(rows, key=lambda r: r["generation_order"])["sample_id"]
            for rows in groups.values() if len(rows) >= 2}


def _validate_row(row, workspace, collection):
    sample_id = row["sample_id"]
    if row["split"] not in SPLITS:
        raise ValueError("Invalid split: " + sample_id)
    if row["kind"] not in KINDS:
        raise ValueError("Invalid sample kind: " + sample_id)
    if row["functionality"] not in FUNCTIONALITY:
        raise ValueError("Invalid functionality status: " + sample_id)
    for field in ("project_id", "source", "source_version", "label_basis", "format", "architecture"):
        if not row[field].strip():
            raise ValueError("Missing " + field + ": " + sample_id)
    if not SHA256.fullmatch(row["sha256"]):
        raise ValueError("Invalid SHA-256: " + sample_id)
    if digest(sample_file(row["path"], workspace, collection)) != row["sha256"]:
        raise ValueError("File hash mismatch: " + sample_id)
    if row["holdout"] not in {"", "true", "false"}:
        raise ValueError("Holdout must be true, false or empty: " + sample_id)
    kind, order = row["kind"], row["generation_order"]
    if kind == "variant":
        if not re.fullmatch(r"[1-9][0-9]{0,8}", order):
            raise ValueError("A variant needs a positive generation order: " + sample_id)
    elif order or row["holdout"] == "true":
        raise ValueError("Only a variant has a generation order or holdout flag: " + sample_id)
    if kind == "benign":
        if row["parent_id"] or row["family_id"] or row["functionality"] != "NOT_APPLICABLE":
            raise ValueError("Unexpected benign lineage/functionality: " + sample_id)
    elif not row["family_id"]:
        raise ValueError("Missing malicious lineage/functionality: " + sample_id)
    if kind == "control_copy":
        if row["functionality"] != "NOT_APPLICABLE":
            raise ValueError("A control copy has no separate functionality outcome: " + sample_id)
    elif kind != "benign" and row["functionality"] == "NOT_APPLICABLE":
        raise ValueError("Missing malicious lineage/functionality: " + sample_id)
    if kind in {"variant", "control_copy"} and not row["parent_id"]:
        raise ValueError("A " + kind + " needs its original: " + sample_id)
    if kind not in {"variant", "control_copy"} and row["parent_id"]:
        raise ValueError("Only a variant or control copy can have a parent: " + sample_id)
    card, evidence = row["card_sha256"], row["functionality_evidence"]
    if card and not SHA256.fullmatch(card):
        raise ValueError("Invalid functionality card hash: " + sample_id)
    record = None
    if row["functionality"] in TESTED_FUNCTIONALITY:
        if not card or not evidence:
            raise ValueError("A functionality outcome needs its card hash and evaluator record: " + sample_id)
    elif row["functionality"] == "NOT_APPLICABLE" and (card or evidence):
        raise ValueError("Unexpected functionality card or record: " + sample_id)
    if evidence:
        if not card:
            raise ValueError("A functionality record needs its card hash: " + sample_id)
        record = functionality_record(local_file(workspace, evidence), row)
    return dict(row, holdout=row["holdout"] == "true",
                generation_order=int(order) if order else None,
                functionality_synthetic=record["synthetic"] if record else None)


def validate_samples(rows, workspace, collection=None):
    by_id, groups, hashes = {}, {}, defaultdict(list)
    if not rows:
        raise ValueError("Manifest is empty; no data have been registered")
    for raw in rows:
        sample_id = raw["sample_id"]
        if not sample_id or sample_id in by_id:
            raise ValueError("Missing or duplicate sample ID: " + sample_id)
        row = _validate_row(raw, workspace, collection)
        # Project IDs must identify common provenance, not merely file names.
        group = row["project_id"]
        if group in groups and groups[group] != row["split"]:
            raise ValueError("Project crosses calibration/evaluation: " + group)
        groups[group] = row["split"]
        hashes[row["sha256"]].append(sample_id)
        by_id[sample_id] = row
    copies, orders = Counter(), defaultdict(set)
    for row in by_id.values():
        if row["kind"] not in {"variant", "control_copy"}:
            continue
        parent = by_id.get(row["parent_id"])
        if (not parent or parent["kind"] != "original"
                or any(parent[k] != row[k] for k in ("split", "family_id", "project_id"))):
            raise ValueError("Invalid or cross-split parent: " + row["sample_id"])
        if row["kind"] == "control_copy":
            copies[parent["sample_id"]] += 1
            if copies[parent["sample_id"]] > 1:
                raise ValueError("An original has more than one control copy: " + parent["sample_id"])
            continue
        if row["card_sha256"] and parent["card_sha256"] and row["card_sha256"] != parent["card_sha256"]:
            raise ValueError("A variant must use its original's functionality card: " + row["sample_id"])
        if row["generation_order"] in orders[row["project_id"]]:
            raise ValueError("Generation order is not unique in its project group: " + row["sample_id"])
        orders[row["project_id"]].add(row["generation_order"])
    for sha, ids in hashes.items():
        if len(ids) == 1:
            continue
        kinds = sorted(by_id[i]["kind"] for i in ids)
        copy = next((by_id[i] for i in ids if by_id[i]["kind"] == "control_copy"), None)
        if len(ids) != 2 or kinds != ["control_copy", "original"] or copy["parent_id"] not in ids:
            raise ValueError("Duplicate SHA-256 is allowed only for a control copy and its original: "
                             + ", ".join(sorted(ids)))
    flagged = {key for key, row in by_id.items() if row["holdout"]}
    if flagged != expected_holdouts(by_id):
        raise ValueError("Holdout flags must mark exactly the last eligible variant of each "
                         "calibration group with at least two eligible variants")
    return by_id


def validate_observations(rows, samples, config, workspace, detected_by=None):
    """Statuses by (sample, tool); AV detections also record which check flagged them."""
    observations = {}
    for row in rows:
        sample = samples.get(row["sample_id"])
        if not sample or row["sha256"] != sample["sha256"]:
            raise ValueError("Unknown sample or stale observation hash")
        tool = row["tool"]
        if tool not in {"av", "yara"} or row["status"] not in STATUSES:
            raise ValueError("Unknown tool or observation status")
        if row["run_id"] != config["run_id"] or row["state_id"] != config[tool]["state_id"]:
            raise ValueError("Observation belongs to a different run/tool state")
        if tool == "yara" and config["yara"]["ruleset_status"] == "EMPTY":
            raise ValueError("An empty rule set has no YARA observations; Y(x)=0 for every file")
        key = (row["sample_id"], tool)
        if key in observations:
            raise ValueError("Duplicate observation: " + str(key))
        if not row["scan_id"].strip():
            raise ValueError("Missing scan ID")
        observed_at = datetime.fromisoformat(row["observed_at"].replace("Z", "+00:00"))
        if observed_at.utcoffset() is None:
            raise ValueError("Observation time must include a time zone")
        local_file(workspace, row["evidence"])
        if tool == "av" and row["status"] == "DETECTED":
            if row["detected_by"] not in DETECTED_BY:
                raise ValueError("An AV detection must name REALTIME or CUSTOM_SCAN: " + row["sample_id"])
        elif row["detected_by"]:
            raise ValueError("Only an AV detection names the check that flagged it: " + row["sample_id"])
        observations[key] = row["status"]
        if detected_by is not None and row["detected_by"]:
            detected_by[row["sample_id"]] = row["detected_by"]
    return observations


def decision(status):
    return {"DETECTED": True, "NOT_DETECTED": False}.get(status)


def combined(av, yara):
    if av is True or yara is True:
        return True
    if av is False and yara is False:
        return False
    return None


def fraction(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "rate": numerator / denominator if denominator else None}


def confusion(malicious, benign):
    """Counts and rates from (malicious decisions, benign decisions); all decisions known."""
    tp, fp = sum(malicious), sum(benign)
    fn, tn = len(malicious) - tp, len(benign) - fp
    return {"tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "recall": fraction(tp, tp + fn), "fpr": fraction(fp, fp + tn),
            # Precision is undefined without positive decisions; F1 is then zero
            # whenever malicious files exist.
            "precision": fraction(tp, tp + fp), "f1": fraction(2 * tp, 2 * tp + fp + fn)}


def _exclusion(row, samples):
    if row["kind"] == "control_copy":
        return "CONTROL_COPY"
    if row["kind"] == "benign" or eligible(row, samples):
        return None
    if row["functionality"] != "PASS":
        return "FUNCTIONALITY_" + row["functionality"]
    return "PARENT_FUNCTIONALITY_" + samples[row["parent_id"]]["functionality"]


def _original_loss_status(original, samples, av, copies):
    if original["functionality"] != "PASS":
        return "ORIGINAL_FUNCTIONALITY_" + original["functionality"], None
    a = av[original["sample_id"]]
    if a is None:
        return "ORIGINAL_INCOMPLETE", None
    if a is False:
        return "ORIGINAL_NOT_DETECTED", None
    copy = copies.get(original["sample_id"])
    if copy is None:
        return "CONTROL_COPY_MISSING", None
    reproducible = "IDENTICAL" if copy["sha256"] == original["sha256"] else "DIFFERENT"
    c = av[copy["sample_id"]]
    if reproducible == "IDENTICAL":
        # Same bytes: the original's response stands; a valid contrary response is a conflict.
        return ("CONTROL_COPY_CONFLICT" if c is False else "ELIGIBLE"), reproducible
    if c is None:
        return "CONTROL_COPY_INCOMPLETE", reproducible
    return ("ELIGIBLE" if c else "CONTROL_COPY_NOT_DETECTED"), reproducible


def detection_loss(samples, av):
    """Loss L over both splits: AV describes the antivirus, not the rules."""
    copies = {row["parent_id"]: row for row in samples.values() if row["kind"] == "control_copy"}
    by_original, excluded, variant_status = {}, Counter(), {}
    for original in samples.values():
        if original["kind"] != "original":
            continue
        status, reproducible = _original_loss_status(original, samples, av, copies)
        lost = included = 0
        for row in samples.values():
            if row["kind"] != "variant" or row["parent_id"] != original["sample_id"]:
                continue
            if not eligible(row, samples):
                reason = "VARIANT_NOT_FUNCTIONAL"
            elif status != "ELIGIBLE":
                reason = status
            elif av[row["sample_id"]] is None:
                reason = "VARIANT_INCOMPLETE"
            else:
                reason = "INCLUDED"
                included += 1
                lost += av[row["sample_id"]] is False
            variant_status[row["sample_id"]] = reason
            if reason != "INCLUDED":
                excluded[reason] += 1
        by_original[original["sample_id"]] = {
            "split": original["split"], "status": status, "control_copy": reproducible or
            ("MISSING" if original["sample_id"] not in copies else None),
            "loss": fraction(lost, included)}
    pooled = fraction(sum(v["loss"]["numerator"] for v in by_original.values()),
                      sum(v["loss"]["denominator"] for v in by_original.values()))
    return {"pooled": pooled, "by_original": by_original,
            "excluded_variants": dict(sorted(excluded.items()))}, variant_status


def _bounds(files, decide):
    """Recall/FPR with every missing response read first as 0, then as 1."""
    result = {}
    for name, fill in (("missing_as_not_detected", False), ("missing_as_detected", True)):
        malicious = [decide(row, fill) for row in files if row["kind"] != "benign"]
        benign = [decide(row, fill) for row in files if row["kind"] == "benign"]
        counts = confusion(malicious, benign)
        result[name] = {"recall": counts["recall"], "fpr": counts["fpr"]}
    return result


def supplementation(samples, av, yara, ruleset_status):
    files = [row for row in samples.values()
             if row["split"] == "evaluation" and row["kind"] != "control_copy" and eligible(row, samples)]
    paired = [row for row in files if av[row["sample_id"]] is not None and yara[row["sample_id"]] is not None]
    paired_ids = {row["sample_id"] for row in paired}
    pick = {"av": lambda r: av[r["sample_id"]], "yara": lambda r: yara[r["sample_id"]],
            "combined": lambda r: av[r["sample_id"]] or yara[r["sample_id"]]}
    result = {"status": "EVALUATED", "ruleset_status": ruleset_status,
              "class_sizes": {"malicious": sum(r["kind"] != "benign" for r in paired),
                              "benign": sum(r["kind"] == "benign" for r in paired)},
              "paired_records": len(paired),
              "incomplete_ids": sorted(r["sample_id"] for r in files if r["sample_id"] not in paired_ids),
              "tools": {}}
    if not paired:
        return {"status": "NOT_EVALUATED", "reason": "NO_PAIRED_RECORDS", "ruleset_status": ruleset_status,
                "paired_records": 0, "incomplete_ids": result["incomplete_ids"]}
    benign = [r for r in paired if r["kind"] == "benign"]
    for tool, value in pick.items():
        overall = confusion([value(r) for r in paired if r["kind"] != "benign"], [value(r) for r in benign])
        overall["recall_by_kind"] = {
            kind: confusion([value(r) for r in paired if r["kind"] == kind], [])["recall"]
            for kind in ("original", "variant")}
        result["tools"][tool] = overall
    added = [r for r in paired if av[r["sample_id"]] is False and yara[r["sample_id"]] is True]
    result["additional_detections"] = {
        "all": sum(r["kind"] != "benign" for r in added),
        "original": sum(r["kind"] == "original" for r in added),
        "variant": sum(r["kind"] == "variant" for r in added)}
    result["additional_false_positives"] = sum(r["kind"] == "benign" for r in added)

    def fill(value, default):
        return default if value is None else value
    result["bounds"] = {
        "av": _bounds(files, lambda r, d: fill(av[r["sample_id"]], d)),
        "yara": _bounds(files, lambda r, d: fill(yara[r["sample_id"]], d)),
        "combined": _bounds(files, lambda r, d: fill(av[r["sample_id"]], d) or fill(yara[r["sample_id"]], d))}
    return result


def holdout_rules(samples, yara, ruleset_status):
    rows = [row for row in samples.values() if row["holdout"]]
    if ruleset_status == "FAILED":
        return {"status": "NOT_EVALUATED", "reason": "RULESET_FAILED", "ids": sorted(r["sample_id"] for r in rows)}
    valid = [row for row in rows if yara[row["sample_id"]] is not None]
    return {"status": "EVALUATED", "ids": sorted(r["sample_id"] for r in rows),
            "detected": fraction(sum(yara[r["sample_id"]] for r in valid), len(valid)),
            "incomplete_ids": sorted(r["sample_id"] for r in rows if yara[r["sample_id"]] is None)}


def summarize(samples, observations, ruleset_status="FROZEN", detected_by=None):
    if ruleset_status not in RULESET_STATUSES:
        raise ValueError("Unknown rule-set status")
    status = {(key, tool): observations.get((key, tool), "NOT_RUN") for key in samples for tool in ("av", "yara")}
    if ruleset_status == "EMPTY":
        status.update({(key, "yara"): "EMPTY_RULESET" for key in samples})
    av = {key: decision(status[(key, "av")]) for key in samples}
    if ruleset_status == "EMPTY":
        yara = {key: False for key in samples}
    elif ruleset_status == "FAILED":
        yara = {key: None for key in samples}
    else:
        yara = {key: decision(status[(key, "yara")]) for key in samples}
    loss, variant_loss = detection_loss(samples, av)
    # Final rule evaluation needs independent original groups in both splits.
    groups = {split: {r["project_id"] for r in samples.values()
                      if r["kind"] == "original" and r["functionality"] == "PASS" and r["split"] == split}
              for split in SPLITS}
    unevaluated = ("RULESET_FAILED" if ruleset_status == "FAILED" else
                   "INDEPENDENT_GROUPS_MISSING" if not all(groups.values()) else None)
    if unevaluated:
        supplement = {"status": "NOT_EVALUATED", "reason": unevaluated, "ruleset_status": ruleset_status,
                      "original_groups": {split: len(groups[split]) for split in SPLITS}}
    else:
        supplement = supplementation(samples, av, yara, ruleset_status)
        supplement["original_groups"] = {split: len(groups[split]) for split in SPLITS}
    paired_ids = set() if unevaluated else {
        r["sample_id"] for r in samples.values()
        if r["split"] == "evaluation" and r["kind"] != "control_copy" and eligible(r, samples)
        and av[r["sample_id"]] is not None and yara[r["sample_id"]] is not None}
    rows = []
    for key, row in sorted(samples.items()):
        exclusion = _exclusion(row, samples)
        if row["kind"] == "control_copy":
            comparison = "CONTROL_COPY"
        elif row["split"] != "evaluation":
            comparison = "CALIBRATION_SPLIT"
        elif exclusion:
            comparison = exclusion
        elif unevaluated:
            comparison = unevaluated
        elif key in paired_ids:
            comparison = "INCLUDED"
        else:
            comparison = "_".join(["AV"] * (av[key] is None) + ["YARA"] * (yara[key] is None)) + "_INCOMPLETE"
        rows.append({"sample_id": key, "kind": row["kind"], "split": row["split"], "holdout": row["holdout"],
                     "functionality": row["functionality"], "av_status": status[(key, "av")],
                     "av_detected_by": (detected_by or {}).get(key, ""),
                     "yara_status": status[(key, "yara")],
                     "A": av[key], "Y": yara[key], "C": combined(av[key], yara[key]),
                     "eligibility": exclusion or "ELIGIBLE", "comparison": comparison,
                     "detection_loss": variant_loss.get(key)})
    counted = [r for r in samples.values() if r["kind"] != "control_copy"]
    return {
        "registered_records": {split: dict(sorted(Counter(r["kind"] for r in samples.values()
                                                          if r["split"] == split).items())) for split in SPLITS},
        "eligible_evaluation_records": sum(r["split"] == "evaluation" and eligible(r, samples) for r in counted),
        "excluded_functionality_ids": sorted(r["sample_id"] for r in counted if not eligible(r, samples)),
        "synthetic_functionality_records": sum(r["functionality_synthetic"] is True for r in samples.values()),
        "status_counts": dict(sorted(Counter(tool + ":" + status[(r["sample_id"], tool)]
                                             for r in counted for tool in ("av", "yara")).items())),
        "supplementation": supplement,
        "detection_loss": loss,
        "holdout_rules": holdout_rules(samples, yara, ruleset_status),
        "rows": rows,
    }


def _rate_text(value):
    if not value["denominator"] or value["rate"] is None:
        return "{}/{} (neapibrėžta)".format(value["numerator"], value["denominator"])
    return "{}/{} ({:.1f}\\,\\%)".format(value["numerator"], value["denominator"],
                                        100 * value["rate"]).replace(".", ",")


def tables(report):
    """CSV and LaTeX fragments; every rate keeps its numerator and denominator."""
    out = {}
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    columns = ("sample_id", "kind", "split", "holdout", "functionality", "av_status", "av_detected_by",
               "yara_status", "A", "Y", "C", "eligibility", "comparison", "detection_loss")
    writer.writerow(columns)
    for row in report["rows"]:
        writer.writerow([row[k] if row[k] is not None else "" for k in columns])
    out["rows.csv"] = stream.getvalue()
    stream = io.StringIO()
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(["original_id", "split", "status", "control_copy", "lost", "eligible_variants", "rate"])
    for key, value in sorted(report["detection_loss"]["by_original"].items()):
        loss = value["loss"]
        writer.writerow([key, value["split"], value["status"], value["control_copy"] or "",
                         loss["numerator"], loss["denominator"], "" if loss["rate"] is None else loss["rate"]])
    pooled = report["detection_loss"]["pooled"]
    writer.writerow(["ALL", "", "", "", pooled["numerator"], pooled["denominator"],
                     "" if pooled["rate"] is None else pooled["rate"]])
    out["detection_loss.csv"] = stream.getvalue()
    supplement = report["supplementation"]
    if supplement["status"] == "EVALUATED":
        stream = io.StringIO()
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(["tool", "metric", "numerator", "denominator", "rate"])
        names = {"av": "Antivirusinė", "yara": "YARA", "combined": "Derinys"}
        lines = []
        for tool, value in supplement["tools"].items():
            for metric in ("recall", "fpr", "precision", "f1"):
                item = value[metric]
                writer.writerow([tool, metric, item["numerator"], item["denominator"],
                                 "" if item["rate"] is None else item["rate"]])
            lines.append(" & ".join([names[tool]] + [_rate_text(value[m]) for m in ("recall", "fpr", "precision", "f1")])
                         + " \\\\")
        out["supplementation.csv"] = stream.getvalue()
        sizes = supplement["class_sizes"]
        out["supplementation.tex"] = (
            "% Generated by Project Aegis accounting. Class sizes: malicious {}, benign {}.\n".format(
                sizes["malicious"], sizes["benign"])
            + "Priemonė & Jautrumas & FPR & Preciziškumas & $F_1$ \\\\\n\\midrule\n" + "\n".join(lines) + "\n")
    return out


def research_evidence(config, samples, rows, workspace):
    """Research mode: every observation must be what a validated report says.

    Returns the tool versions recorded in the evidence. Checks the freeze
    record, the rule-set hash, non-synthetic functionality records and that
    AV checks of evaluation variants and benign files began after freezing.
    """
    import run_guard
    import scan_bridge
    if any(row["functionality_synthetic"] is True for row in samples.values()):
        raise ValueError("Research accounting refuses synthetic functionality records")
    yara = config["yara"]
    if not yara.get("freeze_record"):
        raise ValueError("Research mode needs yara.freeze_record")
    record, _ = run_guard.load_freeze(workspace, yara["freeze_record"])
    if record["run_id"] != config["run_id"]:
        raise ValueError("Freeze record belongs to a different run")
    if record["status"] != yara["ruleset_status"] or record["ruleset_sha256"] != yara.get("ruleset_sha256"):
        raise ValueError("Configuration rule-set status or hash differs from the freeze record")
    if not config.get("series"):
        raise ValueError("Research mode needs the run's detector series record")
    series = scan_bridge.load_series(workspace, config["series"])
    if series["run_id"] != config["run_id"]:
        raise ValueError("Detector series belongs to a different run")
    split = scan_bridge.segments(series["reports"], workspace, config["run_id"])
    frozen_at = datetime.fromisoformat(record["frozen_at_utc"].replace("Z", "+00:00"))
    by_evidence = defaultdict(list)
    for row in rows:
        by_evidence[row["evidence"]].append(row)
    used = {"av": set(), "yara": set()}
    for row in rows:
        used[row["tool"]].add(row["evidence"])
    for tool in ("av", "yara"):
        named = config[tool].get("segment_id")
        if not (used[tool] or named or split[tool]):
            continue  # This tool produced no reports in the run, and none are claimed.
        if not config[tool].get("state_id"):
            raise ValueError("A tool with reports in the run needs a state ID: " + tool)
        chosen = [seg for seg in split[tool] if seg["segment_id"] == named]
        if not chosen:
            raise ValueError("Configuration must name one " + tool + " segment of the detector series")
        # Checked even when no row of this tool is listed: a named segment cannot be dropped.
        if set(chosen[0]["reports"]) != used[tool]:
            raise ValueError("Evidence must be exactly the reports of the named " + tool + " segment")
    versions = {"av": [], "yara": []}
    for relative, listed in by_evidence.items():
        report = scan_bridge.load_report(workspace, relative)
        if report["run_id"] != config["run_id"]:
            raise ValueError("Evidence belongs to a different run: " + relative)
        expected = scan_bridge.report_rows(report, relative, config["run_id"])
        key = lambda r: (r["sample_id"], r["tool"])
        if sorted(map(json.dumps, sorted(expected, key=key))) != sorted(map(json.dumps, sorted(listed, key=key))):
            raise ValueError("Observation rows differ from their evidence report: " + relative)
        tool, recorded = scan_bridge.tool_versions(report)
        versions[tool].append(recorded)
        if tool == "yara":
            if report["ruleset_sha256"] != record["ruleset_sha256"]:
                raise ValueError("YARA evidence used a rule set other than the frozen one: " + relative)
            if report["yara_version"] != record["yara_version"]:
                raise ValueError("YARA evidence used another YARA version than the freeze record: " + relative)
            started = datetime.fromisoformat(report["started_at_utc"].replace("Z", "+00:00"))
            if started < frozen_at:
                raise ValueError("YARA check with the frozen rule set began before freezing: " + relative)
        if tool == "av" and run_guard.needs_final_rules(samples[report["sample_id"]]):
            started = datetime.fromisoformat(report["started_at_utc"].replace("Z", "+00:00"))
            if started < frozen_at:
                raise ValueError("AV check of an evaluation variant or benign file began before the rule set "
                                 "was final: " + report["sample_id"])
    return {tool: values[0] if values else None for tool, values in versions.items()}


def run(config_path, manifest_path, observations_path):
    config_path = external_path(config_path)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    mode = config.get("mode")
    if mode not in {"control", "research"} or not config.get("run_id"):
        raise ValueError("Accounting accepts explicitly labelled control or research runs only")
    if mode == "research" and not config.get("protocol_version"):
        raise ValueError("Research mode needs a protocol version")
    for tool in ("av", "yara"):
        if not isinstance(config.get(tool), dict):
            raise ValueError("Missing tool configuration: " + tool)
        # Research mode may leave a tool without a state when it produced nothing
        # in the run (e.g. no YARA for an EMPTY or FAILED rule set); that is checked
        # against the detector series.
        if not config[tool].get("state_id") and mode != "research":
            raise ValueError("Missing tool state ID: " + tool)
    ruleset_status = config["yara"].get("ruleset_status")
    if ruleset_status not in RULESET_STATUSES:
        raise ValueError("YARA rule-set status must be FROZEN, EMPTY or FAILED. Configurations made "
                         "before schema 2 lack yara.ruleset_status: recreate the control demonstration")
    workspace = external_path(config_path.parent / config["workspace"])
    collection = config.get("collection_root")
    collection = external_path(config_path.parent / collection) if collection else None
    samples = validate_samples(read_csv(external_path(manifest_path), SAMPLE_FIELDS), workspace, collection)
    rows = read_csv(external_path(observations_path), OBSERVATION_FIELDS)
    detected_by = {}
    observations = validate_observations(rows, samples, config, workspace, detected_by)
    if mode == "research":
        tool_states = research_evidence(config, samples, rows, workspace)
        notice = ("Research accounting from validated detector reports. Review the evidence and the "
                  "segments before reporting results.")
    else:
        tool_states = {tool: config[tool] for tool in ("av", "yara")}
        notice = "Accounting check only. Supplied detector responses are simulated; no AV or YARA ran."
    return {"run_id": config["run_id"], "mode": mode, "experiment_results": mode == "research",
            "notice": notice, "code_sha256": digest(Path(__file__)),
            "protocol_version": config.get("protocol_version"),
            "config_sha256": digest(config_path), "manifest_sha256": digest(Path(manifest_path)),
            "observations_sha256": digest(Path(observations_path)),
            "tool_states": tool_states,
            **summarize(samples, observations, ruleset_status, detected_by)}


def write_tables(report, directory):
    directory = external_path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    for name, content in tables(report).items():
        with (directory / name).open("x", encoding="utf-8", newline="") as stream:
            stream.write(content)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--observations", required=True)
    parser.add_argument("--output")
    parser.add_argument("--tables", help="new directory outside the repository for CSV/LaTeX tables")
    args = parser.parse_args(argv)
    try:
        report = run(args.config, args.manifest, args.observations)
        content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            with external_path(args.output).open("x", encoding="utf-8") as stream:
                stream.write(content)
        else:
            print(content, end="")
        if args.tables:
            write_tables(report, args.tables)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print("Control accounting failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
