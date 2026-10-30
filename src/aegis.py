"""Control-stage manifest validation and detection-result accounting; no execution."""
import argparse
from collections import Counter
import csv
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_FIELDS = (
    "sample_id", "project_id", "family_id", "split", "kind", "parent_id",
    "sha256", "path", "functionality", "source", "source_version",
    "label_basis", "format", "architecture",
)
OBSERVATION_FIELDS = (
    "run_id", "sample_id", "sha256", "tool", "status", "state_id",
    "scan_id", "observed_at", "evidence",
)
STATUSES = {"DETECTED", "NOT_DETECTED", "ERROR", "INCONCLUSIVE", "NOT_RUN"}
SHA256 = re.compile(r"[0-9a-f]{64}")


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


def validate_samples(rows, workspace):
    by_id, hashes, groups = {}, set(), {}
    if not rows:
        raise ValueError("Manifest is empty; no data have been registered")
    for row in rows:
        sample_id = row["sample_id"]
        if not sample_id or sample_id in by_id:
            raise ValueError("Missing or duplicate sample ID: " + sample_id)
        if row["split"] not in {"calibration", "evaluation"}:
            raise ValueError("Invalid split: " + sample_id)
        if row["kind"] not in {"original", "variant", "benign"}:
            raise ValueError("Invalid sample kind: " + sample_id)
        if row["functionality"] not in {"PASS", "FAIL", "INCONCLUSIVE", "NOT_RUN", "NOT_APPLICABLE"}:
            raise ValueError("Invalid functionality status: " + sample_id)
        for field in ("project_id", "source", "source_version", "label_basis", "format", "architecture"):
            if not row[field].strip():
                raise ValueError("Missing " + field + ": " + sample_id)
        sha = row["sha256"]
        if not SHA256.fullmatch(sha) or sha in hashes:
            raise ValueError("Invalid or duplicate SHA-256: " + sample_id)
        if digest(local_file(workspace, row["path"])) != sha:
            raise ValueError("File hash mismatch: " + sample_id)
        if row["kind"] == "benign":
            if row["parent_id"] or row["family_id"] or row["functionality"] != "NOT_APPLICABLE":
                raise ValueError("Unexpected benign lineage/functionality: " + sample_id)
        elif not row["family_id"] or row["functionality"] == "NOT_APPLICABLE":
            raise ValueError("Missing malicious lineage/functionality: " + sample_id)
        if row["kind"] != "variant" and row["parent_id"]:
            raise ValueError("Only a variant can have a parent: " + sample_id)
        # Project IDs must identify common provenance, not merely file names.
        group = row["project_id"]
        if group in groups and groups[group] != row["split"]:
            raise ValueError("Project crosses calibration/evaluation: " + group)
        groups[group] = row["split"]
        hashes.add(sha)
        by_id[sample_id] = row
    for row in rows:
        if row["kind"] == "variant":
            parent = by_id.get(row["parent_id"])
            if (not parent or parent["kind"] != "original"
                    or any(parent[k] != row[k] for k in ("split", "family_id", "project_id"))):
                raise ValueError("Invalid or cross-split parent: " + row["sample_id"])
    return by_id


def validate_observations(rows, samples, config, workspace):
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
        key = (row["sample_id"], tool)
        if key in observations:
            raise ValueError("Duplicate observation: " + str(key))
        if not row["scan_id"].strip():
            raise ValueError("Missing scan ID")
        observed_at = datetime.fromisoformat(row["observed_at"].replace("Z", "+00:00"))
        if observed_at.utcoffset() is None:
            raise ValueError("Observation time must include a time zone")
        local_file(workspace, row["evidence"])
        observations[key] = row["status"]
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


def eligible(row, samples):
    if row["kind"] == "benign":
        return True
    if row["functionality"] != "PASS":
        return False
    return row["kind"] != "variant" or samples[row["parent_id"]]["functionality"] == "PASS"


def summarize(samples, observations):
    evaluation = [row for row in samples.values() if row["split"] == "evaluation"]
    included = [row for row in evaluation if eligible(row, samples)]
    outcomes, status_counts = [], Counter()
    for row in included:
        statuses = [observations.get((row["sample_id"], tool), "NOT_RUN") for tool in ("av", "yara")]
        status_counts.update(tool + ":" + status for tool, status in zip(("av", "yara"), statuses))
        av, yara = map(decision, statuses)
        outcomes.append((row, av, yara, combined(av, yara)))
    paired = [item for item in outcomes if item[1] is not None and item[3] is not None]
    report = {"registered_evaluation_records": len(evaluation), "eligible_evaluation_records": len(included),
              "excluded_functionality_ids": [row["sample_id"] for row in evaluation if not eligible(row, samples)],
              "paired_records": len(paired), "status_counts": dict(sorted(status_counts.items())),
              "missing_comparison_ids": [row["sample_id"] for row, av, _, joint in outcomes
                                         if av is None or joint is None],
              "outcomes": [{"sample_id": row["sample_id"], "av": av, "yara": yara, "combined": joint}
                           for row, av, yara, joint in outcomes]}
    for kind in ("original", "variant", "benign"):
        subset = [item for item in paired if item[0]["kind"] == kind]
        report[kind] = {"paired_records": len(subset), "projects": len({i[0]["project_id"] for i in subset}),
                        "av_positive": fraction(sum(i[1] for i in subset), len(subset)),
                        "combined_positive": fraction(sum(i[3] for i in subset), len(subset)),
                        "additional_positive": sum(i[1] is False and i[2] is True for i in subset)}
    losses = {}
    for parent in included:
        if parent["kind"] != "original":
            continue
        variants = [item for item in outcomes if item[0]["kind"] == "variant"
                    and item[0]["parent_id"] == parent["sample_id"]]
        parent_detected = decision(observations.get((parent["sample_id"], "av"))) is True
        valid = [item for item in variants if parent_detected and item[1] is not None]
        losses[parent["sample_id"]] = fraction(sum(i[1] is False for i in valid), len(valid))
    report["detection_loss_by_original"] = losses
    report["detection_loss"] = fraction(sum(v["numerator"] for v in losses.values()),
                                         sum(v["denominator"] for v in losses.values()))
    return report


def run(config_path, manifest_path, observations_path):
    config_path = external_path(config_path)
    config = json.loads(config_path.read_text(encoding="utf-8"))
    if config.get("mode") != "control" or not config.get("run_id"):
        raise ValueError("This initial implementation accepts explicitly labelled control runs only")
    for tool in ("av", "yara"):
        if not config.get(tool, {}).get("state_id"):
            raise ValueError("Missing tool state ID: " + tool)
    workspace = external_path(config_path.parent / config["workspace"])
    samples = validate_samples(read_csv(external_path(manifest_path), SAMPLE_FIELDS), workspace)
    observations = validate_observations(read_csv(external_path(observations_path), OBSERVATION_FIELDS),
                                         samples, config, workspace)
    return {"run_id": config["run_id"], "mode": "control", "experiment_results": False,
            "notice": "Accounting check only. Supplied detector responses are simulated; no AV or YARA ran.",
            "code_sha256": digest(Path(__file__)),
            "protocol_version": config.get("protocol_version"),
            "config_sha256": digest(config_path), "manifest_sha256": digest(Path(manifest_path)),
            "observations_sha256": digest(Path(observations_path)),
            "tool_states": {tool: config[tool] for tool in ("av", "yara")},
            **summarize(samples, observations)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--observations", required=True)
    parser.add_argument("--output")
    args = parser.parse_args(argv)
    try:
        report = run(args.config, args.manifest, args.observations)
        content = json.dumps(report, indent=2, ensure_ascii=False) + "\n"
        if args.output:
            with external_path(args.output).open("x", encoding="utf-8") as stream:
                stream.write(content)
        else:
            print(content, end="")
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print("Control accounting failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
