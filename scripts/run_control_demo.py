"""Create inert text controls and explicitly simulated detector observations."""
import argparse
import csv
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import aegis


def write_csv(path, fields, rows):
    with path.open("x", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def create_demo(output):
    output = aegis.external_path(output)
    output.mkdir(parents=True, exist_ok=False)
    (output / "controls").mkdir()
    (output / "evidence").mkdir()
    note = "Synthetic accounting responses only. Neither Defender nor YARA was run. All objects are inert text.\n"
    (output / "evidence/simulation.txt").write_text(note, encoding="utf-8")
    config = json.loads((aegis.ROOT / "config/control.example.json").read_text(encoding="utf-8"))
    (output / "run.json").write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    card = "Synthetic functionality card for the accounting demonstration; nothing is executed.\n"
    (output / "evidence/demo-card.txt").write_text(card, encoding="utf-8")
    card_sha = aegis.digest(output / "evidence/demo-card.txt")
    samples, observations = [], []
    timestamp = datetime.now(timezone.utc).isoformat()
    # Rows 5-6 carry a synthetic "original" label so that the supplementation
    # scenario has one independent group per split; they are inert text too.
    for index, (split, kind, av, yara) in enumerate([
        ("calibration", "benign", "NOT_DETECTED", "NOT_DETECTED"),
        ("evaluation", "benign", "NOT_DETECTED", "NOT_DETECTED"),
        ("evaluation", "benign", "NOT_DETECTED", "DETECTED"),
        ("evaluation", "benign", "NOT_DETECTED", "NOT_RUN"),
        ("calibration", "original", "DETECTED", "NOT_RUN"),
        ("evaluation", "original", "NOT_DETECTED", "DETECTED"),
    ], start=1):
        name = "control-{:02d}".format(index)
        relative = "controls/" + name + ".txt"
        (output / relative).write_text("Inert Project Aegis accounting control " + name + "\n", encoding="utf-8")
        sha = aegis.digest(output / relative)
        family, functionality, card_hash, evidence = "", "NOT_APPLICABLE", "", ""
        label = "Known inert UTF-8 content"
        if kind == "original":
            family, functionality, card_hash = "synthetic-family", "PASS", card_sha
            evidence = "evidence/functionality-" + name + ".json"
            label = "SYNTHETIC label on inert UTF-8 content; accounting arithmetic only"
            (output / evidence).write_text(json.dumps({
                "schema": 1, "kind": "functionality_record", "record_id": "simulated-card-" + name,
                "sample_sha256": sha, "card_sha256": card_sha, "status": "PASS", "synthetic": True}) + "\n",
                encoding="utf-8")
        samples.append(dict(zip(aegis.SAMPLE_FIELDS, [
            name, name, family, split, kind, "", "", "", sha, relative, functionality, card_hash, evidence,
            "locally generated inert text", "control-v1", label, "text", "none",
        ])))
        for tool, status in (("av", av), ("yara", yara)):
            observations.append(dict(zip(aegis.OBSERVATION_FIELDS, [
                config["run_id"], name, sha, tool, status, config[tool]["state_id"],
                "simulated-" + name + "-" + tool, timestamp, "evidence/simulation.txt",
                "CUSTOM_SCAN" if tool == "av" and status == "DETECTED" else "",
            ])))
    write_csv(output / "manifest.csv", aegis.SAMPLE_FIELDS, samples)
    write_csv(output / "observations.csv", aegis.OBSERVATION_FIELDS, observations)
    report = aegis.run(output / "run.json", output / "manifest.csv", output / "observations.csv")
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="new working directory outside the public repository")
    args = parser.parse_args()
    try:
        report = create_demo(args.output)
    except (ValueError, OSError) as exc:
        parser.exit(1, str(exc) + "\n")
    print("Control accounting passed: {} eligible evaluation records, {} paired; simulated responses only."
          .format(report["eligible_evaluation_records"], report["supplementation"]["paired_records"]))


if __name__ == "__main__":
    main()
