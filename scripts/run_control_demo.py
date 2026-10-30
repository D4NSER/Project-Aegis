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
    samples, observations = [], []
    timestamp = datetime.now(timezone.utc).isoformat()
    for index, (split, av, yara) in enumerate([
        ("calibration", "NOT_DETECTED", "NOT_DETECTED"),
        ("evaluation", "NOT_DETECTED", "NOT_DETECTED"),
        ("evaluation", "NOT_DETECTED", "DETECTED"),
        ("evaluation", "NOT_DETECTED", "NOT_RUN"),
    ], start=1):
        name = "control-{:02d}".format(index)
        relative = "controls/" + name + ".txt"
        (output / relative).write_text("Inert Project Aegis accounting control " + name + "\n", encoding="utf-8")
        sha = aegis.digest(output / relative)
        samples.append(dict(zip(aegis.SAMPLE_FIELDS, [
            name, name, "", split, "benign", "", sha, relative, "NOT_APPLICABLE",
            "locally generated inert text", "control-v1", "Known inert UTF-8 content", "text", "none",
        ])))
        for tool, status in (("av", av), ("yara", yara)):
            observations.append(dict(zip(aegis.OBSERVATION_FIELDS, [
                config["run_id"], name, sha, tool, status, config[tool]["state_id"],
                "simulated-" + name + "-" + tool, timestamp, "evidence/simulation.txt",
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
    print("Control accounting passed: {} registered evaluation records, {} paired; simulated responses only."
          .format(report["registered_evaluation_records"], report["paired_records"]))


if __name__ == "__main__":
    main()
