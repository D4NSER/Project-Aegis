"""Execution guard: what may be checked, and when, before a guest request is made.

Evaluation variants and benign files may go to the AV only after the rule
set is final, so that their responses are unknown while rules are prepared.
Originals' baseline AV checks, calibration checks and YARA checks of the
calibration split may run earlier. Final means a stored freeze record with
status FROZEN, EMPTY or FAILED; a FROZEN record also needs its rule-set file
to match its hash. The guard builds the guest request only when allowed.
"""
from datetime import datetime
import hashlib
import json
from pathlib import Path

import aegis
import rule_workflow

FREEZE_FIELDS = {"schema", "kind", "run_id", "status", "reason", "frozen_at_utc", "yara_version", "ruleset_sha256",
                 "targets", "unknown_av_targets", "undecided_targets", "incomplete_rules", "rules"}


def write_freeze(workspace, directory, text, record):
    """Store a freeze record and, for FROZEN, its rule-set file; never overwrite."""
    folder = aegis.external_path(Path(workspace) / directory)
    folder.mkdir(parents=True, exist_ok=False)
    if record["status"] == "FROZEN":
        with (folder / "frozen.yar").open("x", encoding="utf-8", newline="") as stream:
            stream.write(text)
    with (folder / "freeze.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    return folder


def load_freeze(workspace, relative, run_id=None):
    """A final freeze record of this run; a FROZEN one is verified against its rule-set file."""
    workspace = aegis.external_path(workspace)
    path = aegis.local_file(workspace, relative)
    record = json.loads(path.read_text(encoding="utf-8"))
    if (not isinstance(record, dict) or set(record) != FREEZE_FIELDS or record["kind"] != "ruleset_freeze"
            or record["status"] not in aegis.RULESET_STATUSES):
        raise ValueError("Invalid freeze record: " + relative)
    if datetime.fromisoformat(str(record["frozen_at_utc"]).replace("Z", "+00:00")).utcoffset() is None:
        raise ValueError("Freeze time must include a time zone")
    if run_id is not None and record["run_id"] != run_id:
        raise ValueError("Freeze record belongs to a different run: " + relative)
    if record["status"] == "FROZEN":
        rule_workflow.verify_frozen(path.with_name("frozen.yar"), record)
    elif record["ruleset_sha256"] is not None:
        raise ValueError("Only a FROZEN record names a rule-set hash")
    return record, hashlib.sha256(path.read_bytes()).hexdigest()


def needs_final_rules(row):
    """Evaluation variants and benign files wait for the final rule set."""
    return row["split"] == "evaluation" and row["kind"] in {"variant", "benign"}


def prepare_av_request(samples, sample_id, *, run_id, wait_seconds, workspace, freeze=None):
    """The one-file guest AV request, or a refusal when the order would be broken."""
    row = samples.get(sample_id)
    if row is None:
        raise ValueError("Unknown sample: " + str(sample_id))
    if type(wait_seconds) not in (int, float) or wait_seconds <= 0:
        raise ValueError("The calibrated waiting period must be a positive number of seconds")
    authorization = None
    if needs_final_rules(row):
        if freeze is None:
            raise ValueError("Evaluation variants and benign files go to the AV only after the rule set is final: "
                             + sample_id)
        record, record_sha = load_freeze(workspace, freeze, run_id)
        authorization = {"freeze_record": freeze, "freeze_record_sha256": record_sha,
                         "freeze_status": record["status"], "frozen_at_utc": record["frozen_at_utc"]}
    return {"schema": 1, "kind": "av_check", "run_id": run_id, "wait_seconds": wait_seconds,
            "authorization": authorization,
            "files": [{"sample_id": sample_id, "sha256": row["sha256"], "path": "files/" + sample_id + ".bin"}]}


def prepare_yara_request(samples, sample_ids, *, run_id, yara_sha256, workspace, freeze):
    """A YARA batch with the frozen rule set; evaluation files need the final set too."""
    record, record_sha = load_freeze(workspace, freeze, run_id)
    if record["status"] != "FROZEN":
        raise ValueError("Only a FROZEN rule set is applied; EMPTY means Y(x)=0, FAILED means not evaluated")
    files = []
    for sample_id in sample_ids:
        row = samples.get(sample_id)
        if row is None:
            raise ValueError("Unknown sample: " + str(sample_id))
        files.append({"sample_id": sample_id, "sha256": row["sha256"], "path": "files/" + sample_id + ".bin"})
    return {"schema": 1, "kind": "yara_check", "run_id": run_id, "yara_sha256": yara_sha256,
            "ruleset_sha256": record["ruleset_sha256"],
            "authorization": {"freeze_record": freeze, "freeze_record_sha256": record_sha,
                              "freeze_status": record["status"], "frozen_at_utc": record["frozen_at_utc"]},
            "files": files}
