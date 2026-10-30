"""Bounded, inert-only guest metadata messages. Guest data never supplies paths."""
import base64
from datetime import datetime
import hashlib
import json
import re

from control_workspace import CONTROLS, MARKER

MAX_MESSAGE = 16000


class StaleControlMessage(ValueError):
    """A prior, well-formed challenge has no authority in the current phase."""


def encode_message(value):
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > MAX_MESSAGE:
        raise ValueError("Control message is too large")
    return base64.b64encode(raw).decode("ascii")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate message field")
        value[key] = item
    return value


def decode_message(encoded, *, request, challenge, source_hashes):
    if not isinstance(encoded, str) or len(encoded) > 22000:
        raise ValueError("Control message exceeds transport limit")
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) > MAX_MESSAGE:
            raise ValueError("Control message exceeds content limit")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeError, json.JSONDecodeError, base64.binascii.Error) as exc:
        raise ValueError("Invalid control message encoding") from exc
    fields = {"schema", "phase", "challenge", "run_id", "nonce", "message_id", "platform",
              "architecture", "app_sha256", "run_root_exists", "mutation_exists", "network_up", "report"}
    if not isinstance(value, dict) or set(value) != fields or type(value["schema"]) is not int or value["schema"] != 1:
        raise ValueError("Unexpected control message schema")
    if value["phase"] not in {"ready", "complete"}:
        raise ValueError("Unexpected control phase")
    if not isinstance(value["challenge"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["challenge"]):
        raise ValueError("Invalid response challenge")
    if value["challenge"] != challenge:
        raise StaleControlMessage("Stale or foreign control challenge")
    if value["run_id"] != request["run_id"] or value["nonce"] != request["nonce"]:
        raise ValueError("Foreign control request")
    if not isinstance(value["message_id"], str) or not re.fullmatch(r"[0-9a-f]{32}", value["message_id"]):
        raise ValueError("Invalid control message identity")
    if (value["platform"] != "Windows" or not isinstance(value["architecture"], str)
            or value["architecture"].casefold() not in {"arm64", "aarch64"}):
        raise ValueError("Expected the prepared Windows ARM guest")
    if value["app_sha256"] != source_hashes["guest_control_app.py"]:
        raise ValueError("Guest application version mismatch")
    if any(type(value[field]) is not bool for field in ("run_root_exists", "mutation_exists")):
        raise ValueError("Invalid control existence flags")
    if value["network_up"] is not None and type(value["network_up"]) is not bool:
        raise ValueError("Invalid guest network observation")
    report = value["report"]
    if value["phase"] == "ready":
        if report is not None:
            raise ValueError("Ready message must not claim a completed control")
        return value
    if not value["run_root_exists"] or not value["mutation_exists"] or not isinstance(report, dict):
        raise ValueError("Completed control lacks its mutation marker")
    expected_report_fields = {"schema", "run_id", "nonce", "created_at_utc", "mode", "experiment_results",
        "platform", "architecture", "python_version", "request_sha256", "code_sha256", "controls_code_sha256",
        "marker_engine", "vm_restore_verified", "mutation_marker_created", "work_cleanup_performed", "files"}
    if set(report) != expected_report_fields or type(report["schema"]) is not int or report["schema"] != 1:
        raise ValueError("Unexpected guest report schema")
    if (report["run_id"] != request["run_id"] or report["nonce"] != request["nonce"]
            or report["mode"] != "guest_inert_transfer_control" or report["platform"] != "Windows"
            or report["architecture"] != value["architecture"]):
        raise ValueError("Guest report identity mismatch")
    for field, expected in (("experiment_results", False), ("vm_restore_verified", False),
                            ("work_cleanup_performed", False), ("mutation_marker_created", True)):
        if report[field] is not expected:
            raise ValueError("Guest report exceeded the inert-control scope")
    if (report["request_sha256"] != source_hashes["request.json"]
            or report["code_sha256"] != source_hashes["guest_control.py"]
            or report["controls_code_sha256"] != source_hashes["control_workspace.py"]):
        raise ValueError("Guest report source identity mismatch")
    if (not isinstance(report["python_version"], str)
            or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", report["python_version"])
            or report["marker_engine"] != "literal byte comparison; not YARA"):
        raise ValueError("Invalid guest tool description")
    try:
        if datetime.fromisoformat(report["created_at_utc"]).utcoffset() is None:
            raise ValueError("Timestamp has no offset")
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid guest timestamp") from exc
    rows = report["files"]
    if not isinstance(rows, list) or len(rows) != len(request["selected"]):
        raise ValueError("Wrong number of guest controls")
    for key, row in zip(request["selected"], rows):
        content = CONTROLS[key][1]
        expected = {"id": key, "bytes": len(content), "sha256": hashlib.sha256(content).hexdigest(),
                    "hash_verified": True, "literal_marker_found": MARKER in content,
                    "av_status": "NOT_RUN", "yara_status": "NOT_RUN"}
        if row != expected or any(type(row[field]) is not bool for field in ("hash_verified", "literal_marker_found")):
            raise ValueError("Guest control content or scanner status mismatch")
    return value
