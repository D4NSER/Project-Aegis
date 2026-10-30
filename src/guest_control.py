"""Guest-side inert transfer check. This does not scan or execute samples.

The work and mutation marker deliberately remain for a later, independently
verified VM restore. Running this module never claims that restore happened.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re

import control_workspace
from control_workspace import CONTROLS, MARKER, write_json


def plain_path(path):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        if part.is_symlink() or getattr(part, "is_junction", lambda: False)():
            raise ValueError("Control paths must not contain links or junctions")
    return path


def read_request(root):
    root = plain_path(root)
    request = plain_path(root / "request.json")
    if not request.is_file() or request.stat().st_size > 4096:
        raise ValueError("Oversized control request")
    with request.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict) or set(value) != {"schema", "run_id", "nonce", "selected"}:
        raise ValueError("Unexpected request fields")
    if type(value["schema"]) is not int or value["schema"] != 1:
        raise ValueError("Unsupported control schema")
    if not isinstance(value["run_id"], str) or not re.fullmatch(r"guest-control-[0-9a-f]{32}", value["run_id"]):
        raise ValueError("Invalid control run ID")
    if root.name != value["run_id"]:
        raise ValueError("Run folder identity mismatch")
    if not isinstance(value["nonce"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["nonce"]):
        raise ValueError("Invalid control nonce")
    selected = value["selected"]
    if (not isinstance(selected, list) or not selected
            or any(not isinstance(key, str) or key not in CONTROLS for key in selected)
            or len(set(selected)) != len(selected)):
        raise ValueError("Choose distinct registered inert controls")
    expected = {"request.json", *(key + ".txt" for key in selected)}
    if {entry.name for entry in root.iterdir()} != expected:
        raise ValueError("Unexpected files or a previously used run folder")
    for entry in root.iterdir():
        if plain_path(entry) != entry or not entry.is_file():
            raise ValueError("Unexpected control entry")
    for key in selected:
        path = root / (key + ".txt")
        expected_content = CONTROLS[key][1]
        if path.stat().st_size != len(expected_content) or path.read_bytes() != expected_content:
            raise ValueError("Transferred control content mismatch")
    return root, value, hashlib.sha256(request.read_bytes()).hexdigest()


def run_control(root):
    root, request, request_hash = read_request(root)
    rows = []
    for key in request["selected"]:
        content = (root / (key + ".txt")).read_bytes()
        rows.append({"id": key, "bytes": len(content),
                     "sha256": hashlib.sha256(content).hexdigest(),
                     "hash_verified": True, "literal_marker_found": MARKER in content,
                     "av_status": "NOT_RUN", "yara_status": "NOT_RUN"})
    # No cleanup here: the host must prove that a VM restore removes this marker.
    write_json(root / "mutation.json", {"run_id": request["run_id"], "nonce": request["nonce"]})
    report = {"schema": 1, "run_id": request["run_id"], "nonce": request["nonce"],
              "created_at_utc": datetime.now(timezone.utc).isoformat(),
              "mode": "guest_inert_transfer_control", "experiment_results": False,
              "platform": platform.system(), "architecture": platform.machine(),
              "python_version": platform.python_version(), "request_sha256": request_hash,
              "code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
              "controls_code_sha256": hashlib.sha256(Path(control_workspace.__file__).read_bytes()).hexdigest(),
              "marker_engine": "literal byte comparison; not YARA",
              "vm_restore_verified": False, "mutation_marker_created": True,
              "work_cleanup_performed": False, "files": rows}
    write_json(root / "guest-report.json", report)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", required=True)
    args = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("Guest command must run in Windows; host unit tests are not VM evidence")
    run_control(args.run_root)


if __name__ == "__main__":
    main()
