"""Real checks on fixed inert text controls; no guest or sample execution."""
from datetime import datetime, timezone
import hashlib
import json
import platform
from pathlib import Path
import re
import uuid

from aegis import external_path

CONTROLS = {
    "plain": ("Paprastas tekstas", b"Project Aegis inert text control.\n"),
    "marker": ("Tekstas su kontroliniu žymekliu", b"Project Aegis\nAEGIS_CONTROL_MARKER\n"),
    "unicode": ("Lietuviškas tekstas", "Nekenksmingas tekstas: ąčęėįšųūž.\n".encode("utf-8")),
}
MARKER = b"AEGIS_CONTROL_MARKER"


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
        stream.flush()
        import os
        os.fsync(stream.fileno())


class ControlWorkspace:
    def __init__(self, root):
        self.root = external_path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        for name in ("controls", "runs"):
            path = self.root / name
            if path.is_symlink():
                raise ValueError("Unexpected symlink in control workspace")
            path.mkdir(exist_ok=True)
        for key, (_, content) in CONTROLS.items():
            path = self.root / "controls" / (key + ".txt")
            if path.is_symlink():
                raise ValueError("Control file must not be a symlink")
            if not path.exists():
                with path.open("xb") as stream:
                    stream.write(content)
            if path.read_bytes() != content:
                raise ValueError("Control content changed: " + key)

    def run(self, selected, title=""):
        if not isinstance(title, str) or len(title.strip()) > 100 or any(ord(c) < 32 for c in title):
            raise ValueError("Patikros pavadinimas turi tilpti į 100 simbolių.")
        if not selected or len(set(selected)) != len(selected) or any(k not in CONTROLS for k in selected):
            raise ValueError("Choose one or more distinct registered controls")
        if (self.root / "recovery-required.json").exists():
            raise ValueError("A previous control requires manual recovery")
        for key in selected:
            source = self.root / "controls" / (key + ".txt")
            if source.is_symlink() or source.read_bytes() != CONTROLS[key][1]:
                raise ValueError("Control source changed: " + key)
        run_id = "control-" + uuid.uuid4().hex
        run_root = self.root / "runs" / run_id
        run_root.mkdir()
        work = run_root / "work"
        work.mkdir()
        try:
            rows = []
            for key in selected:
                content = CONTROLS[key][1]
                path = work / (key + ".txt")
                with path.open("xb") as stream:
                    stream.write(content)
                read_back = path.read_bytes()
                rows.append({"id": key, "bytes": len(read_back),
                             "sha256": hashlib.sha256(read_back).hexdigest(),
                             "hash_verified": read_back == content,
                             "literal_marker_found": MARKER in read_back,
                             "av_status": "NOT_RUN", "yara_status": "NOT_RUN"})
            report = {"run_id": run_id, "created_at_utc": datetime.now(timezone.utc).isoformat(),
                      "title": title.strip(),
                      "mode": "inert_text_control", "experiment_results": False,
                      "execution_environment": "local_control_process",
                      "platform": platform.system(),
                      "code_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      "marker_engine": "literal byte comparison; not YARA",
                      "vm_restore_verified": False, "files": rows}
            # Persist results before removing even disposable working files.
            write_json(run_root / "report.json", report)
            self.clean_work(run_root, selected)
            write_json(run_root / "completion.json", {"work_cleanup_verified": not work.exists(),
                                                       "vm_restore_verified": False})
            return run_root, report
        except Exception as exc:
            recovery = self.root / "recovery-required.json"
            if not recovery.exists():
                write_json(recovery, {"run_id": run_id, "error_type": type(exc).__name__})
            raise

    def clean_work(self, run_root, selected):
        if (run_root.parent != self.root / "runs" or run_root.is_symlink()
                or not re.fullmatch(r"control-[0-9a-f]{32}", run_root.name)):
            raise ValueError("Refusing to clean an unowned run")
        work = run_root / "work"
        expected = {key + ".txt" for key in selected}
        if work.is_symlink() or not work.is_dir() or {p.name for p in work.iterdir()} != expected:
            raise ValueError("Unexpected control work directory")
        files = list(work.iterdir())
        for path in files:
            if path.is_symlink() or not path.is_file():
                raise ValueError("Unexpected work file")
        for path in files:
            path.unlink()
        work.rmdir()

    def recent_runs(self):
        return sorted(self.root.glob("runs/control-*/report.json"), key=lambda p: p.stat().st_mtime, reverse=True)
