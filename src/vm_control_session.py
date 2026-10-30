"""Human-launched guest controls with result-before-restore enforcement."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import uuid

from aegis import external_path
from control_channel import decode_message, encode_message, StaleControlMessage
from control_workspace import write_json
from guest_control_app import load_media
from guest_control import plain_path
from vm_results import read_record,validate_cycle
from fusion_control import ManualBootRequired


def now():
    return datetime.now(timezone.utc).isoformat()


class ManualControlSession:
    def __init__(self, connection, media, workspace, vmx, *, account_ready=False, probe=None,
                 free_bytes=None, windows_credentials_used=False):
        self.connection = connection
        _, _, self.request, manifest = load_media(media)
        self.source_hashes = manifest["source_hashes"]
        self.vmx = Path(vmx)
        self.account_ready = account_ready
        self.probe = probe or (lambda: {})
        self.free_bytes = free_bytes or (lambda: shutil.disk_usage(self.vmx.parent).free)
        self.root = external_path(workspace) / "vm-controls" / ("session-" + uuid.uuid4().hex)
        self.root.mkdir(parents=True)
        self.challenge = None
        self.snapshot = None
        self.ready_message = None
        self.last_message = None
        self.cycle_root = None
        self.report_sha256 = None
        self.state = "waiting_ready"
        self.blocked = False
        self.boot_record = None
        write_json(self.root / "session.json", {"created_at_utc": now(), "request": self.request,
                   "source_hashes": self.source_hashes, "experiment_results": False,
                   "windows_credentials_used": windows_credentials_used is True, "credentials_saved": False})
        self.renew_challenge()

    @classmethod
    def resume(cls, connection, media, workspace, vmx, root, *, probe=None, free_bytes=None):
        root = external_path(plain_path(root))
        expected_parent = external_path(workspace) / "vm-controls"
        if root.parent != expected_parent or not re.fullmatch(r"session-[0-9a-f]{32}", root.name):
            raise ValueError("Unknown session location")
        _, _, request, manifest = load_media(media)
        original = read_record(root / "session.json")
        baseline = read_record(root / "baseline.json")
        if (original["request"] != request or original["source_hashes"] != manifest["source_hashes"]
                or baseline["source_hashes"] != manifest["source_hashes"] or baseline.get("cold_snapshot") is not True
                or not re.fullmatch(r"Aegis-Inert-[0-9a-f]{16}", baseline.get("snapshot", ""))):
            raise ValueError("Saved baseline does not match the prepared media")
        if (root / "recovery-required.json").exists():
            reviewed_path = root / "recovery-reviewed.json"
            if not reviewed_path.is_file():raise ValueError("Prior recovery requires an explicit review")
            reviewed = read_record(reviewed_path)
            if reviewed.get("snapshot") != baseline["snapshot"] or reviewed.get("approved_to_verify") is not True:
                raise ValueError("Recovery review does not match the baseline")
        self = cls.__new__(cls)
        self.connection, self.root, self.request = connection, root, request
        self.source_hashes, self.vmx = manifest["source_hashes"], Path(vmx)
        self.probe, self.account_ready = probe or (lambda: {}), False
        self.free_bytes = free_bytes or (lambda: shutil.disk_usage(self.vmx.parent).free)
        self.snapshot, self.challenge = baseline["snapshot"], None
        self.ready_message = self.last_message = self.cycle_root = self.report_sha256 = None
        self.blocked, self.state = False, "resume_check"
        self.boot_record = None
        cycles = sorted(root.glob("cycle-*"), key=lambda p: p.stat().st_mtime_ns)
        for cycle in cycles:
            if cycle.is_symlink() or not cycle.is_dir():raise ValueError("Unexpected cycle entry")
            report = cycle / "report.json"
            transport = read_record(cycle / "transport.json")
            validate_cycle(report,workspace)
            digest = hashlib.sha256(report.read_bytes()).hexdigest()
            message = transport["metadata_message"]
            checked = decode_message(encode_message(message), request=request,
                                     challenge=message["challenge"], source_hashes=self.source_hashes)
            if (digest != transport["report_sha256"] or checked["phase"] != "complete"
                    or json.loads(report.read_text(encoding="utf-8")) != checked["report"]):
                raise ValueError("Saved report/transport identity mismatch")
            completion_path = cycle / "completion.json"
            if completion_path.exists():
                completion = read_record(completion_path)
                if (completion.get("vm_restore_verified") is not True or completion.get("snapshot") != self.snapshot
                        or completion.get("report_sha256") != digest):
                    raise ValueError("Saved completion does not match its report")
            elif cycle != cycles[-1]:
                raise ValueError("An earlier cycle is incomplete")
            else:self.state = "result_saved"
            self.cycle_root, self.report_sha256 = cycle, digest
        pending = sorted(root.glob("boot-pending-*.json"), key=lambda p:p.stat().st_mtime_ns)
        if pending:
            latest = pending[-1]
            value = read_record(latest)
            resolved = latest.with_name(latest.name.replace("boot-pending-", "boot-resolved-"))
            if not resolved.exists():
                if (value.get("snapshot") != self.snapshot or value.get("state") not in {"awaiting_baseline_boot", "awaiting_restore_boot"}
                        or value.get("cycle") != (self.cycle_root.name if self.cycle_root else None)):
                    raise ValueError("Saved boot phase does not match the session")
                self.state, self.boot_record = value["state"], latest
        self.renew_challenge()
        write_json(root / ("resume-" + uuid.uuid4().hex + ".json"), {
            "created_at_utc": now(), "previous_reports_checked": len(cycles), "phase": self.state,
            "windows_credentials_used": True, "credentials_saved": False, "experiment_results": False})
        return self

    def pause_for_boot(self, state):
        self.state = state
        self.boot_record = self.root / ("boot-pending-" + uuid.uuid4().hex + ".json")
        write_json(self.boot_record, {"created_at_utc": now(), "state": state, "snapshot": self.snapshot,
            "cycle": self.cycle_root.name if self.cycle_root else None, "vm_restore_verified": False})

    def finish_boot(self, baseline):
        self.connection.wait_tools()
        self.renew_challenge()
        if baseline:self.connection.allow_inert_run(self.challenge)
        self.state = "baseline_ready" if baseline else "verifying_restore"

    def continue_after_boot(self):
        self.require_available()
        if self.state not in {"awaiting_baseline_boot", "awaiting_restore_boot"}:
            raise ValueError("No manual boot phase is pending")
        baseline = self.state == "awaiting_baseline_boot"
        if not self.connection.reopen()["powered_on"]:
            raise ManualBootRequired("Start the VM in Fusion before continuing")
        self.finish_boot(baseline)
        write_json(self.boot_record.with_name(self.boot_record.name.replace("boot-pending-", "boot-resolved-")),
                   {"created_at_utc": now(), "state": self.state, "snapshot": self.snapshot})

    def renew_challenge(self):
        self.challenge = secrets.token_hex(32)
        self.connection.set_challenge(self.challenge)
        self.last_message = None

    def require_available(self):
        if self.blocked:
            raise ValueError("Session requires recovery review")

    def fail_after_mutation(self):
        self.blocked = True
        self.state = "recovery_required"
        path = self.root / "recovery-required.json"
        if not path.exists():
            write_json(path, {"created_at_utc": now(), "state": self.state,
                             "vm_restore_verified": False, "snapshot": self.snapshot})

    def receive(self):
        self.require_available()
        encoded = self.connection.read_control()
        if not encoded:
            return None
        try:
            message = decode_message(encoded, request=self.request, challenge=self.challenge,
                                     source_hashes=self.source_hashes)
        except StaleControlMessage:
            return None
        if message["message_id"] == self.last_message:
            return None
        self.last_message = message["message_id"]
        if message["phase"] == "ready":
            self.ready_message = message
            if self.state == "verifying_restore":
                if message["run_root_exists"] or message["mutation_exists"] or message["network_up"] is not False:
                    self.fail_after_mutation()
                    raise ValueError("Restored guest did not prove absent work and disconnected networking")
                write_json(self.cycle_root / "completion.json", {
                    "created_at_utc": now(), "vm_restore_verified": True, "snapshot": self.snapshot,
                    "report_sha256": self.report_sha256, "fresh_guest_proof": message,
                    "free_bytes_after_restore": self.free_bytes(), "experiment_results": False})
                self.state = "restored"
            elif self.state == "waiting_ready":
                self.state = "ready"
            return message
        if self.snapshot is None or self.state not in {"baseline_ready", "running_control"}:
            if self.state == "result_saved" and self.cycle_root is not None:
                saved = json.loads((self.cycle_root / "report.json").read_text(encoding="utf-8"))
                if saved == message["report"]:
                    return None
            # Preserve unexpected completion without granting permission to revert it.
            path = self.root / ("unbaselined-" + message["message_id"] + ".json")
            write_json(path, message)
            raise ValueError("Control arrived before a verified baseline phase")
        self.cycle_root = self.root / ("cycle-" + uuid.uuid4().hex)
        self.cycle_root.mkdir()
        try:
            report = self.cycle_root / "report.json"
            write_json(report, message["report"])
            self.report_sha256 = hashlib.sha256(report.read_bytes()).hexdigest()
            write_json(self.cycle_root / "transport.json", {
                "received_at_utc": now(), "metadata_message": message,
                "report_sha256": self.report_sha256, "source_hashes": self.source_hashes,
                "vm_restore_verified": False, "experiment_results": False})
        except Exception:
            self.fail_after_mutation()
            raise
        self.state = "result_saved"
        return message

    def create_baseline(self):
        self.require_available()
        message = self.ready_message
        if (self.state != "ready" or message is None or message["run_root_exists"]
                or message["mutation_exists"] or message["network_up"] is not False):
            raise ValueError("A fresh guest must show absent work and a disconnected network first")
        if self.account_ready is not True:
            raise ValueError("Separation from personal accounts has not been verified")
        flags = self.probe()
        if flags.get("network_config") != "disconnected" or flags.get("sharing_config") != "disabled":
            raise ValueError("VM network/sharing configuration is not ready")
        if self.free_bytes() < 3 * 1024**3:
            raise ValueError("At least 3 GiB of VM-volume reserve is required for a cold control baseline")
        name = "Aegis-Inert-" + secrets.token_hex(8)
        try:
            self.connection.shutdown()
            self.connection.create_cold_snapshot(name)
            self.snapshot = name
            write_json(self.root / "baseline.json", {
                "created_at_utc": now(), "snapshot": name, "cold_snapshot": True,
                "guest_proof_before_snapshot": message, "configuration_observations": flags,
                "personal_account_separation_recorded": True, "source_hashes": self.source_hashes,
                "free_bytes": self.free_bytes(), "experiment_results": False})
            self.connection.power_on()
            self.finish_boot(True)
        except ManualBootRequired:
            self.pause_for_boot("awaiting_baseline_boot")
        except Exception:
            self.fail_after_mutation()
            raise

    def restore(self):
        self.require_available()
        if self.state != "result_saved" or self.snapshot is None or self.cycle_root is None:
            raise ValueError("Save a verified guest report before restore")
        report = self.cycle_root / "report.json"
        if report.is_symlink() or hashlib.sha256(report.read_bytes()).hexdigest() != self.report_sha256:
            raise ValueError("Saved host result changed; restore refused")
        if not (self.cycle_root / "transport.json").is_file():
            raise ValueError("Transport evidence is missing; restore refused")
        try:
            self.connection.shutdown()
            self.connection.revert_cold_snapshot(self.snapshot)
            self.connection.power_on()
            self.finish_boot(False)
            # No run permission in the new phase: inspect the restored state first.
        except ManualBootRequired:
            self.pause_for_boot("awaiting_restore_boot")
        except Exception:
            self.fail_after_mutation()
            raise

    def next_cycle(self):
        self.require_available()
        if self.state != "restored":
            raise ValueError("Verify restore before another control")
        if self.free_bytes() < 3 * 1024**3:
            raise ValueError("VM-volume reserve is too small for another control")
        self.renew_challenge()
        self.connection.allow_inert_run(self.challenge)
        self.cycle_root = None
        self.report_sha256 = None
        self.state = "baseline_ready"
