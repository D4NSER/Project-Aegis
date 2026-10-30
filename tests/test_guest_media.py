"""Inert media selection, guest staging and hostile metadata checks on the host."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from control_channel import decode_message, encode_message
from guest_control_app import load_media, stage_and_run
from guest_media import build_media


class GuestMediaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.media = self.root / "cd"
        self.request, self.manifest = build_media(self.media, ["marker", "unicode"])
        self.challenge = "c" * 64

    def tearDown(self):
        self.temp.cleanup()

    def message(self, complete=False):
        _, transfer, request, manifest = load_media(self.media)
        report = None
        if complete:
            with patch("platform.system", return_value="Windows"), patch("platform.machine", return_value="ARM64"):
                report = stage_and_run(transfer, request, self.root / "guest-work")
        return {"schema": 1, "phase": "complete" if complete else "ready", "challenge": self.challenge,
                "run_id": request["run_id"], "nonce": request["nonce"], "message_id": "d" * 32,
                "platform": "Windows", "architecture": "ARM64",
                "app_sha256": manifest["source_hashes"]["guest_control_app.py"],
                "run_root_exists": complete, "mutation_exists": complete,
                "network_up": False, "report": report}

    def decode(self, value):
        return decode_message(encode_message(value), request=self.request,
                              challenge=self.challenge, source_hashes=self.manifest["source_hashes"])

    def test_media_contains_only_selected_controls_and_staging_keeps_restore_marker(self):
        _, transfer, request, _ = load_media(self.media)
        self.assertEqual({"request.json", "marker.txt", "unicode.txt"}, {p.name for p in transfer.iterdir()})
        report = stage_and_run(transfer, request, self.root / "guest-work")
        self.assertFalse(report["experiment_results"])
        self.assertTrue((self.root / "guest-work" / request["run_id"] / "mutation.json").exists())
        with self.assertRaises(FileExistsError):
            stage_and_run(transfer, request, self.root / "guest-work")
        with self.assertRaises(ValueError):
            build_media(self.media, ["plain"])

    def test_changed_source_and_escaping_media_request_are_rejected(self):
        source = self.media / "src/guest_control.py"
        source.write_text("changed")
        with self.assertRaisesRegex(ValueError, "source"):
            load_media(self.media)
        manifest = self.media / "media-manifest.json"
        value = json.loads(manifest.read_text())
        value["request_path"] = "../outside.json"
        manifest.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            load_media(self.media)

    def test_vendor_installer_copy_requires_separately_verified_hash(self):
        source = self.root / "inert-installer.txt"
        source.write_bytes(b"inert fake installer for a host unit test")
        with self.assertRaises(ValueError):
            build_media(self.root / "bad-cd", ["plain"], installer=source, installer_sha256="0" * 64)
        self.assertFalse((self.root / "bad-cd").exists())
        _, manifest = build_media(self.root / "installer-cd", ["plain"], installer=source,
                                  installer_sha256=hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertIn("1-Install-Python.cmd", manifest["files"])
        self.assertEqual(source.read_bytes(), (self.root / "installer-cd/python-arm64.exe").read_bytes())

    def test_fresh_ready_and_complete_messages_verify_against_host_inputs(self):
        self.assertEqual("ready", self.decode(self.message())["phase"])
        result = self.decode(self.message(True))
        self.assertEqual(["marker", "unicode"], [row["id"] for row in result["report"]["files"]])
        self.assertFalse(result["report"]["vm_restore_verified"])

    def test_stale_foreign_and_malformed_identity_cannot_be_imported(self):
        value = self.message()
        for key, replacement in (("challenge", "e" * 64), ("run_id", "../outside"), ("nonce", "0" * 64),
                                  ("app_sha256", "0" * 64), ("architecture", {}), ("schema", True),
                                  ("mutation_exists", 1), ("network_up", "false")):
            bad = copy.deepcopy(value);bad[key] = replacement
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.decode(bad)

    def test_scanner_restore_or_content_claims_cannot_be_fabricated(self):
        original = self.message(True)
        for field in ("experiment_results", "vm_restore_verified", "work_cleanup_performed"):
            value = copy.deepcopy(original);value["report"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.decode(value)
        for field, replacement in (("sha256", "0" * 64), ("av_status", "DETECTED"), ("yara_status", "DETECTED")):
            value = copy.deepcopy(original);value["report"]["files"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.decode(value)

    def test_duplicate_fields_and_oversized_invalid_encoded_messages_fail(self):
        for encoded in ("!", "a" * 22001, base64.b64encode(b'{"schema":1,"schema":1}').decode()):
            with self.assertRaises(ValueError):
                decode_message(encoded, request=self.request, challenge=self.challenge,
                               source_hashes=self.manifest["source_hashes"])


if __name__ == "__main__":
    unittest.main()
