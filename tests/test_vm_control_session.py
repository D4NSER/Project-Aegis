"""Result durability and fresh post-revert evidence, using an inert fake VM."""
import hashlib
import json
import unittest
from unittest.mock import patch

import test_guest_media
from control_channel import encode_message
from vm_control_session import ManualControlSession


class Connection:
    def __init__(self):
        self.calls = []
        self.response = ""
        self.fail = None

    def set_challenge(self, value): self.challenge = value
    def read_control(self): return self.response
    def allow_inert_run(self, value): self.calls.append("allow")
    def shutdown(self): self.calls.append("shutdown")
    def create_cold_snapshot(self, name): self.calls.append("snapshot")
    def power_on(self): self.calls.append("power_on")
    def wait_tools(self): self.calls.append("tools")
    def revert_cold_snapshot(self, name):
        self.calls.append("revert")
        if self.fail == "revert": raise RuntimeError("synthetic failure")


class ManualSessionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_guest_media.GuestMediaTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.tearDown)
        self.connection = Connection()
        self.session = ManualControlSession(self.connection, self.fixture.media,
            self.fixture.root / "host", self.fixture.root / "vm/control.vmx",
            account_ready=True, probe=lambda: {"network_config": "disconnected", "sharing_config": "disabled"},
            free_bytes=lambda: 5 * 1024**3)

    def deliver(self, complete=False, **changes):
        value = self.fixture.message(complete)
        value.update(challenge=self.session.challenge)
        value.update(changes)
        self.connection.response = encode_message(value)
        return self.session.receive()

    def baseline(self):
        self.deliver()
        self.session.create_baseline()

    def result(self):
        self.baseline()
        self.deliver(True)

    def test_report_is_durable_before_revert_and_restore_needs_fresh_absence_proof(self):
        self.result()
        report = self.session.cycle_root / "report.json"
        self.assertTrue(report.is_file())
        self.assertEqual(self.session.report_sha256, hashlib.sha256(report.read_bytes()).hexdigest())
        self.session.restore()
        self.assertEqual("verifying_restore", self.session.state)
        self.assertIsNone(self.session.receive())  # stale complete packet
        self.assertFalse((self.session.cycle_root / "completion.json").exists())
        self.deliver()
        proof = json.loads((self.session.cycle_root / "completion.json").read_text())
        self.assertTrue(proof["vm_restore_verified"])
        self.assertFalse(proof["experiment_results"])
        self.assertEqual("restored", self.session.state)
        self.session.next_cycle()
        self.assertEqual("baseline_ready", self.session.state)

    def test_personal_account_and_network_guards_precede_all_power_actions(self):
        self.deliver()
        self.session.account_ready = False
        with self.assertRaises(ValueError): self.session.create_baseline()
        self.session.account_ready = True
        self.session.probe = lambda: {"network_config": "connected", "sharing_config": "disabled"}
        with self.assertRaises(ValueError): self.session.create_baseline()
        self.assertEqual([], self.connection.calls)

    def test_guest_network_unknown_and_small_reserve_block_baseline(self):
        self.deliver(network_up=None)
        with self.assertRaises(ValueError): self.session.create_baseline()
        self.deliver(message_id="e" * 32)
        self.session.free_bytes = lambda: 1
        with self.assertRaises(ValueError): self.session.create_baseline()
        self.assertEqual([], self.connection.calls)

    def test_restore_without_saved_result_never_touches_vm(self):
        with self.assertRaises(ValueError): self.session.restore()
        self.assertEqual([], self.connection.calls)

    def test_failed_result_save_blocks_restore(self):
        self.baseline()
        with patch("vm_control_session.write_json", side_effect=OSError("synthetic full disk")):
            with self.assertRaises(OSError): self.deliver(True)
        self.assertTrue(self.session.blocked)
        before = list(self.connection.calls)
        with self.assertRaises(ValueError): self.session.restore()
        self.assertEqual(before, self.connection.calls)

    def test_modified_host_result_prevents_restore(self):
        self.result()
        (self.session.cycle_root / "report.json").write_text("changed")
        before = list(self.connection.calls)
        with self.assertRaises(ValueError): self.session.restore()
        self.assertEqual(before, self.connection.calls)

    def test_revert_failure_blocks_followup_and_never_claims_completion(self):
        self.result()
        self.connection.fail = "revert"
        with self.assertRaises(RuntimeError): self.session.restore()
        self.assertTrue(self.session.blocked)
        self.assertTrue((self.session.root / "recovery-required.json").is_file())
        self.assertFalse((self.session.cycle_root / "completion.json").exists())

    def test_leftover_work_after_revert_is_failure_not_cleanup_success(self):
        self.result()
        self.session.restore()
        with self.assertRaises(ValueError): self.deliver(run_root_exists=True, mutation_exists=True)
        self.assertTrue(self.session.blocked)
        self.assertFalse((self.session.cycle_root / "completion.json").exists())


if __name__ == "__main__":
    unittest.main()
