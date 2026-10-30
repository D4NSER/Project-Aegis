"""Mock native handles: these tests do not prove Fusion guest operations work."""
import ctypes as c
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from fusion_vix import FusionProbe, VixError


class Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


class FakeVix:
    def __init__(self, *, fail_open=False, never_complete=False):
        self.released = []
        self.disconnected = []
        self.fail_open, self.never_complete = fail_open, never_complete
        self.VixHost_Connect = Function(lambda *args: 101)
        self.VixHost_OpenVM = Function(lambda *args: 102)
        self.VixPropertyList_AllocPropertyList = Function(self.properties)
        self.VixJob_CheckCompletion = Function(self.complete)
        self.VixJob_Wait = Function(self.wait)
        self.Vix_GetProperties = Function(self.state)
        self.Vix_ReleaseHandle = Function(self.released.append)
        self.VixHost_Disconnect = Function(self.disconnected.append)

    @staticmethod
    def put(pointer, value):
        c.cast(pointer, c.POINTER(c.c_int))[0] = value

    def properties(self, host, pointer, property_id, credential, end):
        if host != 11 or property_id != 7001 or not isinstance(credential, c.c_char_p):
            raise AssertionError("Incorrect native credential property")
        self.put(pointer, 33)
        return 0

    def complete(self, job, pointer):
        self.put(pointer, 0 if self.never_complete else 1)
        return 0

    def wait(self, job, property_id, pointer, end):
        if job == 102 and self.fail_open:
            return 3034
        self.put(pointer, {101: 11, 102: 22}[job])
        return 0

    def state(self, handle, property_id, pointer, end):
        self.put(pointer, {129: 8 | 64, 152: 2}[property_id])
        return 0


class FusionProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.vmx = Path(self.temp.name) / "control.vmx"
        self.vmx.write_text("synthetic test configuration")

    def tearDown(self):
        self.temp.cleanup()

    def test_authenticated_read_only_state_and_owned_handle_cleanup(self):
        native = FakeVix()
        with FusionProbe(library=native) as probe:
            state = probe.open(self.vmx, "test-only")
            self.assertTrue(state["powered_on"])
            self.assertTrue(state["tools_running"])
            self.assertTrue(state["read_only_probe"])
            self.assertFalse(state["guest_cycle_verified"])
            self.assertFalse(state["vm_restore_verified"])
            with self.assertRaises(ValueError):
                probe.open(self.vmx, "test-only")
        self.assertEqual([101, 102, 33, 22], native.released)
        self.assertEqual([11], native.disconnected)
        probe.close()
        self.assertEqual([11], native.disconnected)

    def test_auth_error_releases_resources_without_echoing_input(self):
        native = FakeVix(fail_open=True)
        probe = FusionProbe(library=native)
        with self.assertRaises(VixError) as caught:
            probe.open(self.vmx, "test-only")
        self.assertEqual(3034, caught.exception.code)
        self.assertNotIn("test-only", str(caught.exception))
        self.assertEqual([101, 102, 33], native.released)
        self.assertEqual([11], native.disconnected)
        self.assertEqual(0, probe.host)
        self.assertEqual(0, probe.vm)

    def test_timeout_releases_job_and_does_not_claim_cancellation(self):
        native = FakeVix(never_complete=True)
        with FusionProbe(library=native, timeout=0) as probe:
            with self.assertRaises(TimeoutError):
                probe.open(self.vmx, "test-only")
        self.assertEqual([101], native.released)
        self.assertEqual([], native.disconnected)

    def test_credential_and_target_validation_happens_before_native_calls(self):
        native = FakeVix()
        with FusionProbe(library=native) as probe:
            for credential in (None, "", "bad\0value"):
                with self.assertRaises(ValueError):
                    probe.open(self.vmx, credential)
            with self.assertRaises(ValueError):
                probe.open(self.vmx.with_suffix(".txt"), "test-only")
        self.assertEqual([], native.released)

    def test_unknown_tools_state_is_not_reported_as_missing(self):
        native = FakeVix()
        original = native.state
        def unknown(handle, property_id, pointer, end):
            if property_id == 152:
                native.put(pointer, 1)
                return 0
            return original(handle, property_id, pointer, end)
        native.Vix_GetProperties = Function(unknown)
        with FusionProbe(library=native) as probe:
            self.assertIsNone(probe.open(self.vmx, "test-only")["tools_running"])


if __name__ == "__main__":
    unittest.main()
