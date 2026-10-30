"""Native VM control mocks contain no Windows login APIs or credentials."""
import ctypes as c
from pathlib import Path
import tempfile
import unittest

from test_fusion_vix import FakeVix, Function
from fusion_control import FusionControl,ManualBootRequired
from fusion_vix import VixError


class NativeControl(FakeVix):
    def __init__(self):
        super().__init__()
        self.power, self.calls, self.results = 8, [], {}
        self.fail_operation = None
        self.buffer = c.create_string_buffer(b"aW5lcnQ=")
        self.freed = []
        self.Vix_FreeBuffer = Function(lambda pointer: self.freed.append(pointer.value))
        self.VixJob_Wait = Function(self.wait)
        self.Vix_GetProperties = Function(self.state)
        for name in ("WaitForToolsInGuest", "PowerOff", "PowerOn", "CreateSnapshot",
                     "RevertToSnapshot", "ReadVariable", "WriteVariable"):
            setattr(self, "VixVM_" + name, Function(lambda *args, name=name: self.operation(name, args)))
        self.VixVM_GetNamedSnapshot = Function(self.snapshot)

    def operation(self, name, args):
        self.calls.append((name, args))
        handle = 200 + len(self.calls);self.results[handle] = name
        if name == "PowerOff" and self.fail_operation != name:self.power = 2
        if name == "PowerOn":self.power = 8
        return handle

    def wait(self, job, property_id, *args):
        if job in (101, 102):return super().wait(job, property_id, *args)
        name = self.results[job]
        if name == self.fail_operation:return 3006
        if property_id == 3056:
            c.cast(args[0], c.POINTER(c.c_void_p))[0] = c.cast(self.buffer, c.c_void_p).value
        elif property_id:self.put(args[0], 44)
        return 0

    def state(self, handle, property_id, pointer, end):
        self.put(pointer, self.power if property_id == 129 else 2);return 0

    def snapshot(self, handle, name, pointer):
        self.put(pointer, 44);return 0


class NativeControlTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.vmx = Path(self.temp.name) / "control.vmx";self.vmx.write_text("inert fake configuration")
        self.native = NativeControl()
        self.connection = FusionControl(library=self.native)
        self.connection.open(self.vmx, "test-only")

    def tearDown(self):
        self.connection.close();self.temp.cleanup()

    def test_metadata_uses_only_fixed_keys_and_frees_native_buffer_without_windows_login(self):
        self.connection.set_challenge("a" * 64)
        self.assertEqual("aW5lcnQ=", self.connection.read_control())
        self.assertEqual(1, len(self.native.freed))
        self.assertEqual(["WriteVariable", "ReadVariable"], [name for name, args in self.native.calls])
        self.assertEqual(b"aegis.challenge", self.native.calls[0][1][2])
        self.assertEqual(b"aegis.control", self.native.calls[1][1][2])
        with self.assertRaises(ValueError):self.connection.set_challenge("bad")

    def test_shutdown_failure_never_becomes_a_hard_stop(self):
        self.native.fail_operation = "PowerOff"
        with self.assertRaises(VixError):self.connection.shutdown()
        self.assertEqual([4], [args[1] for name, args in self.native.calls if name == "PowerOff"])

    def test_cold_snapshots_reject_running_guest_and_unmanaged_names(self):
        name = "Aegis-Inert-" + "a" * 16
        for fn in (self.connection.create_cold_snapshot, self.connection.revert_cold_snapshot):
            with self.assertRaises(ValueError):fn(name)
        self.assertEqual([], self.native.calls)
        self.connection.shutdown()
        with self.assertRaises(ValueError):self.connection.revert_cold_snapshot("other")
        self.connection.create_cold_snapshot(name);self.connection.revert_cold_snapshot(name)
        self.assertEqual(0, [args[3] for key, args in self.native.calls if key == "CreateSnapshot"][0])
        self.assertEqual(0x80, [args[2] for key, args in self.native.calls if key == "RevertToSnapshot"][0])

    def test_timed_out_operation_blocks_followup_mutations(self):
        self.native.never_complete = True
        with self.assertRaises(TimeoutError):self.connection.job(999, "synthetic operation", timeout=0)
        with self.assertRaises(ValueError):self.connection.shutdown()
        self.assertEqual([], self.native.calls)

    def test_failed_native_start_requires_confirmed_off_state_and_keeps_credential_only_until_close(self):
        self.connection.shutdown()
        original=self.native.operation
        def operation(name,args):
            result=original(name,args)
            if name=='PowerOn':self.native.power=2
            return result
        self.native.VixVM_PowerOn=Function(lambda *args:operation('PowerOn',args))
        original_wait=self.native.wait
        self.native.VixJob_Wait=Function(lambda job,prop,*args:1 if self.native.results.get(job)=='PowerOn' else original_wait(job,prop,*args))
        with self.assertRaises(ManualBootRequired):self.connection.power_on()
        self.assertTrue(self.connection.state()['powered_off'])
        self.assertEqual('test-only',self.connection._encryption_credential)
        self.connection.close();self.assertIsNone(self.connection._encryption_credential)


if __name__ == "__main__":
    unittest.main()
