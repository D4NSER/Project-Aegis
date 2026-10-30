"""Optional guest login is bounded and never bypassed after failure."""
from pathlib import Path
import tempfile
import unittest

from test_fusion_control import NativeControl
from test_fusion_vix import Function
from fusion_guest_ops import FusionGuestOps
from fusion_vix import VixError


class GuestNative(NativeControl):
    def __init__(self):
        super().__init__()
        for name in ("LoginInGuest", "LogoutFromGuest", "CreateDirectoryInGuest", "FileExistsInGuest",
                     "CopyFileFromHostToGuest", "CopyFileFromGuestToHost", "RunProgramInGuest"):
            setattr(self, "VixVM_" + name, Function(lambda *args, name=name: self.operation(name, args)))

    def wait(self, job, property_id, *args):
        if property_id in (3011, 3018):
            self.put(args[0], 0)
            return 0
        return super().wait(job, property_id, *args)


class GuestOpsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name);vmx = self.root / "test.vmx";vmx.write_text("inert")
        self.native = GuestNative();self.connection = FusionGuestOps(library=self.native)
        self.connection.open(vmx, "test-only");self.addCleanup(self.connection.close)

    def test_login_failure_does_not_enable_guest_operations_or_expose_credentials(self):
        self.native.fail_operation = "LoginInGuest"
        with self.assertRaises(VixError) as caught:self.connection.login("lab-user", "fixture-pass")
        self.assertNotIn("fixture-pass", str(caught.exception))
        self.assertFalse(self.connection.logged_in)
        with self.assertRaises(ValueError):self.connection.run("program", "args")
        self.assertEqual(["LoginInGuest"], [name for name, args in self.native.calls])

    def test_copy_rejects_overwrites_and_run_uses_native_calls(self):
        self.connection.login("lab-user", "fixture-pass")
        source = self.root / "input.txt";source.write_text("inert")
        self.connection.copy_to(source, "guest-inert.txt")
        self.connection.copy_from("guest-result.json", self.root / "result.json")
        with self.assertRaises(ValueError):self.connection.copy_from("guest-result.json", source)
        self.assertEqual(0, self.connection.run("program", "arguments"))
        self.connection.run("program", "arguments", wait=False)
        calls = [args for name, args in self.native.calls if name == "RunProgramInGuest"]
        self.assertEqual([0, 1], [args[3] for args in calls])

    def test_power_cycle_invalidates_guest_login(self):
        self.connection.login("lab-user", "fixture-pass");self.connection.shutdown()
        self.assertFalse(self.connection.logged_in)
        with self.assertRaises(ValueError):self.connection.mkdir("inert")


if __name__ == "__main__":unittest.main()
