"""VM power, cold snapshots and a small Tools metadata channel.

Only the existing VM encryption credential is used. There is no Windows login,
guest command execution, filesystem sharing, network server or hard power-off.
"""
import ctypes as c
import re
import time

from fusion_vix import FusionProbe, VixError


class ManualBootRequired(RuntimeError):
    """The VM is confirmed off; the encrypted Fusion UI must start it."""


class FusionControl(FusionProbe):
    def __init__(self, *args, **kwargs):
        self.pending = False
        self._vmx = None
        self._encryption_credential = None
        super().__init__(*args, **kwargs)
        bindings = {
            "VixVM_WaitForToolsInGuest": [c.c_int, c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_PowerOff": [c.c_int, c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_PowerOn": [c.c_int, c.c_int, c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_CreateSnapshot": [c.c_int, c.c_char_p, c.c_char_p, c.c_int, c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_RevertToSnapshot": [c.c_int, c.c_int, c.c_int, c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_ReadVariable": [c.c_int, c.c_int, c.c_char_p, c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_WriteVariable": [c.c_int, c.c_int, c.c_char_p, c.c_char_p, c.c_int, c.c_void_p, c.c_void_p],
        }
        for name, arguments in bindings.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = c.c_int, arguments
        function = self.lib.VixVM_GetNamedSnapshot
        function.restype, function.argtypes = c.c_uint64, [c.c_int, c.c_char_p, c.POINTER(c.c_int)]
        self.lib.Vix_FreeBuffer.restype = None
        self.lib.Vix_FreeBuffer.argtypes = [c.c_void_p]

    def open(self, vmx, encryption_password):
        result = super().open(vmx, encryption_password)
        # A cold lifecycle requires reopening the encrypted VM. Memory only.
        self._vmx, self._encryption_credential = str(vmx), encryption_password
        return result

    def close(self):
        try:
            super().close()
        finally:
            self._vmx = self._encryption_credential = None

    def ready(self):
        if not self.vm or self.pending:
            raise ValueError("VM disconnected or an operation has an unknown outcome")

    def job(self, handle, operation, *, result_property=0, pointer=False, timeout=45):
        try:
            deadline = time.monotonic() + timeout
            while True:
                done = c.c_int()
                self.check(self.lib.VixJob_CheckCompletion(handle, c.byref(done)), operation)
                if done.value:
                    break
                if time.monotonic() >= deadline:
                    self.pending = True
                    raise TimeoutError("Operation outcome is unknown; no automatic retry")
                time.sleep(0.2)
            if result_property:
                value = c.c_void_p() if pointer else c.c_int()
                self.check(self.lib.VixJob_Wait(handle, result_property, c.byref(value), c.c_int(0)), operation)
                return value.value
            self.check(self.lib.VixJob_Wait(handle, 0), operation)
        finally:
            self.lib.Vix_ReleaseHandle(handle)

    def wait_tools(self):
        self.ready()
        self.job(self.lib.VixVM_WaitForToolsInGuest(self.vm, 45, None, None), "wait tools", timeout=55)
        if self.state()["tools_running"] is not True:
            raise ValueError("Tools did not report RUNNING")

    def set_challenge(self, challenge):
        self.ready()
        if not isinstance(challenge, str) or not re.fullmatch(r"[0-9a-f]{64}", challenge):
            raise ValueError("Expected a new control challenge")
        self.job(self.lib.VixVM_WriteVariable(self.vm, 1, b"aegis.challenge",
                 challenge.encode("ascii"), 0, None, None), "set control challenge")

    def read_control(self):
        self.ready()
        pointer = self.job(self.lib.VixVM_ReadVariable(self.vm, 1, b"aegis.control", 0, None, None),
                           "read control response", result_property=3056, pointer=True)
        if not pointer:
            return ""
        try:
            raw = c.string_at(pointer)
            if len(raw) > 22000:
                raise ValueError("Control response exceeds metadata limit")
            return raw.decode("ascii")
        finally:
            self.lib.Vix_FreeBuffer(c.c_void_p(pointer))

    def allow_inert_run(self, challenge):
        self.ready()
        if not isinstance(challenge, str) or not re.fullmatch(r"[0-9a-f]{64}", challenge):
            raise ValueError("Expected the current control challenge")
        self.job(self.lib.VixVM_WriteVariable(self.vm, 1, b"aegis.run_permission",
                 challenge.encode("ascii"), 0, None, None), "allow inert control")

    def shutdown(self):
        self.ready()
        # FROM_GUEST only: an unresponsive guest never becomes a hard stop.
        self.job(self.lib.VixVM_PowerOff(self.vm, 4, None, None), "guest shutdown")
        if not self.state()["powered_off"]:
            raise ValueError("Guest shutdown did not finish")

    def power_on(self):
        self.ready()
        if not self.state()["powered_off"]:
            raise ValueError("Power-on requires a powered-off VM")
        vmx, credential = self._vmx, self._encryption_credential
        if not vmx or not credential:
            raise ValueError("Reopen the encrypted VM session before power-on")
        # Do not reuse a handle whose VMX process exited during cold shutdown.
        FusionProbe.close(self)
        FusionProbe.open(self, vmx, credential)
        properties = c.c_int()
        try:
            self.check(self.lib.VixPropertyList_AllocPropertyList(
                self.host, c.byref(properties), 7001, c.c_char_p(credential.encode("utf-8")), c.c_int(0)),
                "power-on properties")
            try:
                self.job(self.lib.VixVM_PowerOn(self.vm, 0, properties.value, None, None), "power on", timeout=60)
            except VixError as exc:
                if exc.code in {1, 6} and self.state()["powered_off"]:
                    raise ManualBootRequired("Start the encrypted VM in Fusion, then continue") from exc
                raise
        finally:
            if properties.value:self.lib.Vix_ReleaseHandle(properties.value)

    def reopen(self):
        self.ready()
        vmx, credential = self._vmx, self._encryption_credential
        if not vmx or not credential:raise ValueError("The encrypted VM session is closed")
        FusionProbe.close(self)
        return FusionProbe.open(self, vmx, credential)

    @staticmethod
    def snapshot_name(name):
        if not isinstance(name, str) or not re.fullmatch(r"Aegis-Inert-[0-9a-f]{16}", name):
            raise ValueError("Expected a managed inert-control snapshot name")
        return name.encode("ascii")

    def create_cold_snapshot(self, name):
        self.ready()
        name = self.snapshot_name(name)
        if not self.state()["powered_off"]:
            raise ValueError("Baseline snapshot requires a powered-off VM")
        handle = self.job(self.lib.VixVM_CreateSnapshot(self.vm, name,
                          b"Inert control baseline; not experiment readiness", 0, 0, None, None),
                          "cold snapshot", result_property=3010)
        self.lib.Vix_ReleaseHandle(handle)

    def revert_cold_snapshot(self, name):
        self.ready()
        name = self.snapshot_name(name)
        if not self.state()["powered_off"]:
            raise ValueError("Revert requires a powered-off VM and saved host results")
        handle = c.c_int()
        self.check(self.lib.VixVM_GetNamedSnapshot(self.vm, name, c.byref(handle)), "find snapshot")
        try:
            self.job(self.lib.VixVM_RevertToSnapshot(self.vm, handle.value, 0x80, 0, None, None), "revert snapshot")
        finally:
            self.lib.Vix_ReleaseHandle(handle.value)
