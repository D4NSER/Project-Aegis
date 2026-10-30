"""Small read-only binding to the VIX library bundled with VMware Fusion.

Credentials stay in process memory: no command-line, environment, file or
logging interface accepts them. Native errors expose operation and code only.
This initial client does not mutate VM power, snapshots, network or guest files.
"""
import ctypes as c
from pathlib import Path
import time


class VixError(RuntimeError):
    def __init__(self, operation, code):
        self.operation, self.code = operation, int(code)
        super().__init__(f"VIX {operation} failed (code {self.code})")


class FusionProbe:
    DEFAULT_LIBRARY = "/Applications/VMware Fusion.app/Contents/Public/libvixAllProducts.dylib"

    def __init__(self, library_path=None, *, library=None, timeout=20):
        self.lib = library if library is not None else c.CDLL(library_path or self.DEFAULT_LIBRARY)
        self.timeout = timeout
        self.host = 0
        self.vm = 0
        # Variadic calls require fixed argument declarations on Apple ARM64.
        bindings = {
            "VixHost_Connect": (c.c_int, [c.c_int, c.c_int, c.c_char_p, c.c_int,
                                         c.c_char_p, c.c_char_p, c.c_int, c.c_int,
                                         c.c_void_p, c.c_void_p]),
            "VixHost_OpenVM": (c.c_int, [c.c_int, c.c_char_p, c.c_int, c.c_int, c.c_void_p, c.c_void_p]),
            "VixPropertyList_AllocPropertyList": (c.c_uint64, [c.c_int, c.POINTER(c.c_int), c.c_int]),
            "VixJob_CheckCompletion": (c.c_uint64, [c.c_int, c.POINTER(c.c_int)]),
            "VixJob_Wait": (c.c_uint64, [c.c_int, c.c_int]),
            "Vix_GetProperties": (c.c_uint64, [c.c_int, c.c_int]),
            "Vix_ReleaseHandle": (None, [c.c_int]),
            "VixHost_Disconnect": (None, [c.c_int]),
        }
        for name, (result, arguments) in bindings.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = result, arguments

    @staticmethod
    def check(code, operation):
        if code:
            raise VixError(operation, code)

    def wait_handle(self, job, operation):
        if not job:
            raise VixError(operation, 1)
        try:
            deadline = time.monotonic() + self.timeout
            while True:
                done = c.c_int()
                self.check(self.lib.VixJob_CheckCompletion(job, c.byref(done)), operation)
                if done.value:
                    break
                if time.monotonic() >= deadline:
                    # Releasing a job handle is not proof that its operation was cancelled.
                    # This client only issues read-only operations.
                    raise TimeoutError(f"VIX {operation} timed out")
                time.sleep(0.1)
            result = c.c_int()
            self.check(self.lib.VixJob_Wait(job, 3010, c.byref(result), c.c_int(0)), operation)
            return result.value
        finally:
            self.lib.Vix_ReleaseHandle(job)

    def open(self, vmx_path, encryption_password):
        if self.host or self.vm:
            raise ValueError("Close the previous VIX session first")
        vmx = Path(vmx_path)
        if not vmx.is_file() or vmx.suffix != ".vmx":
            raise ValueError("Choose an existing VM configuration")
        if not isinstance(encryption_password, str) or not encryption_password or "\0" in encryption_password:
            raise ValueError("Enter the existing VM encryption credential locally")
        properties = c.c_int()
        try:
            self.host = self.wait_handle(self.lib.VixHost_Connect(
                -1, 3, None, 0, None, None, 0, 0, None, None), "connect")
            self.check(self.lib.VixPropertyList_AllocPropertyList(
                self.host, c.byref(properties), 7001,
                c.c_char_p(encryption_password.encode("utf-8")), c.c_int(0)), "open properties")
            self.vm = self.wait_handle(self.lib.VixHost_OpenVM(
                self.host, str(vmx).encode("utf-8"), 0, properties.value, None, None), "open")
            return self.state()
        except Exception:
            if properties.value:
                self.lib.Vix_ReleaseHandle(properties.value)
                properties.value = 0
            self.close()
            raise
        finally:
            if properties.value:
                self.lib.Vix_ReleaseHandle(properties.value)

    def state(self):
        if not self.vm:
            raise ValueError("No VM connection")
        values = []
        for property_id in (129, 152):
            result = c.c_int()
            self.check(self.lib.Vix_GetProperties(self.vm, property_id, c.byref(result), c.c_int(0)), "state")
            values.append(result.value)
        power, tools = values
        return {"power_state_bits": power, "tools_state": tools,
                "powered_on": bool(power & 8), "powered_off": bool(power & 2),
                "suspended": bool(power & 32),
                "tools_running": (tools == 2) if tools in (2, 4) else None,
                "read_only_probe": True, "guest_login_tested": False,
                "guest_cycle_verified": False, "vm_restore_verified": False}

    def close(self):
        if self.vm:
            self.lib.Vix_ReleaseHandle(self.vm)
            self.vm = 0
        if self.host:
            self.lib.VixHost_Disconnect(self.host)
            self.host = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
