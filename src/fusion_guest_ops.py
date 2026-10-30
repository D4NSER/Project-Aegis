"""Optional Tools operations using an existing dedicated Windows lab account.

No credentials are saved, passed to subprocesses or included in error messages.
This adds no network listener and does not change Windows permissions.
"""
import ctypes as c
import base64
from pathlib import Path

from aegis import external_path
from fusion_control import FusionControl


class FusionGuestOps(FusionControl):
    def __init__(self, *args, **kwargs):
        self.logged_in = False
        super().__init__(*args, **kwargs)
        bindings = {
            "VixVM_LoginInGuest": [c.c_int, c.c_char_p, c.c_char_p, c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_LogoutFromGuest": [c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_CreateDirectoryInGuest": [c.c_int, c.c_char_p, c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_FileExistsInGuest": [c.c_int, c.c_char_p, c.c_void_p, c.c_void_p],
            "VixVM_CopyFileFromHostToGuest": [c.c_int, c.c_char_p, c.c_char_p, c.c_int, c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_CopyFileFromGuestToHost": [c.c_int, c.c_char_p, c.c_char_p, c.c_int, c.c_int, c.c_void_p, c.c_void_p],
            "VixVM_RunProgramInGuest": [c.c_int, c.c_char_p, c.c_char_p, c.c_int, c.c_int, c.c_void_p, c.c_void_p],
        }
        for name, arguments in bindings.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = c.c_int, arguments

    @staticmethod
    def native_text(value):
        if not isinstance(value, str) or not value or "\0" in value:
            raise ValueError("Expected a nonempty native string")
        return value.encode("utf-8")

    def login(self, username, credential, *, interactive=False):
        self.ready()
        self.job(self.lib.VixVM_LoginInGuest(self.vm, self.native_text(username),
            self.native_text(credential), 0x08 if interactive else 0, None, None), "lab account login")
        self.logged_in = True

    def guest_ready(self):
        self.ready()
        if not self.logged_in:
            raise ValueError("A dedicated lab account session is required")

    def exists(self, path):
        self.guest_ready()
        return bool(self.job(self.lib.VixVM_FileExistsInGuest(self.vm, self.native_text(path), None, None),
                             "guest existence", result_property=3011))

    def mkdir(self, path):
        self.guest_ready()
        self.job(self.lib.VixVM_CreateDirectoryInGuest(self.vm, self.native_text(path), 0, None, None), "guest directory")

    def copy_to(self, source, destination):
        self.guest_ready()
        source = Path(source)
        if source.is_symlink() or not source.is_file():
            raise ValueError("Expected a regular host source")
        if self.exists(destination):
            raise ValueError("Refusing to overwrite guest data")
        self.job(self.lib.VixVM_CopyFileFromHostToGuest(self.vm, self.native_text(str(source.resolve())),
                 self.native_text(destination), 0, 0, None, None), "copy to guest")

    def copy_from(self, source, destination, *, timeout=45):
        self.guest_ready()
        destination = external_path(destination)
        if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
            raise ValueError("Expected a new external host result")
        self.job(self.lib.VixVM_CopyFileFromGuestToHost(self.vm, self.native_text(source),
                 self.native_text(str(destination)), 0, 0, None, None), "copy from guest", timeout=timeout)

    def run(self, program, arguments, *, wait=True, timeout=60):
        self.guest_ready()
        return self.job(self.lib.VixVM_RunProgramInGuest(self.vm, self.native_text(program),
            self.native_text(arguments), 0 if wait else 1, 0, None, None), "lab program",
            result_property=3018 if wait else 0, timeout=timeout)

    def environment(self, name):
        self.guest_ready()
        if name not in {"LOCALAPPDATA", "USERPROFILE", "USERNAME"}:
            raise ValueError("Only lab path environment values can be read")
        pointer = self.job(self.lib.VixVM_ReadVariable(self.vm, 3, name.encode("ascii"), 0, None, None),
                           "lab environment", result_property=3056, pointer=True)
        if not pointer:
            raise ValueError("Lab environment value is absent")
        try:
            raw = c.string_at(pointer)
            if len(raw) > 2048:
                raise ValueError("Lab environment value exceeds limit")
            return raw.decode("utf-8")
        finally:
            self.lib.Vix_FreeBuffer(c.c_void_p(pointer))

    def stop_old_control_ui(self):
        """Stop only the lab user's older inert UI, which otherwise republishes stale metadata."""
        script = r'''
$ErrorActionPreference='Stop'
Get-CimInstance Win32_Process -Filter "Name='python.exe' OR Name='pythonw.exe'" | ForEach-Object {
 if ($_.CommandLine -match 'guest_control_app\.py' -and $_.CommandLine -match '--media' -and $_.CommandLine -notmatch '--action') {
  $owner=Invoke-CimMethod -InputObject $_ -MethodName GetOwner
  if ($owner.User -eq $env:USERNAME) {Stop-Process -Id $_.ProcessId -ErrorAction Stop}
 }
}
'''
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        code = self.run(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        "-NoLogo -NoProfile -NonInteractive -EncodedCommand " + encoded)
        if code != 0:
            raise ValueError("The prior inert UI could not be stopped")

    def shutdown(self):
        super().shutdown()
        self.logged_in = False

    def reopen(self):
        self.logged_in = False
        return super().reopen()

    def revert_cold_snapshot(self, name):
        super().revert_cold_snapshot(name)
        self.logged_in = False

    def close(self):
        try:
            if self.vm and self.logged_in and not self.pending:
                self.job(self.lib.VixVM_LogoutFromGuest(self.vm, None, None), "lab logout", timeout=10)
        finally:
            self.logged_in = False
            super().close()
