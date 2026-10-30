"""Build a new external inert-control CD tree, never a research collection."""
import hashlib
import json
from pathlib import Path
import re
import secrets
import shutil
import uuid

from aegis import external_path
from control_workspace import CONTROLS, write_json

SOURCE_FILES = ("aegis.py", "control_workspace.py", "guest_control.py", "guest_control_app.py", "guest_environment.py")

INSTALL_COMMAND = r'''@echo off
set "AEGIS_INSTALLER=%~dp0python-arm64.exe"
powershell.exe -NoLogo -NoProfile -Command "$m = [Threading.Mutex]::new($false, 'Local\ProjectAegisPythonSetup'); if (-not $m.WaitOne(0)) { Write-Host 'Aegis setup is already running.'; exit 0 }; try { $p = Join-Path $env:LOCALAPPDATA 'Programs\Python\Python314-arm64\python.exe'; if (Test-Path -LiteralPath $p) { Write-Host 'Python is already installed.'; exit 0 }; if (-not (Test-Path -LiteralPath $env:AEGIS_INSTALLER)) { throw 'Installer is not present on this media.' }; $a = @('/passive', 'InstallAllUsers=0', 'Include_launcher=0', 'Include_test=0', 'Include_doc=0', 'Include_pip=1', 'Include_tcltk=1', 'PrependPath=0'); $r = Start-Process -FilePath $env:AEGIS_INSTALLER -ArgumentList $a -Wait -PassThru; exit $r.ExitCode } finally { $m.ReleaseMutex(); $m.Dispose() }"
echo Setup process finished. See any error above.
pause
'''

START_COMMAND = r'''@echo off
set "AEGIS_PYTHON=%LOCALAPPDATA%\Programs\Python\Python314-arm64\python.exe"
if not exist "%AEGIS_PYTHON%" (
 echo Run 1-Install-Python.cmd first. This launcher does not start installers.
 pause
 exit /b 1
)
"%AEGIS_PYTHON%" "%~dp0src\guest_control_app.py" --media "%~dp0."
if errorlevel 1 pause
'''


def build_media(output, selected, *, installer=None, installer_sha256=None):
    if (not isinstance(selected, list) or not selected
            or any(not isinstance(key, str) or key not in CONTROLS for key in selected)
            or len(set(selected)) != len(selected)):
        raise ValueError("Select distinct registered inert controls")
    output = external_path(output)
    if output.exists():
        raise ValueError("Media output must be new")
    if installer is not None:
        installer = Path(installer)
        if (installer.is_symlink() or not installer.is_file() or not isinstance(installer_sha256, str)
                or not re.fullmatch(r"[0-9a-f]{64}", installer_sha256)
                or hashlib.sha256(installer.read_bytes()).hexdigest() != installer_sha256):
            raise ValueError("Installer must match the separately verified vendor hash")
    output.mkdir(parents=True)
    source = output / "src"
    source.mkdir()
    hashes = {}
    for name in SOURCE_FILES:
        content = (Path(__file__).parent / name).read_bytes()
        (source / name).write_bytes(content)
        hashes[name] = hashlib.sha256(content).hexdigest()
    run_id = "guest-control-" + uuid.uuid4().hex
    request = {"schema": 1, "run_id": run_id, "nonce": secrets.token_hex(32), "selected": selected}
    transfer = output / "transfer" / run_id
    transfer.mkdir(parents=True)
    write_json(transfer / "request.json", request)
    hashes["request.json"] = hashlib.sha256((transfer / "request.json").read_bytes()).hexdigest()
    for key in selected:
        (transfer / (key + ".txt")).write_bytes(CONTROLS[key][1])
    (output / "2-Start-Aegis.cmd").write_bytes(START_COMMAND.replace("\n", "\r\n").encode("ascii"))
    if installer is not None:
        shutil.copyfile(installer, output / "python-arm64.exe")
        (output / "1-Install-Python.cmd").write_bytes(INSTALL_COMMAND.replace("\n", "\r\n").encode("ascii"))
    (output / "SKAITYK.txt").write_text(
        "Project Aegis: tik inertine kontrole, ne tyrimo bandymas.\n"
        "1. Jei Python dar nera, paleiskite 1-Install-Python.cmd viena karta.\n"
        "2. Paleiskite 2-Start-Aegis.cmd. Windows/Microsoft slaptazodzio nereikia.\n"
        "3. Mac ryši atverkite atskirai; VM sifravimo slaptazodis lieka vietinis.\n"
        "AV ir YARA nevykdomi. Programa pati VM neatkuria.\n", encoding="utf-8")
    manifest = {"schema": 1, "kind": "inert_guest_media", "experiment_results": False,
                "request_path": "transfer/" + run_id + "/request.json", "source_hashes": hashes,
                "files": {str(path.relative_to(output)).replace("\\", "/"): hashlib.sha256(path.read_bytes()).hexdigest()
                          for path in sorted(output.rglob("*")) if path.is_file()}}
    write_json(output / "media-manifest.json", manifest)
    return request, manifest
