"""Read-only Windows lab inventory. Never changes protection or account settings."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

from control_workspace import write_json
from guest_control import plain_path

INVENTORY = r'''
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
$ErrorActionPreference='Stop'
$r=[ordered]@{schema=1;current_user=$env:USERNAME;local_appdata=$env:LOCALAPPDATA;current_sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;accounts=$null;administrators=$null;profiles=$null;defender=$null;network_up=$null;errors=@()}
try {$r.accounts=@(Get-LocalUser | Select-Object Name,Enabled,@{n='SID';e={$_.SID.Value}},@{n='Source';e={[string]$_.PrincipalSource}})} catch {$r.errors+='accounts:'+ $_.Exception.GetType().Name}
try {$r.administrators=@(Get-LocalGroup -SID 'S-1-5-32-544' | Get-LocalGroupMember | Select-Object Name,@{n='SID';e={$_.SID.Value}},@{n='Source';e={[string]$_.PrincipalSource}})} catch {$r.errors+='administrators:'+ $_.Exception.GetType().Name}
try {$r.profiles=@(Get-CimInstance Win32_UserProfile | Select-Object SID,LocalPath,Loaded,Special)} catch {$r.errors+='profiles:'+ $_.Exception.GetType().Name}
try {$r.network_up=((Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up' | Measure-Object).Count -gt 0)} catch {$r.errors+='network:'+ $_.Exception.GetType().Name}
try {$r.defender=Get-MpComputerStatus | Select-Object AMEngineVersion,AMProductVersion,AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureVersion,AntivirusSignatureLastUpdated,AntivirusSignatureAge} catch {$r.errors+='defender:'+ $_.Exception.GetType().Name}
$r | ConvertTo-Json -Depth 8 -Compress
'''


def personal_accounts_separated(value):
    """Require a sole enabled local lab user and no other ordinary user profile."""
    if (not isinstance(value, dict) or not isinstance(value.get("current_sid"), str)
            or not isinstance(value.get("accounts"), list) or not isinstance(value.get("profiles"), list)):
        return False
    sid = value["current_sid"]
    enabled = [row for row in value["accounts"] if row.get("Enabled") is True]
    profiles = [row for row in value["profiles"] if row.get("Special") is not True]
    return (len(enabled) == 1 and enabled[0].get("SID") == sid and enabled[0].get("Source") == "Local"
            and bool(profiles) and all(row.get("SID") == sid for row in profiles))


def collect():
    if os.name != "nt":
        raise ValueError("Windows inventory must run inside the Windows guest")
    encoded = base64.b64encode(INVENTORY.encode("utf-16le")).decode("ascii")
    result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            capture_output=True, encoding="utf-8", timeout=45, check=True)
    if len(result.stdout.encode("utf-8")) > 65536:
        raise ValueError("Windows inventory exceeds limit")
    value = json.loads(result.stdout.lstrip("\ufeff"))
    value.update(created_at_utc=datetime.now(timezone.utc).isoformat(), platform=platform.system(),
                 architecture=platform.machine(), python_version=platform.python_version(),
                 collector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                 personal_accounts_separated=personal_accounts_separated(value), experiment_results=False)
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    write_json(plain_path(args.output), collect())


if __name__ == "__main__":main()
