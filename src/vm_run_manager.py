"""Dedicated-account automation for inert controls, with a cold restore proof."""
import json
import base64
import hashlib
import os
from pathlib import Path, PureWindowsPath
import re
import subprocess
import uuid

from aegis import external_path
from control_workspace import write_json
from guest_control_app import load_media
from guest_environment import personal_accounts_separated
from vm_control_session import ManualControlSession


def windows_arguments(*values):
    return subprocess.list2cmdline([str(value) for value in values])


class VMRunManager:
    def __init__(self, connection, media, workspace, vmx, *, username, credential, probe, progress=None, scanner=None):
        self.connection = connection
        self.media, _, self.request, self.manifest = load_media(media)
        self.workspace = external_path(workspace)
        self.vmx = Path(vmx)
        self.username, self.credential = username, credential
        self.probe = probe
        self.progress = progress or (lambda message: None)
        self.session = None
        self.guest_root = None
        self.python = None
        self.environment = None
        self.active_path = self.workspace / "vm-controls" / "active-session.json"
        self.scanner = scanner or {}
        self.pending_scan = None
        self.scanner_cleanup = None
        scanner_folder=self.workspace/'scanner-checks'
        if scanner_folder.is_symlink():raise ValueError('Unexpected scanner workspace link')
        for path in scanner_folder.glob('cleanup-required-*.json'):
            if path.is_symlink() or path.stat().st_size>8192:raise ValueError('Invalid scanner recovery record')
            cleanup=json.loads(path.read_text(encoding='utf-8'));token=cleanup.get('id','')
            if not re.fullmatch(r'[0-9a-f]{32}',token) or path.name!='cleanup-required-'+token+'.json':
                raise ValueError('Invalid scanner recovery identity')
            if (scanner_folder/('cleanup-completed-'+token+'.json')).exists():continue
            if cleanup.get('vmx')!=str(self.vmx.resolve()):continue
            if self.scanner_cleanup:raise ValueError('Multiple scanner recovery records need review')
            self.scanner_cleanup=cleanup
        for path in scanner_folder.glob('pending-*.json'):
            if path.is_symlink() or path.stat().st_size>8192:raise ValueError('Invalid pending scanner record')
            pending=json.loads(path.read_text(encoding='utf-8'));token=pending.get('id','')
            if not re.fullmatch(r'[0-9a-f]{32}',token):raise ValueError('Invalid pending scanner identity')
            if (scanner_folder/('resolved-'+token+'.json')).exists() or (scanner_folder/('deferred-'+token+'.json')).exists():continue
            if pending.get('vmx')!=str(self.vmx.resolve()):continue
            if self.pending_scan:raise ValueError('Multiple unfinished scanner checks need review')
            if Path(pending['host_output'])!=scanner_folder/('scan-'+token+'.json'):
                raise ValueError('Pending scanner output is outside its workspace')
            output=PureWindowsPath(pending['guest_output'])
            if (not output.is_absolute() or '..' in output.parts
                    or output.name!='elevated-'+token+'.json'
                    or not re.fullmatch(r'AegisScanners-[0-9a-f]{32}',output.parent.name)):
                raise ValueError('Invalid pending guest scanner path')
            self.pending_scan=pending
        from vm_lab_preparation import LabPreparation
        self.lab=LabPreparation(self)

    def login(self):
        self.connection.login(self.username, self.credential)
        appdata = self.connection.environment("LOCALAPPDATA")
        base = PureWindowsPath(appdata)
        if not base.is_absolute() or ".." in base.parts or len(appdata) > 1024:
            raise ValueError("Windows lab path is invalid")
        self.python = str(base / "Programs/Python/Python314-arm64/python.exe")
        if not self.connection.exists(self.python):
            raise ValueError("Prepared Windows ARM Python is absent")
        return base

    def deploy(self):
        if self.active_path.is_file():
            value = json.loads(self.active_path.read_text(encoding="utf-8"))
            if value.get("vmx") != str(self.vmx.resolve()):raise ValueError("Active session belongs to another VM")
            return self.resume(value["session_root"])
        self.progress("Tikrinama atskira Windows paskyra ir perkeliami tik kontrolės failai…")
        base = self.login()
        self.connection.stop_old_control_ui()
        # A unique dedicated kit never replaces user files or a mounted CD.
        self.guest_root = base / ("AegisKit-" + uuid.uuid4().hex)
        self.connection.mkdir(str(self.guest_root))
        relative_files = ["media-manifest.json", *["src/" + name for name in self.manifest["source_hashes"] if name != "request.json"]]
        transfer = PureWindowsPath(self.manifest["request_path"]).parent
        relative_files += [str(transfer / "request.json"), *[str(transfer / (key + ".txt")) for key in self.request["selected"]]]
        directories = set()
        for name in relative_files:
            relative = PureWindowsPath(name)
            for parent in relative.parents:
                if str(parent) != ".":directories.add(parent)
        for directory in sorted(directories, key=lambda p: len(p.parts)):
            self.connection.mkdir(str(self.guest_root / directory))
        for name in relative_files:
            relative = PureWindowsPath(name)
            source = self.media.joinpath(*relative.parts)
            self.connection.copy_to(source, str(self.guest_root / relative))
        self.session = ManualControlSession(self.connection, self.media, self.workspace, self.vmx,
                                            account_ready=False, probe=self.probe, windows_credentials_used=True)
        write_json(self.session.root / "deployment.json", {
            "guest_root": str(self.guest_root), "source_hashes": self.manifest["source_hashes"],
            "windows_credentials_used": True, "credentials_saved": False, "experiment_results": False})
        return self.collect_environment()

    def save_active(self):
        if self.active_path.is_symlink():raise ValueError("Unexpected active-session link")
        temporary = self.active_path.with_name("active-" + uuid.uuid4().hex + ".json")
        write_json(temporary, {"vmx": str(self.vmx.resolve()), "session_root": str(self.session.root),
            "media_root": str(self.media), "snapshot": self.session.snapshot, "credentials_saved": False})
        os.replace(temporary, self.active_path)

    def resume(self, root):
        base = self.login()
        deployment = json.loads((Path(root) / "deployment.json").read_text(encoding="utf-8"))
        guest_root = PureWindowsPath(deployment["guest_root"])
        if guest_root.parent != base or not guest_root.name.startswith("AegisKit-"):
            raise ValueError("Saved guest kit is outside the lab workspace")
        self.guest_root = guest_root
        self.session = ManualControlSession.resume(self.connection, self.media, self.workspace, self.vmx, root, probe=self.probe)
        if self.session.state in {"awaiting_baseline_boot", "awaiting_restore_boot"}:
            self.session.continue_after_boot()
            self.login()
        value = self.collect_environment()
        if not self.session.account_ready:raise ValueError("Personal account separation is not verified")
        message = self.status()
        if self.session.state == "resume_check":
            if message is None or message["phase"] != "ready" or message["run_root_exists"] or message["mutation_exists"] or message["network_up"] is not False:
                raise ValueError("Current guest does not match the completed clean state")
            self.session.state = "restored" if self.session.cycle_root else "baseline_ready"
            if self.session.state == "baseline_ready":self.connection.allow_inert_run(self.session.challenge)
        self.save_active()
        self.finish_scanner_cleanup()
        self.lab.audit_restored_artifacts()
        return value

    def run_guest(self, module, *arguments):
        if self.guest_root is None or module not in {"guest_control_app.py", "guest_environment.py"}:
            raise ValueError("Only prepared control/inventory modules may run")
        code = self.connection.run(self.python, windows_arguments(self.guest_root / "src" / module, *arguments), timeout=90)
        if code != 0:
            raise ValueError("Prepared guest program failed with exit code " + str(code))

    def collect_environment(self):
        token = uuid.uuid4().hex
        guest_output = self.guest_root / ("environment-" + token + ".json")
        self.run_guest("guest_environment.py", "--output", guest_output)
        host_output = self.session.root / ("environment-" + token + ".json")
        self.connection.copy_from(str(guest_output), host_output)
        if host_output.stat().st_size > 65536:
            raise ValueError("Guest environment exceeds limit")
        value = json.loads(host_output.read_text(encoding="utf-8"))
        expected_hash = self.manifest["source_hashes"]["guest_environment.py"]
        if (value.get("collector_sha256") != expected_hash or value.get("platform") != "Windows"
                or value.get("architecture", "").casefold() not in {"arm64", "aarch64"}
                or value.get("experiment_results") is not False):
            raise ValueError("Guest environment identity mismatch")
        self.environment = value
        self.session.account_ready = personal_accounts_separated(value)
        return value

    def status(self):
        if self.session is None:raise ValueError("Deploy prepared controls first")
        self.run_guest("guest_control_app.py", "--media", self.guest_root, "--action", "status")
        value = self.session.receive()
        if value is not None:
            write_json(self.session.root / ("proof-" + value["message_id"] + ".json"), value)
        return value

    def baseline(self):
        self.collect_environment()
        self.status()
        self.progress("Windows įprastai išjungiama ir kuriama šalta pradinė kopija…")
        self.session.create_baseline()
        self.save_active()
        if self.session.state == "awaiting_baseline_boot":return self.summary()
        self.login()
        self.status()
        return self.summary()

    def control(self):
        if self.session is None or self.session.state != "baseline_ready":
            raise ValueError("A cold baseline must be ready first")
        self.progress("Windows tikrina pasirinktus inertinius tekstus…")
        try:
            self.run_guest("guest_control_app.py", "--media", self.guest_root, "--action", "control")
        except Exception:
            self.session.fail_after_mutation()
            raise
        value = self.session.receive()
        if self.session.state != "result_saved":
            raise ValueError("Guest result has not been durably saved on the host")
        return value

    def restore(self):
        self.progress("Atkuriama VM; Mac rezultatai jau išsaugoti…")
        self.session.restore()
        if self.session.state == "awaiting_restore_boot":return self.summary()
        self.login()
        self.status()
        if self.session.state != "restored":
            raise ValueError("Fresh absence proof after restore is missing")
        self.finish_scanner_cleanup()
        return self.summary()

    def continue_after_boot(self):
        self.session.continue_after_boot()
        self.login()
        self.status()
        self.finish_scanner_cleanup()
        return self.summary()

    def finish_scanner_cleanup(self):
        """A stored scanner result is separate from proof of a later cold restore."""
        if not self.scanner_cleanup or not self.session or self.session.state!='restored':return
        cycle=str(self.session.cycle_root)
        if cycle==self.scanner_cleanup['previous_cycle']:return
        from vm_results import validate_cycle
        report,completion,evidence=validate_cycle(self.session.cycle_root/'report.json',self.workspace)
        if not completion or evidence.get('vm_restore_verified') is not True:return
        token=self.scanner_cleanup['id']
        write_json(self.workspace/'scanner-checks'/('cleanup-completed-'+token+'.json'),
                   {'id':token,'cycle_root':cycle,'vm_restore_verified':True,'experiment_results':False})
        self.scanner_cleanup=None
        self.lab.record_restore()
        from vm_selection_transfer import record_restore
        record_restore(self)

    def cycle(self):
        if self.lab.pending:raise ValueError('Finish or defer lab preparation before VM restore')
        if self.pending_scan:raise ValueError("Finish or defer the pending scanner check before VM restore")
        if self.session is None:self.deploy()
        if self.session.state == "waiting_ready":self.status()
        if self.session.state == "ready":self.baseline()
        if self.session.state in {"awaiting_baseline_boot", "awaiting_restore_boot"}:return self.summary()
        if self.session.state == "restored":self.session.next_cycle()
        if self.session.state == "result_saved":return self.restore()
        self.control()
        return self.restore()

    def scan_controls(self):
        if self.pending_scan or self.scanner_cleanup:
            raise ValueError('Finish the previous scanner check and cold restore first')
        if self.session is None or self.session.state not in {"baseline_ready","restored"}:
            raise ValueError("Prepare or restore the cold baseline before scanner controls")
        from guest_scanners import validate_report
        vendor=Path(self.scanner.get('yara_executable',''))
        expected=self.scanner.get('yara_sha256')
        if not vendor.is_file() or vendor.is_symlink() or hashlib.sha256(vendor.read_bytes()).hexdigest()!=expected:
            raise ValueError("A vendor-verified YARA executable must be configured first")
        folder=self.workspace/'scanner-checks';folder.mkdir(exist_ok=True)
        token=uuid.uuid4().hex
        cleanup={'id':token,'vmx':str(self.vmx.resolve()),'previous_cycle':str(self.session.cycle_root),'experiment_results':False}
        write_json(folder/('cleanup-required-'+token+'.json'),cleanup)
        self.scanner_cleanup=cleanup
        base=PureWindowsPath(self.connection.environment('LOCALAPPDATA'))
        kit=base/('AegisScanners-'+uuid.uuid4().hex)
        for guest_folder in (kit,kit/'src',kit/'rules'):self.connection.mkdir(str(guest_folder))
        source=Path(__file__).parent
        for name in ('aegis.py','control_workspace.py','guest_control.py','guest_scanners.py'):
            self.connection.copy_to(source/name,str(kit/'src'/name))
        self.connection.copy_to(source.parent/'rules/control-marker.yar',str(kit/'rules/control-marker.yar'))
        self.connection.copy_to(vendor,str(kit/'yara64.exe'))
        output=kit/'report.json'
        arguments=windows_arguments(kit/'src/guest_scanners.py','--yara',kit/'yara64.exe','--yara-sha256',expected,'--output',output)
        code=self.connection.run(self.python,arguments,timeout=240)
        if code!=0:raise ValueError('Scanner control program did not finish successfully: '+str(code))
        path=folder/('scan-'+uuid.uuid4().hex+'.json')
        self.connection.copy_from(str(output),path)
        if path.stat().st_size>65536:raise ValueError('Scanner result exceeds limit')
        code_hash=hashlib.sha256((source/'guest_scanners.py').read_bytes()).hexdigest()
        report=validate_report(json.loads(path.read_text(encoding='utf-8')),code_hash,expected)
        write_json(path.with_name(path.stem+'.identity.json'),{'code_sha256':code_hash,'yara_sha256':expected,'experiment_results':False})
        if report['elevated'] is False:
            token=uuid.uuid4().hex;guest_output=kit/('elevated-'+token+'.json')
            elevated_args=windows_arguments(kit/'src/guest_scanners.py','--yara',kit/'yara64.exe','--yara-sha256',expected,'--output',guest_output)
            # UAC remains enabled; a human launches and approves this one-off command.
            script="$argsText='"+elevated_args.replace("'","''")+"'; Start-Process -FilePath '"+self.python.replace("'","''")+"' -Verb RunAs -ArgumentList $argsText -Wait"
            encoded=base64.b64encode(script.encode('utf-16le')).decode('ascii')
            launcher=folder/('launcher-'+token+'.cmd')
            launcher.write_bytes(('@echo off\r\npowershell.exe -NoLogo -NoProfile -EncodedCommand '+encoded+'\r\n').encode('ascii'))
            desktop=PureWindowsPath(self.connection.environment('USERPROFILE'))/'Desktop'/('Aegis-Scanner-Control-'+token[:8]+'.cmd')
            self.connection.copy_to(launcher,str(desktop))
            self.pending_scan={'guest_output':str(guest_output),'host_output':str(folder/('scan-'+token+'.json')),
                'code_sha256':code_hash,'yara_sha256':expected,'launcher':str(desktop),'id':token,'vmx':str(self.vmx.resolve())}
            write_json(folder/('pending-'+token+'.json'),self.pending_scan)
        return {'report_path':str(path),'report':report,'pending_elevation':self.pending_scan is not None,
                'launcher':self.pending_scan['launcher'] if self.pending_scan else None}

    def finish_scanner(self):
        if self.pending_scan is None:return None
        value=self.pending_scan
        if not self.connection.exists(value['guest_output']):return None
        path=Path(value['host_output'])
        if not path.exists():self.connection.copy_from(value['guest_output'],path)
        if path.stat().st_size>65536:raise ValueError('Scanner result exceeds limit')
        from guest_scanners import validate_report
        report=validate_report(json.loads(path.read_text(encoding='utf-8')),value['code_sha256'],value['yara_sha256'])
        if report['elevated'] is not True:raise ValueError('Elevated scanner confirmation is missing')
        identity=path.with_name(path.stem+'.identity.json')
        if not identity.exists():write_json(identity,{'code_sha256':value['code_sha256'],'yara_sha256':value['yara_sha256'],'experiment_results':False})
        write_json(path.parent/('resolved-'+value['id']+'.json'),{'completed':True,'report':path.name,'experiment_results':False})
        self.pending_scan=None
        return {'report_path':str(path),'report':report}

    def defer_scanner(self):
        if self.pending_scan:
            value=self.pending_scan
            write_json(self.workspace/'scanner-checks'/('deferred-'+value['id']+'.json'),
                       {'defender_status':'NOT_RUN','reason':'Deferred by operator; no result claimed','experiment_results':False})
            self.pending_scan=None

    def summary(self):
        if self.session is None:return {"state": "not_deployed", "experiment_results": False}
        return {"state": self.session.state, "session_root": str(self.session.root),
                "snapshot": self.session.snapshot, "cycle_root": str(self.session.cycle_root) if self.session.cycle_root else None,
                "vm_restore_verified": self.session.state == "restored" and self.scanner_cleanup is None and self.lab.pending is None,
                "scanner_cleanup_required":self.scanner_cleanup is not None,"experiment_results": False}

    def close(self):
        self.credential = None
        self.connection.close()
