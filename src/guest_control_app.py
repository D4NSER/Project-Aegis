"""Manually launched Windows control app; no Windows/account password needed."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import platform
import queue
import re
import subprocess
import threading
import uuid

from aegis import local_file
from guest_control import plain_path, read_request, run_control

MODULES = ("aegis.py", "control_workspace.py", "guest_control.py", "guest_control_app.py", "guest_environment.py")


class LinkUnavailable(ValueError):
    """The Mac has not opened a usable metadata session yet."""


def load_media(media):
    media = plain_path(media)
    path = local_file(media, "media-manifest.json")
    if path.stat().st_size > 65536:
        raise ValueError("Media manifest exceeds limit")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if (manifest.get("schema") != 1 or manifest.get("kind") != "inert_guest_media"
            or manifest.get("experiment_results") is not False):
        raise ValueError("Expected an inert control CD")
    request_path = local_file(media, manifest["request_path"])
    transfer, request, request_hash = read_request(request_path.parent)
    expected_sources = {*MODULES, "request.json"}
    if set(manifest["source_hashes"]) != expected_sources:
        raise ValueError("Unexpected media source inventory")
    for name in MODULES:
        content = local_file(media, "src/" + name).read_bytes()
        if hashlib.sha256(content).hexdigest() != manifest["source_hashes"][name]:
            raise ValueError("Changed guest source")
    if request_hash != manifest["source_hashes"]["request.json"]:
        raise ValueError("Changed guest request")
    return media, transfer, request, manifest


def stage_and_run(transfer, request, root):
    root = plain_path(root)
    root.mkdir(parents=True, exist_ok=True)
    work = root / request["run_id"]
    work.mkdir()  # Existing work is evidence, never overwritten or deleted here.
    for name in ("request.json", *(key + ".txt" for key in request["selected"])):
        source = plain_path(transfer / name)
        with (work / name).open("xb") as stream:
            stream.write(source.read_bytes())
    return run_control(work)


def tools_path():
    path = Path(os.environ["ProgramFiles"]) / "VMware" / "VMware Tools" / "vmtoolsd.exe"
    if not path.is_file():
        raise ValueError("VMware Tools command is missing")
    return path


def tools_command(command):
    result = subprocess.run([str(tools_path()), "--cmd", command], capture_output=True,
                            text=True, timeout=10, check=True)
    return result.stdout.strip()


def current_challenge():
    try:
        value = tools_command("info-get guestinfo.aegis.challenge")
    except (OSError, subprocess.SubprocessError) as exc:
        raise LinkUnavailable("Open the Mac control connection first") from exc
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("Open the Mac control connection first")
    return value


def run_allowed(challenge):
    try:
        return tools_command("info-get guestinfo.aegis.run_permission") == challenge
    except (OSError, subprocess.SubprocessError):
        return False


def guest_network_up():
    command = "(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up' | Measure-Object).Count"
    try:
        result = subprocess.run(["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                                 "-Command", command], capture_output=True, text=True, timeout=10, check=True)
        value = result.stdout.strip()
        return int(value) > 0 if value.isdecimal() else None
    except (OSError, subprocess.SubprocessError):
        return None


def publish_status(request, root, challenge):
    work = plain_path(root / request["run_id"])
    report_path = plain_path(work / "guest-report.json")
    report = None
    if report_path.exists():
        if report_path.stat().st_size > 12000:
            raise ValueError("Guest report exceeds limit")
        report = json.loads(report_path.read_text(encoding="utf-8"))
    value = {"schema": 1, "phase": "complete" if report is not None else "ready",
             "challenge": challenge, "run_id": request["run_id"], "nonce": request["nonce"],
             "message_id": uuid.uuid4().hex, "platform": platform.system(),
             "architecture": platform.machine(),
             "app_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
             "run_root_exists": work.exists(), "mutation_exists": (work / "mutation.json").exists(),
             "network_up": guest_network_up(), "report": report}
    raw = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(raw) > 16000:
        raise ValueError("Control response exceeds metadata limit")
    tools_command("info-set guestinfo.aegis.control " + base64.b64encode(raw).decode("ascii"))
    return value


class GuestApp:
    def __init__(self, root, media, workspace):
        from tkinter import ttk
        self.window = root
        _, self.transfer, self.request, _ = load_media(media)
        self.workspace = workspace
        self.events = queue.Queue()
        self.busy = False
        root.title("Project Aegis – Windows kontrolė")
        root.geometry("680x420")
        root.configure(background="#f5f7fa")
        frame = ttk.Frame(root, padding=24)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Project Aegis", font=("Arial", 21, "bold")).pack(anchor="w")
        ttk.Label(frame, text="Windows kontrolė · tik nekenksmingi tekstai", font=("Arial", 12)).pack(anchor="w", pady=8)
        ttk.Label(frame, text="Pasirinkta laikmenoje: " + ", ".join(self.request["selected"]), wraplength=620).pack(anchor="w", pady=10)
        ttk.Label(frame, text="Programa patikrina turinį ir perduoda mažą atsakymą per VMware Tools.\nAV / YARA nevykdomi. Darbo failai paliekami VM atkūrimo patikrai.\nWindows ir Microsoft paskyros slaptažodžio nereikia.", wraplength=620).pack(anchor="w", pady=8)
        self.status = ttk.Label(frame, text="Atverk Mac ryšį, tada atnaujink būseną.", wraplength=620)
        self.status.pack(anchor="w", pady=16)
        self.refresh_button = ttk.Button(frame, text="Atnaujinti ryšį", command=lambda: self.start(False))
        self.refresh_button.pack(anchor="w", pady=4)
        self.run_button = ttk.Button(frame, text="Vykdyti kontrolę", command=lambda: self.start(True), state="disabled")
        self.run_button.pack(anchor="w", pady=4)
        root.after(200, self.poll)
        root.after(500, self.heartbeat)

    def heartbeat(self):
        # Status transfer continues without coordinating clicks in two windows.
        # start() serializes work; no overlapping Tools or network probes occur.
        self.start(False)
        self.window.after(5000, self.heartbeat)

    def start(self, run):
        if self.busy:
            return
        self.busy = True
        self.refresh_button.configure(state="disabled")
        self.run_button.configure(state="disabled")
        self.status.configure(text="Tikrinama…")
        threading.Thread(target=self.worker, args=(run,), daemon=True).start()

    def worker(self, run):
        try:
            challenge = current_challenge()
            allowed = run_allowed(challenge)
            if run:
                if not allowed:
                    raise ValueError("Prepare the clean baseline in the Mac panel first")
                stage_and_run(self.transfer, self.request, self.workspace)
            self.events.put((True, (publish_status(self.request, self.workspace, challenge), allowed)))
        except Exception as exc:
            self.events.put((False, type(exc).__name__))

    def poll(self):
        try:
            success, value = self.events.get_nowait()
            self.busy = False
            self.refresh_button.configure(state="normal")
            if success:
                value, allowed = value
                if value["phase"] == "complete":
                    self.status.configure(text="Kontrolė baigta. Atsakymas perduotas Mac. VM darbo failai palikti atkūrimo patikrai.")
                elif value["run_root_exists"]:
                    self.status.configure(text="Yra ankstesnių darbo failų. Mac turi patikrinti / atkurti VM būseną.")
                else:
                    self.status.configure(text="Ryšys veikia. Darbo failų nėra. " + ("Galima vykdyti kontrolę." if allowed else "Kontrolė užrakinta: švari VM būsena dar neparuošta. Būsena perduodama automatiškai."))
                    if allowed:
                        self.run_button.configure(state="normal")
            else:
                self.status.configure(text=("Laukiama Mac ryšio. Mac lange atverk VM ryšį; Windows slaptažodžio nereikia." if value == "LinkUnavailable" else "Ryšio patikra nesėkminga: " + value + ". Programa bandys atnaujinti būseną automatiškai."))
        except queue.Empty:
            pass
        self.window.after(200, self.poll)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--media", required=True)
    parser.add_argument("--action", choices=("ui", "status", "control"), default="ui")
    args = parser.parse_args(argv)
    if os.name != "nt":
        parser.error("This guest application runs in Windows only")
    workspace = plain_path(Path(os.environ["LOCALAPPDATA"]) / "ProjectAegis" / "guest-runs")
    workspace.mkdir(parents=True, exist_ok=True)
    if args.action != "ui":
        _, transfer, request, _ = load_media(args.media)
        challenge = current_challenge()
        if args.action == "control":
            if not run_allowed(challenge):
                raise ValueError("Prepare the cold baseline before running controls")
            stage_and_run(transfer, request, workspace)
        publish_status(request, workspace, challenge)
        return
    # OS-backed process lock, released on exit/crash; repeated launches do not make more windows.
    import msvcrt
    with (workspace / ".app.lock").open("a+b") as lock:
        lock.seek(0)
        if not lock.read(1):
            lock.write(b"0"); lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            return
        import tkinter as tk
        root = tk.Tk()
        GuestApp(root, args.media, workspace)
        root.mainloop()


if __name__ == "__main__":
    main()
