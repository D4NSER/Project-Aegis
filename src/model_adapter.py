"""Model access fixed before any attempt: setup record, private exchanges and adapters.

The setup (model identifier, access route, generation settings and task
templates) is written once and identified by its hashes; every attempt names
it, and a changed template or setting is refused rather than used. Requests
and responses are stored only in a private exchange folder outside the public
repository; logs and reports carry their SHA-256 hashes, never their text.

Adapters answer one turn of one session:

* `SimulatedAdapter` - prepared responses, keyed by task, subject, candidate
  and turn; used to check the flow before a model is chosen;
* `ManualAdapter` - a researcher pastes each response into a file; a missing
  response stops the session as pending, so nothing is invented. Its duration
  is the researcher's wait, fixed when the response is first taken, and is
  reported apart from model time.

A refusal is recorded as a refusal. Nothing here rephrases or retries a
refused request.
"""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

import aegis

SETUP_FIELDS = {"schema", "kind", "setup_id", "model_id", "access", "mode", "settings", "settings_sha256",
                "templates", "fixed_at_utc"}
MODES = {"simulated", "manual"}
PLACEHOLDER = re.compile(r"\{([a-z_]+)\}")


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def setup_id(model_id, access, mode, settings, template_hashes):
    """The setup's identity covers everything that shapes a request: model, access, mode, settings, templates."""
    return "setup-" + sha(canonical({"model_id": model_id, "access": access, "mode": mode, "settings": settings,
                                     "templates": template_hashes}))[:16]


def fix_setup(directory, *, model_id, access, mode, settings, templates):
    """Write the setup once: templates as files, the record with their hashes. Never overwritten."""
    if mode not in MODES or not str(model_id).strip() or not str(access).strip():
        raise ValueError("A setup needs a model identifier, an access route and a known mode")
    if not isinstance(settings, dict) or not isinstance(templates, dict) or not templates:
        raise ValueError("Settings and at least one task template are required")
    folder = aegis.external_path(directory)
    folder.mkdir(parents=True, exist_ok=False)
    hashes = {}
    for name, text in sorted(templates.items()):
        if not re.fullmatch(r"[a-z_]{1,40}", name) or not isinstance(text, str) or not text.strip():
            raise ValueError("Invalid template: " + str(name))
        with (folder / (name + ".txt")).open("x", encoding="utf-8", newline="") as stream:
            stream.write(text)
        hashes[name] = sha(text)
    record = {"schema": 1, "kind": "model_setup", "setup_id": setup_id(model_id, access, mode, settings, hashes),
        "model_id": model_id, "access": access, "mode": mode, "settings": settings,
        "settings_sha256": sha(canonical(settings)), "templates": hashes,
        "fixed_at_utc": datetime.now(timezone.utc).isoformat()}
    with (folder / "setup.json").open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    return record


def load_setup(directory):
    """The fixed setup and its templates; any change after fixing is refused."""
    folder = aegis.external_path(directory)
    record = json.loads((folder / "setup.json").read_text(encoding="utf-8"))
    if not isinstance(record, dict) or set(record) != SETUP_FIELDS or record["kind"] != "model_setup":
        raise ValueError("Invalid model setup record")
    if record["settings_sha256"] != sha(canonical(record["settings"])):
        raise ValueError("Model settings changed after the setup was fixed")
    if record["mode"] not in MODES or record["setup_id"] != setup_id(
            record["model_id"], record["access"], record["mode"], record["settings"], record["templates"]):
        raise ValueError("Model setup changed after it was fixed: its identity no longer matches its fields")
    templates = {}
    for name, expected in record["templates"].items():
        text = (folder / (name + ".txt")).read_text(encoding="utf-8")
        if sha(text) != expected:
            raise ValueError("Task template changed after the setup was fixed: " + name)
        templates[name] = text
    return record, templates


def render(template, values):
    """Fill a template's {placeholders}; every placeholder must be supplied, nothing extra."""
    names = set(PLACEHOLDER.findall(template))
    if names != set(values):
        raise ValueError("Template placeholders and supplied values differ: " + ", ".join(sorted(names ^ set(values))))
    return PLACEHOLDER.sub(lambda m: values[m.group(1)], template)


class ExchangeStore:
    """Private request and response texts; the caller keeps only their hashes."""

    def __init__(self, root):
        self.root = aegis.external_path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def save(self, session_id, turn, name, text):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", session_id):
            raise ValueError("Invalid session ID")
        folder = self.root / session_id
        folder.mkdir(exist_ok=True)
        with (folder / ("%02d-%s.txt" % (turn, name))).open("x", encoding="utf-8", newline="") as stream:
            stream.write(text)
        return sha(text)


class PendingResponse(Exception):
    """A manual response has not been provided yet; the session can be resumed."""


class SimulatedAdapter:
    """Prepared responses: {"task:subject:candidate:turn": {"text": ...} or {"refused": true}}."""
    mode = "simulated"

    def __init__(self, script):
        self.script = dict(script)
        self.asked = []

    def complete(self, *, task, subject, candidate, turn, prompt):
        key = "%s:%s:%s:%s" % (task, subject, candidate, turn)
        self.asked.append(key)
        if key not in self.script:
            raise ValueError("No prepared response for " + key)
        entry = self.script[key]
        if entry.get("refused") is True:
            return {"text": entry.get("text", ""), "refused": True, "elapsed_seconds": entry.get("elapsed", 0.0)}
        return {"text": entry["text"], "refused": False, "elapsed_seconds": entry.get("elapsed", 0.0)}


class ManualAdapter:
    """A researcher answers each request by writing `<key>.txt` (or `<key>.refused`) in `folder`."""
    mode = "manual"

    def __init__(self, folder, clock=time.monotonic):
        self.folder = aegis.external_path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.clock = clock

    def complete(self, *, task, subject, candidate, turn, prompt):
        key = "%s-%s-%s-%s" % (task, subject, candidate, turn)
        request = self.folder / (key + ".request.txt")
        if not request.exists():
            request.write_text(prompt, encoding="utf-8")
            (self.folder / (key + ".asked")).write_text(str(self.clock()), encoding="utf-8")
        elif request.read_text(encoding="utf-8") != prompt:
            raise ValueError("A different request was already issued for " + key)
        asked = float((self.folder / (key + ".asked")).read_text(encoding="utf-8"))
        refused = self.folder / (key + ".refused")
        answer = self.folder / (key + ".txt")
        source = refused if refused.exists() else answer if answer.exists() else None
        if source is None:
            raise PendingResponse("Waiting for a manual response: " + answer.name)
        # The wait is fixed when the response is first taken; reading it again does not lengthen it.
        received = self.folder / (key + ".received")
        if not received.exists():
            received.write_text(str(self.clock()), encoding="utf-8")
        wait = round(float(received.read_text(encoding="utf-8")) - asked, 3)
        return {"text": source.read_text(encoding="utf-8"), "refused": source is refused,
                "elapsed_seconds": wait}
