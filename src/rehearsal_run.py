"""One laboratory rehearsal run: frozen plan -> guarded checks -> one report series -> accounting.

The run uses harmless stand-ins made from the two rehearsal programs: each
copy carries its own embedded work-directory token, so every file has its own
hash and its own expected work directory, and none is malware. The phases
follow the protocol's order:

1. plan           - a collection and catalogue of the stand-ins, the frozen
                    original-group and benign assignment records, the fixed
                    simulated model setup with its prepared responses, the
                    expected outcomes and costs, and the hashes of all of them
                    (`plan.json`);
1a. model control - the rule control (state F): the model's rule must match
                    the marker program and not a copy with a changed marker;
                    the code control waits for the C/C++ toolchain decision;
2. functionality  - originals and variants run once under the shared card
                    (state F); the evaluator's records join the manifest;
3. calibration AV - calibration files and the evaluation original, one
                    guarded request (`run_guard`) per cold cycle (state A);
4. rules          - the guard is first shown to refuse final checks, then a
                    generation session asks the (simulated) model for a rule
                    for each undetected calibration target; static rejections
                    are repaired without a YARA run, candidates are checked in
                    state F, accepted from their recorded results and frozen
                    with the run ID; every attempt is logged;
5. final AV       - evaluation variants and benign files, only through
                    `run_guard` with the freeze record;
6. final YARA     - evaluation files with the frozen rule set;
7. accounting     - every AV and YARA report of the run, in order, as one
                    detector series; rehearsal-mode accounting checks the
                    evidence like a research run and reports no experiment
                    results; the cost tables are built from the attempts log.

Only files of the frozen plan can be requested: requests are built from the
manifest, and every phase first re-checks the plan's hashes. All state lives
in the run folder, so phases can be resumed after a restart.
"""
from datetime import datetime, timezone
import csv
import hashlib
import io
import json
from pathlib import Path, PureWindowsPath
import uuid

import aegis
import cost_table
import dataset_plan
import generation
import generation_log
import model_adapter
import functionality_card
import rule_workflow
import run_guard
import scan_bridge
from control_workspace import write_json

PROTOCOL = "rehearsal-2026-11-28"
# (sample_id, program, kind, project, parent, generation order). Calibration and evaluation
# groups are assigned by the frozen rules, not listed here.
SAMPLES = (("C1", "baseline", "original", "rehearsal-group-1", "", ""),
           ("CB1", "variant", "benign", "rehearsal-benign-1", "", ""),
           ("E1", "baseline", "original", "rehearsal-group-2", "", ""),
           ("E1-v1", "baseline", "variant", "rehearsal-group-2", "E1", "1"),
           ("EB1", "variant", "benign", "rehearsal-benign-2", "", ""))
CARD = {"schema": 1, "kind": "functionality_card", "card_id": "rehearsal-baseline-program",
        "original_id": "rehearsal-baseline-program", "created_at_utc": "2026-11-28T12:30:00+00:00",
        "input": {"arguments": ["{workdir}", "{token}"]}, "time_limit_seconds": 8,
        "expected": {"exit_code": 0, "stdout": "AEGIS_REHEARSAL_BASELINE:{token}", "stderr_empty": True,
                     "files": [{"path": "observed.txt", "content": "AEGIS_OK:{token}"}]},
        "evidence": {"monitor": "process_monitor",
                     "operations": [{"operation": "WriteFile", "path": "observed.txt", "result": "SUCCESS"}]}}
# The simulated model's setup and prepared responses, fixed in the plan before any check.
CANDIDATE = ('rule Aegis_Rehearsal_Baseline_Program\n{\n    strings:\n        $s = "AEGIS_REHEARSAL_BASELINE" wide\n'
             '    condition:\n        $s\n}\n')
MARKER, CHANGED_MARKER = "AEGIS_REHEARSAL_BASELINE", "AEGIS_REHEARSAL_CHANGEDX"
TEMPLATES = {"rule": "Write one YARA rule that recognises the file described below. Use only strings that "
                     "appear in the description; do not use file names or paths.\n{description}\n",
             "rule_repair": "The rule did not pass these checks. Return a corrected rule.\n{feedback}\n"}
SETTINGS = {"responses": "prepared", "temperature": 0}


def _yara(text):
    return "Here is the rule.\n```yara\n" + text + "```\n"


LOOSE = CANDIDATE.replace('"AEGIS_REHEARSAL_BASELINE"', '"AEGIS_REHEARSAL_"').replace("Program", "Prefix")
ASCII_ONLY = CANDIDATE.replace(" wide", " ascii")
RESPONSES = {
    # Rule control: a too general rule (also matches the changed copy), then the marker rule.
    "rule_control:marker-program:1:0": {"text": _yara(LOOSE), "elapsed": 1.5},
    "rule_control:marker-program:1:1": {"text": _yara(CANDIDATE), "elapsed": 1.0},
    # Calibration target: an ASCII search the description does not support, then the wide-string rule.
    "rule:C1:1:0": {"text": _yara(ASCII_ONLY), "elapsed": 2.0},
    "rule:C1:1:1": {"text": _yara(CANDIDATE), "elapsed": 1.5},
}
EXPECTED = {"functionality": {"C1": "PASS", "E1": "PASS", "E1-v1": "PASS"},
            "calibration_av": {"C1": "NOT_DETECTED", "CB1": "NOT_DETECTED", "E1": "NOT_DETECTED"},
            "rule": {"target": "C1", "decision": "ACCEPTED", "freeze": "FROZEN"},
            "final_av": {"E1-v1": "NOT_DETECTED", "EB1": "NOT_DETECTED"},
            "final_yara": {"E1": "MATCHED", "E1-v1": "MATCHED", "EB1": "NOT_MATCHED"},
            "guard_refusals": 2,
            "model_control": {"rule": {"outcome": "ACCEPTED", "repairs": 1,
                                       "first_rejection": "REJECTED_CHANGED_COPY_MATCH"},
                              "code": "NOT_RUN_TOOLCHAIN_NOT_CHOSEN"},
            "rule_session": {"C1": {"outcome": "ACCEPTED", "repairs": 1,
                                    "first_rejection": "REJECTED_FEATURE_NOT_IN_DESCRIPTION"}},
            # Hand count from the prepared responses: two attempts, four requests, two repairs.
            "costs": {"rule_control": {"attempts": 1, "requests": 2, "repairs": 1, "refusals": 0, "failures": 0,
                                       "model_seconds": 2.5, "manual_wait_seconds": 0.0, "usable": [1, 1]},
                      "rule": {"attempts": 1, "requests": 2, "repairs": 1, "refusals": 0, "failures": 0,
                               "model_seconds": 3.5, "manual_wait_seconds": 0.0, "usable": [1, 1]}},
            # Hand count: harmless files are never AV-detected; the rule matches the two baseline copies.
            "accounting": {"supplementation": "EVALUATED", "paired_records": 3,
                           "recall": {"av": [0, 2], "yara": [2, 2], "combined": [2, 2]},
                           "fpr": {"av": [0, 1], "yara": [0, 1], "combined": [0, 1]}}}
PHASES = ("plan", "model_control", "functionality", "calibration_av", "rules", "final_av", "final_yara",
          "accounting")


def now():
    return datetime.now(timezone.utc).isoformat()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def write_csv(path, fields, rows):
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    with Path(path).open("x", encoding="utf-8", newline="") as stream:
        stream.write(buffer.getvalue())


def stand_in(program, old_token, new_token):
    """A copy of a rehearsal program whose embedded work directory uses `new_token`."""
    old, new = ("work-" + old_token).encode("utf-16le"), ("work-" + new_token).encode("utf-16le")
    if len(old) != len(new) or program.count(old) != 1:
        raise ValueError("The rehearsal program does not carry exactly one work-directory token")
    return program.replace(old, new)


class RehearsalRun:
    def __init__(self, panel, inputs, *, run_id=None):
        """`inputs`: `research_session.lab_inputs(panel)` (programs, tools, current baseline)."""
        self.panel = aegis.external_path(panel)
        self.inputs = inputs
        base = self.panel / "rehearsals"
        if run_id is None:
            existing = sorted(p.name for p in base.glob("run-*") if (p / "plan.json").is_file()) if base.is_dir() else []
            run_id = existing[-1] if existing else None
        self.run_id = run_id
        self.root = base / run_id if run_id else None
        self.collection = self.panel / "rehearsal-collections" / run_id if run_id else None

    # --- state ------------------------------------------------------------------
    def done(self, phase):
        if self.root is None:
            return False
        marker = {"plan": "plan.json", "model_control": "model-control.json", "functionality": "manifest.csv", "calibration_av": "calibration-av.json",
                  "rules": "rules/freeze/freeze.json", "final_av": "final-av.json",
                  "final_yara": "final-yara.json", "accounting": "accounting.json"}[phase]
        if phase == "accounting":
            return self._accounting_complete()
        return (self.root / marker).is_file()

    def _accounting_complete(self):
        """Only a whole, readable final report marks accounting as complete."""
        try:
            return "expected_comparison" in read(self.root / "accounting.json")
        except (OSError, ValueError):
            return False

    def next_phase(self):
        return next((phase for phase in PHASES if not self.done(phase)), None)

    def plan(self):
        if not self.done("plan"):
            raise ValueError("Prepare the rehearsal plan first")
        value = read(self.root / "plan.json")
        for name, expected in value["hashes"].items():
            if aegis.digest(self.root / name) != expected:
                raise ValueError("The frozen plan changed: " + name)
        catalog = self.catalog()
        if catalog["catalog_sha256"] != value["catalog_sha256"]:
            raise ValueError("The rehearsal catalogue changed after the plan was frozen")
        return value, catalog

    def catalog(self):
        import control_panel
        return control_panel.load_catalog(self.collection, self.root)

    def samples(self):
        self.plan()
        rows = aegis.read_csv(self.root / "manifest.csv", aegis.SAMPLE_FIELDS)
        return aegis.validate_samples(rows, self.root, self.collection)

    def sources(self, samples):
        return {key: aegis.sample_file(row["path"], self.root, self.collection) for key, row in samples.items()}

    # --- 1. plan ----------------------------------------------------------------
    def prepare_plan(self):
        if self.root is not None and not self.done("accounting"):
            raise ValueError("Finish the current rehearsal first: " + self.run_id)
        self.run_id = "run-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + uuid.uuid4().hex[:6]
        self.root = self.panel / "rehearsals" / self.run_id
        self.collection = self.panel / "rehearsal-collections" / self.run_id
        for folder in (self.root, self.collection / "catalog", self.collection / "files", self.root / "derived"):
            folder.mkdir(parents=True)
        programs = {key: Path(value["path"]).read_bytes() for key, value in self.inputs["programs"].items()}
        old_token = PureWindowsPath(self.inputs["programs"]["baseline"]["workdir"]).parent.parent.name[len("work-"):]
        source = {"source_id": "rehearsal", "title": "Project Aegis harmless rehearsal programs",
                  "url": "aegis://controls/v1", "version": "1", "retrieved_at": now(),
                  "usage_terms": "Generated locally; harmless stand-ins for a laboratory rehearsal",
                  "status": "SYNTHETIC_CONTROLS"}
        objects, selection, derived, files = [], [], [], {}
        for sample_id, program, kind, project, parent, order in SAMPLES:
            token = uuid.uuid4().hex
            content = stand_in(programs[program], old_token, token)
            workdir = str(PureWindowsPath(self.inputs["programs"][program]["workdir"]).parent.parent.parent
                          / ("work-" + token) / "runs" / program)
            files[sample_id] = {"program": program, "token": token, "workdir": workdir,
                                "sha256": hashlib.sha256(content).hexdigest()}
            if kind == "variant":
                (self.root / "derived" / (sample_id + ".bin")).write_bytes(content)
                derived.append({"sample_id": sample_id, "parent_id": parent, "order": order})
                continue
            relative = "files/" + sample_id + ".bin"
            (self.collection / relative).write_bytes(content)
            objects.append({"object_id": sample_id, "source_id": "rehearsal", "relative_path": relative,
                            "sha256": files[sample_id]["sha256"], "bytes": str(len(content)),
                            "format": "PE", "architecture": "AnyCPU (.NET)", "project_id": project,
                            "family_id": "rehearsal-family" if kind == "original" else "", "parent_id": "",
                            # Catalogue roles: an original's role is labelled malicious by the catalogue's
                            # convention; the basis states that these are harmless stand-ins.
                            "label": "malicious" if kind == "original" else "benign",
                            "label_basis": "Harmless rehearsal stand-in in the " + kind + " role; not malware",
                            "eligibility_status": "REHEARSAL_ONLY"})
        originals = dataset_plan.assign_original_groups([(o["project_id"], o["object_id"]) for o in objects
                                                         if o["label"] == "malicious"])
        benign = dataset_plan.allocate_benign([(o["project_id"], o["object_id"]) for o in objects
                                               if o["label"] == "benign"], {"calibration": 1, "evaluation": 1})
        splits = {o: item["split"] for record in (originals, benign) for item in record["assignments"]
                  for o in item["object_ids"]}
        for item in objects:
            selection.append({"object_id": item["object_id"], "split": splits.get(item["object_id"], ""),
                              "selection_reason": "Laboratory rehearsal plan", "protocol_version": PROTOCOL})
        import control_panel
        for name, fields, rows in (("sources", control_panel.SOURCE_FIELDS, [source]),
                                   ("objects", control_panel.OBJECT_FIELDS, objects),
                                   ("selection", control_panel.SELECTION_FIELDS, selection)):
            write_csv(self.collection / "catalog" / (name + ".csv"), fields, rows)
        (self.root / "plan").mkdir()
        write_json(self.root / "plan" / "assignment-originals.json", originals)
        write_json(self.root / "plan" / "assignment-benign.json", benign)
        write_json(self.root / "plan" / "card.json", CARD)
        write_json(self.root / "plan" / "stand-ins.json", {"run_id": self.run_id, "files": files,
                                                          "derived": derived})
        write_json(self.root / "plan" / "model-responses.json", RESPONSES)
        # The rule control's marker program is copied into the plan and hashed with it.
        (self.root / "plan" / "control-marker.bin").write_bytes(
            Path(self.inputs["programs"]["baseline"]["path"]).read_bytes())
        setup = model_adapter.fix_setup(self.root / "model" / "setup", model_id="simulated-rehearsal-model",
                                        access="prepared responses in the frozen plan", mode="simulated",
                                        settings=SETTINGS, templates=TEMPLATES)
        write_json(self.root / "expected.json", {"written_at_utc": now(), "before_any_check": True, **EXPECTED})
        catalog = self.catalog()
        dataset_plan.check_coverage(catalog, [originals, benign])
        hashed = ["plan/assignment-originals.json", "plan/assignment-benign.json", "plan/card.json",
                  "plan/stand-ins.json", "plan/model-responses.json", "plan/control-marker.bin", "model/setup/setup.json", "expected.json", *("derived/" + d["sample_id"] + ".bin" for d in derived)]
        write_json(self.root / "plan.json", {
            "schema": 1, "kind": "rehearsal_plan", "run_id": self.run_id, "frozen_at_utc": now(),
            "protocol_version": PROTOCOL, "catalog_sha256": catalog["catalog_sha256"],
            "hashes": {name: aegis.digest(self.root / name) for name in hashed},
            "card_sha256": functionality_card.card_sha256(CARD), "model_setup_id": setup["setup_id"],
            "experiment_results": False})
        return read(self.root / "plan.json")

    # --- model access ------------------------------------------------------------
    def model(self):
        """The fixed setup, its templates, the simulated adapter, the private exchange store and the log."""
        self.plan()
        setup, templates = model_adapter.load_setup(self.root / "model" / "setup")
        adapter = model_adapter.SimulatedAdapter(read(self.root / "plan" / "model-responses.json"))
        return {"setup": setup, "templates": templates, "adapter": adapter,
                "store": model_adapter.ExchangeStore(self.root / "model" / "exchanges"),
                "log": generation_log.GenerationLog(self.root / "model" / "log")}

    def _yara_files(self, lab, text, contents, label):
        """Write control files into the run folder and check `text` on them in state F."""
        folder = self.root / "control" / (label + "-" + uuid.uuid4().hex[:8])
        folder.mkdir(parents=True)
        files, sources = [], {}
        for key, content in contents.items():
            path = folder / (key + ".bin")
            path.write_bytes(content)
            files.append({"sample_id": key, "sha256": hashlib.sha256(content).hexdigest(), "path": "files/" + key + ".bin"})
            sources[key] = path
        cycle, report = lab.candidate(text, files, sources, run_id=self.run_id)
        write_json(folder / "check.json", {"cycle": cycle.name, "report_sha256": aegis.digest(cycle / "report.json")})
        return report

    # --- 1a. model control ----------------------------------------------------------
    def model_control(self, lab):
        self.plan()
        if self.done("model_control"):
            raise ValueError("The model control is already recorded")
        model = self.model()
        plan, _ = self.plan()  # re-checks every planned hash, the marker copy included
        content = (self.root / "plan" / "control-marker.bin").read_bytes()
        if hashlib.sha256(content).hexdigest() != plan["hashes"]["plan/control-marker.bin"]:
            raise ValueError("The rule control's marker program changed after the plan was frozen")

        def run_rule(text, files):
            report = self._yara_files(lab, text, files, "rule-control")
            results = report["results"]
            status = {key: value["status"] for key, value in results["matches"].items()}
            compiled = None if report.get("technical_error") else results["compiled"]
            return {"compiled": compiled, "errors": results["compile_errors"],
                    "matches": {key: {"MATCHED": True, "NOT_MATCHED": False}.get(value) for key, value in status.items()}}

        rule = generation.rule_control(log=model["log"], adapter=model["adapter"], store=model["store"],
                                       setup=model["setup"], templates=model["templates"], content=content,
                                       marker=MARKER, replacement=CHANGED_MARKER, run_rule=run_rule)
        code = {"control": "code", "passed": False, "outcome": "NOT_RUN_TOOLCHAIN_NOT_CHOSEN",
                "reasons": ["The C/C++ toolchain for state F is not chosen yet (decision 3)"]}
        write_json(self.root / "model-control.json", {"rule": rule, "code": code,
                                                      "model_ready": generation.model_ready(code, rule),
                                                      "at_utc": now()})
        return rule, code

    # --- 2. functionality and manifest ---------------------------------------------
    def functionality(self, lab):
        plan, catalog = self.plan()
        if self.done("functionality"):
            raise ValueError("The manifest is already built")
        stand_ins = read(self.root / "plan" / "stand-ins.json")
        runs = []
        for sample_id, _, kind, _, _, _ in SAMPLES:
            if kind in {"original", "variant"} and catalog["selection"].get(sample_id, {}).get("split", "x"):
                path = (self.root / "derived" / (sample_id + ".bin") if kind == "variant"
                        else self.collection / "files" / (sample_id + ".bin"))
                runs.append((sample_id, path, stand_ins["files"][sample_id]["workdir"]))
        cycle, results = lab.functionality(self.root / "plan" / "card.json", runs)
        (self.root / "functionality").mkdir(exist_ok=True)
        records = []
        for sample_id, _, _ in runs:
            target = self.root / "functionality" / (sample_id + ".json")
            target.write_bytes((cycle / ("record-" + sample_id + ".json")).read_bytes())
            records.append("functionality/" + sample_id + ".json")
        write_json(self.root / "functionality.json", {"cycle": cycle.name, "results": results, "at_utc": now()})
        return self.build_manifest(catalog, records)

    def build_manifest(self, catalog, records):
        stand_ins = read(self.root / "plan" / "stand-ins.json")
        functionality = dataset_plan.load_functionality(records, self.root)
        derived = []
        for item in stand_ins["derived"]:
            sample_id = item["sample_id"]
            sha = stand_ins["files"][sample_id]["sha256"]
            status, card, evidence = functionality.get(sha, ("NOT_RUN", "", ""))
            parent = catalog["objects"][item["parent_id"]]
            derived.append(dict(zip(aegis.SAMPLE_FIELDS, [
                sample_id, parent["project_id"], parent["family_id"],
                catalog["selection"][item["parent_id"]]["split"], "variant", item["parent_id"], item["order"], "",
                sha, "derived/" + sample_id + ".bin", status, card, evidence, "Project Aegis harmless rehearsal programs",
                "1", "Harmless rehearsal stand-in in the variant role; not malware", "PE", "AnyCPU (.NET)"])))
        rows = dataset_plan.build_manifest(catalog, self.root, [read(self.root / "plan" / "assignment-originals.json"),
                                                                read(self.root / "plan" / "assignment-benign.json")],
                                           records, derived)
        write_csv(self.root / "manifest.csv", aegis.SAMPLE_FIELDS, rows)
        return rows

    # --- AV phases ------------------------------------------------------------
    def _store(self, cycle, label):
        """Copy a validated cycle report into the run's evidence, numbered in run order."""
        (self.root / "reports").mkdir(exist_ok=True)
        number = len(list((self.root / "reports").glob("*.json"))) + 1
        relative = "reports/%02d-%s.json" % (number, label)
        (self.root / relative).write_bytes((cycle / "report.json").read_bytes())
        return relative

    def _av(self, lab, sample_ids, *, freeze, wait_seconds, record):
        samples = self.samples()
        sources = self.sources(samples)
        done = read(self.root / record) if (self.root / record).is_file() else None
        if done:
            raise ValueError("This phase is already complete")
        progress = self.root / (record + ".partial")
        stored = read(progress) if progress.is_file() else {}
        for sample_id in sample_ids:
            if sample_id in stored:
                continue
            request = run_guard.prepare_av_request(samples, sample_id, run_id=self.run_id,
                                                   wait_seconds=wait_seconds, workspace=self.root, freeze=freeze)
            cycle, _ = lab.av_request(request, sources)
            stored[sample_id] = self._store(cycle, "av-" + sample_id)
            progress.unlink(missing_ok=True)
            write_json(progress, stored)
        write_json(self.root / record, {"reports": stored, "at_utc": now()})
        return stored

    def calibration_av(self, lab, wait_seconds):
        self.plan()
        samples = self.samples()
        # Calibration files and the evaluation originals' baseline checks may precede the freeze.
        ids = [key for key, row in samples.items() if not run_guard.needs_final_rules(row)
               and (row["split"] == "calibration" or row["kind"] == "original")]
        return self._av(lab, sorted(ids), freeze=None, wait_seconds=wait_seconds, record="calibration-av.json")

    def final_av(self, lab, wait_seconds):
        samples = self.samples()
        ids = [key for key, row in samples.items() if run_guard.needs_final_rules(row)]
        return self._av(lab, sorted(ids), freeze="rules/freeze/freeze.json", wait_seconds=wait_seconds,
                        record="final-av.json")

    def av_decisions(self, samples):
        decisions = {}
        for relative in read(self.root / "calibration-av.json")["reports"].values():
            report = scan_bridge.load_report(self.root, relative)
            if report["status"] in {"DETECTED", "NOT_DETECTED"}:
                decisions[report["sample_id"]] = report["status"] == "DETECTED"
        return decisions

    # --- 4. guard, rules and freeze --------------------------------------------
    def guard_refusals(self, samples):
        """Final checks must be refused while no final rule set exists; the refusals are recorded."""
        refusals = []
        final = sorted(key for key, row in samples.items() if run_guard.needs_final_rules(row))
        evaluation = sorted(key for key, row in samples.items() if row["split"] == "evaluation")
        for name, attempt in (
                ("av_without_freeze", lambda: run_guard.prepare_av_request(
                    samples, final[0], run_id=self.run_id, wait_seconds=10, workspace=self.root, freeze=None)),
                ("yara_without_freeze", lambda: run_guard.prepare_yara_request(
                    samples, evaluation, run_id=self.run_id, yara_sha256=self.inputs["tools"]["yara_sha256"],
                    workspace=self.root, freeze="rules/freeze/freeze.json"))):
            try:
                attempt()
            except (ValueError, OSError) as exc:
                refusals.append({"attempt": name, "refused": True, "reason": str(exc)[:300], "at_utc": now()})
            else:
                raise ValueError("The guard allowed a final check before the rule set was final: " + name)
        write_json(self.root / "guard-refusals.json", {"refusals": refusals})
        return refusals

    def rules(self, lab):
        samples = self.samples()
        if not self.done("calibration_av"):
            raise ValueError("Calibration AV checks come first")
        if not (self.root / "guard-refusals.json").exists():
            self.guard_refusals(samples)
        if not self.done("model_control"):
            raise ValueError("The model control comes before rule preparation")
        av = self.av_decisions(samples)
        targets = rule_workflow.rule_targets(samples, av)
        (self.root / "rules").mkdir(exist_ok=True)
        model = self.model()
        texts, decisions, version = {}, {}, None
        for target in targets:
            package = rule_workflow.rule_package(samples, av, target, self.root, self.collection)
            write_json(self.root / "rules" / ("package-" + target + ".json"), package)
            checked = [target] + rule_workflow.group_files(samples, target) + sorted(
                key for key, row in samples.items() if row["split"] == "calibration" and row["kind"] == "benign")
            files = [{"sample_id": key, "sha256": samples[key]["sha256"], "path": "files/" + key + ".bin"}
                     for key in checked]
            checks = []

            def check_rule(text, files=files):
                cycle, report = lab.candidate(text, files, self.sources(samples), run_id=self.run_id)
                checks.append(report)
                (self.root / "rules" / ("candidate-%s-%d.json" % (target, len(checks)))).write_bytes(
                    (cycle / "report.json").read_bytes())
                return report["results"]

            candidate = len(model["log"].candidates_used("rule", target)) + 1
            record, outcome = generation.rule_attempt(
                log=model["log"], adapter=model["adapter"], store=model["store"], setup=model["setup"],
                templates=model["templates"], package=package, candidate=candidate, check_rule=check_rule,
                decide=lambda text, results: rule_workflow.accept_rule(text, package, samples, av, results,
                                                                       self.root, self.collection),
                feedback=lambda results: rule_workflow.repair_feedback(samples, results))
            if outcome is None or outcome[1].get("target_id") != target:
                continue  # refused or rejected before any recorded check: the target has no decision
            text, decision = outcome
            write_json(self.root / "rules" / ("decision-" + target + ".json"), decision)
            texts["rule-" + target], decisions["rule-" + target] = text, decision
            version = next((r.get("yara_version") for r in reversed(checks) if r.get("yara_version")), version)
        if not version:
            raise ValueError("The YARA version was not recorded by the candidate check")
        text, record = rule_workflow.freeze(texts, decisions, samples, av, version, run_id=self.run_id)
        run_guard.write_freeze(self.root, "rules/freeze", text, record)
        return record

    # --- 6. final YARA -----------------------------------------------------------
    def final_yara(self, lab):
        samples = self.samples()
        if self.done("final_yara"):
            raise ValueError("This phase is already complete")
        record, _ = run_guard.load_freeze(self.root, "rules/freeze/freeze.json", self.run_id)
        evaluation = sorted(key for key, row in samples.items() if row["split"] == "evaluation")
        if record["status"] != "FROZEN":
            write_json(self.root / "final-yara.json", {"reports": [], "status": record["status"], "at_utc": now()})
            return []
        request = run_guard.prepare_yara_request(samples, evaluation, run_id=self.run_id,
                                                 yara_sha256=self.inputs["tools"]["yara_sha256"],
                                                 workspace=self.root, freeze="rules/freeze/freeze.json")
        cycle, _ = lab.yara_request(request, self.sources(samples), self.root / "rules" / "freeze" / "frozen.yar")
        relative = self._store(cycle, "yara")
        write_json(self.root / "final-yara.json", {"reports": [relative], "status": "FROZEN", "at_utc": now()})
        return [relative]

    # --- 7. one series and accounting ------------------------------------------------
    ACCOUNTING_OUTPUTS = ("series.json", "observations.csv", "run.json", "tables")

    def _set_aside_partial_accounting(self):
        """Outputs of an accounting attempt that stopped are kept aside, never overwritten, so it can be retried."""
        partial = [name for name in (*self.ACCOUNTING_OUTPUTS, "accounting.json") if (self.root / name).exists()]
        if not partial:
            return None
        folder = self.root / ("accounting-attempt-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f"))
        folder.mkdir()
        for name in partial:
            (self.root / name).rename(folder / name)
        return folder

    def accounting(self):
        samples = self.samples()
        for phase in ("calibration_av", "rules", "final_av", "final_yara"):
            if not self.done(phase):
                raise ValueError("Phase not finished: " + phase)
        if self.done("accounting"):
            raise ValueError("Accounting is already complete for this run")
        self._set_aside_partial_accounting()
        reports = sorted(p.relative_to(self.root).as_posix() for p in (self.root / "reports").glob("*.json"))
        for relative in reports:
            report = scan_bridge.load_report(self.root, relative)
            ids = [report["sample_id"]] if report["kind"] == "av_check" else [f["sample_id"] for f in report["files"]]
            if report["run_id"] != self.run_id or not set(ids) <= set(samples):
                raise ValueError("A report outside this run or its frozen plan: " + relative)
        write_json(self.root / "series.json", {"schema": 1, "kind": "detector_series", "run_id": self.run_id,
                                               "reports": reports})
        rows, states = scan_bridge.observations(reports, samples, self.run_id, self.root)
        split = scan_bridge.segments(reports, self.root, self.run_id)
        if len(split["av"]) > 1 or len(split["yara"]) > 1:
            raise ValueError("Tool versions changed during the rehearsal; the series splits into several segments")
        freeze, _ = run_guard.load_freeze(self.root, "rules/freeze/freeze.json", self.run_id)
        write_csv(self.root / "observations.csv", aegis.OBSERVATION_FIELDS, rows)
        config = {"run_id": self.run_id, "mode": "rehearsal", "workspace": ".", "protocol_version": PROTOCOL,
                  "collection_root": str(self.collection), "series": "series.json",
                  "av": {"state_id": states["av"], "segment_id": split["av"][0]["segment_id"] if split["av"] else None},
                  "yara": {"state_id": states["yara"], "ruleset_status": freeze["status"],
                           "ruleset_sha256": freeze["ruleset_sha256"], "freeze_record": "rules/freeze/freeze.json",
                           "segment_id": split["yara"][0]["segment_id"] if split["yara"] else None}}
        write_json(self.root / "run.json", config)
        result = aegis.run(self.root / "run.json", self.root / "manifest.csv", self.root / "observations.csv")
        records = generation_log.GenerationLog(self.root / "model" / "log", create=False).records()
        folder = self.root / "tables"
        folder.mkdir(exist_ok=False)
        for name, content in cost_table.tables(records, result).items():
            with (folder / name).open("x", encoding="utf-8", newline="") as stream:
                stream.write(content)
        comparison = self.compare(samples, reports, result, records)
        self._publish(self.root / "accounting.json", {**result, "expected_comparison": comparison})
        return result, comparison

    @staticmethod
    def _publish(path, value):
        """Write a whole file next to its final name, then rename it into place; never overwrite."""
        temporary = path.with_name("." + path.name + "." + uuid.uuid4().hex + ".partial")
        write_json(temporary, value)
        if path.exists():
            raise ValueError("Refusing to replace an existing final report: " + path.name)
        temporary.rename(path)

    def compare(self, samples, reports, result, records):
        """Recorded outcomes beside the outcomes written down in the frozen plan."""
        expected = read(self.root / "expected.json")
        observed = {"calibration_av": {}, "final_av": {}, "final_yara": {}}
        final_av = set(read(self.root / "final-av.json")["reports"])
        for relative in reports:
            report = scan_bridge.load_report(self.root, relative)
            if report["kind"] == "av_check":
                observed["calibration_av" if report["sample_id"] not in final_av else "final_av"][
                    report["sample_id"]] = report["status"]
            else:
                observed["final_yara"].update({f["sample_id"]: f["status"] for f in report["files"]})
        observed["functionality"] = {key: row["functionality"] for key, row in samples.items()
                                     if row["kind"] in {"original", "variant"}}
        target = expected["rule"]["target"]
        decision = self.root / "rules" / ("decision-" + target + ".json")
        freeze = read(self.root / "rules" / "freeze" / "freeze.json")
        observed["rule"] = {"target": target, "decision": read(decision)["status"] if decision.is_file() else None,
                            "freeze": freeze["status"]}
        observed["guard_refusals"] = len(read(self.root / "guard-refusals.json")["refusals"])
        control = read(self.root / "model-control.json")
        by_task = {}
        for record in records:
            by_task.setdefault((record["task"], record["subject"]), []).append(record)

        def session(task, subject):
            (record, *_) = by_task.get((task, subject), [None])
            if record is None:
                return None
            statuses = record["artifacts"].get("turn_statuses") or []
            return {"outcome": record["outcome"], "repairs": record["repairs"],
                    "first_rejection": statuses[0] if record["repairs"] and statuses else None}
        observed["model_control"] = {"rule": session("rule_control", "marker-program"),
                                     "code": control["code"]["outcome"]}
        observed["rule_session"] = {target: session("rule", target) for target in expected["rule_session"]}
        figures = cost_table.costs(records)
        observed["costs"] = {task: {"attempts": item["attempts"], "requests": item["requests"],
                                    "repairs": item["repairs"], "refusals": item["refusals"],
                                    "failures": item["failures"], "model_seconds": item["model_seconds"],
                                    "manual_wait_seconds": item["manual_wait_seconds"],
                                    "usable": [item["usable_share"]["numerator"], item["usable_share"]["denominator"]]}
                             for task, item in figures.items()}
        supplement = result["supplementation"]
        tools = supplement.get("tools", {})
        fraction = lambda value: [value["numerator"], value["denominator"]]
        observed["accounting"] = {"supplementation": supplement["status"],
                                  "paired_records": supplement.get("paired_records"),
                                  "recall": {t: fraction(tools[t]["recall"]) for t in ("av", "yara", "combined")
                                             if t in tools},
                                  "fpr": {t: fraction(tools[t]["fpr"]) for t in ("av", "yara", "combined") if t in tools}}
        return {key: {"expected": expected[key], "observed": observed[key], "same": expected[key] == observed[key]}
                for key in ("model_control", "functionality", "calibration_av", "rule_session", "rule", "final_av",
                            "final_yara", "guard_refusals", "accounting", "costs")}
