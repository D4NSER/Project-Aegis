"""Generation log, model adapters and the two model controls, with prepared responses.

No model, compiler or VM: responses are prepared texts, building and the
functionality check are scripted, and the program is a harmless C example.
"""
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import generation
import generation_log as glog
import model_adapter as ma

ORIGINAL = """#include <stdio.h>
/* Harmless control: writes its token to a file. */
int main(int argc, char **argv) {
    FILE *f = fopen(argv[1], "w");  // output file
    if (!f) return 2;
    fprintf(f, "AEGIS_OK:%s", argv[2]);
    fclose(f);
    return 0;
}
"""
VARIANT = """#include <stdio.h>
static int emit(const char *path, const char *token) {
    FILE *out = fopen(path, "w");
    if (out == NULL) return 2;
    fprintf(out, "AEGIS_OK:%s", token);
    return fclose(out) == 0 ? 0 : 3;
}
int main(int argc, char **argv) { return emit(argv[1], argv[2]); }
"""
BROKEN = VARIANT.replace("return emit(argv[1], argv[2]);", "return emit(argv[1], argv[2])")
COMMENTS_ONLY = ORIGINAL.replace("/* Harmless control: writes its token to a file. */", "// reworded comment")
TEMPLATES = {"code_variant": "Restructure this program without changing its behaviour.\n{behaviour}\n```c\n{original_source}```",
             "code_repair": "The variant did not pass these checks:\n{feedback}",
             "rule": "Write one YARA rule for this file description:\n{description}",
             "rule_repair": "The rule did not pass these checks:\n{feedback}"}
SETTINGS = {"temperature": 0.2, "max_output_tokens": 4000}


def fenced(code, lang="c"):
    return {"text": "Here is the variant.\n```" + lang + "\n" + code + "```\n"}


def stub(payload):
    header = bytearray(0x80)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", header, 0x44, 0x8664)
    return bytes(header) + payload


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.setup = ma.fix_setup(self.base / "setup", model_id="simulated-model", access="prepared responses",
                                  mode="simulated", settings=SETTINGS, templates=TEMPLATES)
        _, self.templates = ma.load_setup(self.base / "setup")
        self.log = glog.GenerationLog(self.base / "log")
        self.store = ma.ExchangeStore(self.base / "exchanges")

    def tearDown(self):
        self.temp.cleanup()

    def build(self, outcomes):
        """Scripted builds: source -> (compiled, errors, binary hash)."""
        def run(source):
            if "argv[2]) }" in source:
                return {"compiled": False, "errors": ["variant.c(8): error C2143: missing ';'"], "binary_sha256": None}
            return {"compiled": True, "errors": [], "binary_sha256": outcomes.get(source, ma.sha(source))}
        return run

    def code(self, script, candidate, check=None, builds=None, task="code_variant"):
        adapter = ma.SimulatedAdapter(script)
        call = generation.code_control if task == "code_control" else generation.code_attempt
        return call(log=self.log, adapter=adapter, store=self.store, setup=self.setup, templates=self.templates,
                    subject="O1", candidate=candidate, original_source=ORIGINAL,
                    behaviour="Keep: input path and token; output file content AEGIS_OK:<token>; exit code 0.",
                    original_sha256="0" * 64, build=self.build(builds or {}),
                    check=check or (lambda source, built: {"status": "PASS", "reasons": [], "record_id": "card-eval-1"}))


class SetupTests(Base):
    def test_setup_is_fixed_by_hash(self):
        self.assertEqual(self.setup["templates"]["rule"], ma.sha(TEMPLATES["rule"]))
        (self.base / "setup" / "rule.txt").write_text("Now also use the evaluation results.")
        with self.assertRaisesRegex(ValueError, "template changed"):
            ma.load_setup(self.base / "setup")
        with self.assertRaises(FileExistsError):
            ma.fix_setup(self.base / "setup", model_id="m", access="a", mode="simulated", settings={}, templates=TEMPLATES)

    def test_an_edited_setup_record_is_refused(self):
        path = self.base / "setup" / "setup.json"
        original = path.read_text()
        for field, value in (("model_id", "another-model"), ("access", "another route"), ("mode", "manual")):
            with self.subTest(field=field):
                path.write_text(json.dumps({**json.loads(original), field: value}))
                with self.assertRaisesRegex(ValueError, "identity no longer matches"):
                    ma.load_setup(self.base / "setup")
        path.write_text(original)
        self.assertEqual(ma.load_setup(self.base / "setup")[0]["setup_id"], self.setup["setup_id"])
        other = ma.fix_setup(self.base / "setup-manual", model_id="simulated-model", access="prepared responses",
                             mode="manual", settings=SETTINGS, templates=TEMPLATES)
        self.assertNotEqual(other["setup_id"], self.setup["setup_id"])

    def test_templates_need_exactly_their_values(self):
        with self.assertRaisesRegex(ValueError, "differ"):
            ma.render(TEMPLATES["code_variant"], {"original_source": "x"})


class NormalizationTests(unittest.TestCase):
    def test_comments_and_whitespace_do_not_make_a_new_variant(self):
        self.assertEqual(glog.strip_c(ORIGINAL), glog.strip_c(COMMENTS_ONLY))
        self.assertNotEqual(glog.strip_c(ORIGINAL), glog.strip_c(VARIANT))
        # Comment markers inside string literals are code, not comments.
        self.assertNotEqual(glog.strip_c('puts("// a");'), glog.strip_c('puts("");'))
        self.assertGreater(glog.changed_lines(ORIGINAL, VARIANT), 0)


class CodeAttemptTests(Base):
    def test_a_refusal_is_recorded_and_not_bypassed(self):
        record = self.code({"code_variant:O1:1:0": {"refused": True, "text": "I can't help with that."}}, 1)
        self.assertEqual((record["outcome"], record["repairs"], len(record["turns"])), ("REFUSED", 0, 1))
        self.assertTrue(record["turns"][0]["refused"])

    def test_compile_errors_are_repaired_within_the_session(self):
        script = {"code_variant:O1:2:0": fenced(BROKEN), "code_variant:O1:2:1": fenced(VARIANT)}
        record = self.code(script, 2)
        self.assertEqual((record["outcome"], record["repairs"]), ("ACCEPTED", 1))
        self.assertEqual(record["artifacts"]["source_sha256"], ma.sha(VARIANT))
        repair = (self.base / "exchanges" / record["session_id"] / "01-request.txt").read_text()
        self.assertIn("missing ';'", repair)
        self.assertNotIn("DETECTED", repair)
        # The log keeps hashes only; the texts stay in the private exchange folder.
        stored = json.dumps(record)
        self.assertNotIn("fopen", stored)
        self.assertIn(ma.sha(TEMPLATES["code_variant"]), stored)

    def test_duplicates_by_source_and_by_file(self):
        record = self.code({"code_variant:O1:3:0": fenced(COMMENTS_ONLY)}, 3)
        self.assertEqual((record["outcome"], record["reasons"]), ("DUPLICATE", ["SOURCE_SAME_AS_ORIGINAL"]))
        self.code({"code_variant:O1:4:0": fenced(VARIANT)}, 4)
        other = VARIANT.replace("out", "stream")
        record = self.code({"code_variant:O1:5:0": fenced(other)}, 5, builds={other: ma.sha(VARIANT)})
        self.assertEqual((record["outcome"], record["reasons"]), ("DUPLICATE", ["FILE_SAME_AS_ACCEPTED_VARIANT"]))

    def test_at_most_three_repairs_then_failure(self):
        script = {"code_variant:O1:6:%d" % turn: fenced(VARIANT.replace("3;", "%d;" % (turn + 4)))
                  for turn in range(5)}
        record = self.code(script, 6, check=lambda s, b: {"status": "FAIL", "reasons": ["STDOUT"]})
        self.assertEqual((record["outcome"], record["repairs"], len(record["turns"])), ("FUNC_FAIL", 3, 4))
        repair = (self.base / "exchanges" / record["session_id"] / "03-request.txt").read_text()
        self.assertIn("STDOUT", repair)

    def test_a_technical_check_fault_is_inconclusive_without_repair(self):
        record = self.code({"code_variant:O1:7:0": fenced(VARIANT)}, 7,
                           check=lambda s, b: {"status": "INCONCLUSIVE", "reasons": ["MONITORING_INCOMPLETE"]})
        self.assertEqual((record["outcome"], record["repairs"]), ("FUNC_INCONCLUSIVE", 0))

    def test_each_candidate_is_one_session(self):
        self.code({"code_variant:O1:1:0": fenced(VARIANT)}, 1)
        with self.assertRaisesRegex(ValueError, "already attempted"):
            self.code({"code_variant:O1:1:0": fenced(VARIANT)}, 1)

    def test_summary_gives_outcomes_share_and_costs(self):
        self.code({"code_variant:O1:1:0": {"refused": True, "text": "No.", "elapsed": 1.5}}, 1)
        self.code({"code_variant:O1:2:0": dict(fenced(BROKEN), elapsed=2.0),
                   "code_variant:O1:2:1": dict(fenced(VARIANT), elapsed=3.0)}, 2)
        self.code({"code_variant:O1:3:0": fenced(COMMENTS_ONLY)}, 3)
        item = glog.summary(self.log.records())["code_variant"]
        self.assertEqual(item["outcomes"], {"REFUSED": 1, "ACCEPTED": 1, "DUPLICATE": 1})
        self.assertEqual((item["attempts"], item["requests"], item["repairs"], item["refusals"]), (3, 4, 1, 1))
        self.assertEqual((item["model_seconds"], item["failures"]), (6.5, 1))
        self.assertEqual(item["usable_share"]["numerator"], 1)


class LogUniquenessTests(Base):
    def test_an_attempt_is_logged_once(self):
        attempt = self.log.start("code_variant", "O1", 1, self.setup, "code_variant")
        attempt.turn("initial", "a" * 64, {"refused": True, "elapsed_seconds": 1.0}, "b" * 64)
        attempt.finish("REFUSED", ["MODEL_REFUSED"])
        with self.assertRaisesRegex(ValueError, "already finished"):
            attempt.finish("REFUSED", ["MODEL_REFUSED"])
        with self.assertRaisesRegex(ValueError, "already logged"):
            self.log.write(attempt.record)
        # A copied record file is refused when the log is read, so it cannot be counted twice.
        (first,) = (self.base / "log").glob("*.json")
        (self.base / "log" / ("999-" + attempt.record["attempt_id"] + ".json")).write_text(first.read_text())
        with self.assertRaisesRegex(ValueError, "more than once"):
            self.log.records()


class ManualAdapterTests(Base):
    def test_a_manual_wait_is_fixed_once_and_kept_apart_from_model_time(self):
        manual = ma.fix_setup(self.base / "setup-manual", model_id="m", access="pasted responses", mode="manual",
                              settings=SETTINGS, templates=TEMPLATES)
        times = iter([100.0, 160.0, 900.0, 950.0])
        adapter = ma.ManualAdapter(self.base / "answers", clock=lambda: next(times))
        with self.assertRaises(ma.PendingResponse):
            adapter.complete(task="code_variant", subject="O1", candidate=1, turn=0, prompt="p")
        (self.base / "answers" / "code_variant-O1-1-0.txt").write_text("answer")
        first = adapter.complete(task="code_variant", subject="O1", candidate=1, turn=0, prompt="p")
        again = adapter.complete(task="code_variant", subject="O1", candidate=1, turn=0, prompt="p")
        self.assertEqual((first["elapsed_seconds"], again["elapsed_seconds"]), (60.0, 60.0))
        record = generation.code_attempt(
            log=self.log, adapter=ma.SimulatedAdapter({"code_variant:O2:1:0": dict(fenced(VARIANT), elapsed=4.0)}),
            store=self.store, setup=self.setup, templates=self.templates, subject="O2", candidate=1,
            original_source=ORIGINAL, behaviour="b", original_sha256="0" * 64, build=self.build({}),
            check=lambda s, b: {"status": "PASS", "reasons": []})
        manual_record = {**record, "attempt_id": "attempt-manual0001", "mode": "manual", "setup_id": manual["setup_id"],
                         "turns": [{**record["turns"][0], "elapsed_seconds": 60.0}]}
        item = glog.summary([record, manual_record])["code_variant"]
        self.assertEqual((item["model_seconds"], item["manual_wait_seconds"]), (4.0, 60.0))

    def test_a_missing_manual_response_is_pending_and_resumes(self):
        folder = self.base / "manual"
        clock = iter([10.0, 30.0])
        adapter = ma.ManualAdapter(folder, clock=lambda: next(clock))
        kwargs = dict(log=self.log, adapter=adapter, store=ma.ExchangeStore(self.base / "pending-store"),
                      setup=self.setup, templates=self.templates, subject="O1", candidate=1, original_source=ORIGINAL,
                      behaviour="keep behaviour", original_sha256="0" * 64, build=self.build({}),
                      check=lambda s, b: {"status": "PASS", "reasons": []})
        with self.assertRaises(ma.PendingResponse):
            generation.code_attempt(**kwargs)
        self.assertEqual(self.log.records(), [])
        (folder / "code_variant-O1-1-0.txt").write_text(fenced(VARIANT)["text"])
        kwargs["store"] = ma.ExchangeStore(self.base / "resumed-store")
        record = generation.code_attempt(**kwargs)
        self.assertEqual((record["outcome"], record["turns"][0]["elapsed_seconds"]), ("ACCEPTED", 20.0))


DESCRIPTION_PAYLOAD = b"\0AEGIS_CONTROL_MARKER_ALPHA\0" + "WideText".encode("utf-16le") + b"\0\0"
GOOD_RULE = 'rule Control_Marker\n{\n    strings:\n        $m = "AEGIS_CONTROL_MARKER_ALPHA" ascii\n    condition:\n        $m\n}\n'
PATH_RULE = 'rule Control_Marker\n{\n    strings:\n        $m = "AEGIS_CONTROL_MARKER_ALPHA" ascii\n    condition:\n        $m and filename == "x.exe"\n}\n'
LOOSE_RULE = 'rule Control_Marker\n{\n    strings:\n        $m = "AEGIS_CONTROL_MARKER" ascii\n    condition:\n        $m\n}\n'


class ControlTests(Base):
    def run_rule(self, text, files):
        needle = text.split('"')[1].encode()
        return {"compiled": True, "errors": [], "matches": {key: needle in value for key, value in files.items()}}

    def rule_control(self, script):
        return generation.rule_control(log=self.log, adapter=ma.SimulatedAdapter(script), store=self.store,
                                       setup=self.setup, templates=self.templates, content=stub(DESCRIPTION_PAYLOAD),
                                       marker="AEGIS_CONTROL_MARKER_ALPHA", replacement="AEGIS_CONTROL_MARKER_OMEGA",
                                       run_rule=self.run_rule)

    def test_rule_control_rejects_name_reliance_then_passes(self):
        result = self.rule_control({"rule_control:marker-program:1:0": fenced(PATH_RULE, "yara"),
                                    "rule_control:marker-program:1:1": fenced(GOOD_RULE, "yara")})
        self.assertTrue(result["passed"])
        first = self.log.records()[0]
        self.assertEqual((first["repairs"], first["outcome"]), (1, "ACCEPTED"))

    def test_rule_control_fails_when_the_changed_copy_matches(self):
        script = {"rule_control:marker-program:1:%d" % t: fenced(LOOSE_RULE, "yara") for t in range(4)}
        result = self.rule_control(script)
        self.assertEqual((result["passed"], result["outcome"]), (False, "REJECTED_CHANGED_COPY_MATCH"))

    def test_changed_marker_copy_keeps_length_and_needs_the_marker(self):
        content = stub(DESCRIPTION_PAYLOAD)
        changed = generation.changed_marker_copy(content, "AEGIS_CONTROL_MARKER_ALPHA", "AEGIS_CONTROL_MARKER_OMEGA")
        self.assertEqual(len(changed), len(content))
        with self.assertRaises(ValueError):
            generation.changed_marker_copy(content, "MISSING", "MISSONG")

    def test_model_ready_needs_both_controls(self):
        code = self.code({"code_control:O1:1:0": fenced(VARIANT)}, 1, task="code_control")
        rule = self.rule_control({"rule_control:marker-program:1:0": fenced(GOOD_RULE, "yara")})
        self.assertTrue(generation.model_ready(code, rule))
        self.assertFalse(generation.model_ready(code, {**rule, "passed": False}))


class RuleAttemptTests(Base):
    def test_static_rejection_is_repaired_without_a_yara_run(self):
        package = {"target_id": "C1", "description": {"strings": [{"text": "AEGIS_CONTROL_MARKER_ALPHA",
                                                                     "encoding": "ascii"}]}}
        runs = []
        script = {"rule:C1:1:0": fenced(PATH_RULE, "yara"), "rule:C1:1:1": fenced(GOOD_RULE, "yara")}
        record, (text, decision) = generation.rule_attempt(
            log=self.log, adapter=ma.SimulatedAdapter(script), store=self.store, setup=self.setup,
            templates=self.templates, package=package, candidate=1,
            check_rule=lambda text: runs.append(text) or {"compiled": True, "compile_errors": [], "matches": {}},
            decide=lambda text, results: {"status": "ACCEPTED"},
            feedback=lambda results: {"compile_errors": [], "matches": {}})
        self.assertEqual((record["outcome"], record["repairs"], runs), ("ACCEPTED", 1, [GOOD_RULE]))


if __name__ == "__main__":
    unittest.main()
