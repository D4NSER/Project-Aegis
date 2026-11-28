"""The 1d cost and generation tables on a small, hand-counted log.

The log is produced by the real session code with prepared responses: one
refusal, a compile error repaired once, a duplicate, a functionality failure
after three repairs, a manually answered variant with a build-setting change,
and a rule repaired once after a static rejection.
"""
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import cost_table
import generation
import model_adapter as ma
from test_generation import (Base, BROKEN, COMMENTS_ONLY, GOOD_RULE, ORIGINAL, PATH_RULE, SETTINGS, TEMPLATES,
                             VARIANT, fenced)


class CostTableTests(Base):
    def setUp(self):
        super().setUp()
        timed = lambda entry, seconds: dict(entry, elapsed=seconds)
        script = {
            "code_variant:O1:1:0": {"refused": True, "text": "I can't help with that.", "elapsed": 1.0},
            "code_variant:O1:2:0": timed(fenced(BROKEN), 2.0),
            "code_variant:O1:2:1": timed(fenced(VARIANT), 3.0),
            "code_variant:O1:3:0": timed(fenced(COMMENTS_ONLY), 1.5),
            **{"code_variant:O1:4:%d" % t: timed(fenced(VARIANT.replace("3;", "%d;" % (t + 4))), 0.5)
               for t in range(4)},
        }
        adapter = ma.SimulatedAdapter(script)
        for candidate, check in ((1, None), (2, None), (3, None),
                                 (4, lambda s, b: {"status": "FAIL", "reasons": ["STDOUT"]})):
            generation.code_attempt(log=self.log, adapter=adapter, store=self.store, setup=self.setup,
                                    templates=self.templates, subject="O1", candidate=candidate,
                                    original_source=ORIGINAL, behaviour="keep", original_sha256="0" * 64,
                                    build=self.build({}),
                                    check=check or (lambda s, b: {"status": "PASS", "reasons": []}))
        # A manually answered variant: the researcher's wait, and one build-setting change.
        manual = ma.fix_setup(self.base / "setup-manual", model_id="m", access="pasted responses", mode="manual",
                              settings=SETTINGS, templates=TEMPLATES)
        attempt = self.log.start("code_variant", "O2", 1, manual, "code_variant")
        attempt.turn("initial", "a" * 64, {"refused": False, "elapsed_seconds": 60.0}, "b" * 64)
        attempt.researcher_change("Static runtime linking for O2 and all its variants")
        attempt.finish("ACCEPTED", [], binary_sha256="c" * 64)
        generation.rule_attempt(
            log=self.log, store=self.store, setup=self.setup, templates=self.templates, candidate=1,
            adapter=ma.SimulatedAdapter({"rule:C1:1:0": timed(fenced(PATH_RULE, "yara"), 0.5),
                                         "rule:C1:1:1": timed(fenced(GOOD_RULE, "yara"), 0.5)}),
            package={"target_id": "C1", "description": {"strings": [{"text": "AEGIS_CONTROL_MARKER_ALPHA",
                                                                       "encoding": "ascii"}]}},
            check_rule=lambda text: {"compiled": True, "compile_errors": [], "matches": {}},
            decide=lambda text, results: {"status": "ACCEPTED"}, feedback=lambda results: {})

    def test_costs_match_the_hand_count(self):
        figures = cost_table.costs(self.log.records())
        code = figures["code_variant"]
        self.assertEqual(code["outcomes"], {"REFUSED": 1, "ACCEPTED": 2, "DUPLICATE": 1, "FUNC_FAIL": 1})
        self.assertEqual((code["attempts"], code["requests"], code["repairs"], code["refusals"]), (5, 9, 4, 1))
        self.assertEqual((code["unusable"], code["failures"], code["researcher_changes"]), (3, 2, 1))
        self.assertEqual((code["model_seconds"], code["manual_wait_seconds"]), (9.5, 60.0))
        self.assertEqual(code["usable_share"], {"numerator": 2, "denominator": 5, "rate": 0.4})
        rule = figures["rule"]
        self.assertEqual((rule["attempts"], rule["requests"], rule["repairs"], rule["failures"], rule["model_seconds"]),
                         (1, 2, 1, 0, 1.0))

    def test_tables_are_written_from_the_same_figures(self):
        out = cost_table.tables(self.log.records(), {"run_id": "run-1", "mode": "rehearsal", "status_counts": {
            "av:ERROR": 1, "yara:NOT_RUN": 2, "av:NOT_DETECTED": 5}})
        self.assertEqual(out["costs.csv"].splitlines(), [
            "task,attempts,requests,repairs,refusals,unusable,failures,model_seconds,manual_wait_seconds,"
            "researcher_changes,usable,usable_of",
            "code_variant,5,9,4,1,3,2,9.5,60.0,1,2,5",
            "rule,1,2,1,0,0,0,1.0,0.0,0,1,1"])
        generation_rows = out["generation.csv"].splitlines()
        self.assertEqual(generation_rows[0], "task,subject,attempts,ACCEPTED,COMPILE_FAIL,DUPLICATE,FUNC_FAIL,"
                                             "FUNC_INCONCLUSIVE,REFUSED,usable,usable_of")
        self.assertEqual(generation_rows[1:], ["code_variant,O1,4,1,0,1,1,0,1,1,4",
                                               "code_variant,O2,1,1,0,0,0,0,0,1,1",
                                               "rule,C1,1,1,0,0,0,0,0,1,1"])
        self.assertIn("Kodo variantai & 5 & 9 & 4 & 1 & 2 & 2/5 (40,0\\,\\%) & 9,5 & 60,0 & 1 \\\\", out["costs.tex"])
        self.assertEqual(out["incomplete_checks.csv"].splitlines(),
                         ["tool,ERROR,INCONCLUSIVE,NOT_RUN", "av,1,0,0", "yara,0,0,2"])

    def test_a_repeated_record_stops_the_table(self):
        (first, *_) = sorted((self.base / "log").glob("*.json"))
        (self.base / "log" / ("999-" + first.name.split("-", 1)[1])).write_text(first.read_text())
        with self.assertRaisesRegex(ValueError, "more than once"):
            cost_table.tables(self.log.records())

    def test_missing_or_invalid_inputs_write_nothing(self):
        import json
        target = self.base / "tables"
        missing = self.base / "no-such-log"
        self.assertEqual(cost_table.main(["--log", str(missing), "--tables", str(target)]), 1)
        self.assertFalse(missing.exists() or target.exists())
        empty = self.base / "empty-log"
        empty.mkdir()
        self.assertEqual(cost_table.main(["--log", str(empty), "--tables", str(target)]), 1)
        self.assertFalse(target.exists())
        report = self.base / "report.json"
        for value in ({}, {"run_id": "run-1", "mode": "rehearsal", "status_counts": {}},
                      {"run_id": "run-1", "mode": "rehearsal", "status_counts": {"av:ERROR": -1}}):
            report.write_text(json.dumps(value))
            self.assertEqual(cost_table.main(["--log", str(self.base / "log"), "--tables", str(target),
                                              "--accounting", str(report)]), 1)
            self.assertFalse(target.exists())

    def test_negative_or_non_finite_durations_are_refused(self):
        import json
        (first, *_) = sorted((self.base / "log").glob("*.json"))
        original = first.read_text()
        for value in (-4.0, float("inf"), "4", None, True):
            record = json.loads(original)
            record["turns"][0]["elapsed_seconds"] = value
            first.write_text(json.dumps(record))
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "durations must be finite"):
                cost_table.tables(self.log.records())
        first.write_text(original)
        self.assertEqual(cost_table.costs(self.log.records())["code_variant"]["model_seconds"], 9.5)

    def test_cli_writes_new_tables_only(self):
        target = self.base / "tables"
        self.assertEqual(cost_table.main(["--log", str(self.base / "log"), "--tables", str(target)]), 0)
        self.assertEqual(sorted(p.name for p in target.iterdir()), ["costs.csv", "costs.tex", "generation.csv"])
        self.assertEqual(cost_table.main(["--log", str(self.base / "log"), "--tables", str(target)]), 1)


if __name__ == "__main__":
    unittest.main()
