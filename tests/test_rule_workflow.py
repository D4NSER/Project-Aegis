"""Rule preparation checks with generated header-only PE stubs.

The stubs are a DOS/PE header plus inert marker text; they have no sections or
code and are written only to temporary directories. YARA is not run: compile
and match outcomes are supplied as recorded results, as the laboratory would.
"""
import hashlib
import json
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
import aegis
import rule_workflow as rw
from test_accounting import Workspace


def stub(payload=b"", machine=0x8664):
    header = bytearray(0x80)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 0x40)
    header[0x40:0x44] = b"PE\0\0"
    struct.pack_into("<H", header, 0x44, machine)
    return bytes(header) + payload


PAYLOAD = (b"\0AegisMarkerAlpha\0abc\x01\x01" + "WideMarker".encode("utf-16le")
           + b"\0\0AegisMarkerAlpha\0SharedTextAcrossFiles\0")


def rule(strings, condition="any of them", name="Candidate"):
    return "rule %s {\n  strings:\n%s\n  condition:\n    %s\n}\n" % (
        name, "\n".join("    " + line for line in strings), condition)


class DescriptionTests(unittest.TestCase):
    def test_description_lists_strings_with_encodings_in_file_order(self):
        value = rw.describe(stub(PAYLOAD))
        self.assertEqual(("PE", "0x8664", "x64"), (value["format"], value["machine"], value["architecture"]))
        self.assertEqual([("AegisMarkerAlpha", "ascii"), ("WideMarker", "utf-16le"), ("SharedTextAcrossFiles", "ascii")],
                         [(s["text"], s["encoding"]) for s in value["strings"]])
        # "abc" is below the minimum length; the repeated marker is removed.
        self.assertEqual({"found": 4, "duplicates_removed": 1, "provided": 3, "omitted_by_limit": 0}, value["counts"])
        self.assertEqual(len(stub(PAYLOAD)), value["bytes"])
        self.assertNotIn("path", json.dumps(value))

    def test_input_limit_keeps_the_first_strings(self):
        parameters = dict(rw.DEFAULT_PARAMETERS, max_characters=20)
        value = rw.describe(stub(PAYLOAD), parameters)
        self.assertEqual(["AegisMarkerAlpha"], [s["text"] for s in value["strings"]])
        self.assertEqual(2, value["counts"]["omitted_by_limit"])
        self.assertNotEqual(rw.describe(stub(PAYLOAD))["parameters_sha256"], value["parameters_sha256"])

    def test_non_pe_and_unknown_parameters_rejected(self):
        with self.assertRaisesRegex(ValueError, "Not a PE"):
            rw.describe(b"plain inert text" * 8)
        with self.assertRaisesRegex(ValueError, "PE signature"):
            rw.describe(b"MZ" + b"\0" * 0x7E)
        with self.assertRaisesRegex(ValueError, "Unsupported description parameters"):
            rw.describe(stub(PAYLOAD), dict(rw.DEFAULT_PARAMETERS, encodings=["ascii"]))

    def test_machine_names(self):
        self.assertEqual("x86", rw.describe(stub(PAYLOAD, 0x14C))["architecture"])
        self.assertEqual("unknown", rw.describe(stub(PAYLOAD, 0x1234))["architecture"])


class StaticCheckTests(unittest.TestCase):
    def setUp(self):
        self.description = rw.describe(stub(PAYLOAD))

    def status(self, text):
        return rw.static_check(text, self.description)["status"]

    def test_traceable_text_strings_pass(self):
        for strings in (['$a = "AegisMarker" ascii'], ['$a = "widemarker" wide nocase'],
                        ['$a = "SharedText" fullword', '$b = "MarkerAlpha"']):
            with self.subTest(strings=strings):
                self.assertEqual("PASSED", self.status(rule(strings)))
        self.assertEqual("PASSED", self.status(rule(['$a = "Aegis\\x4darker"'], "#a > 0 and filesize < 2MB")))

    def test_features_must_come_from_the_description(self):
        for strings in (['$a = "WideMarker"'],            # only present as UTF-16
                        ['$a = "AegisMarker" wide'],      # only present as ASCII
                        ['$a = "AegisMarker" ascii wide'],  # regression: wide form not in description
                        ['$a = "NotInTheFile"'],
                        ['$a = { 4D 5A 90 00 }'],         # hex cannot be traced
                        ['$a = /Aegis[A-Z]+/'],
                        ['$a = "AegisMarker" xor']):
            with self.subTest(strings=strings):
                self.assertEqual("REJECTED_FEATURE_NOT_IN_DESCRIPTION", self.status(rule(strings)))

    def test_forbidden_constructs(self):
        cases = (
            'import "hash"\n' + rule(['$a = "AegisMarker"']),
            rule(['$a = "AegisMarker"'], 'filename == "x.exe" or $a'),
            rule(['$a = "AegisMarker"'], "uint16(0) == 0x5A4D and $a"),
            rule(['$a = "AegisMarker"'], "pe.machine == 0x8664 and $a"),
            rule(['$a = "AegisMarker"'], "$b"),
            rule([], "filesize < 10KB").replace("  strings:\n\n", ""),
            rule(['$a = "AegisMarker"']) + rule(['$a = "AegisMarker"'], name="Second"),
            "private " + rule(['$a = "AegisMarker"']),
            rule(['$a = "AegisMarker" xor(1-3)']),
            rule(['$a = "AegisMarker"'], name="Taisyklė"),   # regression: non-ASCII identifier
        )
        for text in cases:
            with self.subTest(text=text[:40]):
                self.assertEqual("REJECTED_FORBIDDEN", self.status(text))

    def test_ascii_wide_needs_both_encodings(self):
        both = {"strings": [{"text": "DualMarker", "encoding": "ascii"},
                            {"text": "DualMarker", "encoding": "utf-16le"}]}
        self.assertEqual("PASSED", rw.static_check(rule(['$a = "DualMarker" ascii wide']), both)["status"])
        ascii_only = {"strings": both["strings"][:1]}
        result = rw.static_check(rule(['$a = "DualMarker" ascii wide']), ascii_only)
        self.assertEqual("REJECTED_FEATURE_NOT_IN_DESCRIPTION", result["status"])
        self.assertIn("utf-16le", result["details"][0])

    def test_wildcard_references_need_matching_strings(self):
        self.assertEqual("PASSED", self.status(rule(['$m1 = "Aegis"', '$m2 = "Shared"'], "all of ($m*)")))
        self.assertEqual("REJECTED_FORBIDDEN", self.status(rule(['$m1 = "Aegis"'], "all of ($x*)")))

    def test_comments_and_meta_are_ignored(self):
        text = ('// comment "NotInTheFile"\nrule Commented {\n meta:\n  note = "NotInTheFile"\n'
                ' strings:\n  $a = "AegisMarker" /* "NotInTheFile" */\n condition:\n  $a\n}\n')
        self.assertEqual("PASSED", self.status(text))


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.ws = ws = Workspace(Path(self.temp.name) / "rules")
        content = {key: stub(PAYLOAD + key.encode()) for key in ("C1", "C1-v1", "C1-v2", "C3", "E1")}
        ws.add("C1", "original", "calibration", "proj-C1", content=content["C1"])
        ws.add("C1-copy", "control_copy", "calibration", "proj-C1", parent="C1", content=content["C1"])
        ws.add("C1-v1", "variant", "calibration", "proj-C1", parent="C1", order=1, holdout="false",
               content=content["C1-v1"])
        ws.add("C1-v2", "variant", "calibration", "proj-C1", parent="C1", order=2, holdout="true",
               content=content["C1-v2"])
        ws.add("C3", "original", "calibration", "proj-C3", content=content["C3"])
        ws.add("CB1", "benign", "calibration", "benign-1")
        ws.add("CB2", "benign", "calibration", "benign-2")
        ws.add("E1", "original", "evaluation", "proj-E1", content=content["E1"])
        ws.add("EB1", "benign", "evaluation", "benign-e")
        self.samples = ws.samples()
        self.av = {"C1": False, "C1-copy": False, "C1-v1": False, "C1-v2": False, "C3": False,
                   "CB1": False, "CB2": False, "E1": False, "EB1": False}
        self.text = rule(['$a = "SharedTextAcrossFiles"'])

    def tearDown(self):
        self.temp.cleanup()

    def package(self, target):
        return rw.rule_package(self.samples, self.av, target, self.ws.root)

    def results(self, text, matches, compiled=True):
        return {"rule_sha256": sha(text), "compiled": compiled, "compile_errors": [],
                "matches": {key: {"status": value, "sha256": self.samples[key]["sha256"]}
                            for key, value in matches.items()}}

    def accept(self, target, matches, compiled=True, text=None):
        text = text or self.text
        return rw.accept_rule(text, self.package(target), self.samples, self.av,
                              self.results(text, matches, compiled), self.ws.root)

    GOOD = {"C1": "MATCHED", "C1-v1": "MATCHED", "CB1": "NOT_MATCHED", "CB2": "NOT_MATCHED"}

    def test_targets_are_undetected_non_held_out_calibration_files(self):
        self.assertEqual(["C1", "C1-v1", "C3"], rw.rule_targets(self.samples, self.av))
        self.av["C1"] = True
        self.assertEqual(["C1-v1", "C3"], rw.rule_targets(self.samples, self.av))
        del self.av["C3"]
        self.assertEqual(["C3"], rw.unknown_targets(self.samples, self.av))

    def test_package_is_computed_from_the_target_file(self):
        for target in ("E1", "C1-v2", "C1-copy", "CB1"):
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, "Rule targets"):
                self.package(target)
        package = self.package("C1")
        self.assertEqual({"schema", "kind", "target_id", "description", "description_sha256"}, set(package))
        self.assertEqual(self.samples["C1"]["sha256"], package["description"]["sample_sha256"])
        (self.ws.root / self.samples["C1"]["path"]).write_bytes(stub(b"changed"))
        with self.assertRaisesRegex(ValueError, "changed since registration"):
            self.package("C1")

    def test_acceptance_conditions(self):
        decision = self.accept("C1", self.GOOD)
        self.assertEqual(("ACCEPTED", "APPLIED"), (decision["status"], decision["group_condition"]))
        # The control copy and the held-out variant are not group evidence.
        self.assertEqual(["C1-v1"], decision["checked"]["group"])
        cases = (
            (dict(self.GOOD, **{"C1-v1": "NOT_MATCHED", "C1-copy": "MATCHED"}), "REJECTED_NO_GROUP_MATCH"),
            (dict(self.GOOD, C1="NOT_MATCHED"), "REJECTED_NO_TARGET_MATCH"),
            (dict(self.GOOD, CB2="MATCHED"), "REJECTED_FALSE_POSITIVE"),
            (dict(self.GOOD, CB2="ERROR"), "INCOMPLETE"),
            ({k: v for k, v in self.GOOD.items() if k != "CB1"}, "INCOMPLETE"),
        )
        for matches, status in cases:
            with self.subTest(status=status, matches=matches):
                self.assertEqual(status, self.accept("C1", matches)["status"])
        self.assertEqual("REJECTED_COMPILE", self.accept("C1", self.GOOD, compiled=False)["status"])
        self.assertEqual("INCOMPLETE", self.accept("C1", self.GOOD, compiled=None)["status"])
        with self.assertRaisesRegex(ValueError, "Invalid YARA results record"):
            self.accept("C1", self.GOOD, compiled="yes")
        traced = self.accept("C1", self.GOOD, text=rule(['$a = "NotInTheFile"']))
        self.assertEqual("REJECTED_FEATURE_NOT_IN_DESCRIPTION", traced["status"])

    def test_group_condition_not_applicable_without_other_group_files(self):
        decision = self.accept("C3", {"C3": "MATCHED", "CB1": "NOT_MATCHED", "CB2": "NOT_MATCHED"})
        self.assertEqual(("ACCEPTED", "NOT_APPLICABLE"), (decision["status"], decision["group_condition"]))

    def test_evaluation_and_held_out_responses_never_reach_acceptance_or_repair(self):
        # Regression: a held-out variant's MATCHED response reached repair feedback.
        for extra in ({"EB1": "NOT_MATCHED"}, {"C1-v2": "MATCHED"}):
            matches = dict(self.GOOD, **extra)
            with self.subTest(extra=extra):
                with self.assertRaisesRegex(ValueError, "calibration responses only|Held-out"):
                    self.accept("C1", matches)
                with self.assertRaisesRegex(ValueError, "calibration responses only|Held-out"):
                    rw.repair_feedback(self.samples, self.results(self.text, matches))
        record = self.results(self.text, {"C1": "NOT_MATCHED"}, compiled=False)
        record["compile_errors"] = ["line 3: syntax error"]
        feedback = rw.repair_feedback(self.samples, record)
        self.assertEqual({"compile_errors": ["line 3: syntax error"], "matches": {"C1": "NOT_MATCHED"}}, feedback)

    def test_results_must_belong_to_this_rule_text_and_files(self):
        # Regression: one results record accepted two different rule texts.
        other = rule(['$a = "AegisMarkerAlpha"'])
        with self.assertRaisesRegex(ValueError, "different rule text"):
            rw.accept_rule(other, self.package("C1"), self.samples, self.av,
                           self.results(self.text, self.GOOD), self.ws.root)
        stale = self.results(self.text, self.GOOD)
        stale["matches"]["CB1"]["sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "not bound to the registered file"):
            rw.accept_rule(self.text, self.package("C1"), self.samples, self.av, stale, self.ws.root)
        malformed = self.results(self.text, self.GOOD)
        malformed["matches"]["CB1"] = ["MATCHED"]
        with self.assertRaisesRegex(ValueError, "not bound"):
            rw.accept_rule(self.text, self.package("C1"), self.samples, self.av, malformed, self.ws.root)
    def test_malformed_results_are_input_errors_in_both_interfaces(self):
        # Regression: compile_errors=None raised TypeError in acceptance, and a
        # wrongly typed status passed through repair feedback unchanged.
        def broken(change):
            value = self.results(self.text, self.GOOD)
            change(value)
            return value
        cases = (
            lambda v: v.update(compile_errors=None),
            lambda v: v.update(compile_errors=[3]),
            lambda v: v["matches"]["CB1"].update(status={"value": "MATCHED"}),
            lambda v: v["matches"]["CB1"].update(status="CLEAN"),
            lambda v: v["matches"]["CB1"].update(extra=True),
            lambda v: v.update(matches=[]),
            lambda v: v.pop("rule_sha256"),
            lambda v: v.update(compiled=1),
            lambda v: v.pop("compiled"),          # regression: KeyError / silently accepted
            lambda v: v.update(extra_field=True),  # regression: extra top-level field accepted
        )
        for index, change in enumerate(cases):
            record = broken(change)
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    rw.accept_rule(self.text, self.package("C1"), self.samples, self.av, record, self.ws.root)
                with self.assertRaises(ValueError):
                    rw.repair_feedback(self.samples, record)

    def test_edited_description_is_rejected(self):
        # Regression: an edited description that kept the file hash was accepted.
        package = self.package("C1")
        package["description"]["strings"].append({"text": "InventedFeature", "encoding": "ascii"})
        text = rule(['$a = "InventedFeature"'])
        with self.assertRaisesRegex(ValueError, "does not match the target's current description"):
            rw.accept_rule(text, package, self.samples, self.av, self.results(text, self.GOOD), self.ws.root)

    # R3 ---------------------------------------------------------------------------

    def decided(self):
        rules = {"r-C1": rule(['$a = "SharedTextAcrossFiles"'], name="Aegis_C1"),
                 "r-C1-v1": rule(['$a = "AegisMarkerAlpha"'], name="Aegis_C1_v1"),
                 "r-C3": rule(['$a = "NotInTheFile"'], name="Aegis_C3")}
        decisions = {
            "r-C1": self.accept("C1", self.GOOD, text=rules["r-C1"]),
            "r-C1-v1": self.accept("C1-v1", self.GOOD, text=rules["r-C1-v1"]),
            "r-C3": self.accept("C3", {"C3": "MATCHED", "CB1": "NOT_MATCHED", "CB2": "NOT_MATCHED"},
                                text=rules["r-C3"]),
        }
        return rules, decisions

    def test_freeze_combines_accepted_rules_and_detects_changes(self):
        rules, decisions = self.decided()
        text, record = rw.freeze(rules, decisions, self.samples, self.av, "4.6.0", run_id="run-1")
        self.assertEqual(("FROZEN", None, "run-1"), (record["status"], record["reason"], record["run_id"]))
        with self.assertRaisesRegex(ValueError, "belongs to one run"):
            rw.freeze(rules, decisions, self.samples, self.av, "4.6.0", run_id="")
        self.assertIn("rule Aegis_C1 ", text)
        self.assertNotIn("Aegis_C3", text)
        self.assertEqual({"ACCEPTED", "REJECTED_FEATURE_NOT_IN_DESCRIPTION"}, {r["status"] for r in record["rules"]})
        path = Path(self.temp.name) / "frozen.yar"
        path.write_text(text)
        self.assertTrue(rw.verify_frozen(path, record))
        path.write_text(text + "\n// edited\n")
        with self.assertRaisesRegex(ValueError, "changed after freezing"):
            rw.verify_frozen(path, record)

    def test_empty_and_failed_rule_sets(self):
        rules, decisions = self.decided()
        detected = {key: True for key in self.av}
        _, record = rw.freeze({}, {}, self.samples, detected, "4.6.0", run_id="run-1")
        self.assertEqual(("EMPTY", "AV_DETECTED_ALL_CALIBRATION_FILES"), (record["status"], record["reason"]))
        only_c3 = dict(detected, C3=False)
        _, record = rw.freeze({"r-C3": rules["r-C3"]}, {"r-C3": decisions["r-C3"]}, self.samples, only_c3, "4.6.0", run_id="run-1")
        self.assertEqual(("EMPTY", "NO_RULE_ACCEPTED"), (record["status"], record["reason"]))
        _, record = rw.freeze({"r-C1": rules["r-C1"]}, {"r-C1": decisions["r-C1"]}, self.samples, self.av, "4.6.0", run_id="run-1")
        self.assertEqual(("FAILED", ["C1-v1", "C3"]), (record["status"], record["undecided_targets"]))
        self.assertIsNone(record["ruleset_sha256"])
        traced = rule(['$a = "AegisMarker"'], name="Aegis_C3")
        incomplete = dict(decisions, **{"r-C3": self.accept("C3", {"C3": "MATCHED"}, text=traced)})
        _, record = rw.freeze(dict(rules, **{"r-C3": traced}), incomplete, self.samples, self.av, "4.6.0", run_id="run-1")
        self.assertEqual(("FAILED", ["r-C3"]), (record["status"], record["incomplete_rules"]))

    def test_missing_av_responses_are_not_an_empty_rule_set(self):
        # Regression: no AV responses at all gave EMPTY / AV_DETECTED_ALL_CALIBRATION_FILES.
        _, record = rw.freeze({}, {}, self.samples, {}, "4.6.0", run_id="run-1")
        self.assertEqual(("FAILED", "AV_RESPONSES_INCOMPLETE"), (record["status"], record["reason"]))
        self.assertEqual(["C1", "C1-v1", "C3"], record["unknown_av_targets"])
        partial = {key: True for key in self.av if key != "C3"}
        _, record = rw.freeze({}, {}, self.samples, partial, "4.6.0", run_id="run-1")
        self.assertEqual(("FAILED", ["C3"]), (record["status"], record["unknown_av_targets"]))

    def test_invalid_av_values_never_settle_targets(self):
        # Regression: "ERROR", 0 or 1 gave EMPTY / AV_DETECTED_ALL_CALIBRATION_FILES.
        for value in ("ERROR", 0, 1, None):
            av = {key: True for key in self.av}
            av["C3"] = value
            with self.subTest(value=value):
                _, record = rw.freeze({}, {}, self.samples, av, "4.6.0", run_id="run-1")
                self.assertEqual(("FAILED", "AV_RESPONSES_INCOMPLETE", ["C3"]),
                                 (record["status"], record["reason"], record["unknown_av_targets"]))
                self.assertNotIn("C3", rw.rule_targets(self.samples, av))

    def test_contradictory_decision_cannot_be_frozen(self):
        # Regression: a REJECTED_FALSE_POSITIVE decision with accepted=True was frozen.
        rules, decisions = self.decided()
        rejected = self.accept("C1", dict(self.GOOD, CB2="MATCHED"), text=rules["r-C1"])
        self.assertEqual("REJECTED_FALSE_POSITIVE", rejected["status"])
        for change in ({"accepted": True}, {"status": "ACCEPTED", "accepted": False},
                       {"status": "MADE_UP"}, {"accepted": 1}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "disagree"):
                rw.freeze(rules, dict(decisions, **{"r-C1": dict(rejected, **change)}), self.samples, self.av, "4.6.0", run_id="run-1")

    def test_freeze_input_integrity(self):
        rules, decisions = self.decided()
        with self.assertRaisesRegex(ValueError, "exactly one decision"):
            rw.freeze(rules, {k: v for k, v in decisions.items() if k != "r-C3"}, self.samples, self.av, "4.6.0", run_id="run-1")
        with self.assertRaisesRegex(ValueError, "does not belong"):
            rw.freeze(dict(rules, **{"r-C1": rules["r-C1"] + "// changed\n"}), decisions, self.samples, self.av, "4.6.0", run_id="run-1")
        twice = dict(decisions, extra=decisions["r-C1"])
        with self.assertRaisesRegex(ValueError, "at most one final"):
            rw.freeze(dict(rules, extra=rules["r-C1"]), twice, self.samples, self.av, "4.6.0", run_id="run-1")
        same_name = dict(rules, **{"r-C1-v1": rules["r-C1-v1"].replace("Aegis_C1_v1", "Aegis_C1")})
        renamed = dict(decisions, **{"r-C1-v1": self.accept("C1-v1", self.GOOD, text=same_name["r-C1-v1"])})
        with self.assertRaisesRegex(ValueError, "distinct rule names"):
            rw.freeze(same_name, renamed, self.samples, self.av, "4.6.0", run_id="run-1")

    def test_cli_describe_writes_new_files_only(self):
        source = Path(self.temp.name) / "stub.bin"
        source.write_bytes(stub(PAYLOAD))
        output = Path(self.temp.name) / "description.json"
        self.assertEqual(0, rw.main(["describe", "--file", str(source), "--output", str(output)]))
        self.assertEqual(3, json.loads(output.read_text())["counts"]["provided"])
        self.assertEqual(1, rw.main(["describe", "--file", str(source), "--output", str(output)]))
        with self.assertRaisesRegex(ValueError, "outside the public repository"):
            aegis.external_path(ROOT / "tests" / "description.json")


if __name__ == "__main__":
    unittest.main()
