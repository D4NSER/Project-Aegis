"""Split assignment and catalogue conversion with generated inert text only.

"malicious" here is a synthetic catalogue label used to exercise conversion;
every object is a short inert UTF-8 text written by the test.
"""
import csv
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import aegis
import control_panel
import dataset_plan

CARD = "c" * 64


def write_rows(path, fields, rows):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


class AssignmentTests(unittest.TestCase):
    def test_original_groups_alternate_calibration_first(self):
        record = dataset_plan.assign_original_groups(
            [("p1", "o1"), ("p2", "o2"), ("p2", "o3"), ("p3", "o4")])
        self.assertEqual([("p1", "calibration", ["o1"]), ("p2", "evaluation", ["o2", "o3"]),
                          ("p3", "calibration", ["o4"])],
                         [(a["project_id"], a["split"], a["object_ids"]) for a in record["assignments"]])
        self.assertFalse(record["detector_responses_used"])

    def test_repeated_object_rejected(self):
        with self.assertRaisesRegex(ValueError, "more than once"):
            dataset_plan.assign_original_groups([("p1", "o1"), ("p2", "o1")])

    def test_benign_groups_fill_quotas_proportionally(self):
        # Plan 2/3, group sizes 1,2,1,3,1:
        # g1 -> calibration (1/2); g2 -> evaluation (2/3); g3 -> calibration (2/2);
        # g4 fits neither; g5 -> evaluation (3/3).
        accepted = [("g1", "a"), ("g2", "b"), ("g2", "c"), ("g3", "d"),
                    ("g4", "e"), ("g4", "f"), ("g4", "g"), ("g5", "h")]
        record = dataset_plan.allocate_benign(accepted, {"calibration": 2, "evaluation": 3})
        self.assertEqual({"calibration": 2, "evaluation": 3}, record["actual"])
        self.assertEqual(["g1", "g2", "g3", "g5"], [a["project_id"] for a in record["assignments"]])
        self.assertEqual(["calibration", "evaluation", "calibration", "evaluation"],
                         [a["split"] for a in record["assignments"]])
        self.assertEqual(["g4"], [a["project_id"] for a in record["unassigned"]])

    def test_small_benign_sample_keeps_both_splits(self):
        # Six single-file groups against the 10/50 plan: 1 calibration, 5 evaluation.
        record = dataset_plan.allocate_benign([("g%d" % i, "b%d" % i) for i in range(6)])
        self.assertEqual({"calibration": 1, "evaluation": 5}, record["actual"])
        self.assertEqual({"calibration": 10, "evaluation": 50}, record["planned"])

    def test_full_plan_is_met_exactly(self):
        record = dataset_plan.allocate_benign([("g%d" % i, "b%d" % i) for i in range(70)])
        self.assertEqual({"calibration": 10, "evaluation": 50}, record["actual"])
        self.assertEqual(10, len(record["unassigned"]))

    def test_plan_is_filled_when_whole_groups_allow_it(self):
        # Regression: group sizes 1, 10, 49 gave 1/10 and left 49 out; 10/50 is possible.
        accepted = [("g1", "a")] + [("g2", "b%d" % i) for i in range(10)] + [("g3", "c%d" % i) for i in range(49)]
        record = dataset_plan.allocate_benign(accepted)
        self.assertEqual({"calibration": 10, "evaluation": 50}, record["actual"])
        self.assertEqual({"g1": "evaluation", "g2": "calibration", "g3": "evaluation"},
                         {a["project_id"]: a["split"] for a in record["assignments"]})
        self.assertEqual([], record["unassigned"])

    def test_allocation_is_deterministic_and_never_exceeds_the_plan(self):
        accepted = [("g%d" % i, "x%d-%d" % (i, j)) for i, size in enumerate([3, 7, 2, 9, 4, 1, 6]) for j in range(size)]
        first = dataset_plan.allocate_benign(accepted, {"calibration": 5, "evaluation": 12})
        self.assertEqual(first, dataset_plan.allocate_benign(accepted, {"calibration": 5, "evaluation": 12}))
        self.assertEqual({"calibration": 5, "evaluation": 12}, first["actual"])

    def test_invalid_plan_rejected(self):
        with self.assertRaises(ValueError):
            dataset_plan.allocate_benign([("g", "b")], {"calibration": -1, "evaluation": 5})


class CatalogueConversionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        base = Path(self.temp.name)
        self.collection = base / "collection"
        self.workspace = base / "workspace"
        (self.collection / "catalog").mkdir(parents=True)
        (self.collection / "objects").mkdir()
        (self.workspace / "records").mkdir(parents=True)
        (self.workspace / "derived").mkdir()
        self.objects = []
        for object_id, label, project, eligibility in (
                ("o1", "malicious", "p1", "ELIGIBLE"), ("o2", "malicious", "p2", "ELIGIBLE"),
                ("b1", "benign", "pb1", "ELIGIBLE")):
            path = self.collection / "objects" / (object_id + ".txt")
            path.write_text("Inert catalogue text " + object_id + "\n")
            self.objects.append(dict(zip(control_panel.OBJECT_FIELDS, [
                object_id, "src", "objects/" + object_id + ".txt", aegis.digest(path), str(path.stat().st_size),
                "text", "none", project, "fam" if label == "malicious" else "", "", label,
                "synthetic label for conversion tests", eligibility])))
        write_rows(self.collection / "catalog/sources.csv", control_panel.SOURCE_FIELDS, [dict(zip(
            control_panel.SOURCE_FIELDS, ["src", "Synthetic source", "https://example.invalid/source", "1",
                                          "2026-11-27", "test only", "SYNTHETIC"]))])
        self.write_catalog()

    def write_catalog(self, splits=None):
        splits = splits or {"o1": "calibration", "o2": "evaluation", "b1": "evaluation"}
        write_rows(self.collection / "catalog/objects.csv", control_panel.OBJECT_FIELDS, self.objects)
        write_rows(self.collection / "catalog/selection.csv", control_panel.SELECTION_FIELDS, [
            dict(zip(control_panel.SELECTION_FIELDS, [key, split, "test selection", "protocol-test"]))
            for key, split in splits.items()])
        return control_panel.load_catalog(self.collection, self.workspace)

    def tearDown(self):
        self.temp.cleanup()

    def assignments(self, originals=(("p1", "o1"), ("p2", "o2")), benign=(("pb1", "b1"),), plan=(0, 1)):
        return [dataset_plan.assign_original_groups(list(originals)),
                dataset_plan.allocate_benign(list(benign), {"calibration": plan[0], "evaluation": plan[1]})]

    def record(self, object_id, status="PASS"):
        sha = next(o["sha256"] for o in self.objects if o["object_id"] == object_id)
        relative = "records/" + object_id + ".json"
        (self.workspace / relative).write_text(json.dumps({
            "schema": 1, "kind": "functionality_record", "record_id": "rec-" + object_id,
            "sample_sha256": sha, "card_sha256": CARD, "status": status, "synthetic": True}))
        return relative

    def test_catalogue_eligibility_is_not_functionality(self):
        rows = dataset_plan.build_manifest(self.write_catalog(), self.workspace, self.assignments())
        by_id = {row["sample_id"]: row for row in rows}
        self.assertEqual("NOT_RUN", by_id["o1"]["functionality"])
        self.assertEqual(("benign", "NOT_APPLICABLE", ""), (by_id["b1"]["kind"], by_id["b1"]["functionality"],
                                                            by_id["b1"]["family_id"]))
        self.assertEqual("collection:objects/o1.txt", by_id["o1"]["path"])

    def test_functionality_comes_from_records_and_derived_rows_join(self):
        catalog = self.write_catalog()
        original = (self.collection / "objects/o1.txt").read_bytes()
        (self.workspace / "derived/o1-copy.txt").write_bytes(original)
        (self.workspace / "derived/o1-v1.txt").write_text("Inert derived variant text\n")
        variant_sha = aegis.digest(self.workspace / "derived/o1-v1.txt")
        (self.workspace / "records/o1-v1.json").write_text(json.dumps({
            "schema": 1, "kind": "functionality_record", "record_id": "rec-v1",
            "sample_sha256": variant_sha, "card_sha256": CARD, "status": "PASS", "synthetic": True}))
        common = ["generated inert text", "v1", "synthetic label", "text", "none"]
        derived = [
            dict(zip(aegis.SAMPLE_FIELDS, ["o1-copy", "p1", "fam", "calibration", "control_copy", "o1", "", "",
                                           aegis.digest(self.workspace / "derived/o1-copy.txt"),
                                           "derived/o1-copy.txt", "NOT_APPLICABLE", "", "", *common])),
            dict(zip(aegis.SAMPLE_FIELDS, ["o1-v1", "p1", "fam", "calibration", "variant", "o1", "1", "",
                                           variant_sha, "derived/o1-v1.txt", "PASS", CARD,
                                           "records/o1-v1.json", *common])),
        ]
        rows = dataset_plan.build_manifest(catalog, self.workspace, self.assignments(), [self.record("o1")], derived)
        samples = aegis.validate_samples(rows, self.workspace, self.collection)
        self.assertEqual("PASS", samples["o1"]["functionality"])
        self.assertEqual(samples["o1"]["sha256"], samples["o1-copy"]["sha256"])

    def test_catalogue_variants_and_unknown_labels_rejected(self):
        self.objects[1]["label"] = "suspicious"
        with self.assertRaisesRegex(ValueError, "another label"):
            dataset_plan.build_manifest(self.write_catalog(), self.workspace, self.assignments())
        self.objects[1].update(label="malicious", parent_id="o1", project_id="p1")
        catalog = self.write_catalog({"o1": "calibration", "o2": "calibration", "b1": "evaluation"})
        with self.assertRaisesRegex(ValueError, "generation records"):
            dataset_plan.build_manifest(catalog, self.workspace, self.assignments(originals=(("p1", "o1"), ("p1", "o2"))))

    def test_manifest_cannot_bypass_the_frozen_assignment(self):
        # Regression: swapping two projects' splits in the catalogue was accepted.
        swapped = self.write_catalog({"o1": "evaluation", "o2": "calibration", "b1": "evaluation"})
        with self.assertRaisesRegex(ValueError, "differs from the frozen assignment"):
            dataset_plan.build_manifest(swapped, self.workspace, self.assignments())
        catalog = self.write_catalog()
        with self.assertRaisesRegex(ValueError, "missing from the frozen assignment"):
            dataset_plan.build_manifest(catalog, self.workspace, self.assignments(originals=(("p1", "o1"),)))
        with self.assertRaisesRegex(ValueError, "one original-group and one benign"):
            dataset_plan.build_manifest(catalog, self.workspace, self.assignments()[:1])

    def test_assignment_groups_must_be_catalogue_projects(self):
        # Regression: o1 (p1) and o2 (p2) recorded as one group were both accepted
        # into calibration, although real groups alternate.
        catalog = self.write_catalog({"o1": "calibration", "o2": "calibration", "b1": "evaluation"})
        merged = self.assignments(originals=(("p1", "o1"), ("p1", "o2")))
        with self.assertRaisesRegex(ValueError, "differs from the catalogue project"):
            dataset_plan.build_manifest(catalog, self.workspace, merged)
        # A recorded group that omits a selected object of its project is rejected too.
        self.objects[1]["project_id"] = "p1"
        catalog = self.write_catalog({"o1": "calibration", "o2": "calibration", "b1": "evaluation"})
        with self.assertRaisesRegex(ValueError, "missing from its group"):
            dataset_plan.check_assignment(catalog, dataset_plan.assign_original_groups([("p1", "o1")]))

    def test_hand_edited_record_must_follow_its_rule(self):
        catalog = self.write_catalog()
        records = self.assignments()
        records[0]["assignments"][0]["split"] = "evaluation"
        records[0]["assignments"][1]["split"] = "calibration"
        swapped = self.write_catalog({"o1": "evaluation", "o2": "calibration", "b1": "evaluation"})
        with self.assertRaisesRegex(ValueError, "does not follow its rule"):
            dataset_plan.build_manifest(swapped, self.workspace, records)
        records = self.assignments()
        records[1]["actual"] = {"calibration": 0, "evaluation": 5}
        with self.assertRaisesRegex(ValueError, "does not follow its rule"):
            dataset_plan.build_manifest(catalog, self.workspace, records)

    def test_derived_rows_cannot_extend_the_selected_sample(self):
        # Regression: a new benign row passed as "derived" entered the manifest.
        catalog = self.write_catalog()
        (self.workspace / "derived/extra.txt").write_text("Inert extra text\n")
        common = ["generated inert text", "v1", "synthetic label", "text", "none"]
        sha = aegis.digest(self.workspace / "derived/extra.txt")
        extra_benign = dict(zip(aegis.SAMPLE_FIELDS, ["extra", "pb-extra", "", "evaluation", "benign", "", "", "",
                                                      sha, "derived/extra.txt", "NOT_APPLICABLE", "", "", *common]))
        orphan_copy = dict(zip(aegis.SAMPLE_FIELDS, ["orphan", "px", "fam", "evaluation", "control_copy", "missing",
                                                     "", "", sha, "derived/extra.txt", "NOT_APPLICABLE", "", "",
                                                     *common]))
        for row in (extra_benign, orphan_copy):
            with self.subTest(row=row["sample_id"]), self.assertRaisesRegex(ValueError, "Derived rows may only"):
                dataset_plan.build_manifest(catalog, self.workspace, self.assignments(), derived_rows=[row])

    def test_duplicate_functionality_records_rejected(self):
        first = self.record("o1")
        (self.workspace / "records/again.json").write_text((self.workspace / first).read_text())
        with self.assertRaisesRegex(ValueError, "More than one"):
            dataset_plan.build_manifest(self.write_catalog(), self.workspace, self.assignments(),
                                        [first, "records/again.json"])

    def test_catalogue_must_match_frozen_assignment(self):
        catalog = self.write_catalog()
        record = dataset_plan.assign_original_groups([("p1", "o1"), ("p2", "o2")])
        dataset_plan.check_assignment(catalog, record)
        record = dataset_plan.assign_original_groups([("p2", "o2"), ("p1", "o1")])
        with self.assertRaisesRegex(ValueError, "differs from the frozen assignment"):
            dataset_plan.check_assignment(catalog, record)
        benign = dataset_plan.allocate_benign([("pb1", "b1")], {"calibration": 0, "evaluation": 0})
        with self.assertRaisesRegex(ValueError, "unassigned object was selected"):
            dataset_plan.check_assignment(catalog, benign)

    def test_cli_writes_new_files_only(self):
        accepted = self.workspace / "accepted.csv"
        write_rows(accepted, ["project_id", "object_id"], [{"project_id": "p1", "object_id": "o1"}])
        output = self.workspace / "assignment.json"
        self.assertEqual(0, dataset_plan.main(["assign-originals", "--accepted", str(accepted),
                                               "--output", str(output)]))
        self.assertEqual("calibration", json.loads(output.read_text())["assignments"][0]["split"])
        self.assertEqual(1, dataset_plan.main(["assign-originals", "--accepted", str(accepted),
                                               "--output", str(output)]))
        records = []
        for index, record in enumerate(self.assignments()):
            records.append(self.workspace / ("record-%d.json" % index))
            records[-1].write_text(json.dumps(record))
        manifest = self.workspace / "manifest.csv"
        self.assertEqual(0, dataset_plan.main(["build-manifest", "--collection", str(self.collection),
                                               "--workspace", str(self.workspace),
                                               "--assignment", *map(str, records), "--output", str(manifest)]))
        self.assertEqual(3, len(aegis.read_csv(manifest, aegis.SAMPLE_FIELDS)))


if __name__ == "__main__":
    unittest.main()
