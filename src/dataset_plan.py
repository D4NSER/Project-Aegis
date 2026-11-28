"""Deterministic split assignment and catalogue-to-manifest conversion; no execution.

Original project groups alternate between calibration and evaluation in their
acceptance order. Benign project groups fill the planned calibration/evaluation
quotas as fully as whole groups allow, keeping each project in one split. Both
records are written before any detector response is collected and never read
detector responses. The converter copies catalogue identity only: functionality
outcomes come from card evaluator records, never from catalogue eligibility.
"""
import argparse
from collections import OrderedDict
import csv
from datetime import datetime, timezone
from fractions import Fraction
import json
from pathlib import Path
import sys

import aegis

PLANNED_BENIGN = {"calibration": 10, "evaluation": 50}
LABELS = {"malicious": "original", "benign": "benign"}


def _ordered_groups(items):
    groups = OrderedDict()
    for project_id, object_id in items:
        if not project_id or not object_id:
            raise ValueError("Every accepted object needs a project and object ID")
        groups.setdefault(project_id, []).append(object_id)
    seen = [key for values in groups.values() for key in values]
    if len(seen) != len(set(seen)):
        raise ValueError("An object appears more than once in the acceptance order")
    return groups


def assign_original_groups(accepted):
    """`accepted`: (project_id, object_id) pairs in acceptance order."""
    groups = _ordered_groups(accepted)
    assignments = []
    for index, (project, objects) in enumerate(groups.items()):
        split = aegis.SPLITS[index % 2]
        assignments.append({"project_id": project, "order": index + 1, "split": split, "object_ids": objects})
    return {"kind": "original_group_assignment", "rule": "alternate by acceptance order, calibration first",
            "detector_responses_used": False, "assignments": assignments}


def _balance(actual, planned):
    """Smallest fill ratio; a zero quota counts as filled."""
    return min(Fraction(actual[s], planned[s]) if planned[s] else Fraction(1) for s in aegis.SPLITS)


def allocate_benign(accepted, planned=None):
    """Fill planned quotas with whole project groups, as fully as the group sizes allow.

    Among allocations that keep every project group in one split, choose the one
    that (1) assigns the most files, (2) keeps the split fill ratios most even,
    and (3) is lexicographically first in acceptance order, preferring
    calibration, then evaluation, then leaving a group out.
    """
    planned = dict(PLANNED_BENIGN if planned is None else planned)
    if set(planned) != set(aegis.SPLITS) or any(type(v) is not int or v < 0 for v in planned.values()):
        raise ValueError("Planned benign quotas need non-negative calibration and evaluation counts")
    groups = list(_ordered_groups(accepted).items())
    sizes = [len(objects) for _, objects in groups]
    choices = (*aegis.SPLITS, None)
    cal, ev = planned["calibration"], planned["evaluation"]

    def key(c, e):
        return (c + e, _balance({"calibration": c, "evaluation": e}, planned))
    # best[i][(c, e)] = (best final key reachable from group i, first choice reaching it).
    # The first choice suffices: each later state's continuation is already minimal.
    following = {(c, e): (key(c, e), None) for c in range(cal + 1) for e in range(ev + 1)}
    table = []
    for size in reversed(sizes):
        current = {}
        for (c, e) in following:
            best = None
            for rank, choice in enumerate(choices):
                state = (c + size, e) if choice == "calibration" else (c, e + size) if choice == "evaluation" else (c, e)
                if state not in following:
                    continue
                candidate = following[state][0]
                if best is None or candidate > best[0]:
                    best = (candidate, rank)
            current[(c, e)] = (best[0], choices[best[1]])
        table.append(current)
        following = current
    table.reverse()
    actual = {split: 0 for split in aegis.SPLITS}
    assignments, unassigned = [], []
    for index, ((project, objects), level) in enumerate(zip(groups, table)):
        split = level[(actual["calibration"], actual["evaluation"])][1]
        if split is None:
            unassigned.append({"project_id": project, "order": index + 1, "object_ids": objects,
                               "reason": "NOT_NEEDED_OR_DOES_NOT_FIT"})
            continue
        actual[split] += len(objects)
        assignments.append({"project_id": project, "order": index + 1, "split": split, "object_ids": objects})
    return {"kind": "benign_allocation", "rule": "whole project groups; most files assigned within the plan, "
            "then most even fill, then earliest acceptance order preferring calibration",
            "planned": planned, "actual": actual,
            "detector_responses_used": False, "assignments": assignments, "unassigned": unassigned}


RECORD_LABELS = {"original_group_assignment": "malicious", "benign_allocation": "benign"}


def check_assignment(catalog, record):
    """The catalogue's selection must equal a frozen assignment record."""
    label = RECORD_LABELS.get(record.get("kind"))
    if label is None or record.get("detector_responses_used") is not False:
        raise ValueError("Unknown or detector-dependent assignment record")
    # Groups must be the catalogue's real project groups ...
    items = sorted(record["assignments"] + record.get("unassigned", []), key=lambda item: item["order"])
    for item in items:
        for object_id in item["object_ids"]:
            if catalog["objects"].get(object_id, {}).get("project_id") != item["project_id"]:
                raise ValueError("Assignment group differs from the catalogue project: " + object_id)
    for project in {item["project_id"] for item in items}:
        listed = sorted(o for item in items if item["project_id"] == project for o in item["object_ids"])
        selected = sorted(key for key, row in catalog["objects"].items()
                          if row["project_id"] == project and catalog["selection"].get(key, {}).get("split"))
        if not set(selected) <= set(listed):
            raise ValueError("A selected object of a recorded project is missing from its group: " + project)
    # ... and the record must be exactly what its rule gives for its own acceptance order.
    accepted = [(item["project_id"], object_id) for item in items for object_id in item["object_ids"]]
    if record["kind"] == "original_group_assignment":
        expected = assign_original_groups(accepted)
        same = expected["assignments"] == record["assignments"] and not record.get("unassigned")
    else:
        expected = allocate_benign(accepted, record.get("planned"))
        same = all(expected[k] == record.get(k) for k in ("assignments", "unassigned", "actual", "planned"))
    if not same:
        raise ValueError("Assignment record does not follow its rule for its acceptance order")
    for item in record["assignments"]:
        for object_id in item["object_ids"]:
            if catalog["objects"].get(object_id, {}).get("label") != label:
                raise ValueError("Assignment record names an object with another label: " + object_id)
            selected = catalog["selection"].get(object_id, {}).get("split")
            if selected != item["split"]:
                raise ValueError("Catalogue split differs from the frozen assignment: " + object_id)
    for item in record.get("unassigned", []):
        for object_id in item["object_ids"]:
            if catalog["selection"].get(object_id, {}).get("split"):
                raise ValueError("An unassigned object was selected: " + object_id)


def check_coverage(catalog, records):
    """Every selected catalogue object must come from exactly one frozen record of its label."""
    kinds = sorted(record.get("kind") for record in records)
    if kinds != sorted(RECORD_LABELS):
        raise ValueError("Building a manifest needs one original-group and one benign assignment record")
    for record in records:
        check_assignment(catalog, record)
    covered = {object_id for record in records for item in record["assignments"] for object_id in item["object_ids"]}
    for object_id, selection in catalog["selection"].items():
        if selection["split"] and object_id not in covered:
            raise ValueError("Selected object is missing from the frozen assignment records: " + object_id)


def load_functionality(records, workspace):
    """Map sample SHA-256 to (status, card, workspace-relative record path)."""
    result = {}
    for relative in records:
        path = aegis.local_file(workspace, relative)
        value = json.loads(path.read_text(encoding="utf-8"))
        if value.get("kind") != "functionality_record" or value.get("status") not in aegis.TESTED_FUNCTIONALITY:
            raise ValueError("Invalid functionality record: " + relative)
        sha = value.get("sample_sha256")
        if sha in result:
            raise ValueError("More than one functionality record for one file: " + relative)
        result[sha] = (value["status"], value["card_sha256"], relative)
    return result


def catalog_rows(catalog, functionality):
    """Manifest rows for selected catalogue originals and benign files.

    Variants and control copies are produced later in the private workspace and
    are appended as their own manifest rows; catalogue objects with a parent are
    therefore rejected here rather than guessed.
    """
    rows = []
    for object_id, selection in sorted(catalog["selection"].items()):
        if not selection["split"]:
            continue
        item = catalog["objects"][object_id]
        source = catalog["sources"][item["source_id"]]
        if item["parent_id"]:
            raise ValueError("Catalogue variants need generation records; register them separately: " + object_id)
        kind = LABELS.get(item["label"])
        if kind is None:
            raise ValueError("Catalogue label must be malicious or benign: " + object_id)
        status, card, evidence = ("NOT_APPLICABLE", "", "") if kind == "benign" else \
            functionality.get(item["sha256"], ("NOT_RUN", "", ""))
        rows.append(dict(zip(aegis.SAMPLE_FIELDS, [
            object_id, item["project_id"], item["family_id"] if kind != "benign" else "", selection["split"], kind,
            "", "", "", item["sha256"], aegis.COLLECTION_PREFIX + item["relative_path"], status, card, evidence,
            source["title"], source["version"], item["label_basis"], item["format"], item["architecture"]])))
    return rows


def build_manifest(catalog, workspace, assignments, functionality_records=(), derived_rows=()):
    """Catalogue rows plus derived (variant/control-copy) rows, validated as one manifest.

    The catalogue selection must match the frozen assignment records, and the
    derived rows may only add variants or control copies of selected originals.
    """
    workspace = aegis.external_path(workspace)
    check_coverage(catalog, assignments)
    rows = catalog_rows(catalog, load_functionality(functionality_records, workspace))
    originals = {row["sample_id"] for row in rows if row["kind"] == "original"}
    for row in derived_rows:
        if row["kind"] not in {"variant", "control_copy"} or row["parent_id"] not in originals:
            raise ValueError("Derived rows may only add variants or control copies of selected originals: "
                             + row["sample_id"])
    rows += list(derived_rows)
    aegis.validate_samples(rows, workspace, Path(catalog["root"]))
    return rows


def write_new(path, content):
    path = aegis.external_path(path)
    with path.open("x", encoding="utf-8", newline="") as stream:
        stream.write(content)


def _pairs(path):
    with aegis.external_path(path).open(encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != ["project_id", "object_id"]:
            raise ValueError("Acceptance order CSV needs columns project_id,object_id")
        return [(row["project_id"], row["object_id"]) for row in reader]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("assign-originals", "allocate-benign"):
        command = commands.add_parser(name)
        command.add_argument("--accepted", required=True, help="CSV project_id,object_id in acceptance order")
        command.add_argument("--output", required=True)
    commands.choices["allocate-benign"].add_argument("--calibration", type=int, default=PLANNED_BENIGN["calibration"])
    commands.choices["allocate-benign"].add_argument("--evaluation", type=int, default=PLANNED_BENIGN["evaluation"])
    build = commands.add_parser("build-manifest")
    build.add_argument("--collection", required=True)
    build.add_argument("--workspace", required=True)
    build.add_argument("--assignment", nargs=2, required=True,
                       help="the frozen original-group and benign assignment records (JSON)")
    build.add_argument("--functionality", nargs="*", default=[], help="workspace-relative evaluator records")
    build.add_argument("--derived", help="manifest-format CSV of variants and control copies")
    build.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build-manifest":
            from control_panel import load_catalog
            catalog = load_catalog(args.collection, args.workspace)
            derived = aegis.read_csv(aegis.external_path(args.derived), aegis.SAMPLE_FIELDS) if args.derived else []
            records = [json.loads(aegis.external_path(path).read_text(encoding="utf-8")) for path in args.assignment]
            rows = build_manifest(catalog, args.workspace, records, args.functionality, derived)
            import io
            stream = io.StringIO()
            writer = csv.DictWriter(stream, fieldnames=aegis.SAMPLE_FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
            write_new(args.output, stream.getvalue())
            return 0
        accepted = _pairs(args.accepted)
        if args.command == "assign-originals":
            record = assign_original_groups(accepted)
        else:
            record = allocate_benign(accepted, {"calibration": args.calibration, "evaluation": args.evaluation})
        record["created_at_utc"] = datetime.now(timezone.utc).isoformat()
        write_new(args.output, json.dumps(record, indent=2, ensure_ascii=False) + "\n")
    except (ValueError, OSError, KeyError) as exc:
        print("Dataset planning failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
