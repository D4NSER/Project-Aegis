"""Rule preparation without a model: PE descriptions, rule acceptance and freezing.

Nothing here executes a file or YARA. Descriptions are read from file bytes on
the host; YARA compile and match outcomes are supplied as recorded results
from the laboratory. The protocol's acceptance conditions are then decided
from those results:

1. the rule compiles;
2. every feature it searches for appears in the description the model saw;
3. it matches its own file and at least one other file of the same group
   (the original or a non-held-out variant; control copies do not count);
4. it matches no calibration benign file;
all from valid responses bound to this rule text and to the checked files.
Only calibration files, never held-out variants, may supply rule targets,
descriptions, acceptance evidence or repair feedback.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

import aegis

DEFAULT_PARAMETERS = {"min_length": 5, "max_characters": 12000,
                      "encodings": ["ascii", "utf-16le"], "order": "file_offset"}
MACHINES = {0x14C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x1C4: "arm"}
PRINTABLE = set(range(0x20, 0x7F)) | {0x09}
TEXT_MODIFIERS = {"ascii", "wide", "nocase", "fullword"}
CONDITION_WORDS = {"and", "or", "not", "all", "any", "none", "of", "them", "at", "in",
                   "filesize", "for", "true", "false"}
CONDITION_OPS = {"(", ")", "==", "!=", "<", ">", "<=", ">=", "+", "-", "*", "\\", "%",
                 "&", "|", "^", "~", "<<", ">>", ",", "..", "[", "]"}
VALID_MATCH = {"MATCHED": True, "NOT_MATCHED": False}
DECISION_STATUSES = {"ACCEPTED", "INCOMPLETE", "REJECTED_COMPILE", "REJECTED_FORBIDDEN",
                     "REJECTED_FEATURE_NOT_IN_DESCRIPTION", "REJECTED_NO_TARGET_MATCH",
                     "REJECTED_NO_GROUP_MATCH", "REJECTED_FALSE_POSITIVE"}


# R1 · Description -----------------------------------------------------------------

def pe_machine(content):
    if len(content) < 0x40 or content[:2] != b"MZ":
        raise ValueError("Not a PE file: missing MZ header")
    offset = struct.unpack_from("<I", content, 0x3C)[0]
    if offset + 6 > len(content) or content[offset:offset + 4] != b"PE\0\0":
        raise ValueError("Not a PE file: missing PE signature")
    return struct.unpack_from("<H", content, offset + 4)[0]


def _runs(content, min_length):
    """(offset, text, encoding) for ASCII and UTF-16LE printable runs."""
    found = []
    start = None
    for index, byte in enumerate(content + b"\0"):
        if byte in PRINTABLE:
            start = index if start is None else start
            continue
        if start is not None and index - start >= min_length:
            found.append((start, content[start:index].decode("ascii"), "ascii"))
        start = None
    for parity in (0, 1):
        start, chars = None, []
        for index in range(parity, len(content) - 1, 2):
            low, high = content[index], content[index + 1]
            if high == 0 and low in PRINTABLE:
                start = index if start is None else start
                chars.append(chr(low))
                continue
            if start is not None and len(chars) >= min_length:
                found.append((start, "".join(chars), "utf-16le"))
            start, chars = None, []
        if start is not None and len(chars) >= min_length:
            found.append((start, "".join(chars), "utf-16le"))
    return sorted(found)


def describe(content, parameters=None):
    """The description the model receives: no file name, path or hash of the content's origin."""
    parameters = dict(DEFAULT_PARAMETERS if parameters is None else parameters)
    if (set(parameters) != set(DEFAULT_PARAMETERS) or type(parameters["min_length"]) is not int
            or parameters["min_length"] < 1 or type(parameters["max_characters"]) is not int
            or parameters["max_characters"] < 1 or parameters["encodings"] != DEFAULT_PARAMETERS["encodings"]
            or parameters["order"] != "file_offset"):
        raise ValueError("Unsupported description parameters")
    machine = pe_machine(content)
    runs = _runs(content, parameters["min_length"])
    seen, unique = set(), []
    for _, text, encoding in runs:
        if (text, encoding) not in seen:
            seen.add((text, encoding))
            unique.append({"text": text, "encoding": encoding})
    provided, used = [], 0
    for item in unique:
        if used + len(item["text"]) > parameters["max_characters"]:
            break
        provided.append(item)
        used += len(item["text"])
    return {"schema": 1, "kind": "pe_description", "sample_sha256": hashlib.sha256(content).hexdigest(),
            "format": "PE", "machine": "0x%04x" % machine, "architecture": MACHINES.get(machine, "unknown"),
            "bytes": len(content), "parameters": parameters,
            "parameters_sha256": hashlib.sha256(json.dumps(parameters, sort_keys=True).encode()).hexdigest(),
            "strings": provided,
            "counts": {"found": len(runs), "duplicates_removed": len(runs) - len(unique),
                       "provided": len(provided), "omitted_by_limit": len(unique) - len(provided)}}


# R2 · Static rule checks ------------------------------------------------------------

def _unescape(raw):
    out, index = [], 0
    while index < len(raw):
        char = raw[index]
        if char != "\\":
            out.append(char)
            index += 1
            continue
        code = raw[index + 1:index + 2]
        if code in {'"', "\\"}:
            out.append(code)
            index += 2
        elif code in {"t", "n", "r"}:
            out.append({"t": "\t", "n": "\n", "r": "\r"}[code])
            index += 2
        elif code == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", raw[index + 2:index + 4]):
            out.append(chr(int(raw[index + 2:index + 4], 16)))
            index += 4
        else:
            raise ValueError("Unsupported escape in text string")
    return "".join(out)


def tokenize(text):
    tokens, index, n = [], 0, len(text)
    while index < n:
        char = text[index]
        if char.isspace():
            index += 1
        elif text.startswith("//", index):
            end = text.find("\n", index)
            index = n if end < 0 else end
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("Unterminated comment")
            index = end + 2
        elif char == '"':
            end = index + 1
            while end < n and text[end] != '"':
                end += 2 if text[end] == "\\" else 1
            if end >= n:
                raise ValueError("Unterminated text string")
            tokens.append(("STR", _unescape(text[index + 1:end])))
            index = end + 1
        elif char == "{" and tokens and tokens[-1] == ("OP", "="):
            end = text.find("}", index)
            if end < 0:
                raise ValueError("Unterminated hex string")
            tokens.append(("HEX", text[index:end + 1]))
            index = end + 1
        elif char == "/" and tokens and tokens[-1] == ("OP", "="):
            end = index + 1
            while end < n and text[end] != "/":
                end += 2 if text[end] == "\\" else 1
            if end >= n:
                raise ValueError("Unterminated regular expression")
            end += 1
            while end < n and text[end] in "is":
                end += 1
            tokens.append(("RE", text[index:end]))
            index = end
        elif char in "$#@!" and not text.startswith("!=", index):
            match = re.match(r"[$#@!][A-Za-z0-9_]*\*?", text[index:])
            tokens.append(("VAR", match.group(0)))
            index += len(match.group(0))
        elif not char.isascii():
            raise ValueError("Non-ASCII character outside a text string")
        elif char.isalpha() or char == "_":
            match = re.match(r"[A-Za-z_][A-Za-z0-9_.]*", text[index:])
            tokens.append(("WORD", match.group(0)))
            index += len(match.group(0))
        elif char.isdigit():
            match = re.match(r"0x[0-9A-Fa-f]+|[0-9]+(?:KB|MB)?", text[index:])
            tokens.append(("NUM", match.group(0)))
            index += len(match.group(0))
        else:
            two = text[index:index + 2]
            if two in {"==", "!=", "<=", ">=", "<<", ">>", ".."}:
                tokens.append(("OP", two))
                index += 2
            else:
                tokens.append(("OP", char))
                index += 1
    return tokens


def parse_rule(text):
    """One plain rule: name, text/hex/regex strings with modifiers, condition tokens."""
    tokens = tokenize(text)
    if not tokens or tokens[0] != ("WORD", "rule"):
        raise ValueError("Expected exactly one plain rule (no imports, includes, private or global rules)")
    if len(tokens) < 4 or tokens[1][0] != "WORD" or tokens[-1] != ("OP", "}"):
        raise ValueError("Malformed rule")
    position = 2
    if tokens[position] == ("OP", ":"):
        position += 1
        while position < len(tokens) and tokens[position][0] == "WORD":
            position += 1
    if tokens[position] != ("OP", "{"):
        raise ValueError("Malformed rule header")
    body = tokens[position + 1:-1]
    if ("WORD", "rule") in body:
        raise ValueError("Expected exactly one plain rule (no imports, includes, private or global rules)")
    sections, current = {}, None
    for index, token in enumerate(body):
        if (token[0] == "WORD" and token[1] in {"meta", "strings", "condition"}
                and index + 1 < len(body) and body[index + 1] == ("OP", ":")):
            if token[1] in sections:
                raise ValueError("Repeated rule section: " + token[1])
            current = token[1]
            sections[current] = []
            continue
        if current is None:
            raise ValueError("Rule body must start with a section")
        sections[current].append(token)
    for name in sections:
        if sections[name] and sections[name][0] == ("OP", ":"):
            sections[name] = sections[name][1:]
    if "condition" not in sections or not sections["condition"]:
        raise ValueError("A rule needs a condition")
    strings, items = {}, sections.get("strings", [])
    index = 0
    while index < len(items):
        if items[index][0] != "VAR" or index + 2 >= len(items) or items[index + 1] != ("OP", "="):
            raise ValueError("Malformed string definition")
        name, kind, value = items[index][1], items[index + 2][0], items[index + 2][1]
        if name in strings or not name.startswith("$") or name.endswith("*"):
            raise ValueError("Duplicate or invalid string identifier: " + name)
        index += 3
        modifiers = []
        while index < len(items) and items[index][0] == "WORD":
            modifiers.append(items[index][1])
            index += 1
        if index < len(items) and items[index][0] != "VAR":
            raise ValueError("Unsupported string modifier syntax: " + name)
        strings[name] = {"type": {"STR": "text", "HEX": "hex", "RE": "regex"}.get(kind), "value": value,
                         "modifiers": modifiers}
        if strings[name]["type"] is None:
            raise ValueError("Malformed string definition: " + name)
    return {"name": tokens[1][1], "strings": strings, "condition": sections["condition"]}


def static_check(text, description):
    """Feature provenance and forbidden constructs; no YARA run needed."""
    try:
        rule = parse_rule(text)
    except ValueError as exc:
        return {"status": "REJECTED_FORBIDDEN", "details": [str(exc)]}
    details, forbidden = [], []
    for token in rule["condition"]:
        if token[0] == "WORD" and token[1] not in CONDITION_WORDS:
            forbidden.append("condition uses " + token[1])
        elif token[0] == "OP" and token[1] not in CONDITION_OPS:
            forbidden.append("condition operator " + token[1])
        elif token[0] == "VAR":
            stem = "$" + token[1][1:]
            if stem not in {"$", "$*"} and not (stem.endswith("*") and any(
                    s.startswith(stem[:-1]) for s in rule["strings"])) and stem not in rule["strings"]:
                forbidden.append("condition refers to undefined " + token[1])
        elif token[0] in {"STR", "HEX", "RE"}:
            forbidden.append("condition contains a literal pattern")
    if not rule["strings"]:
        forbidden.append("rule searches for no string from the description")
    if forbidden:
        return {"status": "REJECTED_FORBIDDEN", "details": forbidden}
    provided = {"ascii": [s["text"] for s in description["strings"] if s["encoding"] == "ascii"],
                "utf-16le": [s["text"] for s in description["strings"] if s["encoding"] == "utf-16le"]}
    for name, item in rule["strings"].items():
        if item["type"] != "text":
            details.append(name + ": " + item["type"] + " pattern cannot be traced to the description")
            continue
        unknown = set(item["modifiers"]) - TEXT_MODIFIERS
        if unknown:
            details.append(name + ": unsupported modifier " + ", ".join(sorted(unknown)))
            continue
        # YARA searches ASCII unless `wide` is given; `ascii wide` searches both.
        encodings = [e for e, flag in (("ascii", "ascii"), ("utf-16le", "wide"))
                     if flag in item["modifiers"]] or ["ascii"]
        fold = "nocase" in item["modifiers"]
        needle = item["value"].casefold() if fold else item["value"]
        # Every encoding YARA will search must hold the feature in the description.
        missing = [encoding for encoding in encodings
                   if not needle or not any(needle in (text.casefold() if fold else text)
                                            for text in provided[encoding])]
        if missing:
            details.append(name + ": not found in the description as " + ", ".join(missing))
    if details:
        return {"status": "REJECTED_FEATURE_NOT_IN_DESCRIPTION", "details": details}
    return {"status": "PASSED", "rule_name": rule["name"], "details": []}


# R4 · Calibration-only guard ----------------------------------------------------------

def _candidates(samples):
    return sorted(key for key, row in samples.items()
                  if row["split"] == "calibration" and row["kind"] in {"original", "variant"}
                  and not row["holdout"] and aegis.eligible(row, samples))


def rule_targets(samples, av):
    """Calibration malicious files the AV did not detect: the only rule targets."""
    return [key for key in _candidates(samples) if av.get(key) is False]


def unknown_targets(samples, av):
    """Candidates without a valid AV decision; only True and False are valid."""
    return [key for key in _candidates(samples) if type(av.get(key)) is not bool]


def _description_sha256(description):
    return hashlib.sha256(json.dumps(description, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()


def _sample_bytes(samples, key, workspace, collection):
    return aegis.sample_file(samples[key]["path"], workspace, collection).read_bytes()


def rule_package(samples, av, target_id, workspace, collection=None, parameters=None):
    """What a rule-generation session may receive: one calibration target's description.

    The description is computed here from the target's bytes, so the package
    cannot carry an edited description.
    """
    if target_id not in rule_targets(samples, av):
        raise ValueError("Rule targets must be undetected, eligible, non-held-out calibration files: " + target_id)
    content = _sample_bytes(samples, target_id, workspace, collection)
    if hashlib.sha256(content).hexdigest() != samples[target_id]["sha256"]:
        raise ValueError("Target file changed since registration: " + target_id)
    description = describe(content, parameters)
    return {"schema": 1, "kind": "rule_request", "target_id": target_id, "description": description,
            "description_sha256": _description_sha256(description)}


MATCH_STATUSES = {"MATCHED", "NOT_MATCHED", "ERROR"}
RESULT_FIELDS = {"rule_sha256", "compiled", "compile_errors", "matches"}


def validate_results(samples, results):
    """One check for both interfaces: a malformed record is an input error.

    Calibration responses only, never a held-out variant's; each bound to the
    checked file. Exactly the fields rule_sha256, compiled, compile_errors and
    matches; `compiled` is True, False or an explicit None (no outcome recorded).
    """
    if (not isinstance(results, dict) or set(results) != RESULT_FIELDS
            or not isinstance(results.get("rule_sha256"), str)
            or not aegis.SHA256.fullmatch(results["rule_sha256"])
            or results.get("compiled") not in (True, False, None) or type(results.get("compiled")) not in (bool, type(None))
            or not isinstance(results.get("compile_errors"), list)
            or not all(isinstance(e, str) for e in results["compile_errors"])
            or not isinstance(results.get("matches"), dict)):
        raise ValueError("Invalid YARA results record")
    for key, value in results["matches"].items():
        row = samples.get(key)
        if row is None or row["split"] != "calibration":
            raise ValueError("Rule acceptance may use calibration responses only: " + str(key))
        if row["holdout"]:
            raise ValueError("Held-out variant responses are not used for rules: " + key)
        if not isinstance(value, dict) or set(value) != {"status", "sha256"} or value["sha256"] != row["sha256"]:
            raise ValueError("YARA response is not bound to the registered file: " + key)
        if not isinstance(value["status"], str) or value["status"] not in MATCH_STATUSES:
            raise ValueError("Invalid YARA response status: " + key)


def repair_feedback(samples, results):
    """Repair prompts may carry compile errors and calibration check responses only."""
    validate_results(samples, results)
    return {"compile_errors": list(results["compile_errors"]),
            "matches": {key: value["status"] for key, value in results["matches"].items()}}


# R2 · Acceptance from recorded YARA results ---------------------------------------------

def group_files(samples, target_id):
    target = samples[target_id]
    return sorted(key for key, row in samples.items()
                  if key != target_id and row["project_id"] == target["project_id"]
                  and row["kind"] in {"original", "variant"} and not row["holdout"]
                  and aegis.eligible(row, samples))


def accept_rule(text, package, samples, av, results, workspace, collection=None):
    """Decide acceptance of `text` for the request `package`.

    `results` = {"rule_sha256", "compiled", "compile_errors", "matches": {id: {"status", "sha256"}}}
    must name this rule text; every response must name the file it checked.
    """
    target_id = package.get("target_id")
    fresh = rule_package(samples, av, target_id, workspace, collection, package["description"]["parameters"])
    if fresh != package:
        raise ValueError("Request package does not match the target's current description")
    description = package["description"]
    rule_sha = hashlib.sha256(text.encode("utf-8")).hexdigest()
    validate_results(samples, results)
    if results["rule_sha256"] != rule_sha:
        raise ValueError("YARA results belong to a different rule text")
    decision = {"target_id": target_id, "rule_sha256": rule_sha, "description_sha256": package["description_sha256"]}
    compiled = results["compiled"]
    if compiled is not True:
        status = "INCOMPLETE" if compiled is None else "REJECTED_COMPILE"
        return {**decision, "status": status, "accepted": False, "group_condition": None,
                "details": list(results["compile_errors"]) if compiled is False else ["compile outcome not recorded"]}
    static = static_check(text, description)
    if static["status"] != "PASSED":
        return {**decision, "status": static["status"], "accepted": False, "group_condition": None,
                "details": static["details"]}
    matches = {key: VALID_MATCH.get(value["status"]) for key, value in results["matches"].items()}
    group = group_files(samples, target_id)
    benign = sorted(key for key, row in samples.items() if row["split"] == "calibration" and row["kind"] == "benign")
    required = [target_id] + group + benign
    missing = [key for key in required if matches.get(key) is None]
    group_condition = "APPLIED" if group else "NOT_APPLICABLE"
    base = {**decision, "rule_name": static["rule_name"], "group_condition": group_condition,
            "checked": {"group": group, "benign": benign}}
    if missing:
        return {**base, "status": "INCOMPLETE", "accepted": False, "details": ["missing or invalid: " + ", ".join(missing)]}
    if not matches[target_id]:
        return {**base, "status": "REJECTED_NO_TARGET_MATCH", "accepted": False, "details": []}
    if group and not any(matches[key] for key in group):
        return {**base, "status": "REJECTED_NO_GROUP_MATCH", "accepted": False, "details": []}
    false_positives = [key for key in benign if matches[key]]
    if false_positives:
        return {**base, "status": "REJECTED_FALSE_POSITIVE", "accepted": False, "details": false_positives}
    return {**base, "status": "ACCEPTED", "accepted": True, "details": []}


# R3 · Freezing ------------------------------------------------------------------------

def freeze(rules, decisions, samples, av, yara_version):
    """Combine accepted rules into one frozen set.

    `rules`: {rule_id: final rule text}; `decisions`: {rule_id: accept_rule result}.
    Targets come from the calibration AV responses. Each target has at most one
    final decision. A missing AV response, a target without a final decision,
    or an INCOMPLETE decision makes the set FAILED: rule preparation did not finish.
    """
    targets = rule_targets(samples, av)
    unknown = unknown_targets(samples, av)
    if set(rules) != set(decisions):
        raise ValueError("Every rule needs exactly one decision")
    decided_targets = [d["target_id"] for d in decisions.values()]
    if len(decided_targets) != len(set(decided_targets)) or not set(decided_targets) <= set(targets):
        raise ValueError("Each listed target has at most one final rule decision")
    for rule_id, decision in decisions.items():
        if decision["rule_sha256"] != hashlib.sha256(rules[rule_id].encode("utf-8")).hexdigest():
            raise ValueError("Decision does not belong to this rule text: " + rule_id)
        if (decision.get("status") not in DECISION_STATUSES or type(decision.get("accepted")) is not bool
                or decision["accepted"] != (decision["status"] == "ACCEPTED")):
            raise ValueError("Decision status and acceptance disagree: " + rule_id)
    decided = {d["target_id"] for d in decisions.values() if d["status"] != "INCOMPLETE"}
    incomplete = sorted(rule_id for rule_id, d in decisions.items() if d["status"] == "INCOMPLETE")
    undecided = sorted(set(targets) - decided)
    accepted = sorted(rule_id for rule_id, d in decisions.items() if d["accepted"])
    names = [decisions[rule_id]["rule_name"] for rule_id in accepted]
    if len(names) != len(set(names)):
        raise ValueError("Accepted rules must have distinct rule names")
    text = "".join(rules[rule_id].rstrip("\n") + "\n\n" for rule_id in accepted)
    if unknown:
        status, reason = "FAILED", "AV_RESPONSES_INCOMPLETE"
    elif incomplete or undecided:
        status, reason = "FAILED", "INCOMPLETE_RULE_CHECKS"
    elif not targets:
        status, reason = "EMPTY", "AV_DETECTED_ALL_CALIBRATION_FILES"
    elif not accepted:
        status, reason = "EMPTY", "NO_RULE_ACCEPTED"
    else:
        status, reason = "FROZEN", None
    return text, {"schema": 1, "kind": "ruleset_freeze", "status": status, "reason": reason,
                  "frozen_at_utc": datetime.now(timezone.utc).isoformat(), "yara_version": yara_version,
                  "ruleset_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest() if status == "FROZEN" else None,
                  "targets": targets, "unknown_av_targets": unknown, "undecided_targets": undecided,
                  "incomplete_rules": incomplete,
                  "rules": [{"rule_id": rule_id, "target_id": d["target_id"], "status": d["status"],
                             "rule_sha256": d["rule_sha256"], "description_sha256": d["description_sha256"]}
                            for rule_id, d in sorted(decisions.items())]}


def verify_frozen(ruleset_path, record):
    """A later change to a frozen rule set is detected by its hash."""
    if record.get("kind") != "ruleset_freeze" or record.get("status") != "FROZEN":
        raise ValueError("Only a FROZEN record has a rule-set file")
    if aegis.digest(Path(ruleset_path)) != record["ruleset_sha256"]:
        raise ValueError("Frozen rule set changed after freezing")
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("describe", help="write the model-facing description of one PE file")
    command.add_argument("--file", required=True)
    command.add_argument("--output", required=True, help="new file outside the public repository")
    args = parser.parse_args(argv)
    try:
        content = aegis.external_path(args.file).read_bytes()
        value = describe(content)
        with aegis.external_path(args.output).open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    except (ValueError, OSError) as exc:
        print("Rule workflow failed: " + str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
