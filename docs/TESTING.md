# Testing

Automated tests validate the publication boundary and control-stage accounting:
file identity, lineage and split separation, control copies, holdout selection,
functionality records, missing responses, shared comparison denominators,
recall/FPR/precision/F1, missing-response bounds and detection-loss arithmetic,
each checked against hand-counted synthetic cases.
They use generated inert text and synthetic labels/responses, not malware.
The complete suite imports Tkinter for the reused UI/worker classes; it does not
create GUI windows. Use a Python installation with Tkinter support. GitHub CI
installs `python3-tk` on Ubuntu and the matching `python-tk` formula on macOS,
then runs the same suite on both platforms, checks JavaScript syntax and compiles
the native host on macOS. These are code checks, not a live Fusion experiment.

```sh
python3 -m unittest discover -s tests -v
```

Check the exact indexed files before committing:

```sh
python3 scripts/check_repository.py
```

Check all reachable committed trees before publishing:

```sh
python3 scripts/check_repository.py --history
```

The checker rejects unexpected paths, symlinks and submodules, non-text files,
oversized files, and recognizable credential or personal-path patterns. It reads
Git's stored blobs, so a different working copy does not hide staged content.
The commit hook checks the index; the push hook also checks committed history.
These checks supplement review; an allowed path does not establish that a file
is suitable for publication.

Future experiment reports must identify the code revision, tool and model
versions, configuration, data-selection procedure, evaluation split, metrics,
and failed cases. Add reviewed reproduction material by explicit filename.
Raw data, raw model exchanges, and machine-specific logs are not test fixtures.

## Control accounting demonstration

Requires Python 3.9 or newer, with no third-party packages. From the repository
root, choose a **new directory outside this repository**:

```sh
python3 scripts/run_control_demo.py --output ../aegis-control-demo
```

This creates six inert UTF-8 text files, their SHA-256 manifest, a control-only
configuration, synthetic functionality records, simulated AV/YARA observation
rows and a JSON accounting report. Four rows are benign controls (one for
calibration, three for evaluation); two carry a synthetic `original` label, one
per split, so that the supplementation scenario has an independent group in each
split. One evaluation row has a deliberately invented YARA positive and another
an unknown response. These exercise false-positive accounting, additional
detections and incomplete comparisons. They are not observed detector behaviour.
Every report has `experiment_results: false`. Demonstrations created before
manifest schema 2 (2026-11-27) lack the new manifest columns and
`yara.ruleset_status`; recreate them in a new directory.

Recalculate an existing control without overwriting its report:

```sh
python3 src/aegis.py --config ../aegis-control-demo/run.json \
  --manifest ../aegis-control-demo/manifest.csv \
  --observations ../aegis-control-demo/observations.csv
```

The manifest records provenance, source version, label basis, format,
architecture, project, family, parent, split, generation order, holdout flag,
functionality status, card hash and evaluator record. Kinds are `original`,
`variant`, `control_copy` and `benign`. Related files must share a project ID.
Distinct originals from a known family may occupy different splits; identifying
close provenance requires human review. Paths are relative to the configured
external workspace, or `collection:<relative>` inside an optional read-only
`collection_root`. Changed files, cross-split projects/parents, duplicate
observations and mixed run/tool-state IDs are rejected. A tool-state ID must
refer to one fixed configuration. The demonstration uses `mode: control`;
inert VM/scanner control reports do not become research runs, and research
mode refuses the demonstration's synthetic functionality records.

Lineage rules:

- A duplicate SHA-256 is accepted only for one `control_copy` and its own
  original (a byte-identical recompilation). Each original has at most one
  control copy; it carries no functionality outcome of its own.
- Every variant has a positive `generation_order`, unique in its project group.
- `holdout` must mark exactly the last eligible calibration variant of every
  project group with at least two eligible variants, and nothing else.
- `PASS`, `FAIL` and `INCONCLUSIVE` need a card hash and a workspace-relative
  evaluator record whose sample hash, card hash and status match the row.
  A variant uses its original's card. Catalogue eligibility is not functionality.

Metrics, with each rate given as numerator and denominator:

- `ERROR`, `INCONCLUSIVE`, `NOT_RUN` and absent observations stay unknown.
  An AV `DETECTED` observation names `REALTIME` or `CUSTOM_SCAN` in
  `detected_by`; every row lists it as `av_detected_by`.
- The supplementation scenario uses eligible evaluation files only. AV, YARA
  and their OR are compared on files where **both** AV and YARA responses are
  valid; others are listed in `incomplete_ids`. Each tool reports TP, FN, FP,
  TN, recall, FPR, precision and F1, plus recall separately for originals and
  variants. Additional detections and false positives need AV=0 and YARA=1.
- Recall and FPR bounds use all eligible evaluation files, reading every
  missing response first as not detected and then as detected. Precision and
  F1 have no such bounds.
- Detection loss covers both splits. A variant counts only if it and its
  original passed functionality, the original was detected, its control copy
  was detected (a byte-identical copy relies on the original's response, and
  a valid contrary copy response is a conflict), and the variant's own AV
  response is valid. Excluded variants are counted by reason.
- The supplementation scenario is evaluated only when both splits contain at
  least one original project group that passed functionality; otherwise it is
  `NOT_EVALUATED` with `INDEPENDENT_GROUPS_MISSING`.
- `yara.ruleset_status` is `FROZEN`, `EMPTY` (no YARA observations; Y=0 for all
  files) or `FAILED` (supplementation and holdout results are not evaluated).
- Holdout variants are reported separately for YARA and never enter
  supplementation metrics. Every row's inclusion reason is listed under `rows`.

Write CSV tables and a LaTeX fragment to a new external directory:

```sh
python3 src/aegis.py --config ../aegis-control-demo/run.json \
  --manifest ../aegis-control-demo/manifest.csv \
  --observations ../aegis-control-demo/observations.csv \
  --output ../aegis-control-report.json --tables ../aegis-control-tables
```

`src/dataset_plan.py` assigns original project groups alternately (calibration
first) by acceptance order. It allocates whole benign project groups to the
planned calibration/evaluation quotas (10/50 by default): the allocation assigns
as many files as the plan allows, then keeps the fill ratios most even, then
follows acceptance order. Neither step reads detector responses.
`build-manifest` requires both frozen records (`--assignment`). Each record
must group objects by their catalogue project and must equal what its rule
gives for its own acceptance order. The command rejects a catalogue whose
selection differs from the records or contains unrecorded objects,
converts selected originals and benign files, and appends only variant or
control-copy rows of selected originals from a separate manifest-format CSV.

The accounting tool reads files for hashing and never executes them. It does not generate
modifications or rules, freeze research data, verify functional behaviour, run
Defender/YARA, or establish laboratory readiness. Simulation checks are separate
from the planned research sample and cannot complete the research protocol.

## Rule preparation without a model

`src/rule_workflow.py` prepares and judges rule candidates without running a
model, a sample or YARA. It reads file bytes on the host and decides from
YARA compile/match outcomes that the laboratory records.

- `describe` writes the model-facing description of one PE file: format,
  machine, size and printable ASCII/UTF-16LE strings in file order, with a
  minimum length (5), duplicates removed, a character budget (12 000) keeping
  the first strings, and counts of found, removed, provided and omitted
  strings. The parameters and their hash are part of the description; no
  file name or path is included.
- A candidate must be one plain rule. Its text strings (with `ascii`, `wide`,
  `nocase`, `fullword` only) must occur in the description in **every**
  encoding YARA will search (`ascii wide` needs both); hex strings, regular expressions and other modifiers cannot be
  traced and are rejected as `REJECTED_FEATURE_NOT_IN_DESCRIPTION`. Imports,
  includes, private/global rules, external variables such as `filename`,
  module fields, byte-offset functions, undefined string references and
  non-ASCII identifiers are `REJECTED_FORBIDDEN`. Only `filesize` and string references are allowed in
  conditions.
- `rule_package` computes the description from the target's registered bytes;
  acceptance recomputes it and refuses an edited package. The YARA results
  record must name the SHA-256 of the exact rule text, and every match
  response must name the SHA-256 of the file it checked. Acceptance and
  repair feedback share one record check: exactly the fields `rule_sha256`,
  `compiled`, `compile_errors` and `matches`; `compiled` is true, false or an
  explicit null (not recorded), `compile_errors` a list of strings, and each status
  `MATCHED`, `NOT_MATCHED` or `ERROR`; any other record is refused as an
  input error.
- Acceptance then needs: compiled; a match on its own file; a match on at
  least one other eligible original or non-held-out variant of the same group
  (`NOT_APPLICABLE` when the group has none; control copies never count); no
  match on any calibration benign file. A missing or `ERROR` response makes
  the decision `INCOMPLETE`.
- Rule targets are eligible, non-held-out calibration originals and variants
  that the AV did not detect. Packages, acceptance and repair feedback refuse
  any evaluation file or response and any held-out variant's response.
- `freeze` combines the accepted final rules into one rule set and records its
  SHA-256, YARA version and every decision. Targets are derived from the
  calibration AV responses, where only `true` and `false` are valid; a
  decision whose `accepted` flag disagrees with its status is refused. The
  status is `FROZEN`, `EMPTY` (every candidate
  detected, or no accepted rule) or `FAILED` (a candidate without a valid AV
  response, a target without a final decision, or an `INCOMPLETE` one). `verify_frozen` detects later edits.

Tests use generated header-only PE stubs (a DOS/PE header and inert marker
text, no sections or code) in temporary directories and recorded results.

## Detector checks of selected files and the accounting bridge

`src/guest_research_scan.py` holds the guest-side decisions; files are
scanned, never executed. Tests drive it with a fake Windows system, so no
Defender, YARA or sample runs.

- AV, state A: Defender and real-time protection must be on, otherwise
  `ERROR`/`STATE_MISMATCH`. One file per run. After the fixed waiting period,
  a threat-history resource or the `Path` field of event 1116/1117 that
  equals the file's path, recorded at or after the check started, gives
  `DETECTED` with `detected_by: REALTIME`. Every such record's detection
  source must fit the label (`Real-Time Protection`, threat source type 3 for
  `REALTIME`; `User` or `System`, types 1–2 for `CUSTOM_SCAN`); a contrary or
  missing source makes the outcome `INCONCLUSIVE`. These source values are to
  be confirmed with the laboratory's EICAR controls. Older records and other paths do not count; an exact-path record
  without a readable time makes the history unknown. Otherwise a missing or
  changed file is `INCONCLUSIVE`, and a custom scan runs; a record dated after
  its start gives `CUSTOM_SCAN`, but only when the real-time lookup was
  readable. `NOT_DETECTED` needs exit code 0, unchanged bytes and readable
  history; the exit code alone never decides. Any valid response also needs
  protection on and unchanged product, engine and signature versions before
  and after, otherwise it becomes `INCONCLUSIVE`. A scan timeout is `ERROR`.
- YARA, state F: real-time protection must be off, and `--version` must exit
  0 and print a version, otherwise every file is `ERROR`. The YARA executable
  and the frozen rule set must match their pinned hashes; if either is missing
  or differs, the check refuses to start and produces no record. Each
  file is `MATCHED` (with rule names), `NOT_MATCHED`, `ERROR` (timeout, exit
  code, unexpected output, unreadable or changed file) or `NOT_RUN` (missing
  input); one file's error never stops the series.
- Candidate rules: a compile check on an empty file, then per-file matches,
  returned as the four-field record that `rule_workflow.accept_rule` expects.
  Only diagnostics that point into the candidate file make `compiled: false`;
  a technical failure while running YARA leaves `compiled: null`, so
  acceptance stays `INCOMPLETE`. A missing or different pinned YARA
  executable is refused before anything runs, and no record is produced.

`src/scan_bridge.py` validates stored reports and writes the observation CSV
for `src/aegis.py`, with each report as evidence. YARA `MATCHED` and
`NOT_MATCHED` become `DETECTED` and `NOT_DETECTED`; `ERROR` and `NOT_RUN`
stay unknown. The bridge re-checks each valid response against its evidence:
an AV response needs state A and unchanged versions before and after, at
least one real-time or custom-scan record whose sources fit the label, and for a negative a completed scan
of unchanged bytes with readable history; a YARA response needs state F and a
recorded version of the form `x.y.z`, and an incomplete one needs its reason. Tool-state IDs are derived from the Defender product, engine
and signature versions and from the YARA version, executable and rule-set
hashes; a series whose state changes is refused. Observations now carry
`detected_by`, required for AV detections and forbidden otherwise.
Deploying these checks into the VM, one AV file per restore cycle, is a
separate laboratory step.

## Research-mode accounting, the execution guard and segments

`mode: research` (see `config/research.example.json`) accepts only evidence
from detector reports. On top of the control checks it requires:

- a protocol version and `yara.freeze_record` of this run; the record's
  status and rule-set hash must equal `yara.ruleset_status` and
  `yara.ruleset_sha256`, and a FROZEN record's `frozen.yar` must still match
  its hash;
- `series`: the run's complete, ordered list of detector reports kept by the
  laboratory (`kind: detector_series`), and `av.segment_id` /
  `yara.segment_id` naming one segment of it per tool; the evidence must be
  exactly that segment's reports, so A → B → A cannot be joined and a named
  segment cannot be dropped by listing no rows for its tool;
- no synthetic functionality record;
- every observation's evidence to be a validated AV or YARA report, and the
  rows of each report to be exactly the rows `scan_bridge` derives from it;
- YARA evidence produced with the frozen rule set and the YARA version named
  in the freeze record;
- AV checks of evaluation variants and benign files, and every YARA check
  with the frozen rule set, to have started after the freeze time
  (originals' baseline and calibration AV checks may precede it).

Supplementation with zero paired records is `NOT_EVALUATED` /
`NO_PAIRED_RECORDS` in every mode.

A tool with no reports, rows or named segment in the run (YARA for an EMPTY
or FAILED rule set) may have `state_id: null` in research mode; control mode
needs both state IDs. The report then names `mode: research`,
`experiment_results: true` and the tool versions recorded in the evidence.

Freeze records name their run. `src/run_guard.py` stores them without
overwriting, refuses a record of another run, and builds guest requests only
in an allowed order: a one-file AV request for an evaluation
variant or benign file needs a final freeze record (FROZEN, EMPTY or FAILED)
and carries its hash; a YARA request needs a FROZEN record. The accounting
order check compares guest and host clock times, so it complements this
guard rather than replacing it.

`scan_bridge.py --segments` lists, per tool, consecutive reports of one run
that share one tool state in finish-time order, each with a segment ID over
the run, the state and the ordered report hashes; reports of another run are
refused. A configuration change starts a new
segment; each segment is accounted as its own run. How many records make a
segment comparable is a protocol decision recorded outside this code.

## Native WebKit desktop

`src/mac_app.m` loads exactly `src/desktop_ui/index.html` and its two reviewed
local assets. Its navigation delegate rejects other document destinations;
only the main local document can use the fixed native bridge. The content
security policy permits local scripts/styles, blocks network connections and
frames, and allows no inline script or style. The native view uses a temporary
WebKit data store. Credentials are submitted through in-memory process pipes,
not command-line arguments, configuration files or a network listener.

The compiled local app reads `AegisProjectRoot`, `AegisDataRoot`,
`AegisLabStatus` and `AegisPython` from its private bundle configuration.
`AegisHostLog` is optional and contains only host diagnostics. Compiled bundles,
actual paths and raw outputs remain outside this repository. Building uses the
installed macOS Cocoa/WebKit frameworks, without third-party web dependencies.
The Python bridge can be checked independently using newline-delimited JSON on
stdin/stdout with `--workspace` and `--lab-status` arguments. `refresh` is
read-only; all other commands use an explicit operation allowlist.

Tests exercise result-key ownership, selected-object plan/export identity,
unknown commands, missing selections, private snapshot contents and the inherited
VM worker's busy/restore/environment gates. The WebKit bridge reuses the same
serialized VM worker as the Tk interface. A new view is not evidence of a fresh
VM/scanner/restore experiment; each live check must be recorded separately.

Manual UI verification should include the fixed home viewport, scrollable
results with preserved selection position, filters, native file dialogs, guide
stages, reduced motion, the laboratory pane, close/reopen and minimum window size.
Keyboard navigation and the ordinary arrow cursor should remain available.

### Build a local bundle from this checkout

On macOS, use an installed Apple command-line compiler and a Python 3.9+ build
with Tkinter (the reused VM worker imports the legacy UI module). No third-party
Python packages are needed. From this repository root, the following creates a
**new sibling directory**; it refuses to reuse an existing one. It does not start
Fusion, create a VM or install vendor tools.

```sh
python3 - <<'PY'
from pathlib import Path
import plistlib
import subprocess
import sys

project = Path.cwd().resolve()
assert (project / 'src/mac_app.m').is_file(), 'Run from the repository root'
output = project.parent / 'aegis-desktop-local'
output.mkdir(mode=0o700, exist_ok=False)
app = output / 'Project Aegis.app'
contents = app / 'Contents'
binary = contents / 'MacOS/aegis-control'
binary.parent.mkdir(parents=True)
status = output / 'lab-status.json'
status.write_text('{}\n', encoding='utf-8')
info = {
    'CFBundleExecutable': 'aegis-control',
    'CFBundleIdentifier': 'local.project-aegis.control',
    'CFBundleName': 'Project Aegis',
    'CFBundlePackageType': 'APPL',
    'CFBundleShortVersionString': '0.7',
    'CFBundleVersion': '0.7',
    'NSHighResolutionCapable': True,
    'AegisProjectRoot': str(project),
    'AegisDataRoot': str(output / 'panel'),
    'AegisLabStatus': str(status),
    'AegisPython': sys.executable,
    'AegisHostLog': str(output / 'desktop-host.log'),
}
(contents / 'Info.plist').write_bytes(plistlib.dumps(info))
subprocess.run(['clang', '-fobjc-arc', str(project / 'src/mac_app.m'),
                '-framework', 'Cocoa', '-framework', 'WebKit', '-o', str(binary)], check=True)
print(app)
PY
open '../aegis-desktop-local/Project Aegis.app'
```

The bundle references this checkout and the chosen Python installation; keep both
in place. `{}` is sufficient for inert catalogue/result exploration. VM/scanner
setup needs private configuration described below. To use a locally owned icon,
place an `.icns` file in `Contents/Resources` and set `CFBundleIconFile` to its
filename in the local plist; the host applies it to the running app's Dock icon.
Do not put actual local paths, passwords, vendor files or that generated bundle
in the public repository.

## Legacy Tk preparation panel

Requires Python with Tkinter. Windows/macOS packages from Python.org include
Tkinter; some Linux distributions package it separately. No pip packages are
needed. Use another external working directory, separate from the simulated
accounting demonstration:

```sh
python3 src/control_app.py --workspace ../aegis-panel
```

The panel's three fixed controls are inert UTF-8 text. Selecting a subset makes
only those working copies, verifies hashes, and performs a real literal-marker
check. Marker findings are not AV or YARA responses. Results are flushed to
disk before the owned work directory is cleaned. Sources and results remain.
Failed result storage or cleanup produces a recovery record and blocks the next
control cycle. Tests exercise these failures and rejection of modified sources,
symlinks, invalid selections and unowned cleanup paths.

The native panel shows four main sections: workspace, files, results and help.
Its local vector components use installed fonts, rounded surfaces, cancellable
button feedback and short page entrances. Decorative motion stops after a
bounded entrance and when leaving the overview; the View menu can reduce motion
for the open session. Custom buttons retain keyboard activation and reject
disabled actions, including a transition to disabled between press and release.
An Advanced group contains VM/storage, local controls and settings; the native
section menu also reaches all seven pages. The Windows session window keeps
credentials separate from actions and hides setup/recovery details until needed.
Intermediate transfer/scanner reports keep actions locked until restore finishes;
refreshing an unsafe environment revokes previously available test actions.
Use the local demo catalogue to explore selection,
selected-object hashing and plan creation without a disk or research data.
The demo is generated in a separate sibling directory, uses only the three inert
texts, and is labelled `DEMO_ONLY`. It is not part of the research sample.

Optional `--lab-status` reads a trusted local preparation record. Supported host
configuration fields include `vm_bundle`, `disk_image`, `installer_path` and
`mac_lab_budget_bytes`. Verified preparation flags remain records, not live tests.
On macOS, `vmrun list` checks runtime membership; a saved-state file distinguishes
a non-running VM with a saved state. A command failure stays unknown. VMX network
and sharing flags are configuration observations, not proof of isolation.
VM-image attachment identity is checked before reporting its free space. The
budget estimate includes reserved image capacity, the retained installer,
Fusion and runtime files; it is not a system-wide filesystem quota.

The main VM page also opens a separate Windows control window. Existing VM
encryption and dedicated local guest credentials stay in the window's process
memory and are discarded on close; the primary Microsoft account is unnecessary.
There is no saved-password feature. The panel does not format/resize storage,
change networking or protection settings, or hard-stop a VM.
Tools authentication does not unlock the visible Windows desktop. Open Fusion
and sign in there when interactive desktop access is needed; automatic desktop
unlock is not implemented. The existing encrypted startup fallback is retained.

Collection roots contain `catalog/sources.csv`, `objects.csv` and `selection.csv`.
Exact header contracts are `SOURCE_FIELDS`, `OBJECT_FIELDS` and `SELECTION_FIELDS`
in `src/control_panel.py`. All registered objects must exist; only explicitly
selected objects are read for hashing. Missing provenance, malformed rows,
duplicate identities/hashes, escaping paths, symlinks and cross-split related
projects/parents are rejected. Hash checks record mismatches without executing
files. Plans require matching current hashes, one split/protocol and selected
parents. A plan remains `PLAN_ONLY`, with no guest execution or restore claim.

Results and plans are outside the public repository. Export preserves the JSON,
adds a CSV and a hash inventory, and never overwrites an existing destination.
Spreadsheet formula prefixes are escaped. Corrupt result records are reported
without preventing other history entries from loading. Background work leaves
the interface responsive; periodic VM probes pause during native file dialogs.
Tests cover the catalogue/plan boundary, changed files/registries, result export,
demo reuse, output ownership and independent VM observations. No real malware,
AV/YARA experiment is covered by these tests. VM/scanner unit tests use native
mocks and synthetic guest storage, including failure and fresh-proof checks;
passing them alone does not establish live Windows compatibility or restoration.

## Guest preparation modules

`src/guest_control.py` implements an inert transfer-control protocol for future
Windows guest use. A new `guest-control-<32 lowercase hex characters>` directory
contains `request.json` and exactly the selected registered text controls. The
request has schema `1`, the matching `run_id`, a 64-character hexadecimal nonce,
and a `selected` list drawn from `plain`, `marker`, `unicode`. Unexpected files,
links, changed contents, malformed identities and reused run directories fail.
The Windows-only command is:

```sh
python src/guest_control.py --run-root <prepared-run-directory>
```

It persists a mutation marker and guest JSON report, leaving all working files
in place. That marker is intended for a separate restore check; its creation
does not verify restore. Reports retain `experiment_results: false`, AV/YARA
`NOT_RUN`, and `vm_restore_verified: false`. Host unit tests call its protocol
functions directly and must not be described as Windows execution evidence.
This low-level module does not itself deploy or transfer files; the optional
manager described below orchestrates those operations.

`src/fusion_vix.py` provides an initial read-only client for the native VIX
library shipped with Fusion. It opens an existing VM using a credential passed
in process memory and reads power/Tools state. It does not launch subprocesses,
log credentials or mutate guest files, VM power, networking or snapshots.
The caller must obtain the existing credential locally and discard it after
use; there is no saved-credential feature. Native mock tests check handle
cleanup, authentication failures and timeouts. They do not establish live
compatibility, guest login, transport or restore support.


The preparation modules also include `guest_media.py` and
`guest_control_app.py`: externally built inert media and a Windows Tk app that
a human launches in the guest. The generated installer launcher serializes
Python setup, and the guest app uses an OS process lock. Neither needs a Windows
account credential. The proposed small metadata channel uses VMware Tools;
its native mock tests do not verify live Fusion transport compatibility.

`fusion_control.py` adds normal guest shutdown, powered-off snapshots and
runtime metadata calls. A timeout blocks subsequent mutations. No hard-stop
operation is provided. `fusion_guest_ops.py` adds optional login as an existing
dedicated local guest account and explicit file/program operations through Tools.
`guest_environment.py` captures current Windows architecture, local accounts,
profiles, network and Defender state without changing those settings.

`vm_run_manager.py`, `vm_control_session.py` and `vm_control_ui.py` integrate
the fixed inert controls into the main panel. Local-account separation,
disconnected network/sharing observations, guest absence evidence and free space
are required before a cold baseline. The original report and transport proof are
durably stored on the host before revert. A fresh challenge and absent work and
mutation markers are required afterwards; deleting files cannot satisfy this
check. Saved sessions and interrupted cold-start phases can be resumed, with
records revalidated before use. Unknown native operation outcomes stay blocked.

Some encrypted Fusion installations reject native power-on even when the VM is
confirmed off. This is recorded as awaiting startup; the UI opens the existing VM
through Fusion and waits for its running state, Tools and a new guest response.
If Fusion does not start it, use its normal Start Up command. An attempted start
or an old response is never a completed restore. No credential is placed in
subprocess arguments, environment variables or files.

## Optional Windows scanner control

Configure `yara_executable` and `yara_sha256` in the trusted local lab record.
Obtain that Windows binary from the official YARA release and independently
verify the vendor archive digest; binaries stay outside this repository.
The control copies only its own Python modules, the reviewed
`rules/control-marker.yar`, that pinned executable and three fixed inert texts.
It records the actual YARA version, binary architecture and hashes, Defender
engine/product/signature versions and per-file responses.

Defender runs its normal custom scan without weakening protection. If the guest
process is not elevated, AV remains `NOT_RUN` and a one-off desktop launcher
requires normal Windows UAC approval. The host retrieves and validates the
atomic report, then performs an inert VM cycle and cold restore. A restart can
resume the pending result. Deferring it records `NOT_RUN`, then restores the VM.
Defender exit code zero alone does not prove a negative: stable enabled engine,
readable threat history and unchanged control bytes are also required; ambiguous
or failed observations remain unknown. These are operational controls, not
research detection results or functionality validation.

Result history validates the original guest report and accompanying identity or
transport/completion evidence. ZIP exports retain JSON, CSV, scope notes, hashes
and relevant restore proof. Live verification evidence belongs in a private
external workspace, separately from unit-test output and research results.

## ARM lab preparation and harmless PE rehearsal

`guest_lab.py` and `vm_lab_preparation.py` provide a separate fixed-control path.
The trusted local record can name `procmon_vendor_root`, an external folder with
the official `Procmon64a.exe`, `Eula.txt` and its provenance/hash record. Download
the archive from the official Microsoft Sysinternals source. A locally calculated
archive hash is for reproducibility, not a claim that Microsoft published a
matching digest. The guest additionally checks Authenticode status, signer,
version and ARM64 PE machine type before offering the tool to the operator.

The operator opens the generated preparation command, reviews the real Process
Monitor license and approves its ordinary administrator access. There is no
automatic EULA acceptance or persistent elevation task. A fresh cold baseline
then retains the prepared kit and the operator's license state. The separately
generated rehearsal launcher requires ordinary UAC approval. No protection,
network or sharing settings are weakened to make the controls pass.

The built-in signed C# compiler creates only two fixed harmless .NET AnyCPU PE
programs. Their only intended effect is a challenge-bound file in a guarded owned
directory and fixed stdout. Functionality requires exact bytes, stdout, exit zero
and a bounded runtime. Process Monitor must independently show a successful
WriteFile for that PID and exact path. PML/CSV and source/build identities remain
private evidence. Managed-PE success does not establish arbitrary native ARM64 or
x64 binary compatibility, full behavioral equivalence or complete monitoring.

YARA controls exercise a known positive, negative and deliberately invalid rule.
Defender negatives require stable observations, readable threat history and
unchanged bytes, not just exit zero. The official harmless EICAR file is created
only inside the VM and is never executed or exported. A real-time detection is
reported as such: it does not separately validate custom-scan-only positive
handling. A missing input stays NOT_RUN. Before restore, the host validates the
report and transports a bounded exact artifact inventory with SHA-256. Reports
remain immutable; later restore proof is separate. A pending job blocks the next
cycle, survives app restart and can be explicitly deferred before recovery.

Unit tests verify the file-effect criterion, timeout behavior, PID/path/event
matching and rejection of invented positives, false restore claims and escaping
artifact paths. They do not execute Windows programs or replace a live rehearsal.

## Selected catalogue byte transfer

`guest_selection.py` and `vm_selection_transfer.py` verify a frozen plan against
the currently loaded read-only catalogue, recheck source hashes and copy only
selected bytes to a unique guest directory. Limits are sixteen files, 16 MiB per
file and 64 MiB per batch, with at least 3 GiB host-volume headroom for the VM.
Files receive fixed `.bin` names and are never executed or scanned by this mode.
The Windows collector verifies its own source and manifest identities and reports
VERIFIED, MISMATCH or MISSING_INPUT. No unknown result becomes a negative scan.

The host preserves the original report before the cold restore. A separate proof
requires a fresh VM response and absence of every transferred file, manifest,
collector and guest report. Failed transfers retain recovery records and block
another transfer until restoration. Disposable fake-guest tests cover subset
selection, changed sources, missing guest input and preservation across revert;
they are not a live HDD or malware execution test.
