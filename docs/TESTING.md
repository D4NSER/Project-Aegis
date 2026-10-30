# Testing

Automated tests validate the publication boundary and control-stage accounting:
file identity, lineage and split separation, missing responses, functionality
exclusions, shared comparison denominators, and detection-loss arithmetic.
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

This creates four inert UTF-8 text files, their SHA-256 manifest, a control-only
configuration, simulated AV/YARA observation rows and a JSON accounting report.
One control is for calibration; three are for evaluation. One evaluation row has
a deliberately invented YARA positive and another an unknown response. These
exercise false-positive accounting and incomplete comparisons. They are not
observed detector behaviour. Every report has `experiment_results: false`.

Recalculate an existing control without overwriting its report:

```sh
python3 src/aegis.py --config ../aegis-control-demo/run.json \
  --manifest ../aegis-control-demo/manifest.csv \
  --observations ../aegis-control-demo/observations.csv
```

The manifest records provenance, source version, label basis, format,
architecture, project, family, parent, split and functionality status. Related
files must share a project ID. Distinct originals from a known family may occupy
different splits; identifying close provenance requires human review.
All files and evidence paths are relative to the configured external workspace.
Duplicate hashes, changed files, cross-split projects/parents, duplicate
observations and mixed run/tool-state IDs are rejected. A tool-state ID must
refer to one fixed configuration. This accounting demonstration supports only
`mode: control`; separate inert VM/scanner reports do not become research runs.

`ERROR`, `INCONCLUSIVE`, `NOT_RUN`, and absent observations stay unknown.
`true OR unknown` is true; `false OR unknown` is unknown. AV versus combined
rates use the same subset where AV and the combined decision are known.
Additional positives require a known AV negative and YARA positive. Originals
and variants require `PASS`; a variant also requires its original to pass.
Detection loss includes only known variant AV responses whose original was
detected, independently of YARA completeness. Empty denominators yield `null`.

The accounting tool reads files for hashing and never executes them. It does not generate
modifications or rules, freeze research data, verify functional behaviour, run
Defender/YARA, or establish laboratory readiness. Simulation checks are separate
from the planned research sample and cannot complete the research protocol.

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
