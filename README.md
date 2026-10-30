# Project Aegis

Research code for evaluating malware-detection robustness and the additional
coverage of AI-assisted YARA rules.

An initial control-stage accounting implementation validates file hashes,
provenance groups and split boundaries, and summarizes supplied detector statuses.
The demonstration uses inert text and explicitly simulated responses. It does
not invoke antivirus software or YARA, execute samples, or run detection experiments.

`src/mac_app.m` hosts a local WebKit desktop interface, backed by the validated
Python operations in `src/desktop_backend.py` over private process pipes.
There is no HTTP server. Navigation and document resources stay local; the page
has no network connection permission, and secrets are not passed in process
arguments. The dark workspace uses top navigation, explicit filter buttons,
independently scrolling lists and a separate result detail pane. Its guide is
organized by workflow stage; maintenance actions live in Settings. The earlier
Tk interface remains available in `src/control_app.py` for compatibility.

The host control panel provides an overview, live Fusion
runtime membership and storage checks, local inert controls, a read-only collection
catalogue, selection plans, result history and ZIP export (JSON, CSV and hashes).
An included inert catalogue lets the workflow be explored without an external disk.
Everyday navigation shows home, files, results and a staged guide. Storage,
paths and local controls are grouped in Settings; guest preparation and recovery
remain in the laboratory pane. Credentials are masked, cleared on submit and retained
only for the open session. Tools authentication does not unlock the visible
Windows desktop; interactive sign-in still takes place in Fusion.
Only selected collection objects are read for SHA-256. A frozen selection plan
can copy a bounded subset into Windows for byte verification without execution;
the collection is never written to or passed through as a whole disk.
The optional Windows control window uses
Fusion's native Tools interface and an existing dedicated local guest account.
It transfers three fixed inert texts, saves their verified report on the host,
and restores a powered-off baseline. A fresh guest challenge must confirm absent
work and mutation markers before restore is reported as verified. Encrypted VM
startup can require Fusion's normal document-opening/startup flow.

An optional scanner control invokes a locally configured, SHA-256-pinned official
Windows YARA executable and Windows Defender on the same three harmless texts.
Defender requires an ordinary user-approved elevation step. Tool versions and
unknown/error states are retained; neither literal-marker checks nor these small
scanner controls establish malware detection performance. Research-sample
execution, functionality validation, modifications, AI rule generation and the
full experiment pipeline remain unimplemented. Preparation records and VMX
configuration are distinguished from live observations and isolation claims.

An additional ARM lab preparation path deploys an externally pinned official
Process Monitor ARM64 binary, verifies its Microsoft signature inside Windows,
and locates the built-in Microsoft-signed C# compiler. The operator reviews the
actual license and approves elevation. A new cold baseline retains the approved
tool setup before a fixed benign managed-PE rehearsal. That rehearsal checks
two generated harmless programs, independent process/file observations, YARA
positive/negative/error controls and Defender controls, including the official
EICAR file without executing or exporting it. Original evidence is retrieved
before restore. This is a readiness check, not CAPE/Cuckoo installation, arbitrary
sample execution, AI generation or proof of native-PE compatibility on ARM.

The selected-byte transfer check limits a batch to sixteen files, 16 MiB per
file and 64 MiB total. Source identities, grouping and guest hashes must agree.
Missing or quarantined input is not a negative detector response. Its host report
precedes cold restoration, followed by an explicit check that transferred files
are absent. This transfer mode does not invoke scanners or execute catalogue files.

| Path | Purpose |
| --- | --- |
| `src/` | Local desktop UI, VM controls, manifest validation and result accounting |
| `tests/` | Automated tests and small synthetic fixtures |
| `config/` | Example configuration without credentials |
| `rules/` | Reviewed detection rules |
| `scripts/` | Supporting code and repository checks |
| `docs/TESTING.md` | Test commands and reproducibility requirements |

Use Python 3.9 or newer and Git to run the current checks:

```sh
python3 -m unittest discover -s tests -v
python3 scripts/check_repository.py
```

Enable the commit and push checks after cloning:

```sh
git config core.hooksPath .githooks
```

Only explicitly allowed code, configuration examples, tests, rules, and essential
test instructions belong here. New documentation paths or file types require an
explicit update to both `.gitignore` and the repository checker. Generated files,
datasets, raw experiment output, and credentials remain outside Git.

This source checkpoint is version 0.7. The compiled Mac app, its icon and private
bundle configuration, VM, Windows ISO, vendor binaries, research documents and
raw readiness evidence are not distributed here. See
[Testing and local setup](docs/TESTING.md#native-webkit-desktop) to build a local
desktop bundle. A fresh checkout can explore inert files and accounting without
a VM; VM operations require a separately prepared laboratory. This checkpoint
does not implement automatic Windows desktop unlock or research experiments.
