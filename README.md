# Project Aegis

Research code for evaluating malware-detection robustness and the additional
coverage of AI-assisted YARA rules.

The experimental implementation is in preparation. The current code enforces
the repository's publication boundary and tests that boundary; it does not yet
run detection experiments.

| Path | Purpose |
| --- | --- |
| `src/` | Experiment implementation |
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
