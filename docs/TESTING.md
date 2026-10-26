# Testing

The current automated tests validate the repository's file and content boundary.
They are infrastructure tests, not malware-detection results.

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
