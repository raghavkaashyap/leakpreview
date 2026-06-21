# leakpreview
- leakpreview scans a folder before you share, upload, zip, or commit it, warning about secrets, private files, junk metadata, and bulky artifacts.  
- leakpreview is a pre-share safety preview tool. It is not a replacement for mature secret scanners like Gitleaks or TruffleHog.

## Current MVP

- Python CLI scaffold with recursive directory scanning
- Heuristic detection for secret-like filenames, private config files, junk metadata, and large files
- Text and JSON output modes

## Usage

```bash
python -m leakpreview ./
python -m leakpreview ./some-folder --json
python -m leakpreview ./some-folder --max-size-mb 25
```

## Docs

- PRD: `docs/prd.md`
- Backlog: `docs/issues.md`
