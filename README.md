# N-Day Nexus

N-Day Nexus is a local research pipeline for comparing vulnerable and patched builds, analyzing their binaries with Ghidra, diffing them with BinDiff, running an isolated crash check, and producing a report. All probes run in local Docker containers; no network target is supported.

## Requirements

- Docker Engine
- Ghidra (tested with 12.1.4)
- Git, curl, unzip, `ar`, and Java 21+
- Python 3.10+ (Python 3.11 is recommended; pwntools' Unicorn dependency currently fails to build under the machine's Python 3.14)
- `python3.11 -m venv .venv`
- `.venv/bin/pip install -r requirements.txt`

## Usage

```sh
.venv/bin/python run.py CVE-2019-18634
.venv/bin/python run.py CVE-2019-18634 --step diff  # requires the images to be built first
.venv/bin/python run.py CVE-2019-18634 --step build
.venv/bin/python run.py --all
```

## Ghidra and BinDiff setup

```sh
./scripts/setup_reverse_tools.sh
```

The setup script builds the BinExport extension against the detected Ghidra installation and extracts BinDiff under `.tools/`; it does not use a system package manager or write to system directories. Set `NDAY_GHIDRA_HOME` if Ghidra is outside `/opt/ghidra_*`, or `NDAY_BINDIFF` to use a separate BinDiff executable. Ghidra settings, projects, extracted binaries, BinExport files, and BinDiff databases are stored under the ignored `.work/` directory.

The `diff` stage runs Ghidra headless analysis on both binaries, exports BinExport v2 files, compares them with BinDiff, and records matched functions, similarity/confidence, and the BinDiff database path. The report lists low-similarity functions as candidates for human review; this is a prioritization aid, not automatic proof of root cause. For code-review value, targets should retain symbols and use matching build settings.

The pipeline builds both images, analyzes and diffs their binaries, runs five isolated crash probes per image, and writes JSON and text reports under `reports/`. CVE-2023-0341 compares editorconfig-core-c 0.12.5 with the upstream fix in 0.12.6. The target Dockerfiles pin upstream source commits and enable `pwfeedback` only in the disposable vulnerable sudo image. Docker builds require network access to fetch upstream source and Ubuntu packages; the reverse-tool setup downloads BinDiff/BinExport source and Gradle into project-local tool directories.
