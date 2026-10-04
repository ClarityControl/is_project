# N-Day Nexus

N-Day Nexus is a local research pipeline for comparing vulnerable and patched builds, running an isolated crash check, and producing a report. The first target is CVE-2019-18634. All exploit execution is through local Docker containers; no network target is supported.

## Requirements

- Docker Engine
- Python 3.10+ (Python 3.11 is recommended; pwntools' Unicorn dependency currently fails to build under the machine's Python 3.14)
- `python3.11 -m venv .venv`
- `.venv/bin/pip install -r requirements.txt`

## Usage

```sh
.venv/bin/python run.py CVE-2019-18634
.venv/bin/python run.py CVE-2019-18634 --step diff
.venv/bin/python run.py CVE-2019-18634 --step build
.venv/bin/python run.py --all
```

The pipeline builds both images, compares symbols/disassembly, runs five isolated trials per image, and writes JSON and text reports under `reports/`. The Ghidra/Diaphora visual comparison remains a documented manual supplement. The CVE-2 files are placeholders until the primary target is validated.

The target Dockerfiles pin upstream tags and enable `pwfeedback` only in the disposable vulnerable image. Docker builds require network access to fetch upstream source and Ubuntu packages.
