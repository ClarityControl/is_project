# N-Day Nexus

N-Day Nexus is a local research pipeline for comparing vulnerable and patched builds, analyzing their binaries with Ghidra, diffing them with BinDiff, running an isolated crash check, and producing a report. All probes run in local Docker containers; no network target is supported.

For a plain-language project walkthrough, vulnerability background, team role suggestions, and viva questions, see [the teammate guide](docs/TEAMMATE_GUIDE.md).

## Requirements

- Docker Engine
- Ghidra (tested with 12.1.4)
- Git, curl, unzip, `ar`, and Java 21+
- Python 3.10+ (Python 3.11 is recommended; pwntools' Unicorn dependency currently fails to build under the machine's Python 3.14)
- Python 3.11 (`python3.11`)
- `.venv311/bin/python -m pip install -r requirements.txt`

## Usage

```sh
python3.11 -m venv .venv311  # once, if this environment does not exist
.venv311/bin/python -m pip install -r requirements.txt
.venv311/bin/python run.py CVE-2019-18634
.venv311/bin/python run.py CVE-2019-18634 --step diff  # requires the images to be built first
.venv311/bin/python run.py CVE-2019-18634 --step build
.venv311/bin/python run.py --all
```

### Graphical dashboard

Install the Python dependencies, then launch the local dashboard:

```sh
.venv311/bin/python -m pip install -r requirements.txt
.venv311/bin/streamlit run ui.py --server.address 127.0.0.1
```

The dashboard lets you select a configured CVE, run the full pipeline, compare the vulnerable/patched source, use Ollama, and download reports. Its **Control-flow lab** tab separately builds and runs a synthetic benign callback-overwrite example: the vulnerable build redirects to a fixed `hello_world` function, while the patched build rejects the same oversized input. This is a teaching demo, not a real CVE finding. The lab runs as an unprivileged user in Docker with networking disabled, no capabilities, and a read-only filesystem. The browser URL is printed by Streamlit (normally `http://127.0.0.1:8501`).

Lab evidence is saved at `.work/artifacts/LAB-CFH-001/control_flow_demo.json` and can also be downloaded from the dashboard. Sources and Docker build definitions are under `labs/control_flow/`; the lab does not add a fake CVE to `targets/` or the reports.

The **Ollama explanation** tab has two modes. **Explain saved results** uses source differences, Ghidra/BinDiff, and sanitizer outcomes already recorded in a report. **Blind patch analysis** builds both images and runs Ghidra/BinDiff, then asks Ollama for likely vulnerability classes using only the source diff and changed-function decompilations; it does not provide the CVE advisory text or probe results. Start the local Ollama service and install a model first (for example, `ollama serve` in another terminal and `ollama pull <model>`). The normal explanation is available from the CLI with `.venv311/bin/python run.py <CVE-ID> --step explain --model <model>`; blind analysis is `.venv311/bin/python run.py <CVE-ID> --step blind --model <model>`. Blind results are saved under `.work/artifacts/<CVE-ID>/blind_hypothesis.md` and `.json`, separately from the reports. Both modes return natural prose/Markdown labeled as hypotheses. Blind mode still requires a configured target with source versions, Docker build definitions, binary locations, and a source path; it does not discover these from a CVE ID alone.

## Ghidra and BinDiff setup

```sh
./scripts/setup_reverse_tools.sh
```

The setup script builds the BinExport extension against the detected Ghidra installation and extracts BinDiff under `.tools/`; it does not use a system package manager or write to system directories. Set `NDAY_GHIDRA_HOME` if Ghidra is outside `/opt/ghidra_*`, or `NDAY_BINDIFF` to use a separate BinDiff executable. Ghidra settings and analysis artifacts (extracted binaries, BinExport files, BinDiff databases, and function evidence) are stored under the ignored `.work/` directory. Headless Ghidra project files are temporary and removed after each analysis.

The `diff` stage runs Ghidra headless analysis on both binaries, exports BinExport v2 files, compares them with BinDiff, and records matched functions, similarity/confidence, and the BinDiff database path. The report lists low-similarity functions as candidates for human review; this is a prioritization aid, not automatic proof of root cause. For code-review value, targets should retain symbols and use matching build settings.

The pipeline builds both images, analyzes and diffs their binaries, runs five isolated crash probes per image, and writes JSON and text reports under `reports/`. The configured cases are CVE-2019-18634 (sudo), CVE-2023-0341 (editorconfig-core-c), and CVE-2021-3177 (CPython ctypes). The CPython probe uses the upstream regression input `ctypes.c_double.from_param(1e300)` and checks its representation in vulnerable 3.9.1 and patched 3.9.2 builds. All probes run only inside their target containers. Docker builds require network access to fetch upstream source and Ubuntu packages; the reverse-tool setup downloads BinDiff/BinExport source and Gradle into project-local tool directories.

Probe output records payload size and target process exit/signal per trial. The pipeline also builds an AddressSanitizer-instrumented copy of each target and reports whether the same input is identified as an out-of-bounds write in the vulnerable build and remains clean in the patched build. Reports summarize the source-level vulnerable operation and upstream patch behavior with direct version-diff links. This supports crash and root-cause review; it does not establish instruction-pointer control or prove an exploit chain.

The separate `LAB-CFH-001` synthetic example demonstrates controlled function-pointer redirection to a benign print function. It does not change the real-CVE pipeline's evidence or claim that any configured CVE permits control-flow hijacking.

### Results

- Human-readable summaries: `reports/<CVE-ID>.txt`
- Machine-readable results: matching `.json` files in `reports/`
- Binary and reverse-engineering evidence: `.work/artifacts/<CVE>/` (`vuln.elf`, `patched.elf`, `*.BinExport`, `vuln_vs_patched.BinDiff`, and function JSON)

To inspect a diff interactively, open the `.BinDiff` database with the BinDiff UI from `.tools/bindiff/`. Ghidra projects themselves are not retained; import either ELF in the GUI for follow-up analysis.
