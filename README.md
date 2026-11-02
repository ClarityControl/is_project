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

For the fast OpenSSL demonstration, build the two images once, then run the isolated comparison:

```sh
.venv311/bin/python run.py CVE-2023-5363 --step build
.venv311/bin/python run.py CVE-2023-5363 --step probe
```

Expected probe labels are `CRYPTO_WEAKNESS_CONFIRMED` for OpenSSL 3.0.11 and `CRYPTO_BEHAVIOR_DISTINCT` for 3.0.12. The dashboard also has a **Run crypto demo** button for this target; it shows one full vulnerable/patched evidence record without waiting for Ghidra/BinDiff.

### Graphical dashboard

Install the Python dependencies, then launch the local dashboard:

```sh
.venv311/bin/python -m pip install -r requirements.txt
.venv311/bin/streamlit run ui.py --server.address 127.0.0.1
```

The dashboard is arranged by task. On first launch, create a report-vault password of at least 12 characters; later launches require that password to unlock the dashboard. Choose a CVE in the sidebar and start the full pipeline from the target header. **Overview** contains the outcome summary, root cause, and pipeline log; **Patch evidence** contains source and binary comparisons; **Runtime validation** contains probe results and conditions. The synthetic **Control-flow lab**, **Ollama**, and **Reports** each have a separate tab. JSON and text reports are encrypted at rest as `reports/<CVE-ID>.json.enc` and `.txt.enc` with AES-256-GCM; the dashboard decrypts them after unlock and offers normal JSON/text downloads. Blind-analysis JSON/Markdown outputs are encrypted under `.work/artifacts/<CVE-ID>/`. Existing plaintext reports and blind-analysis outputs are encrypted and removed at first vault setup. The vault verifier is stored under `.work/report_vault.json`; back it up with the encrypted report files, because losing it or the password means those files cannot be decrypted. Pipeline output streams into the page, with a 90-minute overall dashboard limit. Docker builds have a 20-minute per-image limit and Ghidra analysis has a 15-minute per-run limit by default; the CLI limits can be adjusted with `NDAY_DOCKER_BUILD_TIMEOUT` and `NDAY_GHIDRA_TIMEOUT`. The control-flow lab separately builds and runs a synthetic benign callback-overwrite example: the vulnerable build redirects to a fixed `hello_world` function, while the patched build rejects the same oversized input. This is a teaching demo, not a real CVE finding. The lab runs as an unprivileged user in Docker with networking disabled, no capabilities, and a read-only filesystem. Each lab image build has a 10-minute limit, and the tab loads a previously saved successful result instead of rebuilding it automatically. The browser URL is printed by Streamlit (normally `http://127.0.0.1:8501`).

For CLI report generation, first create/unlock the vault in the dashboard, then set `NDAY_REPORT_PASSWORD` in the shell before running a reporting step. For example, use `read -rsp 'Report password: ' NDAY_REPORT_PASSWORD; echo; export NDAY_REPORT_PASSWORD`, run the CLI, then `unset NDAY_REPORT_PASSWORD`. Install the updated dependencies with `pip install -r requirements.txt` to add the AES-GCM implementation.

The dashboard opens on CVE-2026-109618 by default and loads its preliminary report from `reports/CVE-2026-109618.*`. It includes the configured source-level root-cause summary and currently available vulnerable-side function evidence; the report status identifies the pending patched-side diff and runtime probes. A successful full pipeline run replaces it with measured results.

Lab evidence is saved at `.work/artifacts/LAB-CFH-001/control_flow_demo.json` and can also be downloaded from the dashboard. Sources and Docker build definitions are under `labs/control_flow/`; the lab does not add a fake CVE to `targets/` or the reports.

The **Ollama explanation** tab has two modes. **Explain saved results** uses the evidence produced by the selected target's analysis method. For PHP this includes its six-file source diff, ELF symbol comparison, and runtime probe; it does not require Ghidra decompilations or ASan output. Other targets can contribute source, Ghidra/BinDiff, and sanitizer or impact evidence. **Blind patch analysis** uses patch evidence without CVE advisory text or probe results. Prepared binary evidence is cached by image ID where the target's analysis method supports it. Enable the rebuild option after changing target source or build settings. The prompt and generated answer are bounded for faster local inference. Start Ollama and install a model first (for example, `ollama serve` in another terminal and `ollama pull <model>`). CLI: `.venv311/bin/python run.py <CVE-ID> --step explain --model <model>` or `--step blind`. Blind results are encrypted under `.work/artifacts/<CVE-ID>/blind_hypothesis.md.enc` and `.json.enc`, separately from reports. Both modes return natural prose/Markdown labeled as hypotheses. Blind mode requires a configured target; an ID alone is not enough.

## Ghidra and BinDiff setup

```sh
./scripts/setup_reverse_tools.sh
```

The setup script builds the BinExport extension against the detected Ghidra installation and extracts BinDiff under `.tools/`; it does not use a system package manager or write to system directories. Set `NDAY_GHIDRA_HOME` if Ghidra is outside `/opt/ghidra_*`, or `NDAY_BINDIFF` to use a separate BinDiff executable. Ghidra settings and analysis artifacts (extracted binaries, BinExport files, BinDiff databases, and function evidence) are stored under the ignored `.work/` directory. Headless Ghidra project files are temporary and removed after each analysis.

For four targets, the `diff` stage runs Ghidra headless analysis on both binaries, exports BinExport v2 files, compares them with BinDiff, and records matched functions, similarity/confidence, and the BinDiff database path. The PHP target instead compares configured source files and defined ELF symbols from both `libphp.so` builds. The report and dashboard show the target-appropriate evidence for review. BinDiff candidates prioritize functions for review; symbol deltas provide compiled-build context alongside PHP's source patch.

The pipeline builds both images, analyzes and diffs their binaries, runs five isolated probes per image, and writes encrypted JSON/text reports under `reports/`. Configured cases include CVE-2019-18634 (sudo), CVE-2023-0341 (editorconfig-core-c), CVE-2021-3177 (CPython ctypes), CVE-2026-109618 (PHP mod_php), and CVE-2023-5363 (OpenSSL EVP/AES-GCM). The OpenSSL target compares 3.0.11 and 3.0.12 with identical build flags. Its local probe uses two distinct 16-byte IVs, then demonstrates that the vulnerable build reuses an effective GCM nonce: it emits identical ciphertext/tags for the same message and shows ciphertext-XOR equals plaintext-XOR for two different messages. This confirms the API-level confidentiality failure in the controlled harness; it does not recover a real secret, and the upstream advisory explicitly excludes OpenSSL's TLS implementation. The CPython probe uses the upstream regression input `ctypes.c_double.from_param(1e300)` and checks its representation in vulnerable 3.9.1 and patched 3.9.2 builds. The PHP target compares 8.4.26 with 8.4.27 using identical Apache module build flags and a pinned local PoC; its fixed `id` command probe runs in a Docker container with no network or host port. It targets CVE-2026-109618 only; CVE-2026-109619 is a separate advisory and is not claimed as validated by this target. All probes run only inside their target containers. Docker builds require network access to fetch upstream source and Ubuntu packages; the reverse-tool setup downloads BinDiff/BinExport source and Gradle into project-local tool directories.

Probe output records target behavior and process telemetry per trial. Memory-safety targets use AddressSanitizer to check whether the vulnerable input produces an out-of-bounds write in the vulnerable build and remains clean in the patched build. The OpenSSL crypto target instead records the ciphertext, tag, IV configuration, and XOR relation that demonstrates the nonce-reuse consequence. Reports summarize the source-level vulnerable operation and upstream patch behavior with direct version-diff links. Results are scoped to each target's documented trigger; they do not establish an attack on unrelated applications or protocols.

The separate `LAB-CFH-001` synthetic example demonstrates controlled function-pointer redirection to a benign print function. It does not change the real-CVE pipeline's evidence or claim that any configured CVE permits control-flow hijacking.

### Local `stb_image` research harness

An exploratory libFuzzer + ASan/UBSan harness is under [research/stb_image](research/stb_image/README.md). It is separate from the CVE pipeline and operates only on an in-memory decoder in local binaries. Before running it, review the upstream's currently public memory-safety report and verify the checked-out revision includes the maintainer's fixes; do not report already disclosed cases as new findings.

### Results

- Human-readable summaries: encrypted `reports/<CVE-ID>.txt.enc`
- Machine-readable results: encrypted `reports/<CVE-ID>.json.enc`
- Patch-comparison artifacts: `.work/artifacts/<CVE>/` (Ghidra/BinExport/BinDiff files where configured; PHP `source_patch.diff` and `symbol_diff.json`)

To inspect a diff interactively, open the `.BinDiff` database with the BinDiff UI from `.tools/bindiff/`. Ghidra projects themselves are not retained; import either ELF in the GUI for follow-up analysis.
