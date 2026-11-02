# N-Day Nexus

N-Day Nexus is a local patch-assurance workflow. It builds vulnerable and patched versions of selected software, runs the same controlled probe against each, gathers target-appropriate source, runtime, sanitizer, and compiled-program evidence, and presents the paired results in a dashboard and report.

The project contains five historical CVE targets, a separate synthetic control-flow lab, encrypted JSON/text reports, a Streamlit dashboard, and optional Ollama explanations and blind patch hypotheses. Four targets use Ghidra, BinExport, and BinDiff. PHP uses a six-file source diff and ELF symbol comparison. All probes run locally in Docker; no hosted or remote target is supported.

For a plain-language explanation, vulnerability summaries, team contribution split, and viva questions, see [the teammate guide](docs/TEAMMATE_GUIDE.md).

## Targets

| CVE | Software and versions | Focus |
|---|---|---|
| CVE-2019-18634 | sudo 1.8.25p1 / 1.8.31p1 | Password-feedback buffer handling |
| CVE-2021-3177 | CPython 3.9.1 / 3.9.2 | `ctypes` floating-point formatting overflow |
| CVE-2023-0341 | editorconfig-core-c 0.12.5 / 0.12.6 | `ec_glob` pattern buffer overflow |
| CVE-2023-5363 | OpenSSL 3.0.11 / 3.0.12 | AES-GCM EVP key/IV parameter handling |
| CVE-2026-109618 | PHP 8.4.26 / 8.4.27, Apache mod_php | OOM request-state corruption |

Each target has its own Docker build, probe, and verdict criteria. The PHP case uses source and ELF-symbol evidence; its report has no BinDiff similarity score. The synthetic lab is `LAB-CFH-001` and is not a CVE target.

## Requirements

Host requirements:

- x86_64 Linux with Docker Engine available to the current user; the documented setup is for Fedora/Linux. The bundled BinDiff download is the amd64 build.
- Python 3.11 and `venv`/`pip`.
- Git, `curl`, `unzip`, `ar`, `tar`, and Java 21 or newer for the reverse-tool setup.
- Ghidra installed locally (the project has been used with Ghidra 12.1.4).
- Network access during setup and Docker image builds to download Python packages, reverse-tool dependencies, upstream source, and OS packages.
- Ollama and a local model are optional; they are only needed for LLM features.

The probes execute only in local Docker containers and do not publish host ports or target remote services. Most probe containers explicitly use `--network none`; the sudo probe feeds input to a local command-line process inside its container and does not start a network service. Image builds need network access to retrieve pinned source and build dependencies. The tool setup installs/extracts BinDiff and builds BinExport under project-local `.tools/` and `.work/` directories; it does not use a system package manager.

## Setup

Run from the repository root:

```sh
python3.11 --version
docker info
java -version

python3.11 -m venv .venv311
.venv311/bin/python -m pip install --upgrade pip
.venv311/bin/python -m pip install -r requirements.txt
```

Install the project-local Ghidra/BinExport/BinDiff support:

```sh
./scripts/setup_reverse_tools.sh
```

The script detects Ghidra under `/opt/ghidra_*`. It downloads the BinDiff amd64 `.deb` and extracts its files into `.tools/` without installing the package into Fedora. If Ghidra is elsewhere, set its path before running setup:

```sh
export NDAY_GHIDRA_HOME=/path/to/ghidra
./scripts/setup_reverse_tools.sh
```

If you use a separately installed BinDiff executable, set `NDAY_BINDIFF` to its path when running the pipeline. The setup script requires the installed Ghidra directory and Java, plus Git, `curl`, `unzip`, `ar`, and `tar`.

## Run the pipeline

Run one complete case (build, patch comparison, five probe trials per build, and report generation). The report vault must be available: create it in the dashboard first, or let the first CLI report run create it using `NDAY_REPORT_PASSWORD`.

```sh
read -rsp 'Report password: ' NDAY_REPORT_PASSWORD; echo
export NDAY_REPORT_PASSWORD
.venv311/bin/python run.py CVE-2019-18634
unset NDAY_REPORT_PASSWORD
```

Choose any configured CVE ID from the table above. To process every configured CVE sequentially:

```sh
read -rsp 'Report password: ' NDAY_REPORT_PASSWORD; echo
export NDAY_REPORT_PASSWORD
.venv311/bin/python run.py --all
unset NDAY_REPORT_PASSWORD
```

The separate stages are available when their prerequisites exist:

```sh
.venv311/bin/python run.py CVE-2019-18634 --step build
.venv311/bin/python run.py CVE-2019-18634 --step diff   # after building both images
.venv311/bin/python run.py CVE-2019-18634 --step probe  # after building both images
```

`--step build` and `--step diff` do not need the report password. A standalone `--step probe` prints trial results and updates a report when a prior report with diff evidence exists; that report update needs the vault password. The complete command is the simplest way to generate a fresh paired report.

### OpenSSL quick demonstration

The dashboard's **Run crypto demo** button runs one local vulnerable/patched AES-GCM evidence record. Build the images first, either with the full pipeline or:

```sh
.venv311/bin/python run.py CVE-2023-5363 --step build
```

Then start the dashboard and choose CVE-2023-5363. The normal OpenSSL `--step probe` runs five trials per build and reports `CRYPTO_WEAKNESS_CONFIRMED` / `CRYPTO_BEHAVIOR_DISTINCT` outcomes. The probe compares requested and effective IV behavior, ciphertext, tags, and the ciphertext-XOR relationship for controlled inputs; it does not contact a server.

### Dashboard

Start Streamlit on loopback:

```sh
.venv311/bin/streamlit run ui.py --server.address 127.0.0.1
```

Open the URL printed by Streamlit, normally `http://127.0.0.1:8501`. On first use, create a report-vault password of at least 12 characters. Later sessions ask for that password to unlock the dashboard. The dashboard selects PHP by default; choose a target in the sidebar and use **Run full pipeline**. Tabs provide the overview, patch evidence, runtime validation, control-flow lab, Ollama features, and reports.

Reports are encrypted at rest with AES-256-GCM. The password-derived key uses scrypt, and each encrypted file has a fresh random nonce. The vault settings are stored in `.work/report_vault.json`; back up that file with the encrypted reports. Losing the password or vault settings prevents report recovery. On first vault creation, existing plaintext reports and blind-analysis files are encrypted and their plaintext copies are removed.

For any standalone CLI command that reads or writes encrypted reports, provide the vault password through `NDAY_REPORT_PASSWORD`, using the prompt/export pattern shown under **Run the pipeline**. The dashboard can create the vault first; the first CLI report command can also create it.

### Ollama

Ollama is optional. Start the local Ollama service and pull a model, for example:

```sh
ollama serve
ollama pull <model>
```

In the dashboard's Ollama tab, **Explain report** uses the selected target's saved evidence. **Blind patch analysis** uses available before/after source and binary evidence without advisory text or probe outcomes. PHP supplies source and ELF-symbol evidence; the other configured targets can supply Ghidra/BinDiff and source evidence. Blind analysis requires a configured target and prepared artifacts; it does not analyze a CVE from its identifier alone. The CLI equivalents are:

```sh
.venv311/bin/python run.py CVE-2019-18634 --step explain --model <model>
.venv311/bin/python run.py CVE-2021-3177 --step blind --model <model>
```

The model returns explanatory prose or hypotheses, not the pipeline's verdict. CLI explain/blind commands need the report-vault password in `NDAY_REPORT_PASSWORD`; build both target images before blind analysis. Blind outputs are encrypted under `.work/artifacts/<CVE-ID>/`.

## Patch comparison and artifacts

For sudo, CPython, EditorConfig, and OpenSSL, the diff stage imports each binary into Ghidra headlessly, exports BinExport v2, and uses BinDiff to match functions and rank changed-function candidates. Similarity and confidence guide manual review; they do not independently establish root cause. PHP's target-specific comparison uses a source diff across six configured files and GNU `nm` symbol-table comparison of the Apache modules.

Results are stored here:

- `reports/<CVE-ID>.txt.enc`: encrypted readable report.
- `reports/<CVE-ID>.json.enc`: encrypted structured report, with trial outcomes, impact/ASan evidence, patch comparison, and saved explanation where available.
- `.work/artifacts/<CVE-ID>/`: extracted binaries, source diffs, BinExport files, BinDiff databases, function evidence, and other analysis artifacts. PHP includes `source_patch.diff` and `symbol_diff.json` instead of a BinDiff database.
- `.work/artifacts/LAB-CFH-001/control_flow_demo.json`: saved synthetic-lab result.

The synthetic **Control-flow lab** runs two isolated Docker builds of a small C program. A 40-byte input overwrites a callback pointer at offset 32 and redirects it to a benign `hello_world` function in the vulnerable build; the patched build rejects the oversized input. It is a separate teaching demonstration and does not attribute callback hijacking to any CVE target.

The report verdict is target-specific. Crash cases use vulnerable/patched crash-rate thresholds; PHP checks for the benign command marker; OpenSSL checks the configured weak-IV and distinct-IV outcomes. Read the per-trial evidence alongside the verdict. For example, the recorded PHP run showed 0/5 command confirmations in the vulnerable build and 5/5 no-command outcomes in the patched build. A prior CVE-2021-3177 run crashed in both builds in all five trials and had an ASan runtime initialization error; check the current report before quoting results, since subsequent runs may differ.

## Optional `stb_image` research harness

An exploratory local libFuzzer + ASan/UBSan harness is kept separately under [research/stb_image](research/stb_image/README.md). It is independent of the CVE pipeline and should be used only after reviewing the upstream status and its already public findings.
