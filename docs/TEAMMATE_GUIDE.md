# N-Day Nexus: teammate and viva guide

## 1. Project in one minute

N-Day Nexus is a local patch-assurance workflow. For each configured vulnerability, it builds the affected and fixed software versions, runs a controlled probe against both in Docker, gathers target-appropriate evidence, and presents the paired results for review. Four targets use Ghidra, BinExport, and BinDiff; PHP uses source and ELF-symbol comparison. Memory-safety cases add AddressSanitizer (ASan), while the OpenSSL case measures the tested AES-GCM parameter behavior.

The project includes five historical CVE cases, a separate synthetic callback-overwrite lab, a Streamlit dashboard, encrypted JSON/text reports, and optional Ollama assistance. Ollama can explain collected results or form a blind hypothesis from source and binary evidence without the advisory or probe outcome. The goal is to show **what changed, where it changed, and how the configured vulnerable and patched builds behaved under the same controlled experiment**. Results apply to the selected build and probe input.

## 2. Basic terms

- **Vulnerability:** a weakness or condition in software that can be exploited to cause harm, such as unauthorized access, data changes, information disclosure, or a crash.
- **CVE:** a public identifier for a disclosed vulnerability, such as `CVE-2021-3177`. It helps people and tools refer to the same issue. CVE is an identification and information-sharing system; the identifier alone does not explain how to detect or fix the bug. [CVE Program](https://www.cve.org/)
- **N-day vulnerability:** a publicly known vulnerability for which a fix or enough technical information may already be available. N-Day Nexus studies how to validate selected fixes.
- **CWE:** a category describing a kind of software weakness. For example, CWE-121 means a buffer overflow in storage allocated on the stack. CVE says *which reported issue*; CWE says *what kind of weakness*. [MITRE CWE-121](https://cwe.mitre.org/data/definitions/121.html)
- **Buffer:** a region of memory reserved to hold data. Code must keep writes within that region’s size.
- **Buffer overflow / out-of-bounds write:** code writes beyond the end of a buffer. Nearby data can be corrupted. Depending on the program and conditions, the result may be a crash or, in some circumstances, a more serious security impact.
- **Stack:** memory used for a function’s temporary local data. A fixed-size local character array is commonly allocated here. Writing past it is a *stack-based buffer overflow*.
- **Global / BSS storage:** memory for global or static variables. BSS is the program’s zero-initialized global storage area. Writing past a buffer there is a *global buffer overflow*.
- **Patch:** a source-code change intended to correct a weakness. Comparing versions helps identify what changed, but changed code is not automatically security-related.
- **ASan:** a compiler/runtime memory-error detector. In this project it reports observed invalid memory access in an instrumented build. It helps validate a memory-safety bug; it does not establish that an attacker can control execution.
- **Ghidra:** reverse-engineering software used here to inspect compiled binaries and recover function/disassembly/decompiled-code evidence.
- **BinExport / BinDiff:** BinExport passes Ghidra’s program representation to BinDiff. BinDiff matches functions between the two binaries and gives similarity/confidence metrics. A changed-function candidate is a lead for review, not proof of root cause.
- **ELF symbol comparison:** GNU `nm` lists defined symbols in compiled ELF files. Comparing two symbol lists can show names added or removed by a build; it does not measure function similarity.
- **AES-GCM:** an authenticated-encryption mode that uses a key and a nonce/IV. Reusing a nonce with the same key can undermine confidentiality and authentication. The OpenSSL target tests the configured API behavior in a local harness.
- **CIA:** confidentiality limits information disclosure, integrity protects correct data and program state, and availability keeps services usable. N-Day Nexus uses target-specific evidence to help a maintainer assess a fix against one of these properties.

## 3. What vulnerability types does this project target?

The sample set covers memory corruption, cryptographic parameter handling, and request-state corruption:

| CVE | Program and versions | Vulnerability in plain language | Location / type |
|---|---|---|---|
| CVE-2019-18634 | sudo 1.8.25p1 → 1.8.31p1 | With `pwfeedback` enabled, an erase-write failure can desynchronize the input pointer and remaining-capacity counter, allowing a write beyond the password buffer. | Advisory: stack-based; pinned target source uses a static buffer in BSS, and ASan reports a global overflow |
| CVE-2021-3177 | CPython 3.9.1 → 3.9.2 | `PyCArg_repr` formats a very large `ctypes` floating-point value into a fixed-size local buffer. | Stack buffer |
| CVE-2023-0341 | editorconfig-core-c 0.12.5 → 0.12.6 | `ec_glob` can append escaped/expanded pattern characters past a fixed-size pattern buffer. | Stack buffer |
| CVE-2023-5363 | OpenSSL 3.0.11 → 3.0.12 | EVP cipher initialization handles AES-GCM key/IV parameters incorrectly; the vulnerable key-length path can reuse an effective nonce for distinct requested IVs, while the patched build preserves distinct-IV behavior. | Cryptographic parameter handling; confidentiality of protected data |
| CVE-2026-109618 | PHP 8.4.26 → 8.4.27 (Apache mod_php) | An OOM bailout can interrupt request processing while internal state is partly initialized; later request handling can use invalid state. The configured PoC checks for a benign command response in an isolated container. | OOM/error-path request-state corruption |

For CVE-2019-18634, the vulnerable behavior depends on `pwfeedback`; it is not enabled in every sudo configuration. Ubuntu classifies the CVE as stack-based, but the pinned source used by this project declares the `tgetpass` buffer `static`, and the project's ASan result labels the observed write as global. Preserve this distinction when describing the case: the advisory classification and the instrumented target's storage classification differ. See the [Ubuntu advisory](https://ubuntu.com/security/CVE-2019-18634) and [pinned vulnerable source](https://github.com/sudo-project/sudo/blob/f0f115bcd97b88f83c96bd2c6a9f55dae202e8b0/src/tgetpass.c). The [EditorConfig advisory](https://ubuntu.com/security/CVE-2023-0341) describes the `ec_glob` stack overflow and the 0.12.6 fix. The CPython case is described by [Ubuntu](https://ubuntu.com/security/CVE-2021-3177) and the [Python issue](https://bugs.python.org/issue42938).

The PHP comparison is configured across `Zend/zend_alloc.c`, `ext/session/session.c`, `main/rfc1867.c`, `Zend/zend_execute_API.c`, `main/SAPI.c`, and `main/main.c`. The saved comparison reports 1,093 changed lines, 97 added symbols, and 9 removed symbols; focused allocator symbols show the OOM-handler changes. A recorded benign-command probe reported 0/5 command confirmations for the vulnerable image and 5/5 no-command outcomes for the patched image. Use the saved report when explaining this result and its target-specific verdict.

Each target has its own version pair, build configuration, evidence path, and probe. The shared workflow is extensible through target metadata and adapters; conclusions remain specific to the configured case.

### Important scope note for EditorConfig

This target compares the historical versions used for CVE-2023-0341 (0.12.5 and 0.12.6). A later Ubuntu advisory, [CVE-2026-40489](https://ubuntu.com/security/CVE-2026-40489), describes another stack overflow in `ec_glob` and calls it an incomplete fix related to the earlier issue. Therefore, the project’s 0.12.6 result must be read narrowly: it evaluates the selected historical patch and probe, not whether every later EditorConfig release is safe.

## 4. How the program works

```text
Target metadata + Dockerfiles
             │
             ▼
Build vulnerable and patched source versions
             │
       ┌─────┴─────┐
       ▼           ▼
 Run same probe   Extract target binaries
 in each image    → Ghidra / BinExport
       │           → BinDiff function comparison
       ▼           │
       ASan evidence
       └─────┬─────┘
             ▼
       JSON and text report
          ┌──┴──┐
          ▼     ▼
     Dashboard  Ollama explanation or blind hypothesis
```

1. **Configure a target.** `targets/<CVE-ID>/meta.json` records the program, source versions, bug notes, source path, binary path(s), and probe inputs. Each version has a Dockerfile under `vuln/` or `patched/`.
2. **Build both versions.** `modules/builder.py` builds separate Docker images. Historical source and dependencies are fetched during the image build; the probe itself runs in a local container with networking disabled and reduced capabilities.
3. **Run the probe.** `modules/runner.py` runs each target’s `exploit.py` five times per version and collects the target-specific impact result. The PHP target is an exception to the crash-only probes: it runs a fixed benign `id` command inside a network-disabled Docker container to check the upstream CVE’s demonstrated impact. This does not authorize testing against external systems.
4. **Compare the patch.** `modules/differ.py` runs Ghidra, BinExport, and BinDiff for sudo, CPython, EditorConfig, and OpenSSL, recording matched functions, similarity/confidence, and changed-function candidates. PHP follows a target-specific path: `modules/source_diff.py` compares configured source files and GNU `nm` compares defined symbols in the paired Apache modules.
5. **Generate reports.** `modules/reporter.py` combines metadata and run results into AES-GCM-encrypted `reports/<CVE-ID>.json.enc` and `.txt.enc` files. Unlock the dashboard with the report-vault password to view or download them. Root-cause descriptions and patch notes originate in target metadata; they are curated project data, not automatically discovered by the report generator.
6. **Optionally use Ollama.** The report explanation uses saved report evidence. Blind patch analysis uses the available patch evidence without CVE advisory text or probe outcomes: source and ELF symbols for PHP; source, BinDiff, and selected Ghidra function evidence where those artifacts are configured. Prepared reverse-engineering evidence is reused by image ID on repeat runs; select the dashboard rebuild option after changing the target source/build. The model receives a bounded prompt and answer length to keep local inference responsive. It proposes hypotheses for a researcher to review. A blind run needs a configured target; a CVE identifier by itself is not enough.
7. **View results.** `ui.py` provides a Streamlit dashboard with overview, patch evidence, runtime validation, Ollama, reports, and Control-flow lab views. The separate lab builds vulnerable and patched versions of a small C program: a 40-byte input overwrites a callback at offset 32 and redirects it to a harmless `hello_world` function; the patched build rejects the oversized input. This illustrates control-flow redirection in the lab program and is separate from evidence about CVEs. Detailed outputs remain in `reports/` and `.work/artifacts/`.

For standard crash-probe targets, `CONFIRMED` means the vulnerable build crashed in at least 80% of trials and the patched build in at most 20%. For PHP, confirmation requires benign command output in at least 80% of vulnerable trials and at most 20% of patched trials. OpenSSL uses crypto-specific criteria: repeated weak behavior in the vulnerable build and distinct effective-IV behavior in the patched build. Results apply only to these pinned builds, flags, probes, and isolated containers.

## 5. How the project relates to CIA

The project is used defensively to review whether a selected update changes behavior associated with a CIA property:

- **Confidentiality:** the OpenSSL case exercises AES-GCM parameter handling and records effective IVs, ciphertext, tags, and XOR relations. This shows the consequence in a controlled local harness and helps a library user review the fixed version.
- **Integrity:** memory-safety cases evaluate whether crafted input corrupts program state. LAB-CFH-001 gives a visual example: a deliberately vulnerable program redirects a callback to a benign print function, and its patched counterpart rejects the oversized input. The lab illustrates the concept independently of CVE results.
- **Availability:** crash probes record whether the same input terminates the vulnerable and patched program.

Encrypted report storage protects generated evidence while stored and accessed through the vault. The main CIA use case is the paired patch evaluation above: users apply the workflow to a dependency update before making a release or remediation decision.

## 6. Methodology and interpretation

The method is a **paired before/after experiment**:

1. Select a known vulnerable version and its fixed version.
2. Keep the probe input and measurement process the same across both builds.
3. Observe process outcomes and memory-safety diagnostics.
4. Compare the compiled binaries to locate changed functions.
5. Relate runtime and binary evidence to the source patch, then review the evidence manually.

This offers multiple kinds of evidence: a known source change, runtime behavior, sanitizer output, and a compiled-binary comparison. Using all of them gives a reviewer useful cross-checks. None should be treated as a complete proof by itself. BinDiff can surface unrelated build changes; sanitizer findings depend on the instrumented build and input; a passing probe only means that this input did not reproduce the issue in that run; and Ollama can make mistakes. The curated root-cause text is useful documentation but is not an independent discovery result.

The configured inventory contains CVE-2019-18634, CVE-2021-3177, CVE-2023-0341, CVE-2023-5363, and CVE-2026-109618. Quote outcomes from the unlocked report for the specific run being presented. One recorded CVE-2021-3177 run showed five crashes in each build, so that run did not distinguish the versions; its ASan runtime also failed to initialize correctly. A recorded PHP run showed 0/5 benign command confirmations for the vulnerable image and 5/5 no-command outcomes for the patched image. Present verdicts with their underlying diagnostics. PHP uses source/symbol evidence rather than a BinDiff similarity score, and OpenSSL uses a crypto-specific outcome rather than a crash-rate verdict.

## 7. Setup and run

### One-time setup

Requirements include Docker, Python 3.11, Git, Ghidra, Java, and the project’s Python packages. From the repository root:

```sh
python3.11 -m venv .venv311
.venv311/bin/python -m pip install -r requirements.txt
./scripts/setup_reverse_tools.sh
```

The reverse-tool setup keeps BinDiff/BinExport support in project-local directories. If Ghidra is not under `/opt/ghidra_*`, set `NDAY_GHIDRA_HOME`; if BinDiff is not found automatically, set `NDAY_BINDIFF`.

### Run the pipeline

```sh
.venv311/bin/python run.py CVE-2019-18634
```

The normal run builds both images, performs the configured patch comparison, executes probes, and writes reports. Four targets use Ghidra/BinDiff; PHP uses source/ELF-symbol analysis. Individual stages can be run with `--step build`, `--step diff`, `--step probe`, or `--step report`; later stages need outputs from earlier stages. Use any configured ID from the target list in place of the example. The OpenSSL probe can be run without Ghidra after building its images:

```sh
.venv311/bin/python run.py CVE-2023-5363 --step build
.venv311/bin/python run.py CVE-2023-5363 --step probe
```

### Dashboard and Ollama

```sh
.venv311/bin/streamlit run ui.py --server.address 127.0.0.1
```

The dashboard listens on loopback and asks you to create or unlock the report-vault password. It has a **Run full pipeline** action, separate overview/patch/runtime views, an **Ollama** tab, report downloads, and the control-flow lab. For local Ollama, start the service and install a model first. CLI options are:

```sh
.venv311/bin/python run.py CVE-2019-18634 --step explain --model <model>
.venv311/bin/python run.py CVE-2021-3177 --step blind --model <model>
```

The first explains evidence in a saved report. The second creates a blind patch hypothesis from configured source/binary evidence. Blind outputs are encrypted under `.work/artifacts/<CVE-ID>/blind_hypothesis.md.enc` and `.json.enc`.

## 8. Where to find results

- `reports/<CVE-ID>.txt.enc`: encrypted readable summary; view it after unlocking the dashboard.
- `reports/<CVE-ID>.json.enc`: encrypted structured metadata, probe outcomes, ASan evidence, BinDiff summary, and any saved report explanation.
- `.work/artifacts/<CVE-ID>/`: extracted binaries, BinExport files, BinDiff database, function decompilations, source patch diff, and blind-analysis artifacts.
- PHP artifacts include `source_patch.diff` and `symbol_diff.json` instead of a BinDiff database.
- `.work/artifacts/LAB-CFH-001/control_flow_demo.json`: saved record for the synthetic callback demonstration.
- `nday_work/ghidra_projects/`: temporary Ghidra headless projects may be deleted after analysis; import an extracted ELF in the Ghidra GUI for interactive inspection.

## 9. Team contributions

The project has five CVE cases and one synthetic lab. Member labels follow the author order in the project report: Member 1 is Nipun Nitin Bhattad, Member 2 is Krish Rohilla, and Member 3 is Amitanshu Yadav. Members 1 and 2 each own two CVE case studies; Member 3 owns the synthetic lab and the PHP runtime case, while Member 1 handles PHP's source/ELF-symbol comparison. This divides PHP's work across the source and runtime tracks. Each member also owns a substantial project subsystem and should deliver one working code or analysis contribution, written evidence notes, and a live demonstration segment.

| Team member | Case studies owned | Shared subsystem ownership and concrete deliverables | Presentation contribution |
|---|---|---|---|
| **Member 1 — Nipun Nitin Bhattad: memory-safety and source evidence** | CVE-2019-18634 (sudo) and CVE-2021-3177 (CPython). Verify versions, trigger conditions, source locations, upstream fixes, and the distinct storage/root-cause details. | Own target metadata and source-patch evidence quality, including PHP source/ELF-symbol comparison as a shared case. Deliver case notes, validate changes against pinned code, and contribute one source-evidence improvement. | Explain one overflow case, how the paired source diff supports the finding, and how to interpret ASan evidence. |
| **Member 2 — Krish Rohilla: runtime and binary validation** | CVE-2023-0341 (EditorConfig) and CVE-2023-5363 (OpenSSL). Validate each safe probe and explain why one is a memory-safety test and the other is an AES-GCM parameter/confidentiality test. | Own Docker/probe execution and outcome interpretation; review Ghidra/BinDiff evidence for the assigned targets and maintain reproducible runtime/ASan/crypto evidence. Deliver two evidence notes and one runtime or binary-evidence improvement. | Demonstrate one memory-safety result and the OpenSSL AES-GCM comparison; explain what the output says about integrity, availability, or confidentiality. |
| **Member 3 — Amitanshu Yadav: PHP runtime, control-flow lab, and interface** | CVE-2026-109618 (PHP) runtime evidence and LAB-CFH-001. Verify the benign command-probe result; explain the synthetic callback overwrite and patched rejection separately. | Own PHP runtime demonstration, Streamlit interface, report-vault views, Ollama modes, and synthetic-lab evidence. Deliver PHP/lab evidence notes and one interface or lab improvement. Member 1 owns PHP source/symbol comparison, so the PHP case is shared across these packages. Coordinate the end-to-end demonstration. | Show the PHP runtime result, dashboard flow, Ollama modes, and benign callback redirection in the separate lab. |

### Equal contribution checklist

Each member should complete the same set of contribution records:

1. One code, configuration, or analysis improvement merged into the shared project.
2. Evidence notes for both assigned case studies (Member 3's second is the synthetic lab; the PHP case is split between source/symbol and runtime evidence).
3. A verified run record with versions, commands, outcome counts, and artifact links.
4. A short report subsection and a demonstration segment of similar length.
5. One peer review of another member's work and one response to review feedback.

Record work in a shared contribution log with commits, artifact paths, and the report or guide section each person authored. If the PHP integration or another package takes longer than expected, shift a concrete task such as a dashboard panel, probe review, or report subsection so effort stays balanced.

### Shared responsibilities

- Use a review cycle: Member 1 reviews Member 2's runtime evidence, Member 2 reviews Member 3's integration/demo evidence, and Member 3 reviews Member 1's source evidence. The author addresses feedback before the presentation.
- All three should be able to explain the full workflow, the target-specific verdict rules, the distinction between a CVE case and LAB-CFH-001, and why a test result applies only to its configured build and input.
- Present the project in three similar-length sections: (1) paired-build workflow and memory-safety cases; (2) runtime evidence, ASan, and OpenSSL confidentiality case; (3) PHP source/symbol analysis, dashboard/Ollama, and the synthetic callback demonstration.
- All members should be ready to navigate the dashboard and answer questions about the full project, even when another teammate owns the detailed implementation.

## 10. Possible viva questions

1. **What does CVE stand for, and what does its identifier tell us?**
   Common Vulnerabilities and Exposures; the ID names a publicly disclosed issue. It does not by itself prove the weakness or describe the complete exploit conditions.
2. **How is CWE different from CVE?**
   CVE identifies a reported instance; CWE categorizes the underlying weakness pattern.
3. **What vulnerability types are represented?**
   The configured cases include stack/global memory corruption, AES-GCM parameter handling, and PHP request-state corruption after an out-of-memory bailout.
4. **What is the difference between a stack buffer overflow and a global buffer overflow?**
   The buffer’s storage location differs: a local function buffer on the stack versus global/static storage such as BSS.
5. **What does ASan contribute?**
   It detects memory errors during execution of the instrumented build and gives diagnostic evidence. It does not prove exploitability or code execution.
6. **Why test vulnerable and patched versions with the same input?**
   The paired setup controls the input and lets us observe whether behavior changes across the fix.
7. **Why use Docker?**
   It gives each historical build a repeatable local environment and keeps the probe away from the host process space. It is an isolation measure, not a mathematical guarantee of safety.
8. **What do Ghidra and BinDiff each do?**
   Ghidra analyzes/decompiles compiled binaries; BinDiff matches functions and highlights differences between the builds.
9. **Does a low similarity score identify the vulnerable function?**
   No. It prioritizes candidate changes. The candidate must be checked against source, call behavior, and runtime evidence.
10. **How are the text and JSON reports produced?**
    The reporter combines target metadata with collected diff and probe outputs; Jinja renders the text report. Root-cause prose is curated in target metadata.
11. **What is the difference between normal Ollama explanation and blind analysis?**
    Normal explanation includes a saved report’s evidence and advisory context. Blind analysis omits the advisory and probe result, and forms hypotheses from source/binary patch evidence.
12. **Can blind analysis process any CVE from only its ID?**
    No. A target must first be configured with source versions, Docker build instructions, binary paths, and relevant evidence.
13. **What does the project’s `CONFIRMED` verdict mean?**
    It means the configured outcome criteria were met for that target: crash-rate separation for crash probes, command-response separation for PHP, or the configured weak/distinct-IV criteria for OpenSSL. It is evidence for the selected experiment, not a general exploitability claim.
14. **How general is the workflow?**
    The build/report structure is reusable, while each target still needs versions, build instructions, binary/source locations, and a probe that matches its vulnerability class. The current examples show several classes rather than every possible vulnerability.
15. **What would be the next improvement?**
    Add more vulnerability families with target-specific evidence and validation, make probes and impact criteria explicit per target, and measure false positives/negatives against a larger benchmark.
16. **How does the project demonstrate confidentiality?**
    The OpenSSL harness records how the vulnerable and fixed EVP implementations handle distinct requested AES-GCM IVs and the resulting ciphertext/tag behavior. It demonstrates the consequence in a controlled local test and provides evidence for reviewing the fix.
17. **Why does PHP use source and ELF-symbol comparison instead of BinDiff?**
    Whole-program Ghidra analysis of the PHP module is too expensive for this workflow. The PHP path compares six configured fix files and symbol tables; its runtime path checks a benign command marker inside the isolated Apache lab.
18. **What does the synthetic callback lab demonstrate?**
    It shows that oversized input can overwrite a callback and reach a benign print function in the lab program, while the patched build rejects the input. This demonstrates the concept in the synthetic program, independently of the CVE results.
19. **Is report encryption the project's CIA demonstration?**
    Report encryption protects saved artifacts. The primary defensive CIA work is patch evaluation: OpenSSL addresses confidentiality, memory-state evidence addresses integrity, and crash probes address availability.
20. **What do BinDiff similarity and confidence mean?**
    Similarity estimates structural resemblance between a matched function pair; confidence represents the strength BinDiff assigns to that match. The scores prioritize review, while source and runtime evidence establish relevance to the patch.

## References

- [CVE Program](https://www.cve.org/)
- [MITRE CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [Ubuntu: CVE-2019-18634](https://ubuntu.com/security/CVE-2019-18634)
- [Ubuntu: CVE-2023-0341](https://ubuntu.com/security/CVE-2023-0341)
- [Ubuntu: CVE-2026-40489](https://ubuntu.com/security/CVE-2026-40489)
- [Ubuntu: CVE-2021-3177](https://ubuntu.com/security/CVE-2021-3177)
- [Python issue 42938](https://bugs.python.org/issue42938)
- [OpenSSL CVE-2023-5363 advisory](https://mta.openssl.org/pipermail/openssl-announce/2023-October/000282.html)
- [PHP fix commit](https://github.com/php/php-src/commit/31c0ea7d)
