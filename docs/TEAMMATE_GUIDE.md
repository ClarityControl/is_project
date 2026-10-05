# N-Day Nexus: teammate and viva guide

## 1. Project in one minute

N-Day Nexus is a local research tool for studying a known software vulnerability and its fix. It builds a vulnerable and a patched version of the same program, runs a controlled input against both inside Docker, checks for memory errors with AddressSanitizer (ASan), compares the compiled binaries with Ghidra and BinDiff, and creates JSON and text reports. An optional local Ollama model explains saved evidence or suggests vulnerability types from patch evidence alone.

The aim is to help a researcher understand **what changed, where it changed, and whether a safe test still triggers a memory error after the patch**. It is not a general-purpose scanner, and a crash is not proof of code execution.

## 2. Basic terms

- **Vulnerability:** a weakness or condition in software that can be exploited to cause harm, such as unauthorized access, data changes, information disclosure, or a crash.
- **CVE:** a public identifier for a disclosed vulnerability, such as `CVE-2021-3177`. It helps people and tools refer to the same issue. CVE is an identification and information-sharing system; the identifier alone does not explain how to detect or fix the bug. [CVE Program](https://www.cve.org/)
- **CWE:** a category describing a kind of software weakness. For example, CWE-121 means a buffer overflow in storage allocated on the stack. CVE says *which reported issue*; CWE says *what kind of weakness*. [MITRE CWE-121](https://cwe.mitre.org/data/definitions/121.html)
- **Buffer:** a region of memory reserved to hold data. Code must keep writes within that region’s size.
- **Buffer overflow / out-of-bounds write:** code writes beyond the end of a buffer. Nearby data can be corrupted. Depending on the program and conditions, the result may be a crash or, in some circumstances, a more serious security impact.
- **Stack:** memory used for a function’s temporary local data. A fixed-size local character array is commonly allocated here. Writing past it is a *stack-based buffer overflow*.
- **Global / BSS storage:** memory for global or static variables. BSS is the program’s zero-initialized global storage area. Writing past a buffer there is a *global buffer overflow*.
- **Patch:** a source-code change intended to correct a weakness. Comparing versions helps identify what changed, but changed code is not automatically security-related.
- **ASan:** a compiler/runtime memory-error detector. In this project it reports observed invalid memory access in an instrumented build. It helps validate a memory-safety bug; it does not establish that an attacker can control execution.
- **Ghidra:** reverse-engineering software used here to inspect compiled binaries and recover function/disassembly/decompiled-code evidence.
- **BinExport / BinDiff:** BinExport passes Ghidra’s program representation to BinDiff. BinDiff matches functions between the two binaries and gives similarity/confidence metrics. A changed-function candidate is a lead for review, not proof of root cause.

## 3. What vulnerability types does this project target?

The current sample set focuses on **out-of-bounds writes and buffer overflows**, with both stack and global storage represented:

| CVE | Program and versions | Vulnerability in plain language | Buffer location |
|---|---|---|---|
| CVE-2019-18634 | sudo 1.8.25p1 → 1.8.31p1 | With `pwfeedback` enabled, specially supplied password input can make sudo write beyond its password buffer. | Global/BSS buffer |
| CVE-2023-0341 | editorconfig-core-c 0.12.5 → 0.12.6 | `ec_glob` can append escaped/expanded pattern characters past a fixed-size pattern buffer. | Stack buffer |
| CVE-2021-3177 | CPython 3.9.1 → 3.9.2 | `PyCArg_repr` formats a very large `ctypes` floating-point value into a fixed-size local buffer. | Stack buffer |

For CVE-2019-18634, the vulnerable behavior depends on `pwfeedback`; it is not enabled in every sudo configuration. See the [Ubuntu advisory](https://ubuntu.com/security/CVE-2019-18634). The [EditorConfig advisory](https://ubuntu.com/security/CVE-2023-0341) describes the `ec_glob` stack overflow and the 0.12.6 fix. The CPython case is described by [Ubuntu](https://ubuntu.com/security/CVE-2021-3177) and the [Python issue](https://bugs.python.org/issue42938).

These are three examples of a relatively narrow weakness family. The pipeline is **not currently a universal detector for arbitrary CVEs** such as authentication bypasses, injection, cryptographic mistakes, or logic flaws. Each target needs a vulnerable/patched source pair, build instructions, the right binary paths, and an appropriate safe probe.

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
3. **Run the probe.** `modules/runner.py` runs each target’s `exploit.py` five times per version and asks for an ASan impact result. Here “exploit” names the probe script; the project’s test goal is safe crash/memory-error reproduction, not weaponized code execution.
4. **Compare compiled programs.** `modules/differ.py` extracts the configured binary from each image, runs Ghidra headlessly to produce BinExport and function evidence, then runs BinDiff. It records similarity/confidence and changed-function candidates.
5. **Generate reports.** `modules/reporter.py` combines metadata and run results into `reports/<CVE-ID>.json` and `.txt`. Root-cause descriptions and patch notes originate in the target metadata; they are curated project data, not automatically discovered by the report generator.
6. **Optionally use Ollama.** The report explanation uses saved report evidence. Blind patch analysis builds/diffs a configured target and gives Ollama source differences, BinDiff information, and selected Ghidra decompilations, without the CVE description or probe result. It can propose hypotheses but cannot verify them. A blind run still needs a configured target; a CVE identifier by itself is not enough.
7. **View results.** `ui.py` provides a small Streamlit dashboard. Its Patch tab shows changed-line counts, a highlighted source diff, version/commit provenance, build instrumentation notes, and available BinDiff candidates. The detailed outputs remain in `reports/` and `.work/artifacts/<CVE-ID>/`.

The report’s `CONFIRMED` label is the program’s threshold-based verdict: the vulnerable build crashed in at least 80% of trials and the patched build in at most 20%. ASan evidence is recorded separately. Interpret that label as a reproducible difference in this configured experiment, **not** as proof of remote reachability, privilege escalation, or arbitrary code execution.

## 5. Methodology and limits

The method is a **paired before/after experiment**:

1. Select a known vulnerable version and its fixed version.
2. Keep the probe input and measurement process the same across both builds.
3. Observe process outcomes and memory-safety diagnostics.
4. Compare the compiled binaries to locate changed functions.
5. Relate runtime and binary evidence to the source patch, then review the evidence manually.

This offers multiple kinds of evidence: a known source change, runtime behavior, sanitizer output, and a compiled-binary comparison. Using all of them gives a reviewer useful cross-checks. None should be treated as a complete proof by itself. BinDiff can surface unrelated build changes; sanitizer findings depend on the instrumented build and input; a passing probe only means that this input did not reproduce the issue in that run; and Ollama can make mistakes. The curated root-cause text is useful documentation but is not an independent discovery result.

The current reports for CVE-2019-18634 and CVE-2023-0341 record crashes and ASan overflow detections in vulnerable builds, and clean/no-overflow observations in their paired patched builds. The CVE-2021-3177 images have been built, but its probe, Ghidra/BinDiff comparison, and final report still need to be run before quoting results for that case.

## 6. Setup and run

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

The normal run builds both images, performs the Ghidra/BinDiff comparison, executes probes, and writes reports. Individual stages can be run with `--step build`, `--step diff`, `--step probe`, or `--step report`; later stages need the outputs from earlier stages. Use an already configured case, such as `CVE-2021-3177`, in place of the example ID.

### Dashboard and Ollama

```sh
.venv311/bin/streamlit run ui.py --server.address 127.0.0.1
```

The dashboard has a **Run full pipeline** button, an **Ollama** tab, and report downloads. For local Ollama, start the Ollama service and install a model first. CLI options are:

```sh
.venv311/bin/python run.py CVE-2019-18634 --step explain --model <model>
.venv311/bin/python run.py CVE-2021-3177 --step blind --model <model>
```

The first explains evidence in a saved report. The second creates a blind patch hypothesis from configured source/binary evidence. Hypotheses are saved in `.work/artifacts/<CVE-ID>/blind_hypothesis.md` and `.json`.

## 7. Where to find results

- `reports/<CVE-ID>.txt`: readable summary.
- `reports/<CVE-ID>.json`: structured metadata, probe outcomes, ASan evidence, BinDiff summary, and any saved report explanation.
- `.work/artifacts/<CVE-ID>/`: extracted binaries, BinExport files, BinDiff database, function decompilations, source patch diff, and blind-analysis artifacts.
- `nday_work/ghidra_projects/`: temporary Ghidra headless projects may be deleted after analysis; import the extracted ELF in the Ghidra GUI for interactive inspection.

## 8. Suggested team contributions

Divide ownership across three people while keeping the workload and presentation contribution balanced. Each member should understand the overall workflow and review the final claims.

| Team member | Main ownership | Concrete contributions and deliverables |
|---|---|---|
| **Member 1 — CVE research and validation** | The vulnerability cases and their evidence. | Verify the vulnerable/fixed versions against upstream references; explain each root cause and patch; maintain target metadata and safe probes with Member 2; interpret the crash and ASan results; prepare the vulnerability background and case-study slides. |
| **Member 2 — Builds and reverse engineering** | Reproducible target builds and binary comparison. | Maintain the vulnerable/patched Dockerfiles; build the isolated images; extract target binaries; run Ghidra, BinExport, and BinDiff; review changed-function candidates with Member 1; document build requirements, binary evidence, and tool limitations. |
| **Member 3 — Pipeline, Ollama, and presentation** | Running the stages together and making results usable. | Maintain the CLI, report generation, Streamlit dashboard, and Ollama explanation/blind-analysis flow; check that reports link back to evidence; write setup/run instructions; prepare the workflow diagram and demo; coordinate the final review and viva preparation. |

### Shared responsibilities

- Each member reviews one other member’s work before the final demonstration.
- All three should be able to explain the project workflow, what the `CONFIRMED` verdict means, and why it does not prove code execution.
- Present together: Member 1 introduces CVEs and the three cases; Member 2 demonstrates the paired builds and Ghidra/BinDiff evidence; Member 3 walks through reports, the dashboard, and Ollama. Everyone answers questions about limitations and methodology.
- Keep a short contribution log showing who completed each deliverable. Swap tasks if someone is blocked, while preserving these three areas of ownership.

## 9. Possible viva questions

1. **What does CVE stand for, and what does its identifier tell us?**  
   Common Vulnerabilities and Exposures; the ID names a publicly disclosed issue. It does not by itself prove the weakness or describe the complete exploit conditions.
2. **How is CWE different from CVE?**  
   CVE identifies a reported instance; CWE categorizes the underlying weakness pattern.
3. **What vulnerability family does N-Day Nexus currently target?**  
   Primarily memory corruption caused by out-of-bounds writes/buffer overflows, including stack and global-buffer cases.
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
    It means the configured crash-rate thresholds differed between vulnerable and patched builds. It does not mean code execution or real-world exploitability was proven.
14. **What is the biggest limitation?**  
    The current target set and probes are narrow and manually configured. Many vulnerability classes do not produce a detectable crash from a simple test input.
15. **What would be the next improvement?**  
    Add more vulnerability families with target-specific evidence and validation, make probes and impact criteria explicit per target, and measure false positives/negatives against a larger benchmark.

## References

- [CVE Program](https://www.cve.org/)
- [MITRE CWE-121: Stack-based Buffer Overflow](https://cwe.mitre.org/data/definitions/121.html)
- [Ubuntu: CVE-2019-18634](https://ubuntu.com/security/CVE-2019-18634)
- [Ubuntu: CVE-2023-0341](https://ubuntu.com/security/CVE-2023-0341)
- [Ubuntu: CVE-2026-40489](https://ubuntu.com/security/CVE-2026-40489)
- [Ubuntu: CVE-2021-3177](https://ubuntu.com/security/CVE-2021-3177)
- [Python issue 42938](https://bugs.python.org/issue42938)
