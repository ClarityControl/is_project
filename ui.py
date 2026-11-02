#!/usr/bin/env python3
"""Small local dashboard for running and reviewing N-Day Nexus."""
import json
import base64
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import streamlit as st

from modules.ollama_explainer import blind_analyze, explain as explain_with_ollama, list_models
from modules.builder import build
from modules.control_flow_demo import run_control_flow_demo
from modules.source_diff import get_source_comparison
from modules.report_security import (
    VAULT_PATH, ReportSecurityError, clear_active_key, create_vault, encrypt_legacy_reports,
    read_encrypted_artifact, read_json_report, read_report_bytes, set_active_key, unlock_vault,
)


ROOT = Path(__file__).resolve().parent
TARGETS = ROOT / "targets"
REPORTS = ROOT / "reports"


def load_targets():
    result = {}
    for path in sorted(TARGETS.iterdir()):
        meta = path / "meta.json"
        if path.is_dir() and meta.is_file():
            try:
                result[path.name] = json.loads(meta.read_text())
            except (OSError, json.JSONDecodeError):
                continue
    return result


def load_report(cve_id):
    try:
        return read_json_report(cve_id)
    except (OSError, json.JSONDecodeError, ReportSecurityError):
        return None


def run_pipeline_with_progress(command, status, timeout=5400):
    """Run one target pipeline with streamed output and a hard overall deadline."""
    env = os.environ.copy()
    env["PYTHONUNBUFFERED"] = "1"
    env["NDAY_REPORT_KEY"] = base64.b64encode(st.session_state["report_key"]).decode("ascii")
    process = subprocess.Popen(
        command, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, env=env, start_new_session=True,
    )
    output_queue = queue.Queue()

    def collect_output():
        try:
            for line in process.stdout:
                output_queue.put(line)
        finally:
            output_queue.put(None)

    reader = threading.Thread(target=collect_output, daemon=True)
    reader.start()
    lines = []
    tail = []
    deadline = time.monotonic() + timeout
    reader_finished = False
    timed_out = False
    log_view = st.empty()

    while not (reader_finished and process.poll() is not None):
        if time.monotonic() >= deadline:
            timed_out = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            break
        try:
            line = output_queue.get(timeout=0.5)
        except queue.Empty:
            continue
        if line is None:
            reader_finished = True
            continue
        lines.append(line)
        tail.append(line)
        if len(tail) > 60:
            tail.pop(0)
        message = line.strip()
        if message:
            status.update(label=message[-120:], state="running", expanded=True)
            log_view.code("".join(tail), language="text")

    reader.join(timeout=2)
    return process.returncode, "".join(lines[-2000:]), timed_out


st.set_page_config(page_title="N-Day Nexus", page_icon="🧭", layout="wide")

if not st.session_state.get("report_authenticated"):
    st.title("N-Day Nexus · Report vault")
    first_setup = not VAULT_PATH.exists()
    artifact_dir = ROOT / ".work" / "artifacts"
    encrypted_reports_present = (
        (any(REPORTS.glob("*.enc")) if REPORTS.is_dir() else False)
        or (any(artifact_dir.glob("*/blind_hypothesis.*.enc")) if artifact_dir.is_dir() else False)
    )
    if first_setup and encrypted_reports_present:
        st.error("Encrypted reports exist but the vault settings are missing. Restore `.work/report_vault.json` to unlock them; creating a new vault cannot recover those files.")
        st.stop()
    st.write("Set a password to encrypt reports." if first_setup else "Enter your report password to unlock the dashboard.")
    with st.form("report_vault_login"):
        password = st.text_input("Report password", type="password")
        confirmation = st.text_input("Confirm password", type="password") if first_setup else None
        submitted = st.form_submit_button("Create encrypted vault" if first_setup else "Unlock dashboard", type="primary")
    if submitted:
        try:
            if first_setup:
                if password != confirmation:
                    raise ReportSecurityError("The passwords do not match.")
                key = create_vault(password)
            else:
                key = unlock_vault(password)
            st.session_state["report_migrated_count"] = encrypt_legacy_reports(key)
            set_active_key(key)
            st.session_state["report_key"] = key
            st.session_state["report_authenticated"] = True
            st.rerun()
        except ReportSecurityError as exc:
            st.error(str(exc))
    st.stop()

try:
    set_active_key(st.session_state["report_key"])
except (KeyError, ReportSecurityError):
    st.session_state.pop("report_authenticated", None)
    st.session_state.pop("report_key", None)
    st.rerun()

targets = load_targets()
if not targets:
    st.error("No configured targets found in targets/.")
    st.stop()

st.title("N-Day Nexus")
with st.sidebar:
    st.caption("Report vault unlocked")
    if st.button("Lock dashboard", use_container_width=True):
        clear_active_key()
        st.session_state.pop("report_authenticated", None)
        st.session_state.pop("report_key", None)
        st.rerun()
    target_options = list(targets)
    preferred_target = "CVE-2026-109618"
    default_target_index = (target_options.index(preferred_target)
                            if preferred_target in target_options else 0)
    cve_id = st.selectbox("CVE target", target_options, index=default_target_index)

meta = targets[cve_id]
crypto_mode_selected = meta.get("probe", {}).get("mode") == "crypto"
st.subheader(f"{meta.get('program', cve_id)} · {cve_id}")
version = f"{meta.get('version_vuln', '?')} → {meta.get('version_patch', '?')}"
st.caption(f"{version} · {meta.get('bug_type', 'Vulnerability type not recorded')}")

if crypto_mode_selected:
    action_left, action_right = st.columns(2)
    run_pipeline = action_left.button("Run full pipeline", type="primary", use_container_width=True)
    run_crypto_demo = action_right.button("Run crypto demo", use_container_width=True)
else:
    run_pipeline = st.button("Run full pipeline", type="primary")
    run_crypto_demo = False

if run_crypto_demo:
    exploit = TARGETS / cve_id / "exploit.py"
    crypto_events = {}
    for variant in ("vuln", "patched"):
        try:
            result = subprocess.run([sys.executable, str(exploit), variant], cwd=ROOT,
                                    capture_output=True, text=True, timeout=15)
            line = result.stdout.strip().splitlines()[-1] if result.stdout.strip() else ""
            event = json.loads(line) if line else {"outcome": "ERROR", "error": result.stderr[-1000:]}
            if result.returncode not in (0, 1):
                event["outcome"] = "ERROR"
            crypto_events[variant] = event
        except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
            crypto_events[variant] = {"outcome": "ERROR", "error": str(exc)}
    st.session_state[f"crypto_demo_{cve_id}"] = crypto_events

if run_pipeline:
    command = [sys.executable, "-u", str(ROOT / "run.py"), cve_id]
    progress = st.status(f"Starting {cve_id} pipeline (90 minute limit)…", expanded=True)
    try:
        returncode, output, timed_out = run_pipeline_with_progress(command, progress)
        st.session_state["pipeline_log"] = output
        st.session_state["pipeline_ok"] = returncode == 0 and not timed_out
        if timed_out:
            st.session_state["pipeline_log"] += "\nPipeline stopped after the 90 minute dashboard limit."
            progress.update(label="Pipeline timed out", state="error", expanded=True)
        elif returncode:
            progress.update(label="Pipeline failed; see streamed output", state="error", expanded=True)
        else:
            progress.update(label="Pipeline complete", state="complete", expanded=False)
    except OSError as exc:
        st.session_state["pipeline_log"] = str(exc)
        st.session_state["pipeline_ok"] = False
        progress.update(label="Could not start pipeline", state="error", expanded=True)
    st.rerun()

report = load_report(cve_id)
if report is None:
    report = {}

overview, evidence, validation, control_flow, ollama, reports = st.tabs(
    ["Overview", "Patch evidence", "Runtime validation", "Control-flow lab", "Ollama", "Reports"]
)

with overview:
    if "pipeline_ok" in st.session_state:
        if st.session_state["pipeline_ok"]:
            st.success("Pipeline finished.")
        else:
            st.error("Pipeline stopped or failed. See the run output below.")
        with st.expander("Pipeline output", expanded=not st.session_state["pipeline_ok"]):
            st.code(st.session_state.get("pipeline_log", ""), language="text")
    if not report:
        st.info("No report yet. Run the pipeline, or use blind analysis from the Ollama tab.")
    elif report.get("status") == "PRELIMINARY":
        st.caption("Report status: preliminary · binary comparison and runtime validation are pending")

    results = report.get("results", {})
    vulnerable = results.get("vuln", {}).get("impact", {}).get("outcome", "NOT RUN")
    patched = results.get("patched", {}).get("impact", {}).get("outcome", "NOT RUN")
    rce_mode = meta.get("probe", {}).get("mode") == "rce"
    crypto_mode = meta.get("probe", {}).get("mode") == "crypto"
    left, right = st.columns(2)
    left.metric("Vulnerable · crypto behavior" if crypto_mode else "Vulnerable · command proof" if rce_mode else "Vulnerable build · ASan", vulnerable)
    right.metric("Patched · crypto behavior" if crypto_mode else "Patched · command proof" if rce_mode else "Patched build · ASan", patched)
    st.markdown("**Root cause**")
    st.write(report.get("description", meta.get("description", "No report generated yet.")))
    root_cause = report.get("root_cause", {})
    if root_cause.get("source_location"):
        st.caption(f"Location: {root_cause['source_location']}")
    if root_cause.get("source_diff"):
        st.markdown(f"[View upstream patch]({root_cause['source_diff']})")

    with st.expander("Root-cause details"):
        st.write(root_cause.get("vulnerable_operation", "No detailed root-cause evidence recorded yet."))
        if root_cause.get("patch_change"):
            st.markdown("**Patch change**")
            st.write(root_cause["patch_change"])

with validation:
    st.markdown("Review the observed vulnerable-versus-patched behavior and probe conditions here.")
    results = report.get("results", {})
    rce_mode = meta.get("probe", {}).get("mode") == "rce"
    crypto_mode = meta.get("probe", {}).get("mode") == "crypto"
    st.markdown("**Probe results**")
    if crypto_mode and st.session_state.get(f"crypto_demo_{cve_id}"):
        demo = st.session_state[f"crypto_demo_{cve_id}"]
        left, right = st.columns(2)
        left.markdown("**Vulnerable build**")
        left.json(demo.get("vuln", {}))
        right.markdown("**Patched build**")
        right.json(demo.get("patched", {}))
    probe_results = report.get("results", {})
    vuln_probe = probe_results.get("vuln", {})
    patched_probe = probe_results.get("patched", {})
    left, right = st.columns(2)
    if crypto_mode:
        left.caption(f"Vulnerable effective-IV collision: {vuln_probe.get('crypto_weakness_rate', 0):.0%}")
        right.caption(f"Patched distinct-IV behavior: {patched_probe.get('crypto_distinct_rate', 0):.0%}")
        with st.expander("AES-GCM evidence"):
            left, right = st.columns(2)
            left.markdown("**Vulnerable sample**")
            left.json((vuln_probe.get("trials") or [{}])[0])
            right.markdown("**Patched sample**")
            right.json((patched_probe.get("trials") or [{}])[0])
    elif rce_mode:
        if not vuln_probe.get("trials"):
            left.caption("Vulnerable command proof: NOT RUN")
        else:
            left.caption(f"Vulnerable command proof: {vuln_probe.get('rce_rate', 0):.0%}")
        if not patched_probe.get("trials"):
            right.caption("Patched command proof: NOT RUN")
        else:
            right.caption(f"Patched command proof: {patched_probe.get('rce_rate', 0):.0%}")
    else:
        left.caption(f"Vulnerable crashes: {vuln_probe.get('crash_rate', 0):.0%}")
        right.caption(f"Patched crashes: {patched_probe.get('crash_rate', 0):.0%}")
    with st.expander("Probe conditions"):
        if crypto_mode:
            st.write(meta.get("probe", {}).get("label", "Cryptographic behavior probe"))
            st.caption(meta.get("probe", {}).get("limitation", "Local test only; interpret the output with the CVE advisory."))
        elif rce_mode:
            st.write(f"Benign command: `{meta.get('probe', {}).get('command', 'not recorded')}`")
            st.caption("RCE probe runs only inside a Docker container with networking disabled and no published host port.")
        else:
            st.write(f"Configured input: `{meta.get('trigger_args', [])}`")
            st.write(f"Configured payload size: {meta.get('payload_size', 'not recorded')} bytes")
            st.caption("Crash and ASan results indicate observed behavior; they do not prove code execution.")

with evidence:
    binary_diff = report.get("diff", {})
    source_summary = binary_diff.get("source_comparison", {})
    symbol_summary = binary_diff.get("symbol_comparison", {})
    if binary_diff.get("analysis_method") == "source_and_symbols":
        st.markdown("**PHP patch evidence · source and ELF symbols**")
        st.caption(binary_diff.get("diff_summary", "Source and symbol comparison completed."))
        source_cols = st.columns(3)
        source_cols[0].metric("Source lines changed", source_summary.get("changed_lines", 0))
        source_cols[1].metric("Files changed", len(source_summary.get("source_paths", [])))
        source_cols[2].metric("Symbols added / removed",
                              f"{symbol_summary.get('added_symbol_count', 0)} / {symbol_summary.get('removed_symbol_count', 0)}")
        st.caption("Changed source files: " + ", ".join(source_summary.get("source_paths", [])))
        source_artifact = source_summary.get("artifact", "")
        source_file = (ROOT / source_artifact).resolve() if source_artifact else None
        if source_file and source_file.is_relative_to(ROOT) and source_file.is_file():
            patch_text = source_file.read_text(errors="replace")
            st.download_button("Download full PHP source diff", patch_text,
                               file_name=f"{cve_id}-source-patch.diff", mime="text/x-diff")
            st.code(patch_text[:30000], language="diff", line_numbers=True, wrap_lines=False)
            if len(patch_text) > 30000:
                st.caption("The full patch is available from the download button.")
        focus_symbols = symbol_summary.get("focus_symbols", [])
        if focus_symbols:
            st.markdown("**Focused symbol changes**")
            st.dataframe([{
                "Symbol": item.get("name"), "Comparison": item.get("status"),
                "Vulnerable address": (item.get("vulnerable") or {}).get("address", "—"),
                "Patched address": (item.get("patched") or {}).get("address", "—"),
            } for item in focus_symbols], hide_index=True, use_container_width=True)
        st.caption("Address changes can result from layout differences; source changes provide the root-cause context.")
        with st.expander("Symbol comparison details"):
            st.write(f"Defined symbols: vulnerable {symbol_summary.get('defined_symbol_count', {}).get('vuln', 0)} · patched {symbol_summary.get('defined_symbol_count', {}).get('patched', 0)}")
            st.write(f"Symbol artifact: `{ROOT / symbol_summary['artifact']}`" if symbol_summary.get("artifact") else "Symbol artifact unavailable.")
            added = symbol_summary.get("added_symbols", [])
            removed = symbol_summary.get("removed_symbols", [])
            left, right = st.columns(2)
            left.markdown("**Added**")
            left.code("\n".join(added[:80]) or "None")
            right.markdown("**Removed**")
            right.code("\n".join(removed[:80]) or "None")
    else:
        st.write("Compare the configured source file from the vulnerable and patched Docker images.")
    comparison_key = f"source_comparison_{cve_id}"
    if binary_diff.get("analysis_method") != "source_and_symbols" and st.button("Load source comparison", key=f"source_diff_{cve_id}"):
        with st.spinner("Preparing the target images and extracting the source change…"):
            try:
                build(cve_id)
                st.session_state[comparison_key] = get_source_comparison(cve_id)
                st.session_state.pop(f"source_diff_error_{cve_id}", None)
            except (RuntimeError, OSError, ValueError) as exc:
                st.session_state[f"source_diff_error_{cve_id}"] = str(exc)
    if st.session_state.get(f"source_diff_error_{cve_id}"):
        st.error(st.session_state[f"source_diff_error_{cve_id}"])

    comparison = st.session_state.get(comparison_key)
    if comparison:
        st.caption(f"{comparison['source_path']} · {comparison['function'] or 'function not specified'}")
        count_cols = st.columns(3)
        count_cols[0].metric("Lines changed", comparison["changed_lines"])
        count_cols[1].metric("Added", f"+{comparison['additions']}")
        count_cols[2].metric("Removed", f"−{comparison['deletions']}")
        st.caption("Counts cover the configured source file. LOC describes patch size, not severity.")
        if comparison.get("display_truncated"):
            st.info("The display is narrowed to relevant patch hunks. Download the full diff to review all changes.")
        diff_path = comparison["diff_path"]
        st.download_button("Download full source diff", diff_path.read_bytes(),
                           file_name=f"{cve_id}-source-patch.diff", mime="text/x-diff")
        st.code(comparison["diff"], language="diff", line_numbers=True, wrap_lines=False)

        with st.expander("Version and patch provenance"):
            target_meta = comparison["meta"]
            st.write(f"Vulnerable: {target_meta.get('version_vuln', '?')} · commit `{target_meta.get('vuln_commit', 'not recorded')}`")
            st.write(f"Patched: {target_meta.get('version_patch', '?')} · commit `{target_meta.get('patched_commit', 'not recorded')}`")
            st.markdown(f"[CVE record](https://www.cve.org/CVERecord?id={cve_id})")
            source_diff = target_meta.get("root_cause", {}).get("source_diff")
            if source_diff:
                st.markdown(f"[Upstream patch reference]({source_diff})")
        with st.expander("Build and instrumentation details"):
            for variant in ("vuln", "patched"):
                st.markdown(f"**{variant.capitalize()} image**")
                details = comparison["build_details"].get(variant, [])
                st.code("\n".join(details) if details else "No build flags recorded in Dockerfile.",
                        language="dockerfile")

    changed_functions = report.get("diff", {}).get("changed_function_matches", [])
    if changed_functions:
        with st.expander("Changed binary functions · BinDiff candidates"):
            st.caption("Candidates are ranked by binary similarity; review them against source and runtime evidence.")
            st.dataframe([
                {"Vulnerable function": item.get("vulnerable_name"),
                 "Patched function": item.get("patched_name"),
                 "Similarity": item.get("similarity"),
                 "Confidence": item.get("confidence")}
                for item in changed_functions[:8]
            ], hide_index=True, use_container_width=True)
    if not comparison and binary_diff.get("analysis_method") != "source_and_symbols":
        st.caption("Load the comparison to see changed-line counts and the highlighted source diff.")

with control_flow:
    st.markdown("**Synthetic lab · benign callback redirect**")
    st.caption(
        "This self-contained teaching case deliberately places a function pointer after a fixed-size buffer. "
        "It is separate from the selected CVE and does not demonstrate exploitability of a real CVE."
    )
    st.caption("The lab builds two local images. Build progress is shown below and each build has a 10 minute limit.")
    if st.button("Run benign redirect demo", type="primary", key="run_control_flow_demo"):
        progress = st.status("Preparing isolated lab…", expanded=True)

        def update_lab_progress(message):
            progress.update(label=message, state="running", expanded=True)

        try:
            st.session_state["control_flow_demo_result"] = run_control_flow_demo(
                progress=update_lab_progress
            )
            st.session_state.pop("control_flow_demo_error", None)
            progress.update(label="Lab demo complete", state="complete", expanded=False)
        except (RuntimeError, OSError, ValueError) as exc:
            st.session_state["control_flow_demo_error"] = str(exc)
            progress.update(label="Lab demo failed", state="error", expanded=True)

    if st.session_state.get("control_flow_demo_error"):
        st.error(st.session_state["control_flow_demo_error"])
    demo_result = st.session_state.get("control_flow_demo_result")
    if demo_result is None:
        saved_demo = ROOT / ".work" / "artifacts" / "LAB-CFH-001" / "control_flow_demo.json"
        if saved_demo.is_file():
            try:
                demo_result = json.loads(saved_demo.read_text())
                st.session_state["control_flow_demo_result"] = demo_result
            except (OSError, json.JSONDecodeError):
                demo_result = None
    if demo_result:
        vuln_col, patch_col = st.columns(2)
        vuln_col.metric("Vulnerable lab", "Redirected" if demo_result["vulnerable"]["redirected"] else "No redirect")
        patch_col.metric("Patched lab", "Rejected" if demo_result["patched"]["rejected"] else "Not rejected")
        st.code(demo_result["vulnerable"]["output"], language="text")
        with st.expander("Patched build output"):
            st.code(demo_result["patched"]["output"], language="text")
        st.caption(
            f"Payload: {demo_result['payload_bytes']} bytes · callback offset: "
            f"{demo_result['callback_offset']} · target: {demo_result['benign_target']} · "
            "No shell or external command is invoked."
        )
        artifact = ROOT / ".work" / "artifacts" / "LAB-CFH-001" / "control_flow_demo.json"
        if artifact.is_file():
            st.download_button("Download demo evidence", artifact.read_bytes(),
                               file_name="LAB-CFH-001-control-flow-demo.json",
                               mime="application/json")
        with st.expander("What this demonstrates"):
            st.write("The vulnerable build lets input overwrite a callback pointer, then dispatches to a fixed function that prints HELLO WORLD. The patched build checks input length and rejects the same bytes.")
            st.caption("This confirms the mechanics in this synthetic program only. Real CVE targets need their own safe, case-specific evidence.")

with ollama:
    if meta.get("diff_strategy") == "source_symbols":
        st.caption("For PHP, report explanation uses the six-file source patch, ELF symbol comparison, and runtime probe results.")
    try:
        models = list_models()
    except RuntimeError as exc:
        models = []
        st.info(str(exc))

    if models:
        model = st.selectbox("Local model", models, key=f"model_{cve_id}")
        explain_col, blind_col = st.columns(2)
        explain_clicked = explain_col.button(
            "Explain report",
            disabled=(not load_report(cve_id) or report.get("status") == "PRELIMINARY"),
            key=f"explain_{cve_id}",
            help="Complete the binary comparison and runtime probes before asking Ollama to explain the report."
            if report.get("status") == "PRELIMINARY" else None,
        )
        blind_clicked = blind_col.button("Blind patch analysis", key=f"blind_{cve_id}")
        refresh_evidence = st.checkbox(
            "Rebuild images and refresh patch evidence before blind analysis",
            key=f"blind_refresh_{cve_id}",
            help="Turn this on after changing target source or build settings; the target's configured analysis method will run.",
        )

        if explain_clicked or blind_clicked:
            st.session_state.pop(f"ollama_error_{cve_id}", None)
            st.session_state.pop(f"ollama_result_{cve_id}", None)
            st.session_state.pop(f"ollama_mode_{cve_id}", None)
            if explain_clicked:
                label = "Generating a concise explanation…"
                progress_area = st.status(label, expanded=True)
                try:
                    generated = explain_with_ollama(cve_id, model)
                    progress_area.update(label="Explanation complete", state="complete", expanded=False)
                    st.session_state[f"ollama_result_{cve_id}"] = generated.get("text", "")
                    st.session_state[f"ollama_label_{cve_id}"] = generated.get("label", "Model hypothesis")
                    st.session_state[f"ollama_mode_{cve_id}"] = "report"
                    st.session_state[f"ollama_seconds_{cve_id}"] = generated.get("generation_seconds")
                except (RuntimeError, OSError) as exc:
                    progress_area.update(label="Explanation failed", state="error", expanded=True)
                    st.session_state[f"ollama_error_{cve_id}"] = str(exc)
            else:
                progress_area = st.status("Preparing blind-analysis evidence…", expanded=True)

                def update_blind_progress(message):
                    progress_area.update(label=message, state="running", expanded=True)

                try:
                    generated = blind_analyze(
                        cve_id, model, refresh_evidence=refresh_evidence,
                        progress=update_blind_progress,
                    )
                    progress_area.update(label="Blind analysis complete", state="complete", expanded=False)
                    st.session_state[f"ollama_result_{cve_id}"] = generated.get("hypothesis_text", "")
                    st.session_state[f"ollama_label_{cve_id}"] = generated.get("label", "Model hypothesis")
                    st.session_state[f"ollama_mode_{cve_id}"] = "blind"
                    st.session_state[f"ollama_seconds_{cve_id}"] = generated.get("generation_seconds")
                    st.session_state[f"ollama_cache_hit_{cve_id}"] = generated.get("evidence_cache_reused", False)
                    st.session_state[f"ollama_preparation_seconds_{cve_id}"] = generated.get("preparation_seconds")
                except (RuntimeError, OSError) as exc:
                    progress_area.update(label="Blind analysis failed", state="error", expanded=True)
                    st.session_state[f"ollama_error_{cve_id}"] = str(exc)

    if st.session_state.get(f"ollama_error_{cve_id}"):
        st.error(st.session_state[f"ollama_error_{cve_id}"])

    saved_text = st.session_state.get(f"ollama_result_{cve_id}")
    saved_label = st.session_state.get(f"ollama_label_{cve_id}", "Model hypothesis")
    if not saved_text and not st.session_state.get(f"ollama_error_{cve_id}"):
        saved = report.get("llm_explanation", {})
        saved_text = saved.get("text", "")
        saved_label = saved.get("label", saved_label)
    blind_path = ROOT / ".work" / "artifacts" / cve_id / "blind_hypothesis.json.enc"
    if st.session_state.get(f"ollama_mode_{cve_id}") == "blind" and blind_path.is_file():
        try:
            blind_saved = json.loads(read_encrypted_artifact(blind_path).decode("utf-8"))
            saved_text = blind_saved.get("hypothesis_text", "")
        except (OSError, json.JSONDecodeError):
            saved_text = ""
        saved_label = "Blind patch analysis · hypothesis"
    if saved_text:
        st.caption(saved_label)
        duration = st.session_state.get(f"ollama_seconds_{cve_id}")
        if duration is not None:
            prep = st.session_state.get(f"ollama_preparation_seconds_{cve_id}")
            timing = f"Model generation: {duration}s"
            if prep is not None:
                timing = f"Evidence preparation: {prep}s · {timing}"
            if st.session_state.get(f"ollama_cache_hit_{cve_id}"):
                timing += " · reused Ghidra/BinDiff evidence"
            st.caption(timing)
        st.markdown(saved_text)
    elif not st.session_state.get(f"ollama_error_{cve_id}"):
        st.caption("Choose a mode above. Blind analysis can run without a saved report.")
    else:
        st.warning("No hypothesis text was received. The error above explains why; you can retry with a shorter prompt or another local model.")

with reports:
    json_path = REPORTS / f"{cve_id}.json.enc"
    text_path = REPORTS / f"{cve_id}.txt.enc"
    if json_path.is_file():
        st.download_button("Download JSON report", read_report_bytes(cve_id, "json"),
                           f"{cve_id}.json", mime="application/json")
    if text_path.is_file():
        text_report = read_report_bytes(cve_id, "txt").decode("utf-8")
        st.download_button("Download text report", text_report, f"{cve_id}.txt",
                           mime="text/plain")
        with st.expander("Read text report"):
            st.text(text_report)
    if not json_path.is_file() and not text_path.is_file():
        st.caption("Reports appear here after running the pipeline.")
