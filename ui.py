#!/usr/bin/env python3
"""Small local dashboard for running and reviewing N-Day Nexus."""
import json
import subprocess
import sys
from pathlib import Path

import streamlit as st

from modules.ollama_explainer import blind_analyze, explain as explain_with_ollama, list_models
from modules.builder import build
from modules.control_flow_demo import run_control_flow_demo
from modules.source_diff import get_source_comparison


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
        return json.loads((REPORTS / f"{cve_id}.json").read_text())
    except (OSError, json.JSONDecodeError):
        return None


st.set_page_config(page_title="N-Day Nexus", page_icon="🧭", layout="centered")
targets = load_targets()
if not targets:
    st.error("No configured targets found in targets/.")
    st.stop()

st.title("N-Day Nexus")
with st.sidebar:
    cve_id = st.selectbox("CVE target", list(targets))
    run_pipeline = st.button("Run full pipeline", type="primary", use_container_width=True)

if run_pipeline:
    command = [sys.executable, str(ROOT / "run.py"), cve_id]
    with st.spinner(f"Running pipeline for {cve_id}…"):
        try:
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, check=False)
            st.session_state["pipeline_log"] = result.stdout + ("\n" + result.stderr if result.stderr else "")
            st.session_state["pipeline_ok"] = result.returncode == 0
        except OSError as exc:
            st.session_state["pipeline_log"] = str(exc)
            st.session_state["pipeline_ok"] = False
    st.rerun()

if "pipeline_ok" in st.session_state:
    if st.session_state["pipeline_ok"]:
        st.success("Pipeline finished.")
    else:
        st.error("Pipeline failed. See details below.")
    with st.expander("Pipeline output"):
        st.code(st.session_state.get("pipeline_log", ""), language="text")

meta = targets[cve_id]
report = load_report(cve_id)
if report is None:
    report = {}
    st.info("No report yet. Run the pipeline, or use blind analysis below.")

st.subheader(f"{meta.get('program', cve_id)} · {cve_id}")
version = f"{meta.get('version_vuln', '?')} → {meta.get('version_patch', '?')}"
st.caption(f"{version} · {meta.get('bug_type', 'Vulnerability type not recorded')}")

summary, patch_tab, control_flow, ollama, reports = st.tabs(
    ["Overview", "Patch", "Control-flow lab", "Ollama", "Reports"]
)

with summary:
    results = report.get("results", {})
    vulnerable = results.get("vuln", {}).get("impact", {}).get("outcome", "NOT RUN")
    patched = results.get("patched", {}).get("impact", {}).get("outcome", "NOT RUN")
    left, right = st.columns(2)
    left.metric("Vulnerable build · ASan", vulnerable)
    right.metric("Patched build · ASan", patched)
    st.markdown("**Root cause**")
    st.write(report.get("description", meta.get("description", "No report generated yet.")))
    root_cause = report.get("root_cause", {})
    if root_cause.get("source_location"):
        st.caption(f"Location: {root_cause['source_location']}")
    if root_cause.get("source_diff"):
        st.markdown(f"[View upstream patch]({root_cause['source_diff']})")

    st.markdown("**Probe results**")
    probe_results = report.get("results", {})
    vuln_probe = probe_results.get("vuln", {})
    patched_probe = probe_results.get("patched", {})
    left, right = st.columns(2)
    left.caption(f"Vulnerable crashes: {vuln_probe.get('crash_rate', 0):.0%}")
    right.caption(f"Patched crashes: {patched_probe.get('crash_rate', 0):.0%}")
    with st.expander("Probe conditions"):
        st.write(f"Configured input: `{meta.get('trigger_args', [])}`")
        st.write(f"Configured payload size: {meta.get('payload_size', 'not recorded')} bytes")
        st.caption("Crash and ASan results indicate observed behavior; they do not prove code execution.")

with patch_tab:
    st.write("Compare the configured source file from the vulnerable and patched Docker images.")
    comparison_key = f"source_comparison_{cve_id}"
    if st.button("Load source comparison", key=f"source_diff_{cve_id}"):
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
    if not comparison:
        st.caption("Load the comparison to see changed-line counts and the highlighted source diff.")

with control_flow:
    st.markdown("**Synthetic lab · benign callback redirect**")
    st.caption(
        "This self-contained teaching case deliberately places a function pointer after a fixed-size buffer. "
        "It is separate from the selected CVE and does not demonstrate exploitability of a real CVE."
    )
    if st.button("Run benign redirect demo", type="primary", key="run_control_flow_demo"):
        with st.spinner("Building isolated lab images and comparing both outcomes…"):
            try:
                st.session_state["control_flow_demo_result"] = run_control_flow_demo()
                st.session_state.pop("control_flow_demo_error", None)
            except (RuntimeError, OSError, ValueError) as exc:
                st.session_state["control_flow_demo_error"] = str(exc)

    if st.session_state.get("control_flow_demo_error"):
        st.error(st.session_state["control_flow_demo_error"])
    demo_result = st.session_state.get("control_flow_demo_result")
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
    try:
        models = list_models()
    except RuntimeError as exc:
        models = []
        st.info(str(exc))

    if models:
        model = st.selectbox("Local model", models, key=f"model_{cve_id}")
        explain_col, blind_col = st.columns(2)
        explain_clicked = explain_col.button(
            "Explain report", disabled=not load_report(cve_id), key=f"explain_{cve_id}")
        blind_clicked = blind_col.button("Blind patch analysis", key=f"blind_{cve_id}")
        refresh_evidence = st.checkbox(
            "Rebuild images and rerun Ghidra/BinDiff before blind analysis",
            key=f"blind_refresh_{cve_id}",
            help="Leave unchecked to reuse prepared evidence. Turn this on after changing target source or build settings.",
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
    blind_path = ROOT / ".work" / "artifacts" / cve_id / "blind_hypothesis.json"
    if st.session_state.get(f"ollama_mode_{cve_id}") == "blind" and blind_path.is_file():
        try:
            blind_saved = json.loads(blind_path.read_text())
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
    json_path = REPORTS / f"{cve_id}.json"
    text_path = REPORTS / f"{cve_id}.txt"
    if json_path.is_file():
        st.download_button("Download JSON report", json_path.read_bytes(), json_path.name,
                           mime="application/json")
    if text_path.is_file():
        st.download_button("Download text report", text_path.read_bytes(), text_path.name,
                           mime="text/plain")
        with st.expander("Read text report"):
            st.text(text_path.read_text())
    if not json_path.is_file() and not text_path.is_file():
        st.caption("Reports appear here after running the pipeline.")
