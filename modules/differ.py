"""Analyze and compare the binaries from the vulnerable and patched images."""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".work"


def _ghidra_home() -> Path:
    configured = os.environ.get("NDAY_GHIDRA_HOME") or os.environ.get("GHIDRA_HOME")
    if configured:
        home = Path(configured).expanduser().resolve()
        if (home / "support" / "analyzeHeadless").is_file():
            return home
        raise RuntimeError(f"GHIDRA_HOME has no support/analyzeHeadless: {home}")
    candidates = sorted(Path("/opt").glob("ghidra_*/support/analyzeHeadless"), reverse=True)
    if candidates:
        return candidates[0].parent.parent
    raise RuntimeError("Ghidra not found; set NDAY_GHIDRA_HOME to its installation directory")


def _bindiff_binary() -> Path:
    configured = os.environ.get("NDAY_BINDIFF")
    candidates = [Path(configured).expanduser() if configured else None,
                  ROOT / ".tools" / "bindiff" / "bin" / "bindiff"]
    for candidate in candidates:
        if candidate and candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate.resolve()
    found = shutil.which("bindiff")
    if found:
        return Path(found)
    raise RuntimeError("BinDiff not found; run scripts/setup_reverse_tools.sh or set NDAY_BINDIFF")


def _ghidra_settings_name(home: Path) -> str:
    props = home / "Ghidra" / "application.properties"
    values = dict(re.findall(r"^(application\.(?:version|release\.name))=(.*)$",
                             props.read_text(), re.MULTILINE))
    version = values.get("application.version")
    if not version:
        raise RuntimeError(f"Could not read Ghidra version from {props}")
    release = values.get("application.release.name", "").strip()
    return f"ghidra_{version}_{release}" if release else f"ghidra_{version}"


def _extract_binary(image: str, variant: str, source: str, destination: Path) -> None:
    container = f"ndaynexus-diff-{variant}-{os.getpid()}"
    subprocess.run(["docker", "create", "--name", container, image], check=True,
                   capture_output=True, text=True)
    try:
        subprocess.run(["docker", "cp", f"{container}:{source}", str(destination)],
                       check=True, capture_output=True, text=True)
    finally:
        subprocess.run(["docker", "rm", container], check=False, capture_output=True)


def _export_binexport(ghidra: Path, variant: str, binary: Path, output: Path,
                      evidence: Path, affected_function: str) -> None:
    settings_name = _ghidra_settings_name(ghidra)
    config_home = WORK / "ghidra_config"
    ext = config_home / "ghidra" / settings_name / "Extensions" / "BinExport"
    script = ext / "ghidra_scripts" / "BinExport.java"
    if not script.is_file():
        raise RuntimeError(
            f"BinExport extension for Ghidra {version} is missing at {ext}; "
            "run scripts/setup_reverse_tools.sh"
        )

    script_dir = WORK / "scripts" / variant
    script_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(script, script_dir / "BinExport.java")
    shutil.copy2(ROOT / "tools" / "ghidra_scripts" / "ExportFunctionEvidence.java",
                 script_dir / "ExportFunctionEvidence.java")
    (script_dir / "BinExport.properties").write_text(
        f'Choose export file Export = {output}\n'
        'Choose options IDA Pro Compatibility = "Subtract Imagebase;Remap mnemonics;Prepend Namespace to Function Names"\n'
    )
    # Ghidra rejects project paths containing a dot-prefixed directory component.
    project_dir = ROOT / "nday_work" / "ghidra_projects"
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = f"NDay_{variant}_{os.getpid()}"
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(config_home)
    command = [str(ghidra / "support" / "analyzeHeadless"), str(project_dir), project_name,
               "-import", str(binary), "-postScript", "BinExport.java", "-scriptPath",
               str(script_dir), "-postScript", "ExportFunctionEvidence.java", affected_function,
               str(evidence), "-deleteProject"]
    proc = subprocess.run(command, check=False, capture_output=True, text=True, env=env, timeout=900)
    if (proc.returncode or not output.is_file() or output.stat().st_size == 0
            or not evidence.is_file()):
        detail = (proc.stdout + "\n" + proc.stderr)[-6000:]
        raise RuntimeError(f"Ghidra/BinExport failed for {variant}:\n{detail}")


def _run_bindiff(binary: Path, first: Path, second: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    proc = subprocess.run([str(binary), f"--output_dir={out_dir}", str(first), str(second)],
                          check=False, capture_output=True, text=True, timeout=900)
    dbs = sorted(out_dir.glob("*.BinDiff"))
    if proc.returncode or not dbs:
        detail = (proc.stdout + "\n" + proc.stderr)[-6000:]
        raise RuntimeError(f"BinDiff failed:\n{detail}")
    return dbs[0]


def _read_bindiff(path: Path, affected: str) -> dict:
    with sqlite3.connect(path) as db:
        rows = db.execute(
            'SELECT name1, name2, address1, address2, similarity, confidence, flags, algorithm '
            'FROM "function" ORDER BY similarity ASC, confidence DESC'
        ).fetchall()
        counts = db.execute('SELECT functions FROM file ORDER BY id').fetchall()
        similarity, confidence = db.execute(
            "SELECT similarity, confidence FROM metadata"
        ).fetchone()
    matches = [{"vulnerable_name": r[0], "patched_name": r[1],
                "vulnerable_address": hex(r[2]), "patched_address": hex(r[3]),
                "similarity": round(float(r[4]), 5), "confidence": round(float(r[5]), 5),
                "flags": r[6], "algorithm_id": r[7]} for r in rows]
    changed = [m for m in matches if m["similarity"] < 0.99999]
    named = [m for m in matches if affected and m["vulnerable_name"] == affected
             and m["patched_name"] == affected]
    return {"engine": "Ghidra + BinExport + BinDiff", "similarity": round(float(similarity), 5),
            "confidence": round(float(confidence), 5), "function_counts": [r[0] for r in counts],
            "matched_function_count": len(matches), "changed_candidates": changed[:100],
            "affected_function_matches": named, "function_matches": matches}


def _export_candidate_decompilations(ghidra: Path, variant: str, binary: Path,
                                     candidates: list[dict], output: Path) -> None:
    """Decompile a short BinDiff-ranked candidate list for blind review."""
    addresses = []
    key = "vulnerable_address" if variant == "vuln" else "patched_address"
    for candidate in candidates[:10]:
        address = candidate.get(key, "")
        if re.fullmatch(r"0x[0-9a-fA-F]+", address):
            addresses.append(address)
    if not addresses:
        output.write_text('{"functions": []}\n')
        return
    settings_name = _ghidra_settings_name(ghidra)
    script_dir = WORK / "scripts" / variant
    script_dir.mkdir(parents=True, exist_ok=True)
    script = script_dir / "ExportCandidateEvidence.java"
    shutil.copy2(ROOT / "tools" / "ghidra_scripts" / "ExportCandidateEvidence.java", script)
    project_dir = ROOT / "nday_work" / "ghidra_projects"
    project_dir.mkdir(parents=True, exist_ok=True)
    project_name = f"NDay_candidates_{variant}_{os.getpid()}"
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(WORK / "ghidra_config")
    command = [str(ghidra / "support" / "analyzeHeadless"), str(project_dir), project_name,
               "-import", str(binary), "-scriptPath", str(script_dir),
               "-postScript", script.name, str(output), *addresses,
               "-deleteProject"]
    proc = subprocess.run(command, check=False, capture_output=True, text=True, env=env, timeout=900)
    if proc.returncode or not output.is_file() or output.stat().st_size == 0:
        detail = (proc.stdout + "\n" + proc.stderr)[-5000:]
        raise RuntimeError(f"Ghidra candidate decompilation failed for {variant}:\n{detail}")


def diff(cve_id: str, include_candidate_decomp: bool = False) -> dict:
    target = ROOT / "targets" / cve_id
    meta = json.loads((target / "meta.json").read_text())
    if not meta.get("patched_ref"):
        raise ValueError(f"{cve_id} has no validated patch reference")

    ghidra = _ghidra_home()
    bindiff = _bindiff_binary()
    artifact_dir = WORK / "artifacts" / cve_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    exported = {}
    diff_paths = meta.get("diff_binary_paths", {})
    common_path = meta.get("diff_binary_path")
    for variant in ("vuln", "patched"):
        image = f"ndaynexus-{cve_id.lower()}-{variant}"
        binary_name = meta["binary_name"]
        source = diff_paths.get(variant) or common_path or f"/usr/local/bin/{binary_name}_{variant}"
        extracted = artifact_dir / f"{variant}.elf"
        export = artifact_dir / f"{variant}.BinExport"
        evidence = artifact_dir / f"{variant}_function.json"
        _extract_binary(image, variant, source, extracted)
        _export_binexport(ghidra, variant, extracted, export, evidence,
                          meta.get("function") or "__no_known_affected_function__")
        exported[variant] = export

    db = _run_bindiff(bindiff, exported["vuln"], exported["patched"], artifact_dir)
    data = _read_bindiff(db, meta["function"])
    candidates = data["changed_candidates"]
    affected = data["affected_function_matches"]
    reviewed_candidates = [m for m in candidates if m["confidence"] >= 0.60
                           and m["vulnerable_name"] and m["patched_name"]
                           and not m["vulnerable_name"].startswith("UndefinedFunction_")
                           and not m["patched_name"].startswith("UndefinedFunction_")]
    candidate_evidence_files = []
    if include_candidate_decomp:
        for variant in ("vuln", "patched"):
            evidence_path = artifact_dir / f"{variant}_changed_functions.json"
            _export_candidate_decompilations(ghidra, variant, artifact_dir / f"{variant}.elf",
                                             reviewed_candidates, evidence_path)
            candidate_evidence_files.append(str(evidence_path.relative_to(ROOT)))
    changed_names = sorted({name for item in reviewed_candidates
                            for name in (item["vulnerable_name"], item["patched_name"])
                            if name and not name.startswith("UndefinedFunction_")})
    full_evidence = {variant: json.loads((artifact_dir / f"{variant}_function.json").read_text())
                     for variant in ("vuln", "patched")}
    evidence_summary = {}
    for variant, evidence in full_evidence.items():
        evidence_summary[variant] = {k: v for k, v in evidence.items() if k != "decompiled"}
        evidence_summary[variant]["decompiled_characters"] = len(evidence.get("decompiled", ""))
    # The advisory's affected function is retained as a separately labeled match,
    # never promoted to a changed candidate unless BinDiff reports a code difference.
    summary = (f"{data['engine']} matched {data['matched_function_count']} functions "
               f"(overall similarity {data['similarity']:.3f}, confidence {data['confidence']:.3f}); "
               f"{len(candidates)} lower-similarity matches, of which {len(reviewed_candidates)} "
               f"have confidence >= 0.60 and recovered names. "
               f"Affected-function matches: {len(affected)} ({meta.get('function') or 'unspecified'}).")
    data.update({"changed_functions": changed_names,
                 "changed_function_matches": reviewed_candidates[:100],
                 "changed_match_count": len(candidates),
                 "low_confidence_matches_excluded": len(candidates) - len(reviewed_candidates),
                 "function_evidence": evidence_summary,
                 "diff_binary_path": str(db.relative_to(ROOT)),
                 "binexport_files": [str(p.relative_to(ROOT)) for p in exported.values()],
                 "function_evidence_files": [str((artifact_dir / f"{v}_function.json").relative_to(ROOT))
                                             for v in ("vuln", "patched")],
                 "candidate_function_evidence_files": candidate_evidence_files,
                 "diff_summary": summary})
    # The standalone .BinDiff artifact retains the full match graph. Keep reports
    # compact by including candidate matches and the CVE function, not every match.
    data.pop("function_matches", None)
    data.pop("changed_candidates", None)
    return data
