"""Analyze and compare the binaries from the vulnerable and patched images."""
from __future__ import annotations

import json
import os
import re
import shutil
import sqlite3
import subprocess
from pathlib import Path

from modules.source_diff import get_source_comparison

ROOT = Path(__file__).resolve().parents[1]
WORK = ROOT / ".work"


def _timeout_seconds(name: str, default: int) -> int:
    """Read a positive subprocess timeout, allowing slow large binaries to finish."""
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be a positive number of seconds") from exc
    if value <= 0:
        raise RuntimeError(f"{name} must be a positive number of seconds")
    return value


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
                   capture_output=True, text=True, timeout=60)
    try:
        subprocess.run(["docker", "cp", f"{container}:{source}", str(destination)],
                       check=True, capture_output=True, text=True, timeout=60)
    finally:
        subprocess.run(["docker", "rm", container], check=False, capture_output=True)


def _export_binexport(ghidra: Path, variant: str, binary: Path, output: Path,
                      evidence: Path, affected_function: str,
                      scope_seeds: list[str] | None = None) -> list[str]:
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
    if scope_seeds:
        shutil.copy2(ROOT / "tools" / "ghidra_scripts" / "ExportScopedBinExport.java",
                     script_dir / "ExportScopedBinExport.java")
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
               "-import", str(binary), "-scriptPath", str(script_dir)]
    if scope_seeds:
        command += ["-postScript", "ExportScopedBinExport.java", str(output), *scope_seeds]
    else:
        command += ["-postScript", "BinExport.java"]
    command += ["-postScript", "ExportFunctionEvidence.java", affected_function,
                str(evidence), "-deleteProject"]
    timeout = _timeout_seconds("NDAY_GHIDRA_TIMEOUT", 900)
    try:
        proc = subprocess.run(command, check=False, capture_output=True, text=True,
                              env=env, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Ghidra/BinExport timed out for {variant} after {timeout} seconds. "
            "The imported binary and partial Ghidra project are retained; "
            "retry with a larger NDAY_GHIDRA_TIMEOUT if needed."
        ) from exc
    if (proc.returncode or not output.is_file() or output.stat().st_size == 0
            or not evidence.is_file()):
        detail = (proc.stdout + "\n" + proc.stderr)[-6000:]
        raise RuntimeError(f"Ghidra/BinExport failed for {variant}:\n{detail}")
    scope_file = Path(str(output) + ".scope.txt")
    return scope_file.read_text().splitlines() if scope_file.is_file() else []


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


def _symbol_source_diff(cve_id: str, meta: dict, artifact_dir: Path) -> dict:
    """Compare configured source files and ELF symbols without whole-program decompilation."""
    if not shutil.which("nm"):
        raise RuntimeError("GNU nm is required for the PHP symbol comparison (install binutils).")
    binary_name = meta["binary_name"]
    binary_paths = meta.get("diff_binary_paths", {})
    common_path = meta.get("diff_binary_path")
    artifacts = {}
    symbols = {}
    for variant in ("vuln", "patched"):
        image = f"ndaynexus-{cve_id.lower()}-{variant}"
        source = binary_paths.get(variant) or common_path or f"/usr/local/bin/{binary_name}_{variant}"
        extracted = artifact_dir / f"{variant}.elf"
        _extract_binary(image, variant, source, extracted)
        proc = subprocess.run(["nm", "-a", "--defined-only", "--format=posix", str(extracted)],
                              check=False, capture_output=True, text=True, timeout=120)
        if proc.returncode:
            raise RuntimeError(f"nm failed for {variant} PHP binary: {(proc.stderr or proc.stdout)[-3000:]}")
        rows = {}
        for line in proc.stdout.splitlines():
            fields = line.split()
            if len(fields) >= 3 and len(fields[1]) == 1:
                rows[fields[0]] = {"type": fields[1], "address": fields[2]}
        symbols[variant] = rows
        artifacts[variant] = str(extracted.relative_to(ROOT))

    vuln_names, patched_names = set(symbols["vuln"]), set(symbols["patched"])
    added, removed = sorted(patched_names - vuln_names), sorted(vuln_names - patched_names)
    focus = meta.get("symbol_names", [])
    focused = [{"name": name,
                "vulnerable": symbols["vuln"].get(name),
                "patched": symbols["patched"].get(name),
                "status": ("added" if name not in symbols["vuln"] else
                           "removed" if name not in symbols["patched"] else
                           "present in both; address changed" if symbols["vuln"][name]["address"] != symbols["patched"][name]["address"]
                           else "present in both; address unchanged")}
               for name in focus]
    symbol_data = {
        "engine": "GNU nm symbol-table comparison",
        "binary_artifacts": artifacts,
        "defined_symbol_count": {key: len(value) for key, value in symbols.items()},
        "added_symbol_count": len(added), "removed_symbol_count": len(removed),
        "added_symbols": added[:250], "removed_symbols": removed[:250],
        "focus_symbols": focused,
    }
    symbols_path = artifact_dir / "symbol_diff.json"
    symbols_path.write_text(json.dumps(symbol_data, indent=2) + "\n")
    symbol_data["artifact"] = str(symbols_path.relative_to(ROOT))
    symbols_path.write_text(json.dumps(symbol_data, indent=2) + "\n")

    source = get_source_comparison(cve_id)
    source_data = {
        "engine": "unified source diff",
        "source_paths": source["source_paths"],
        "additions": source["additions"], "deletions": source["deletions"],
        "changed_lines": source["changed_lines"],
        "artifact": str(source["diff_path"].relative_to(ROOT)),
        "display_truncated": source["display_truncated"],
    }
    summary = (
        f"PHP source + symbol comparison: {source_data['changed_lines']} changed source lines across "
        f"{len(source_data['source_paths'])} files; {symbol_data['defined_symbol_count']['vuln']} vulnerable and "
        f"{symbol_data['defined_symbol_count']['patched']} patched defined symbols; "
        f"{len(added)} symbols added and {len(removed)} removed. "
        "ELF symbols corroborate the source comparison; Ghidra/BinDiff is not used for this target."
    )
    return {
        "engine": "Source diff + GNU nm symbol comparison",
        "analysis_method": "source_and_symbols",
        "changed_functions": [item["name"] for item in focused
                              if item["status"] in ("added", "removed")],
        "similarity": None, "confidence": None,
        "source_comparison": source_data,
        "symbol_comparison": symbol_data,
        "diff_summary": summary,
    }


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
    timeout = _timeout_seconds("NDAY_GHIDRA_TIMEOUT", 900)
    try:
        proc = subprocess.run(command, check=False, capture_output=True, text=True,
                              env=env, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"Ghidra candidate decompilation timed out for {variant} after {timeout} seconds. "
            "Retry with a larger NDAY_GHIDRA_TIMEOUT if needed."
        ) from exc
    if proc.returncode or not output.is_file() or output.stat().st_size == 0:
        detail = (proc.stdout + "\n" + proc.stderr)[-5000:]
        raise RuntimeError(f"Ghidra candidate decompilation failed for {variant}:\n{detail}")


def diff(cve_id: str, include_candidate_decomp: bool = False) -> dict:
    target = ROOT / "targets" / cve_id
    meta = json.loads((target / "meta.json").read_text())
    if not meta.get("patched_ref"):
        raise ValueError(f"{cve_id} has no validated patch reference")

    artifact_dir = WORK / "artifacts" / cve_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    if meta.get("diff_strategy") == "source_symbols":
        print("[DIFF] PHP source diff and ELF symbol comparison", flush=True)
        return _symbol_source_diff(cve_id, meta, artifact_dir)

    ghidra = _ghidra_home()
    bindiff = _bindiff_binary()
    exported = {}
    exported_scope = {}
    scope_seeds = meta.get("binexport_scope_seeds")
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
        exported_scope[variant] = _export_binexport(
            ghidra, variant, extracted, export, evidence,
            meta.get("function") or "__no_known_affected_function__", scope_seeds)
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
    scope_label = ("target functions and their direct callers/callees" if scope_seeds
                   else "entire binary")
    summary = (f"{data['engine']} ({scope_label}) matched {data['matched_function_count']} functions "
               f"(similarity {data['similarity']:.3f}, confidence {data['confidence']:.3f}); "
               f"{len(candidates)} lower-similarity matches, of which {len(reviewed_candidates)} "
               f"have confidence >= 0.60 and recovered names. "
               f"Affected-function matches: {len(affected)} ({meta.get('function') or 'unspecified'}).")
    data.update({"changed_functions": changed_names,
                 "diff_scope": scope_label,
                 "binexport_scope_functions": exported_scope,
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
