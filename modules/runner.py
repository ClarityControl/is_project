"""Repeat the local Docker exploit probe and summarize crash rates."""
import subprocess
import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def run(cve_id: str, trials: int = 5) -> dict:
    exploit = ROOT / "targets" / cve_id / "exploit.py"
    results = {}
    for variant in ("vuln", "patched"):
        observed = []
        trials_data = []
        for _ in range(trials):
            try:
                p = subprocess.run([sys.executable, str(exploit), variant], capture_output=True, text=True, timeout=10)
                last_line = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
                try:
                    event = json.loads(last_line)
                except json.JSONDecodeError:
                    event = {"outcome": last_line if last_line in ("CRASHED", "CLEAN") else "ERROR"}
                label = event.get("outcome", "ERROR")
                if label not in ("CRASHED", "CLEAN") or p.returncode not in (0, 1):
                    label = "ERROR"
                event.update(outcome=label, probe_exit_code=p.returncode)
            except subprocess.TimeoutExpired:
                label = "ERROR"
                event = {"outcome": label, "error": "probe timeout"}
            observed.append(label)
            trials_data.append(event)
        try:
            impact_proc = subprocess.run([sys.executable, str(exploit), variant, "--impact"],
                                         capture_output=True, text=True, timeout=15)
            impact_line = impact_proc.stdout.strip().splitlines()[-1] if impact_proc.stdout.strip() else ""
            try:
                impact = json.loads(impact_line)
            except json.JSONDecodeError:
                impact = {"outcome": "ERROR", "error": impact_proc.stderr[-1000:] or "missing impact output"}
            if impact_proc.returncode not in (0, 1):
                impact["outcome"] = "ERROR"
        except subprocess.TimeoutExpired:
            impact = {"outcome": "ERROR", "error": "AddressSanitizer probe timed out"}
        results[variant] = {"results": observed, "trials": trials_data, "crash_rate": observed.count("CRASHED") / trials,
                            "clean_rate": observed.count("CLEAN") / trials, "impact": impact}
    return results
