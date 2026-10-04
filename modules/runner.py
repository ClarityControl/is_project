"""Repeat the local Docker exploit probe and summarize crash rates."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def run(cve_id: str, trials: int = 5) -> dict:
    exploit = ROOT / "targets" / cve_id / "exploit.py"
    results = {}
    for variant in ("vuln", "patched"):
        observed = []
        for _ in range(trials):
            try:
                p = subprocess.run([sys.executable, str(exploit), variant], capture_output=True, text=True, timeout=10)
                label = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else "ERROR"
                if label not in ("CRASHED", "CLEAN") or p.returncode not in (0, 1):
                    label = "ERROR"
            except subprocess.TimeoutExpired:
                label = "ERROR"
            observed.append(label)
        results[variant] = {"results": observed, "crash_rate": observed.count("CRASHED") / trials,
                            "clean_rate": observed.count("CLEAN") / trials}
    return results
