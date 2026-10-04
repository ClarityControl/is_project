#!/usr/bin/env python3
"""N-Day Nexus command line entry point."""
import argparse
import json
from pathlib import Path

from modules.builder import build
from modules.differ import diff
from modules.runner import run as run_exploit
from modules.reporter import report

ROOT = Path(__file__).resolve().parent

def target_ids():
    return sorted(p.name for p in (ROOT / "targets").iterdir() if p.is_dir() and (p / "meta.json").exists())

def main():
    parser = argparse.ArgumentParser(description="Compare and validate local historical CVE builds")
    parser.add_argument("cve_id", nargs="?", help="CVE identifier, or use --all")
    parser.add_argument("--all", action="store_true", help="run every configured target")
    parser.add_argument("--step", choices=("build", "diff", "probe", "exploit", "report"), help="run one pipeline step")
    args = parser.parse_args()
    ids = target_ids() if args.all else ([args.cve_id] if args.cve_id else [])
    if not ids or (args.all and args.cve_id):
        parser.error("provide a CVE ID or --all")
    for cve_id in ids:
        if cve_id not in target_ids():
            parser.error(f"unknown CVE: {cve_id}")
        print(f"[N-DAY NEXUS] {cve_id}\n{'─' * 41}")
        diff_data = None
        results = None
        built = None
        if args.step in (None, "build"):
            built = build(cve_id)
        if args.step in (None, "diff"):
            diff_data = diff(cve_id)
            visible = diff_data["changed_functions"]
            preview = ", ".join(visible[:15]) or "none"
            more = f" (+{len(visible) - 15} more)" if len(visible) > 15 else ""
            print(f"[DIFF] Changed-function candidates: {preview}{more}")
        if args.step in (None, "probe", "exploit"):
            results = run_exploit(cve_id)
            for variant in ("vuln", "patched"):
                data = results[variant]
                summary = (f"CRASHED {data['results'].count('CRASHED')}/5" if variant == "vuln"
                           else f"{'CLEAN' if data['crash_rate'] <= .2 else 'CRASHED'} {data['results'].count('CLEAN')}/5")
                print(f"[PROBE] {variant}: {summary}")
        if args.step == "build":
            continue
        if args.step == "diff":
            continue
        if args.step in ("probe", "exploit"):
            continue
        if args.step == "report":
            prior = ROOT / "reports" / f"{cve_id}.json"
            if not prior.exists():
                parser.error("run build, diff, and exploit before report")
            old = json.loads(prior.read_text())
            diff_data, results = old["diff"], old["results"]
        output = report(cve_id, diff_data, results)
        print(f"[REPORT] reports/{cve_id}.json")
        print(f"[REPORT] reports/{cve_id}.txt")
        print(f"[VERDICT] {output['verdict']}")

if __name__ == "__main__":
    main()
