"""Write machine-readable and human-readable CVE reports."""
import json
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parents[1]

def report(cve_id: str, diff: dict, results: dict) -> dict:
    meta = json.loads((ROOT / "targets" / cve_id / "meta.json").read_text())
    verdict = "CONFIRMED" if results["vuln"]["crash_rate"] >= .8 and results["patched"]["crash_rate"] <= .2 else "UNCONFIRMED"
    payload = {**meta, "diff": diff, "results": results, "timestamp": datetime.now(timezone.utc).isoformat(), "verdict": verdict}
    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    (out / f"{cve_id}.json").write_text(json.dumps(payload, indent=2) + "\n")
    env = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=select_autoescape())
    text = env.get_template("report.txt.j2").render(meta=meta, diff=diff, results=results, verdict=verdict)
    (out / f"{cve_id}.txt").write_text(text + "\n")
    return payload
