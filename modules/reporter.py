"""Write machine-readable and human-readable CVE reports."""
import json
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

ROOT = Path(__file__).resolve().parents[1]

def write_text_report(payload: dict) -> None:
    """Render the human-readable report from a complete report payload."""
    env = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=select_autoescape())
    text = env.get_template("report.txt.j2").render(
        meta=payload, diff=payload["diff"], results=payload["results"],
        verdict=payload["verdict"], llm_explanation=payload.get("llm_explanation"),
    )
    (ROOT / "reports" / f"{payload['cve_id']}.txt").write_text(text + "\n")

def report(cve_id: str, diff: dict, results: dict) -> dict:
    meta = json.loads((ROOT / "targets" / cve_id / "meta.json").read_text())
    saved_path = ROOT / "reports" / f"{cve_id}.json"
    previous = json.loads(saved_path.read_text()) if saved_path.exists() else {}
    verdict = "CONFIRMED" if results["vuln"]["crash_rate"] >= .8 and results["patched"]["crash_rate"] <= .2 else "UNCONFIRMED"
    payload = {**meta, "diff": diff, "results": results, "timestamp": datetime.now(timezone.utc).isoformat(), "verdict": verdict}
    # Keep a generated draft only when the evidence it analyzed is unchanged.
    if (previous.get("llm_explanation") and previous.get("diff") == diff
            and previous.get("results") == results):
        payload["llm_explanation"] = previous["llm_explanation"]
    out = ROOT / "reports"
    out.mkdir(exist_ok=True)
    saved_path.write_text(json.dumps(payload, indent=2) + "\n")
    write_text_report(payload)
    return payload
