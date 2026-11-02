"""Write machine-readable and human-readable CVE reports."""
import json
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape
from modules.report_security import read_json_report, save_report_bytes

ROOT = Path(__file__).resolve().parents[1]

def write_text_report(payload: dict) -> None:
    """Render the human-readable report from a complete report payload."""
    env = Environment(loader=FileSystemLoader(ROOT / "templates"), autoescape=select_autoescape())
    text = env.get_template("report.txt.j2").render(
        meta=payload, diff=payload["diff"], results=payload["results"],
        verdict=payload["verdict"], llm_explanation=payload.get("llm_explanation"),
    )
    save_report_bytes(payload["cve_id"], "txt", (text + "\n").encode("utf-8"))

def report(cve_id: str, diff: dict, results: dict) -> dict:
    meta = json.loads((ROOT / "targets" / cve_id / "meta.json").read_text())
    try:
        previous = read_json_report(cve_id)
    except FileNotFoundError:
        previous = {}
    if meta.get("probe", {}).get("mode") == "rce":
        confirmed = results["vuln"].get("rce_rate", 0) >= .8 and results["patched"].get("rce_rate", 0) <= .2
    elif meta.get("probe", {}).get("mode") == "crypto":
        confirmed = (results["vuln"].get("crypto_weakness_rate", 0) >= .8
                     and results["patched"].get("crypto_distinct_rate", 0) >= .8)
    else:
        confirmed = results["vuln"]["crash_rate"] >= .8 and results["patched"]["crash_rate"] <= .2
    verdict = "CONFIRMED" if confirmed else "UNCONFIRMED"
    payload = {**meta, "diff": diff, "results": results, "timestamp": datetime.now(timezone.utc).isoformat(), "verdict": verdict}
    # Keep a generated draft only when the evidence it analyzed is unchanged.
    if (previous.get("llm_explanation") and previous.get("diff") == diff
            and previous.get("results") == results):
        payload["llm_explanation"] = previous["llm_explanation"]
    save_report_bytes(cve_id, "json", (json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    write_text_report(payload)
    return payload
