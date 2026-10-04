"""Build the two isolated target images."""
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def build(cve_id: str) -> dict:
    target = ROOT / "targets" / cve_id
    if not target.is_dir():
        raise ValueError(f"Unknown target: {cve_id}")
    result = {}
    for variant in ("vuln", "patched"):
        tag = f"ndaynexus-{cve_id.lower()}-{variant}"
        start = time.monotonic()
        print(f"[BUILD] {variant} image: {tag}")
        proc = subprocess.run(["docker", "build", "-t", tag, str(target / variant)], check=False)
        elapsed = time.monotonic() - start
        result[variant] = {"ok": proc.returncode == 0, "seconds": elapsed, "image": tag}
        print(f"[BUILD] {variant} image: {'OK' if proc.returncode == 0 else 'FAILED'} ({elapsed:.1f}s)")
        if proc.returncode:
            raise RuntimeError(f"Docker build failed for {variant} ({cve_id})")
    return result
