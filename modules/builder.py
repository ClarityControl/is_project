"""Build the two isolated target images."""
import subprocess
import time
import os
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
        print(f"[BUILD] {variant} image: {tag}", flush=True)
        try:
            timeout = int(os.environ.get("NDAY_DOCKER_BUILD_TIMEOUT", "1200"))
            if timeout <= 0:
                raise ValueError("NDAY_DOCKER_BUILD_TIMEOUT must be a positive number")
            proc = subprocess.run(
                ["docker", "build", "--progress=plain", "-t", tag,
                 str(target / variant)], check=False, timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError(
                f"Docker build timed out for {variant} ({cve_id}) after {timeout} seconds. "
                "Set NDAY_DOCKER_BUILD_TIMEOUT to adjust the limit."
            ) from exc
        elapsed = time.monotonic() - start
        result[variant] = {"ok": proc.returncode == 0, "seconds": elapsed, "image": tag}
        print(f"[BUILD] {variant} image: {'OK' if proc.returncode == 0 else 'FAILED'} ({elapsed:.1f}s)", flush=True)
        if proc.returncode:
            raise RuntimeError(f"Docker build failed for {variant} ({cve_id})")
    return result
