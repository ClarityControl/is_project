"""Run the local, synthetic benign control-flow redirection demonstration."""
from __future__ import annotations

import json
import platform
import re
import struct
import subprocess
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "labs" / "control_flow"
ARTIFACT_DIR = ROOT / ".work" / "artifacts" / "LAB-CFH-001"
IMAGES = {
    "vulnerable": "ndaynexus-lab-cfh-001-vuln",
    "patched": "ndaynexus-lab-cfh-001-patched",
}
MARKER = "HELLO WORLD: benign callback reached."


def _docker(args: list[str], *, input_bytes: bytes | None = None,
            timeout: int = 600) -> subprocess.CompletedProcess:
    try:
        result = subprocess.run(
            ["docker", *args], input=input_bytes, capture_output=True,
            text=input_bytes is None, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Docker command failed: {exc}") from exc
    if result.returncode:
        stderr = result.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        raise RuntimeError(f"Docker command exited {result.returncode}: {stderr.strip()}")
    return result


def _build_images() -> None:
    for variant, image in IMAGES.items():
        dockerfile_variant = "vuln" if variant == "vulnerable" else variant
        dockerfile = LAB / dockerfile_variant / "Dockerfile"
        _docker(["build", "--tag", image, "--file", str(dockerfile), str(LAB)])


def _run(image: str, payload: bytes | None = None, *, info: bool = False) -> str:
    command = [
        "run", "--rm", "-i", "--network", "none", "--memory", "128m",
        "--cpus", "1", "--pids-limit", "32", "--read-only", "--user",
        "65534:65534", "--cap-drop", "ALL", "--security-opt",
        "no-new-privileges:true", image,
    ]
    if info:
        command.append("--demo-info")
    result = _docker(command, input_bytes=payload, timeout=20)
    output = result.stdout
    if isinstance(output, bytes):
        output = output.decode("utf-8", errors="replace")
    return output


def run_control_flow_demo() -> dict:
    """Build both lab variants, run the fixed benign redirect, and save evidence."""
    if platform.machine().lower() not in {"x86_64", "amd64"} or struct.calcsize("P") != 8:
        raise RuntimeError("This teaching demo currently requires a 64-bit x86 host.")

    _build_images()
    info = _run(IMAGES["vulnerable"], info=True)
    address_match = re.search(r"^TARGET_ADDR=0x([0-9a-fA-F]+)$", info, re.MULTILINE)
    offset_match = re.search(r"^CALLBACK_OFFSET=(\d+)$", info, re.MULTILINE)
    if not address_match or not offset_match:
        raise RuntimeError(f"Could not read lab target details from container: {info.strip()}")

    callback_address = int(address_match.group(1), 16)
    callback_offset = int(offset_match.group(1))
    if not callback_address or callback_offset != 32:
        raise RuntimeError("Lab layout differs from the expected fixed demo layout.")
    payload = b"A" * callback_offset + struct.pack("<Q", callback_address)

    vulnerable_output = _run(IMAGES["vulnerable"], payload)
    patched_output = _run(IMAGES["patched"], payload)
    vulnerable_redirected = MARKER in vulnerable_output
    patched_rejected = "rejected oversized input" in patched_output.lower()
    result = {
        "lab_id": "LAB-CFH-001",
        "title": "Synthetic benign function-pointer overwrite",
        "classification": "teaching demonstration; not a real CVE",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "architecture": platform.machine(),
        "payload_bytes": len(payload),
        "callback_offset": callback_offset,
        "benign_target": "hello_world",
        "vulnerable": {"image": IMAGES["vulnerable"], "redirected": vulnerable_redirected,
                       "output": vulnerable_output.strip()},
        "patched": {"image": IMAGES["patched"], "rejected": patched_rejected,
                    "output": patched_output.strip()},
        "success": vulnerable_redirected and patched_rejected,
        "limitations": "Demonstrates a deliberately introduced callback overwrite only; it is not evidence of code execution in any real CVE target.",
    }
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACT_DIR / "control_flow_demo.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    if not result["success"]:
        raise RuntimeError("The lab did not show both expected outcomes. See saved artifact.")
    return result
