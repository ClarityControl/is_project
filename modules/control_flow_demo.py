"""Run the local, synthetic benign control-flow redirection demonstration."""
from __future__ import annotations

import json
import os
import platform
import queue
import re
import signal
import struct
import subprocess
import threading
import time
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
            timeout: int = 600, progress=None) -> subprocess.CompletedProcess:
    command = ["docker", *args]
    try:
        if progress and input_bytes is None:
            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1, start_new_session=True,
            )
            output_queue = queue.Queue()

            def collect_output():
                try:
                    for line in process.stdout:
                        output_queue.put(line)
                finally:
                    output_queue.put(None)

            reader = threading.Thread(target=collect_output, daemon=True)
            reader.start()
            output = []
            deadline = time.monotonic() + timeout
            reader_finished = False
            while not (reader_finished and process.poll() is not None):
                if time.monotonic() >= deadline:
                    try:
                        os.killpg(process.pid, signal.SIGTERM)
                        process.wait(timeout=5)
                    except (ProcessLookupError, subprocess.TimeoutExpired):
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                    reader.join(timeout=2)
                    raise RuntimeError(
                        f"Docker build exceeded {timeout} seconds. Last output:\n"
                        + "".join(output[-40:])
                    )
                try:
                    line = output_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                if line is None:
                    reader_finished = True
                    continue
                output.append(line)
                progress(line.strip()[-140:] or "Docker build is running…")
            reader.join(timeout=2)
            result = subprocess.CompletedProcess(command, process.returncode,
                                                  stdout="".join(output), stderr="")
        else:
            result = subprocess.run(
                command, input=input_bytes, capture_output=True,
                text=input_bytes is None, timeout=timeout, check=False,
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Docker command failed: {exc}") from exc
    if result.returncode:
        stderr = result.stderr
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        detail = stderr or result.stdout or "no output"
        raise RuntimeError(f"Docker command exited {result.returncode}: {detail.strip()[-6000:]}")
    return result


def _build_images(progress=None) -> None:
    for variant, image in IMAGES.items():
        dockerfile_variant = "vuln" if variant == "vulnerable" else variant
        dockerfile = LAB / dockerfile_variant / "Dockerfile"
        if progress:
            progress(f"Building {variant} control-flow lab image (maximum 10 minutes)…")
        _docker(["build", "--progress=plain", "--tag", image,
                 "--file", str(dockerfile), str(LAB)], timeout=600,
                progress=progress)
        if progress:
            progress(f"{variant.capitalize()} lab image is ready; continuing…")


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


def run_control_flow_demo(progress=None) -> dict:
    """Build both lab variants, run the fixed benign redirect, and save evidence."""
    if platform.machine().lower() not in {"x86_64", "amd64"} or struct.calcsize("P") != 8:
        raise RuntimeError("This teaching demo currently requires a 64-bit x86 host.")

    _build_images(progress)
    if progress:
        progress("Reading the benign callback address from the isolated image…")
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

    if progress:
        progress("Running the vulnerable lab input…")
    vulnerable_output = _run(IMAGES["vulnerable"], payload)
    if progress:
        progress("Running the same input against the patched lab…")
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
