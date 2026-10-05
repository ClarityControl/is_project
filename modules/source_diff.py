"""Extract and summarize the configured vulnerable-to-patched source change."""
import difflib
import json
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / ".work" / "artifacts"


def get_source_comparison(cve_id: str) -> dict:
    """Extract the target source file from both built images and save its diff."""
    if not re.fullmatch(r"CVE-\d{4}-\d+", cve_id):
        raise RuntimeError(f"Invalid CVE identifier: {cve_id}")
    target = ROOT / "targets" / cve_id
    meta_path = target / "meta.json"
    if not meta_path.is_file():
        raise RuntimeError(f"No configured target exists for {cve_id}.")
    meta = json.loads(meta_path.read_text())
    build_details = {}
    for variant in ("vuln", "patched"):
        dockerfile = target / variant / "Dockerfile"
        try:
            lines = dockerfile.read_text().splitlines()
        except OSError:
            lines = []
        build_details[variant] = [
            line[:500] for line in lines
            if line.startswith("FROM ") or any(
                marker in line for marker in ("CFLAGS", "CMAKE_C_FLAGS", "-fsanitize", "--disable-hardening")
            )
        ]
    location = meta.get("root_cause", {}).get("source_location", "")
    relative_path = meta.get("source_path") or location.split(":", 1)[0]
    source_path = Path(relative_path)
    if (not relative_path or source_path.is_absolute() or ".." in source_path.parts
            or "\\" in relative_path):
        raise RuntimeError(f"Target has no safe source path configured: {relative_path!r}")

    artifact_dir = ARTIFACTS / cve_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    source_lines = {}
    for variant in ("vuln", "patched"):
        image = f"ndaynexus-{cve_id.lower()}-{variant}"
        container = f"ndaynexus-source-{variant}-{os.getpid()}"
        destination = artifact_dir / f"{variant}_{source_path.name}.source"
        try:
            subprocess.run(["docker", "create", "--name", container, image], check=True,
                           capture_output=True, text=True, timeout=30)
            subprocess.run(["docker", "cp", f"{container}:/build/{source_path.as_posix()}",
                            str(destination)], check=True, capture_output=True, text=True,
                           timeout=30)
            source_lines[variant] = destination.read_text(errors="replace").splitlines(keepends=True)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(
                f"Could not read {relative_path} from the {variant} image. "
                f"Build both images first with the dashboard's full pipeline action. ({exc})"
            ) from exc
        finally:
            try:
                subprocess.run(["docker", "rm", "-f", container], check=False,
                               capture_output=True, text=True, timeout=30)
            except (OSError, subprocess.SubprocessError):
                pass

    diff_lines = list(difflib.unified_diff(
        source_lines["vuln"], source_lines["patched"],
        fromfile=f"vulnerable/{relative_path}",
        tofile=f"patched/{relative_path}",
        n=5,
    ))
    if not diff_lines:
        raise RuntimeError(f"No source changes found in {relative_path}.")

    additions = sum(1 for line in diff_lines if line.startswith("+") and not line.startswith("+++"))
    deletions = sum(1 for line in diff_lines if line.startswith("-") and not line.startswith("---"))
    diff_text = "".join(diff_lines)
    display_truncated = len(diff_text) > 20000
    if display_truncated:
        diff_rows = diff_text.splitlines()
        function_name = location.split(":", 1)[1].split("(", 1)[0] if ":" in location else meta.get("function", "")
        hunks = []
        for line in diff_rows[2:]:
            if line.startswith("@@ "):
                hunks.append([line])
            elif hunks:
                hunks[-1].append(line)
        relevant = [hunk for hunk in hunks if function_name and function_name in "\n".join(hunk)]
        selected = relevant if relevant else hunks
        displayed = diff_rows[:2] + [line for hunk in selected for line in hunk]
        diff_text = "\n".join(displayed)
        if len(diff_text) > 20000:
            diff_text = diff_text[:20000] + "\n[display truncated; use the saved source_patch.diff for the complete patch]\n"
    diff_file = artifact_dir / "source_patch.diff"
    full_diff = "".join(diff_lines)
    diff_file.write_text(full_diff)
    return {
        "diff": diff_text,
        "display_truncated": display_truncated,
        "diff_path": diff_file,
        "source_path": relative_path,
        "function": location.split(":", 1)[1] if ":" in location else meta.get("function", ""),
        "additions": additions,
        "deletions": deletions,
        "changed_lines": additions + deletions,
        "meta": meta,
        "build_details": build_details,
    }
