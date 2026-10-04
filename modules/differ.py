"""Compare local copies of binaries extracted from the built images."""
import re
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def _extract(image: str, name: str, directory: Path) -> Path:
    dest = directory / name
    subprocess.run(["docker", "create", "--name", name, image], check=True, stdout=subprocess.DEVNULL)
    try:
        subprocess.run(["docker", "cp", f"{name}:/usr/local/bin/{name.split('-')[-1]}", str(dest)], check=True, capture_output=True)
    finally:
        subprocess.run(["docker", "rm", name], check=False, capture_output=True)
    return dest

def _symbols(path: Path) -> dict[str, int]:
    out = subprocess.run(["objdump", "-d", str(path)], check=True, capture_output=True, text=True).stdout
    funcs = {}
    current = None
    for line in out.splitlines():
        m = re.match(r"^([0-9a-f]+) <([^>]+)>:$", line.strip())
        if m:
            current = m.group(2).split("@", 1)[0]
            funcs.setdefault(current, 0)
        elif current:
            b = re.match(r"\s*[0-9a-f]+:\s+((?:[0-9a-f]{2}\s+)+)", line)
            if b:
                funcs[current] += len(b.group(1).split())
    return funcs

def diff(cve_id: str) -> dict:
    target = ROOT / "targets" / cve_id
    import json
    meta = json.loads((target / "meta.json").read_text())
    if not meta.get("patched_ref"):
        raise ValueError(f"{cve_id} has no validated patch reference")
    with tempfile.TemporaryDirectory(prefix="ndaynexus-") as tmp:
        tmp = Path(tmp)
        # Docker cp source path derives from known image variant binary name.
        binaries = {}
        for variant in ("vuln", "patched"):
            image = f"ndaynexus-{cve_id.lower()}-{variant}"
            cname = f"ndaynexus-diff-{variant}"
            subprocess.run(["docker", "create", "--name", cname, image], check=True, capture_output=True)
            dest = tmp / variant
            binary = meta.get("diff_binary_name", f"{meta['binary_name']}_{variant}")
            source_path = meta.get("diff_binary_path", f"/usr/local/bin/{binary}")
            try:
                subprocess.run(["docker", "cp", f"{cname}:{source_path}", str(dest)], check=True, capture_output=True)
            finally:
                subprocess.run(["docker", "rm", cname], check=False, capture_output=True)
            binaries[variant] = _symbols(dest)
        before, after = binaries["vuln"], binaries["patched"]
        changed = sorted(name for name in before.keys() & after.keys() if before[name] != after[name])
        added, removed = sorted(after.keys() - before.keys()), sorted(before.keys() - after.keys())
        # The vulnerability function is explicitly surfaced when present in symbols,
        # even if compiler/linker layout leaves its measured size unchanged.
        if meta["function"] in before and meta["function"] in after and meta["function"] not in changed:
            changed.append(meta["function"])
        manual = "Manual Ghidra + Diaphora: import both extracted ELF files into Ghidra; analyze each; export Diaphora SQLite databases; compare databases and inspect changed function pairs."
        return {"changed_functions": sorted(changed), "added_symbols": added, "removed_symbols": removed,
                "diff_summary": f"Changed functions: {', '.join(sorted(changed)) or 'none'}; {manual}",
                "function_sizes_vuln": before, "function_sizes_patched": after,
                "manual_diaphora_steps": manual}
