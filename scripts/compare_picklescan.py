#!/usr/bin/env python3
"""Compare PickleProbe vs picklescan on the manifest corpus (when picklescan is installed)."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CORPUS = ROOT / "tests" / "corpus"
MANIFEST = CORPUS / "manifest.yaml"
sys.path.insert(0, str(ROOT / "src"))

from pickleprobe.analysis.analyzer import PickleAnalyzer


def _picklescan_available() -> bool:
    return importlib.util.find_spec("picklescan") is not None


def _run_picklescan(path: Path) -> tuple[bool, str]:
    try:
        from picklescan import scanner

        result = scanner.scan_file_path(str(path))
        infected = bool(getattr(result, "infected_files", None))
        if not infected and hasattr(result, "issues"):
            infected = bool(result.issues)
        detail = str(result)
        return infected, detail[:120]
    except Exception as exc:  # noqa: BLE001 — comparison harness
        proc = subprocess.run(
            [sys.executable, "-m", "picklescan", str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        out = (proc.stdout + proc.stderr).strip()
        infected = proc.returncode != 0 or "dangerous" in out.lower() or "infected" in out.lower()
        return infected, out[:120] or str(exc)


def main() -> int:
    with MANIFEST.open() as fh:
        entries = yaml.safe_load(fh)["samples"]

    if not _picklescan_available():
        print("picklescan not installed — pip install picklescan to fill this table.")
        print("PickleProbe-only preview:\n")

    analyzer = PickleAnalyzer()
    print(f"{'id':<28} {'label':<9} {'pscan':>6} {'scope':>6} {'notes'}")
    print("-" * 72)

    for entry in entries:
        path = CORPUS / entry["path"]
        if not path.exists():
            print(f"{entry['id']:<28} {entry['label']:<9} {'miss':>6} {'miss':>6} file missing")
            continue

        report = analyzer.analyze_file(path).primary
        scope_hit = bool(report.sink_invocations) or bool(report.suspicious_invocations)
        if entry["label"] == "malicious" and not scope_hit:
            scope_hit = report.reduce_events and any(r.is_resolved for r in report.global_refs)

        if _picklescan_available():
            pscan_hit, note = _run_picklescan(path)
        else:
            pscan_hit, note = False, "n/a"

        print(
            f"{entry['id']:<28} {entry['label']:<9} "
            f"{'yes' if pscan_hit else 'no':>6} {'yes' if scope_hit else 'no':>6} "
            f"{entry.get('technique', '')}"
        )

    print()
    print("Install: pip install picklescan")
    print("See docs/COMPARISON.md for interpretation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
