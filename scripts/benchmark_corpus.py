#!/usr/bin/env python3
"""Compare PickleProbe vs a naive GLOBAL-only sink scanner on the corpus manifest."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import pickletools
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pickleprobe.analysis.analyzer import PickleAnalyzer
from pickleprobe.formats.loader import load_file

from pickleprobe.domain.policy import get_policy

CORPUS = ROOT / "tests" / "corpus"
MANIFEST = CORPUS / "manifest.yaml"

_NAIVE_SINKS = get_policy().sinks


@dataclass
class Row:
    sample_id: str
    label: str
    technique: str
    present: bool
    naive_globals: int
    pickleprobe_sinks: int
    pickleprobe_suspicious: int
    pickleprobe_reduces: int
    pickleprobe_detected: bool
    naive_detected: bool
    gap: str


def naive_global_scan(data: bytes) -> set[str]:
    """Flag only resolved GLOBAL opcode targets that match known sink pairs."""
    hits: set[str] = set()
    for opcode, arg, _pos in pickletools.genops(data):
        if opcode.name != "GLOBAL" or not isinstance(arg, str):
            continue
        module, sep, name = arg.partition(" ")
        if not sep:
            continue
        if (module, name) in _NAIVE_SINKS:
            hits.add(f"{module}.{name}")
    return hits


def analyze_sample(path: Path, analyzer: PickleAnalyzer) -> tuple[set[str], object]:
    loaded = load_file(path)
    naive_hits: set[str] = set()
    for stream in loaded.streams:
        naive_hits |= naive_global_scan(stream.data)
    result = analyzer.analyze_file(path)
    report = result.primary
    return naive_hits, report


def gap_note(label: str, naive_hit: bool, poly_hit: bool) -> str:
    if naive_hit and poly_hit:
        return "both"
    if poly_hit and not naive_hit:
        return "pickleprobe-only"
    if naive_hit and not poly_hit:
        return "naive-only (unexpected)"
    if label == "malicious":
        return "missed"
    return "clean"


def main() -> int:
    with MANIFEST.open() as fh:
        entries = yaml.safe_load(fh)["samples"]

    analyzer = PickleAnalyzer()
    rows: list[Row] = []

    for entry in entries:
        path = CORPUS / entry["path"]
        present = path.exists()
        naive_globals: set[str] = set()
        poly_sinks = poly_suspicious = poly_reduces = 0
        if present:
            naive_globals, report = analyze_sample(path, analyzer)
            poly_sinks = len(report.sink_invocations)
            poly_suspicious = len(report.suspicious_invocations)
            poly_reduces = len(report.reduce_events)

        naive_hit = bool(naive_globals)
        poly_hit = poly_sinks > 0 or (
            entry.get("label") == "malicious"
            and entry.get("expect_no_sinks") is False
            and poly_suspicious > 0
        )
        # For malicious samples that use REDUCE gadgets, pickleprobe detection = any sink OR suspicious+reduce
        if present and entry.get("label") == "malicious":
            poly_hit = (
                poly_sinks > 0
                or (poly_suspicious > 0 and poly_reduces > 0)
                or (
                    poly_reduces >= entry.get("min_reduce_events", 1)
                    and any(ref.is_resolved for ref in report.global_refs)
                )
            )

        rows.append(
            Row(
                sample_id=entry["id"],
                label=entry["label"],
                technique=entry.get("technique", ""),
                present=present,
                naive_globals=len(naive_globals),
                pickleprobe_sinks=poly_sinks,
                pickleprobe_suspicious=poly_suspicious,
                pickleprobe_reduces=poly_reduces,
                pickleprobe_detected=poly_hit,
                naive_detected=naive_hit,
                gap=gap_note(entry["label"], naive_hit, poly_hit) if present else "missing",
            )
        )

    print(f"{'id':<28} {'label':<10} {'naive':>5} {'poly':>5} {'gap':<18} present")
    print("-" * 80)
    for r in rows:
        print(
            f"{r.sample_id:<28} {r.label:<10} {r.naive_globals:>5} {r.pickleprobe_sinks:>5}"
            f" {r.gap:<18} {'yes' if r.present else 'no'}"
        )

    present_rows = [r for r in rows if r.present]
    mal = [r for r in present_rows if r.label == "malicious"]
    poly_only = [r for r in mal if r.gap == "pickleprobe-only"]
    missed = [r for r in mal if r.gap == "missed"]

    print()
    print(f"Samples in manifest: {len(rows)}")
    print(f"On disk: {len(present_rows)}")
    print(f"Malicious on disk: {len(mal)}")
    print(f"PickleProbe-only detections (naive GLOBAL missed): {len(poly_only)}")
    if poly_only:
        for r in poly_only:
            print(f"  - {r.sample_id} ({r.technique})")
    if missed:
        print(f"Missed malicious: {len(missed)}")
        for r in missed:
            print(f"  - {r.sample_id}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
