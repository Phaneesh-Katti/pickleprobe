#!/usr/bin/env python3
"""Benchmark hand-picked PickleBall archive members (fast subset eval)."""

from __future__ import annotations

import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from pickleprobe.analysis.analyzer import PickleAnalyzer

SUBSET = ROOT / "tests" / "corpus" / "pickleball_subset.yaml"


def main() -> int:
    with SUBSET.open() as fh:
        doc = yaml.safe_load(fh)
    archives = {k: ROOT / v for k, v in doc["archives"].items()}
    analyzer = PickleAnalyzer()

    print(f"{'id':<24} {'label':<10} {'sinks':>5} {'warn':>5} {'bytes':>10}")
    print("-" * 60)

    for entry in doc["samples"]:
        arch = archives[entry["archive"]]
        member = entry["member"]
        path = ROOT / arch if not Path(arch).is_absolute() else arch
        if not path.exists():
            print(f"{entry['id']:<24} {entry['label']:<10} {'miss':>5}")
            continue
        report = analyzer.analyze_archive_member(path, member)
        sinks = len(report.sink_invocations)
        warn = len(report.suspicious_invocations)
        print(
            f"{entry['id']:<24} {entry['label']:<10} {sinks:>5} {warn:>5} "
            f"{report.raw_size:>10}"
        )

    print()
    print(f"Subset manifest: {SUBSET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
