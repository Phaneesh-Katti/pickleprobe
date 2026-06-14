"""Parametrized corpus tests driven by tests/corpus/manifest.yaml."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from polyglot.analysis.analyzer import PickleAnalyzer
from polyglot.domain.security import SecurityTaint

CORPUS_ROOT = Path(__file__).resolve().parent / "corpus"
MANIFEST = CORPUS_ROOT / "manifest.yaml"


def _load_manifest() -> list[dict[str, Any]]:
    with MANIFEST.open() as fh:
        doc = yaml.safe_load(fh)
    return list(doc.get("samples", []))


def _sample_id(entry: dict[str, Any]) -> str:
    return str(entry["id"])


@pytest.fixture(scope="module")
def analyzer() -> PickleAnalyzer:
    return PickleAnalyzer()


@pytest.mark.parametrize("entry", _load_manifest(), ids=_sample_id)
def test_manifest_sample_analyzes(entry: dict[str, Any], analyzer: PickleAnalyzer) -> None:
    path = CORPUS_ROOT / entry["path"]
    if not path.exists():
        pytest.skip(f"corpus file missing: {path}")

    result = analyzer.analyze_file(path)
    report = result.primary

    for expected in entry.get("expected_globals", []):
        matches = [
            ref
            for ref in report.global_refs
            if ref.module == expected.get("module")
            and ref.name == expected.get("name")
            and (expected.get("opcode") is None or ref.opcode == expected["opcode"])
        ]
        if expected.get("resolved", True):
            assert matches, f"expected global {expected!r} not found in {entry['id']}"
            ref = matches[0]
            if "resolved" in expected:
                assert ref.is_resolved is expected["resolved"]

    expected_sinks = entry.get("expected_sink_invocations", [])
    if expected_sinks:
        found = {ev.callable_qualified for ev in report.sink_invocations}
        for spec in expected_sinks:
            qn = spec if isinstance(spec, str) else spec.get("callable")
            assert qn in found, f"expected sink {qn!r} missing in {entry['id']}"

    expected_sink_count = entry.get("expected_sink_count")
    if expected_sink_count is not None:
        assert len(report.sink_invocations) == expected_sink_count

    if entry.get("label") == "benign" and entry.get("expect_no_sinks", True):
        assert not report.sink_invocations, f"benign sample {entry['id']} flagged as sink"

    min_reduces = entry.get("min_reduce_events")
    if min_reduces is not None:
        assert len(report.reduce_events) >= min_reduces

    min_newobj = entry.get("min_newobj_events")
    if min_newobj is not None:
        assert len(report.newobj_events) >= min_newobj

    min_build = entry.get("min_build_events")
    if min_build is not None:
        assert len(report.build_events) >= min_build
