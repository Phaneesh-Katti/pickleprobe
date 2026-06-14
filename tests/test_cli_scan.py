"""CLI scan and SARIF output tests."""

from __future__ import annotations

import json
from pathlib import Path

from pickleprobe.cli import main
from pickleprobe.reporting.sarif import file_results_to_sarif
from pickleprobe.analysis.analyzer import PickleAnalyzer

CORPUS = Path(__file__).resolve().parent / "corpus" / "samples"


def test_sarif_emits_sink_rule() -> None:
    path = CORPUS / "picklescan/malicious0.pkl"
    result = PickleAnalyzer().analyze_file(path)
    sarif = file_results_to_sarif([result])
    assert sarif["version"] == "2.1.0"
    results = sarif["runs"][0]["results"]
    assert any(r["ruleId"] == "pickle-sink-invocation" for r in results)


def test_scan_directory_json(capsys) -> None:
    root = CORPUS / "picklescan"
    code = main(["scan", str(root), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert out["target_count"] >= 1
    assert "targets" in out
    assert code in (0, 1, 2)


def test_analyze_sarif_flag(capsys) -> None:
    path = CORPUS / "picklescan/benign0_v4.pkl"
    code = main(["analyze", str(path), "--sarif"])
    payload = json.loads(capsys.readouterr().out)
    assert payload["runs"][0]["tool"]["driver"]["name"] == "pickleprobe"
    assert code in (0, 1, 2)
