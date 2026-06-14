"""Tests for CFG-based taint propagation and exploit paths."""

from __future__ import annotations

from polyglot.analysis.analyzer import PickleAnalyzer
from polyglot.domain.security import SecurityTaint

MALICIOUS_GLOBAL = b"cos\nsystem\n(S'echo pwned'\ntR."


class TestCfgTaint:
    def test_propagates_sink_to_reduce_node(self) -> None:
        report = PickleAnalyzer().analyze(MALICIOUS_GLOBAL)
        assert report.cfg_taint is not None
        assert report.cfg_taint.max_propagated is SecurityTaint.SINK

    def test_exploit_path_from_global_to_reduce(self) -> None:
        report = PickleAnalyzer().analyze(MALICIOUS_GLOBAL)
        assert report.exploit_paths
        path = report.exploit_paths[0]
        assert path.sink_callable == "os.system"
        opcodes = [step[0] for step in path.steps]
        assert "GLOBAL" in opcodes or "REDUCE" in opcodes or "MEMO_STORE" in opcodes
