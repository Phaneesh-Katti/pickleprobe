"""Tests for adversarial memo pattern detection."""

from __future__ import annotations

from polyglot.analysis.analyzer import PickleAnalyzer


class TestMemoWarnings:
    def test_get_before_put_warns(self) -> None:
        # BINGET key 0 before anything stored at 0
        payload = b"g0\n."
        report = PickleAnalyzer().analyze(payload)
        assert any("before PUT" in w for w in report.memo_warnings)

    def test_overwrite_put_warns(self) -> None:
        payload = b"S'a'\np0\nS'b'\np0\n."
        report = PickleAnalyzer().analyze(payload)
        assert any("overwrote" in w for w in report.memo_warnings)

    def test_memo_fed_stack_global_in_errors(self) -> None:
        payload = (
            b"S'os'\n"
            b"p0\n"
            b"S'system'\n"
            b"p1\n"
            b"g0\n"
            b"g1\n"
            b"\x93"
            b"(S'id'\n"
            b"tR."
        )
        report = PickleAnalyzer().analyze(payload)
        assert any("memo-fed STACK_GLOBAL" in e and "SINK" in e for e in report.emulation_errors)
