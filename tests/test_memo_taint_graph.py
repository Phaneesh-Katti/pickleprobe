"""Tests for full memo taint graph and precision on benign pickles."""

from __future__ import annotations

import pickle

from pickleprobe.analysis.analyzer import PickleAnalyzer
from pickleprobe.domain.cfg import EdgeKind, NodeKind
from pickleprobe.domain.security import SecurityTaint

MEMO_ATTACK = (
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


class TestMemoPrecision:
    def test_benign_datetime_memo_stays_clean(self) -> None:
        import datetime

        data = pickle.dumps(datetime.datetime(2024, 1, 1), protocol=4)
        report = PickleAnalyzer().analyze(data)
        assert not report.sink_invocations
        assert report.cfg_taint is not None
        assert report.cfg_taint.max_propagated is SecurityTaint.CLEAN

    def test_memo_load_inherits_clean_not_suspicious(self) -> None:
        payload = b"S'datetime'\np0\ng0\n."
        report = PickleAnalyzer().analyze(payload)
        loads = [e for e in report.memo_events if e.kind == "load"]
        assert loads
        assert loads[0].security is SecurityTaint.CLEAN


class TestMemoGraph:
    def test_cfg_has_memo_store_and_load_nodes(self) -> None:
        report = PickleAnalyzer().analyze(MEMO_ATTACK)
        assert report.cfg.memo_stores
        assert report.cfg.memo_loads

    def test_memo_flow_edges_connect_store_to_load(self) -> None:
        report = PickleAnalyzer().analyze(MEMO_ATTACK)
        memo_flows = [e for e in report.cfg.edges if e.kind is EdgeKind.MEMO_FLOW]
        assert memo_flows

    def test_exploit_path_includes_memo_steps(self) -> None:
        report = PickleAnalyzer().analyze(MEMO_ATTACK)
        assert report.exploit_paths
        steps = report.exploit_paths[0].steps
        opcodes = [s[0] for s in steps]
        assert any("MEMO" in op or op in ("PUT", "BINGET", "GET") for op in opcodes)

    def test_obfuscation_note_only_for_risky_memo_stack_global(self) -> None:
        report = PickleAnalyzer().analyze(MEMO_ATTACK)
        assert any("memo-fed STACK_GLOBAL" in e and "SINK" in e for e in report.emulation_errors)
