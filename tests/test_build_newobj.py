"""Tests for BUILD and NEWOBJ opcode tracking and CFG edges."""

from __future__ import annotations

import pickle
from pathlib import Path

import pytest

from pickleprobe.analysis.analyzer import PickleAnalyzer
from pickleprobe.domain.cfg import EdgeKind, NodeKind
from pickleprobe.domain.security import SecurityTaint

CORPUS = Path(__file__).resolve().parent / "corpus" / "samples"


class Newable:
    def __new__(cls, x):
        return super().__new__(cls)

    def __init__(self, x):
        self.x = x


def _newobj_build_payload() -> bytes:
    path = CORPUS / "benign/raw/newobj_build_protocol2.pkl"
    if path.exists():
        return path.read_bytes()
    return pickle.dumps(Newable(1), protocol=2)


class TestNewObjTracking:
    def test_records_newobj_event(self) -> None:
        report = PickleAnalyzer().analyze(_newobj_build_payload())
        assert len(report.newobj_events) == 1
        ev = report.newobj_events[0]
        assert ev.opcode == "NEWOBJ"
        assert ev.class_qualified is not None
        assert "Newable" in ev.class_qualified
        assert ev.invocation_security in (SecurityTaint.CLEAN, SecurityTaint.INCONCLUSIVE)

    def test_newobj_cfg_invoke_node(self) -> None:
        report = PickleAnalyzer().analyze(_newobj_build_payload())
        invokes = report.cfg.newobj_invocations
        assert len(invokes) == 1
        assert invokes[0].newobj_event is not None

        invoke_id = invokes[0].id
        callable_edges = [
            e for e in report.cfg.edges
            if e.target == invoke_id and e.kind is EdgeKind.CALLABLE_FLOW
        ]
        assert len(callable_edges) == 1
        source = report.cfg.nodes[callable_edges[0].source]
        assert source.kind is NodeKind.GLOBAL_LOOKUP


class TestBuildTracking:
    def test_records_build_event(self) -> None:
        report = PickleAnalyzer().analyze(_newobj_build_payload())
        assert len(report.build_events) == 1
        ev = report.build_events[0]
        assert ev.instance_qualified is not None
        assert "Newable" in ev.instance_qualified
        assert ev.invocation_security in (SecurityTaint.CLEAN, SecurityTaint.INCONCLUSIVE)

    def test_build_cfg_state_flow(self) -> None:
        report = PickleAnalyzer().analyze(_newobj_build_payload())
        invokes = report.cfg.build_invocations
        assert len(invokes) == 1
        invoke_id = invokes[0].id

        instance_edges = [
            e for e in report.cfg.edges
            if e.target == invoke_id and e.kind is EdgeKind.INSTANCE_FLOW
        ]
        state_edges = [
            e for e in report.cfg.edges
            if e.target == invoke_id and e.kind is EdgeKind.STATE_FLOW
        ]
        assert len(instance_edges) == 1
        assert state_edges

        instance_source = report.cfg.nodes[instance_edges[0].source]
        assert instance_source.kind is NodeKind.NEWOBJ_INVOKE
