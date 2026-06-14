"""Tests for REDUCE analysis, security taint, and CFG dataflow."""

from __future__ import annotations

import pickle

from polyglot.analysis.analyzer import PickleAnalyzer
from polyglot.domain.cfg import EdgeKind, NodeKind
from polyglot.domain.security import SecurityTaint

MALICIOUS_GLOBAL = b"cos\nsystem\n(S'echo pwned'\ntR."
MALICIOUS_STACK_GLOBAL = b"S'os'\nS'system'\n\x93(S'id'\ntR."


class TestReduceSinkDetection:
    def test_direct_os_system_reduce_is_sink(self) -> None:
        report = PickleAnalyzer().analyze(MALICIOUS_GLOBAL)
        assert len(report.reduce_events) == 1
        ev = report.reduce_events[0]
        assert ev.callable_qualified == "os.system"
        assert ev.args == ("echo pwned",)
        assert ev.invocation_security is SecurityTaint.SINK
        assert len(report.sink_invocations) == 1

    def test_stack_global_chain_reduce_is_sink(self) -> None:
        report = PickleAnalyzer().analyze(MALICIOUS_STACK_GLOBAL)
        assert len(report.reduce_events) == 1
        ev = report.reduce_events[0]
        assert ev.callable_qualified == "os.system"
        assert ev.invocation_security is SecurityTaint.SINK


class TestReduceCfg:
    def test_reduce_invoke_node_linked_to_global(self) -> None:
        report = PickleAnalyzer().analyze(MALICIOUS_GLOBAL)
        reduces = report.cfg.reduce_invocations
        assert len(reduces) == 1
        assert reduces[0].kind is NodeKind.REDUCE_INVOKE
        assert reduces[0].reduce_event is not None
        assert reduces[0].reduce_event.callable_qualified == "os.system"

        invoke_id = reduces[0].id
        callable_edges = [
            e for e in report.cfg.edges
            if e.target == invoke_id and e.kind is EdgeKind.CALLABLE_FLOW
        ]
        assert len(callable_edges) == 1
        source = report.cfg.nodes[callable_edges[0].source]
        assert source.kind is NodeKind.GLOBAL_LOOKUP
        assert source.global_ref is not None
        assert source.global_ref.qualified_name == "os.system"

    def test_args_flow_from_string_and_tuple(self) -> None:
        report = PickleAnalyzer().analyze(MALICIOUS_GLOBAL)
        invoke = report.cfg.reduce_invocations[0]
        args_edges = [
            e
            for e in report.cfg.edges
            if e.target == invoke.id and e.kind is EdgeKind.ARGS_FLOW
        ]
        source_nodes = [report.cfg.nodes[e.source] for e in args_edges]
        opcodes = {(n.opcode, n.offset) for n in source_nodes}

        # Payload string and the TUPLE that packaged it flow into REDUCE args.
        assert ("STRING", 12) in opcodes
        assert ("TUPLE", 26) in opcodes
        assert len(args_edges) >= 2


class TestGetattrGadgetChain:
    def test_getattr_to_system_produces_sink_result(self) -> None:
        # getattr(os_module, 'system') via two REDUCEs — no GLOBAL os system
        payload = (
            b"cbuiltins\n__import__\n"
            b"(S'os'\n"
            b"tR"
            b"p0\n"
            b"cbuiltins\ngetattr\n"
            b"(g0\n"
            b"S'system'\n"
            b"tR."
        )
        report = PickleAnalyzer().analyze(payload)
        assert len(report.reduce_events) == 2

        import_ev, getattr_ev = report.reduce_events
        assert import_ev.callable_qualified == "builtins.__import__"
        assert import_ev.invocation_security is SecurityTaint.SUSPICIOUS

        assert getattr_ev.callable_qualified == "builtins.getattr"
        assert getattr_ev.result_qualified == "os.system"
        assert getattr_ev.result_security is SecurityTaint.SINK

        # os module arg flows from first REDUCE; 'system' from STRING
        assert any(r.kind == "REDUCE" and r.offset == 29 for r in getattr_ev.args_producer_refs)
        assert any(r.kind == "STRING" for r in getattr_ev.args_producer_refs)

        invoke = report.cfg.reduce_invocations[1]
        args_edges = [
            e for e in report.cfg.edges
            if e.target == invoke.id and e.kind is EdgeKind.ARGS_FLOW
        ]
        assert args_edges


class TestBenignReduce:
    def test_datetime_reduce_is_clean(self) -> None:
        import datetime

        data = pickle.dumps(datetime.datetime(2024, 1, 1), protocol=0)
        report = PickleAnalyzer().analyze(data)
        assert report.reduce_events
        assert not report.sink_invocations
        assert all(
            e.invocation_security is SecurityTaint.CLEAN
            for e in report.reduce_events
        )
