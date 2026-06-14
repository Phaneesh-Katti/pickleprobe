"""Tests for GLOBAL and STACK_GLOBAL resolution."""

from __future__ import annotations

import pickle

from polyglot.analysis.analyzer import PickleAnalyzer
from polyglot.domain.cfg import NodeKind
from polyglot.domain.values import TaintKind


# Classic direct GLOBAL RCE shape (never call pickle.load on untrusted input).
MALICIOUS_GLOBAL = b"cos\nsystem\n(S'echo pwned'\ntR."

# STACK_GLOBAL with literal strings on the stack.
MALICIOUS_STACK_GLOBAL = b"S'os'\nS'system'\n\x93(S'id'\ntR."

# Benign: datetime constructor via GLOBAL (common legitimate pattern).
def _benign_datetime_pickle() -> bytes:
    import datetime

    return pickle.dumps(datetime.datetime(2024, 1, 1, 12, 0, 0), protocol=0)


class TestGlobalOpcode:
    def test_resolves_global_target(self) -> None:
        report = PickleAnalyzer().analyze(MALICIOUS_GLOBAL)
        assert len(report.global_refs) == 1

        ref = report.global_refs[0]
        assert ref.opcode == "GLOBAL"
        assert ref.module == "os"
        assert ref.name == "system"
        assert ref.is_resolved
        assert ref.taint is TaintKind.CONST

    def test_cfg_contains_global_lookup_node(self) -> None:
        report = PickleAnalyzer().analyze(MALICIOUS_GLOBAL)
        lookups = report.cfg.global_lookups
        assert len(lookups) == 1
        assert lookups[0].kind is NodeKind.GLOBAL_LOOKUP
        assert lookups[0].global_ref is not None
        assert lookups[0].global_ref.qualified_name == "os.system"


class TestStackGlobalOpcode:
    def test_resolves_stack_global_literals(self) -> None:
        report = PickleAnalyzer().analyze(MALICIOUS_STACK_GLOBAL)
        assert len(report.global_refs) == 1

        ref = report.global_refs[0]
        assert ref.opcode == "STACK_GLOBAL"
        assert ref.module == "os"
        assert ref.name == "system"
        assert ref.is_resolved

    def test_cfg_links_opcode_to_lookup(self) -> None:
        report = PickleAnalyzer().analyze(MALICIOUS_STACK_GLOBAL)
        lookups = report.cfg.global_lookups
        assert len(lookups) == 1
        assert lookups[0].opcode == "STACK_GLOBAL"


class TestMemoIndirection:
    def test_binget_restores_strings_for_stack_global(self) -> None:
        # os + system stored in memo, retrieved before STACK_GLOBAL
        payload = (
            b"S'os'\n"
            b"p0\n"
            b"S'system'\n"
            b"p1\n"
            b"g0\n"
            b"g1\n"
            b"\x93"
            b"."
        )
        report = PickleAnalyzer().analyze(payload)
        assert len(report.global_refs) == 1
        ref = report.global_refs[0]
        assert ref.module == "os"
        assert ref.name == "system"
        assert ref.taint is TaintKind.MEMO


class TestBenignPickle:
    def test_datetime_global_is_resolved(self) -> None:
        report = PickleAnalyzer().analyze(_benign_datetime_pickle())
        globals_found = [r for r in report.global_refs if r.is_resolved]
        assert globals_found
        qualified = {r.qualified_name for r in globals_found}
        assert any("datetime" in (q or "") for q in qualified)
