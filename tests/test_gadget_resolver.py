"""Tests for multi-hop gadget resolution with adaptive hop limits."""

from __future__ import annotations

from pickleprobe.analysis.analyzer import PickleAnalyzer
from pickleprobe.analysis.gadget_resolver import GadgetMetrics, max_resolution_hops
from pickleprobe.domain.taint import SecurityTaint
from pickleprobe.pvm.emulator import PvmEmulator


def _import_getattr_partial_chain() -> bytes:
    """__import__('os') → getattr → getattr → partial → invoke (5 REDUCE hops)."""
    return (
        b"c__builtin__\n__import__\n"
        b"(S'os'\n"
        b"tR"
        b"p0\n"
        b"c__builtin__\ngetattr\n"
        b"(g0\n"
        b"S'system'\n"
        b"tR"
        b"p1\n"
        b"cfunctools\npartial\n"
        b"(g1\n"
        b"tR"
        b"p2\n"
        b"g2\n"
        b"(S'echo multi-hop'\n"
        b"tR."
    )


class TestMultiHopGadgets:
    def test_import_getattr_partial_chain_resolves_sink(self) -> None:
        report = PickleAnalyzer().analyze(_import_getattr_partial_chain())
        assert len(report.reduce_events) >= 4
        assert any(ev.invocation_security is SecurityTaint.SINK for ev in report.reduce_events)
        assert report.gadget_hop_cap >= 8
        assert report.gadget_iterations >= 1

    def test_hop_cap_scales_with_reduce_count(self) -> None:
        emu = PvmEmulator().emulate(_import_getattr_partial_chain())
        metrics = GadgetMetrics.from_emulation(emu)
        assert metrics.reduce_count >= 4
        assert max_resolution_hops(metrics) >= 8
        small = GadgetMetrics(reduce_count=1, memo_event_count=0, global_lookup_count=2, build_count=0, newobj_count=0, max_stack_depth=4)
        large = GadgetMetrics(reduce_count=10, memo_event_count=6, global_lookup_count=5, build_count=2, newobj_count=2, max_stack_depth=12)
        assert max_resolution_hops(large) > max_resolution_hops(small)


class TestBuildStateInjection:
    def test_build_with_exec_string_in_state(self) -> None:
        # NEWOBJ list + BUILD with dict state containing os.system string
        payload = (
            b"(lp0\n"
            b"(dp1\n"
            b"S'payload'\n"
            b"S'import os; os.system(\"id\")'\n"
            b"tp2\n"
            b"b."
        )
        report = PickleAnalyzer().analyze(payload)
        if report.build_events:
            assert any(
                ev.invocation_security in (SecurityTaint.SUSPICIOUS, SecurityTaint.SINK)
                for ev in report.build_events
            )
