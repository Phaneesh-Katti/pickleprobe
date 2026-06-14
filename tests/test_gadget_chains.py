"""Tests for extended gadget chain symbolic folding."""

from __future__ import annotations

from pickleprobe.analysis.analyzer import PickleAnalyzer
from pickleprobe.domain.security import SecurityTaint


class TestPartialGadget:
    def test_partial_os_system_is_sink(self) -> None:
        # REDUCE partial → REDUCE result; second REDUCE invokes partial(cmd)
        payload = (
            b"cfunctools\npartial\n"
            b"(cos\n"
            b"system\n"
            b"tR"
            b"p0\n"
            b"(S'id'\n"
            b"tR."
        )
        report = PickleAnalyzer().analyze(payload)
        assert len(report.reduce_events) == 2
        partial_ev, invoke_ev = report.reduce_events
        assert partial_ev.callable_qualified == "functools.partial"
        invoke_ev.callable_qualified in ("functools.partial", "os.system")
        assert invoke_ev.invocation_security is SecurityTaint.SINK


class TestMethodcallerGadget:
    def test_methodcaller_system_is_suspicious(self) -> None:
        payload = (
            b"coperator\nmethodcaller\n"
            b"(S'system'\n"
            b"S'id'\n"
            b"tR."
        )
        report = PickleAnalyzer().analyze(payload)
        assert len(report.reduce_events) == 1
        ev = report.reduce_events[0]
        assert ev.callable_qualified == "operator.methodcaller"
        assert ev.invocation_security is SecurityTaint.SUSPICIOUS
