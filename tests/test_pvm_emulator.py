"""Unit tests for the PVM emulator in isolation."""

from __future__ import annotations

from polyglot.pvm.emulator import PvmEmulator


class TestPvmEmulator:
    def test_empty_stream_yields_no_globals(self) -> None:
        result = PvmEmulator().emulate(b".")
        assert result.global_refs == []

    def test_stack_underflow_marks_unresolved(self) -> None:
        # STACK_GLOBAL with nothing on the stack
        result = PvmEmulator().emulate(b"\x93.")
        assert len(result.global_refs) == 1
        assert result.global_refs[0].module is None
        assert result.global_refs[0].name is None
