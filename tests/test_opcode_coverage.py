"""Tests for full opcode coverage on benign real-world pickles."""

from __future__ import annotations

import pickle

from polyglot.analysis.analyzer import PickleAnalyzer


class TestProtocol4Containers:
    def test_dict_setitems_no_errors(self) -> None:
        data = pickle.dumps({"a": 1, "b": 2, "c": 3}, protocol=4)
        report = PickleAnalyzer().analyze(data)
        assert not any("SETITEMS" in e for e in report.emulation_errors)

    def test_list_appends_no_errors(self) -> None:
        data = pickle.dumps([1, 2, 3, 4], protocol=4)
        report = PickleAnalyzer().analyze(data)
        assert not any("APPENDS" in e for e in report.emulation_errors)

    def test_set_additems_no_errors(self) -> None:
        data = pickle.dumps({1, 2, 3}, protocol=4)
        report = PickleAnalyzer().analyze(data)
        assert not any("ADDITEMS" in e for e in report.emulation_errors)

    def test_datetime_still_clean(self) -> None:
        import datetime

        data = pickle.dumps(datetime.datetime(2024, 1, 1), protocol=0)
        report = PickleAnalyzer().analyze(data)
        assert not report.sink_invocations
