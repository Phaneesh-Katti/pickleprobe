"""Tests for format detection and PyTorch ZIP extraction."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from polyglot.analysis.analyzer import PickleAnalyzer
from polyglot.domain.security import SecurityTaint
from polyglot.formats.loader import FileFormat, detect_format, extract_streams, load_file

MALICIOUS_GLOBAL = b"cos\nsystem\n(S'echo pwned'\ntR."
CORPUS = Path(__file__).resolve().parent / "corpus" / "samples"


class TestFormatDetection:
    def test_raw_pickle_detected(self) -> None:
        assert detect_format(MALICIOUS_GLOBAL) is FileFormat.RAW_PICKLE

    def test_zip_detected(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("data.pkl", MALICIOUS_GLOBAL)
        assert detect_format(buf.getvalue()) is FileFormat.PYTORCH_ZIP


class TestZipExtraction:
    def test_extracts_pkl_members(self) -> None:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl", MALICIOUS_GLOBAL)
            zf.writestr("meta.json", b"{}")

        streams = extract_streams(buf.getvalue())
        assert len(streams) == 1
        assert streams[0].name == "archive/data.pkl"
        assert streams[0].data == MALICIOUS_GLOBAL

    def test_analyze_file_on_zip_pickle(self, tmp_path: Path) -> None:
        path = tmp_path / "model.pt"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("archive/data.pkl", MALICIOUS_GLOBAL)
        path.write_bytes(buf.getvalue())

        result = PickleAnalyzer().analyze_file(path)
        assert result.format is FileFormat.PYTORCH_ZIP
        assert len(result.streams) == 1
        report = result.primary
        assert report.sink_invocations
        assert report.sink_invocations[0].callable_qualified == "os.system"
        assert report.sink_invocations[0].invocation_security is SecurityTaint.SINK

    def test_load_file_round_trip(self) -> None:
        path = CORPUS / "malicious/raw/global_os_system.pkl"
        loaded = load_file(path)
        assert loaded.format is FileFormat.RAW_PICKLE
        assert len(loaded.streams) == 1
        assert loaded.streams[0].data == path.read_bytes()
