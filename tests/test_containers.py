"""Tests for nested container peeling."""

from __future__ import annotations

import io
import tarfile
import zipfile
from pathlib import Path

from pickleprobe.analysis.analyzer import PickleAnalyzer
from pickleprobe.formats.loader import FileFormat, iter_archive_members, load_file

MALICIOUS_GLOBAL = b"cos\nsystem\n(S'echo nested'\ntR."


class TestNestedContainers:
    def test_zip_wrapped_pickle_analyzed(self, tmp_path: Path) -> None:
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("payload/inner.pkl", MALICIOUS_GLOBAL)
        path = tmp_path / "nested.zip.pkl"
        path.write_bytes(inner.getvalue())

        loaded = load_file(path)
        assert len(loaded.streams) >= 1
        result = PickleAnalyzer().analyze_file(path)
        assert result.primary.sink_invocations

    def test_nested_zip_format_detected(self, tmp_path: Path) -> None:
        outer = io.BytesIO()
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as zf:
            zf.writestr("data.pkl", MALICIOUS_GLOBAL)
        with zipfile.ZipFile(outer, "w") as zf:
            zf.writestr("wrapper.zip", inner.getvalue())
        path = tmp_path / "double.zip"
        path.write_bytes(outer.getvalue())
        loaded = load_file(path)
        assert loaded.format in (FileFormat.NESTED_CONTAINER, FileFormat.PYTORCH_ZIP)
        assert len(loaded.streams) >= 1

    def test_tar_gz_archive_read_without_extract(self, tmp_path: Path) -> None:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = io.BytesIO(MALICIOUS_GLOBAL)
            info = tarfile.TarInfo(name="models/evil.pkl")
            info.size = len(MALICIOUS_GLOBAL)
            tf.addfile(info, data)
        path = tmp_path / "pickleball-sample.tar.gz"
        path.write_bytes(buf.getvalue())

        assert iter_archive_members(path) == ("models/evil.pkl",)
        loaded = load_file(path)
        assert loaded.format is FileFormat.TAR_GZ_ARCHIVE
        result = PickleAnalyzer().analyze_file(path)
        assert result.primary.sink_invocations
