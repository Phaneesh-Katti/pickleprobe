"""Tests for streaming batch scan targets."""

from __future__ import annotations

import io
import tarfile
from pathlib import Path

from pickleprobe.analysis.batch import iter_scan_targets
from pickleprobe.analysis.analyzer import PickleAnalyzer

MALICIOUS = b"cos\nsystem\n(S'id'\ntR."


def test_iter_scan_targets_archive_members(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name in ("a/evil.pkl", "b/clean.pkl"):
            data = io.BytesIO(MALICIOUS)
            info = tarfile.TarInfo(name=name)
            info.size = len(MALICIOUS)
            tf.addfile(info, data)
    arch = tmp_path / "corpus.tar.gz"
    arch.write_bytes(buf.getvalue())

    targets = list(iter_scan_targets(arch, archive_members=True))
    assert len(targets) == 2
    assert targets[0].member == "a/evil.pkl"


def test_analyze_target_single_member(tmp_path: Path) -> None:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        data = io.BytesIO(MALICIOUS)
        info = tarfile.TarInfo(name="evil.pkl")
        info.size = len(MALICIOUS)
        tf.addfile(info, data)
    arch = tmp_path / "one.tar.gz"
    arch.write_bytes(buf.getvalue())

    reports = PickleAnalyzer().analyze_target(arch, member="evil.pkl")
    assert len(reports) == 1
    assert reports[0].sink_invocations
