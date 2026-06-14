"""Streaming batch scan over files and archive members."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from pickleprobe.formats.loader import _is_archive_path, iter_archive_member_names


@dataclass(frozen=True)
class ScanTarget:
    """One analyzable unit: a file, or one member inside a ``.tar.gz`` archive."""

    path: Path
    member: str | None = None

    @property
    def label(self) -> str:
        if self.member:
            return f"{self.path.name}|{self.member}"
        return str(self.path)


@dataclass
class ScanSummaryRow:
    target: str
    sinks: int
    suspicious: int
    risky_builds: int
    streams: int
    exit_code: int
    bytes_analyzed: int
    error: str | None = None


def iter_scan_targets(
    root: Path,
    *,
    recursive: bool = False,
    archive_members: bool = True,
    limit: int | None = None,
    max_member_bytes: int | None = None,
) -> Iterator[ScanTarget]:
    """Yield scan units without loading file contents upfront."""
    count = 0
    if root.is_file():
        for target in _targets_for_path(
            root, archive_members=archive_members, max_member_bytes=max_member_bytes
        ):
            yield target
            count += 1
            if limit is not None and count >= limit:
                return
        return

    if not root.is_dir():
        raise FileNotFoundError(f"not a file or directory: {root}")

    paths = sorted(root.rglob("*") if recursive else root.iterdir())
    for path in paths:
        if not path.is_file():
            continue
        for target in _targets_for_path(
            path, archive_members=archive_members, max_member_bytes=max_member_bytes
        ):
            yield target
            count += 1
            if limit is not None and count >= limit:
                return


def _targets_for_path(
    path: Path,
    *,
    archive_members: bool,
    max_member_bytes: int | None,
) -> Iterator[ScanTarget]:
    if archive_members and _is_archive_path(path):
        for member_name in iter_archive_member_names(path, max_member_bytes=max_member_bytes):
            yield ScanTarget(path=path, member=member_name)
        return
    yield ScanTarget(path=path)


def summarize_reports(reports: list) -> tuple[int, int, int, int]:
    """Return (sinks, suspicious, risky_builds, bytes) across analysis reports."""
    sinks = suspicious = risky_builds = nbytes = 0
    for report in reports:
        sinks += len(report.sink_invocations)
        suspicious += len(report.suspicious_invocations)
        risky_builds += len(report.risky_builds)
        nbytes += report.raw_size
    return sinks, suspicious, risky_builds, nbytes
