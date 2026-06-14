"""Input format detection and pickle stream extraction."""

from __future__ import annotations

import io
import tarfile
import zipfile
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Iterator

from pickleprobe.formats.containers import PeelLimits, peel_pickle_streams
from pickleprobe.formats.types import PickleStream

# Common PyTorch zip layouts (torch.save legacy and zip-serialization).
_PYTORCH_PICKLE_PATHS = (
    "archive/data.pkl",
    "data.pkl",
    "pickle.pkl",
    "constants.pkl",
)

_PICKLE_MEMBER_SUFFIXES = (".pkl", ".pickle", ".pth", ".pt", ".pt2", ".bin")


class FileFormat(Enum):
    RAW_PICKLE = auto()
    PYTORCH_ZIP = auto()
    NESTED_CONTAINER = auto()
    PYTORCH_TAR = auto()
    TAR_GZ_ARCHIVE = auto()


@dataclass(frozen=True)
class LoadedFile:
    """A file loaded and split into analyzable pickle streams."""

    path: Path
    format: FileFormat
    streams: tuple[PickleStream, ...]


def _is_archive_path(path: Path) -> bool:
    lower = path.name.lower()
    return lower.endswith(".tar.gz") or lower.endswith(".tgz")


def _is_pickle_member(name: str) -> bool:
    lower = name.lower()
    return lower.endswith(_PICKLE_MEMBER_SUFFIXES) or "pickle" in lower


def detect_format(data: bytes) -> FileFormat:
    if len(data) >= 262 and data[257:262] == b"ustar":
        return FileFormat.PYTORCH_TAR
    if len(data) >= 4 and data[:2] == b"PK":
        return FileFormat.PYTORCH_ZIP
    if len(data) >= 2 and data[:2] == b"\x1f\x8b":
        return FileFormat.NESTED_CONTAINER
    return FileFormat.RAW_PICKLE


def iter_archive_member_names(
    path: Path,
    *,
    max_member_bytes: int | None = None,
) -> Iterator[str]:
    """Yield pickle-like member paths inside a ``.tar.gz`` (headers only, no payload read)."""
    if not _is_archive_path(path):
        return
    with tarfile.open(path, mode="r:gz") as tf:
        for member in tf:
            if not member.isfile() or not _is_pickle_member(member.name):
                continue
            if max_member_bytes is not None and member.size > max_member_bytes:
                continue
            yield member.name


def iter_archive_members(
    path: Path,
    *,
    max_member_bytes: int | None = None,
) -> tuple[str, ...]:
    """List pickle-like member paths inside a ``.tar.gz`` without extracting to disk."""
    return tuple(iter_archive_member_names(path, max_member_bytes=max_member_bytes))


def iter_archive_pickle_members(
    path: Path,
    *,
    member_names: set[str] | None = None,
    max_member_bytes: int | None = None,
) -> Iterator[tuple[str, bytes]]:
    """Stream ``(member_name, data)`` from a tarball — no full extract to disk."""
    if not _is_archive_path(path):
        return
    lim = max_member_bytes
    with tarfile.open(path, mode="r:gz") as tf:
        for member in tf:
            if not member.isfile() or not _is_pickle_member(member.name):
                continue
            if member_names is not None and member.name not in member_names:
                continue
            if lim is not None and member.size > lim:
                continue
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            yield member.name, extracted.read()


def read_archive_member(path: Path, member_name: str) -> bytes:
    """Read one named member from a ``.tar.gz`` archive."""
    for name, data in iter_archive_pickle_members(path, member_names={member_name}):
        if name == member_name:
            return data
    raise FileNotFoundError(f"member {member_name!r} not found in {path}")


def load_file(
    path: Path,
    *,
    peel_limits: PeelLimits | None = None,
    archive_member_limit: int = 64,
) -> LoadedFile:
    """Load a pickle artifact; ``.tar.gz`` archives are read member-wise (no full extract)."""
    if _is_archive_path(path):
        return _load_tar_gz_archive(
            path, peel_limits=peel_limits, member_limit=archive_member_limit
        )

    data = path.read_bytes()
    fmt = detect_format(data)
    if fmt is FileFormat.PYTORCH_TAR:
        streams = _extract_from_tar(data, label=path.name)
    elif fmt is FileFormat.PYTORCH_ZIP:
        streams = _extract_from_zip(data)
        if not streams:
            streams = peel_pickle_streams(data, label=path.name, limits=peel_limits)
    else:
        streams = peel_pickle_streams(data, label=path.name, limits=peel_limits)
    if fmt is FileFormat.RAW_PICKLE and len(streams) > 1:
        fmt = FileFormat.NESTED_CONTAINER
    return LoadedFile(path=path, format=fmt, streams=tuple(streams))


def extract_streams(data: bytes, *, label: str = "raw") -> tuple[PickleStream, ...]:
    fmt = detect_format(data)
    if fmt is FileFormat.PYTORCH_TAR:
        return _extract_from_tar(data, label=label)
    if fmt is FileFormat.PYTORCH_ZIP:
        streams = _extract_from_zip(data)
        return streams if streams else peel_pickle_streams(data, label=label)
    if fmt is FileFormat.NESTED_CONTAINER:
        return peel_pickle_streams(data, label=label)
    return peel_pickle_streams(data, label=label)


def _extract_from_zip(data: bytes) -> tuple[PickleStream, ...]:
    streams: list[PickleStream] = []
    seen: set[str] = set()

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()

        for preferred in _PYTORCH_PICKLE_PATHS:
            if preferred in names and preferred not in seen:
                inner = zf.read(preferred)
                streams.extend(peel_pickle_streams(inner, label=preferred))
                seen.add(preferred)

        for name in sorted(names):
            if name.endswith("/") or name in seen:
                continue
            lower = name.lower()
            if lower.endswith(_PICKLE_MEMBER_SUFFIXES) or "pickle" in lower:
                inner = zf.read(name)
                streams.extend(peel_pickle_streams(inner, label=name))
                seen.add(name)

    return tuple(streams)


def _extract_from_tar(data: bytes, *, label: str) -> tuple[PickleStream, ...]:
    streams: list[PickleStream] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                if not _is_pickle_member(member.name):
                    continue
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                inner = extracted.read()
                streams.extend(peel_pickle_streams(inner, label=f"{label}|tar:{member.name}"))
    except tarfile.TarError:
        return peel_pickle_streams(data, label=label)
    return tuple(streams) if streams else peel_pickle_streams(data, label=label)


def _load_tar_gz_archive(
    path: Path,
    *,
    peel_limits: PeelLimits | None,
    member_limit: int,
) -> LoadedFile:
    """Stream members from a gzip tarball — keeps disk usage to one archive file."""
    streams: list[PickleStream] = []
    lim = peel_limits or PeelLimits()
    try:
        with tarfile.open(path, mode="r:gz") as tf:
            members = [
                m for m in tf.getmembers() if m.isfile() and _is_pickle_member(m.name)
            ]
            for member in sorted(members, key=lambda m: m.name)[:member_limit]:
                extracted = tf.extractfile(member)
                if extracted is None:
                    continue
                inner = extracted.read()
                if len(inner) > lim.max_total_bytes:
                    continue
                nested_label = f"{path.name}|{member.name}"
                streams.extend(
                    peel_pickle_streams(inner, label=nested_label, limits=lim)
                )
    except (tarfile.TarError, OSError):
        return LoadedFile(
            path=path,
            format=FileFormat.TAR_GZ_ARCHIVE,
            streams=(PickleStream(name=path.name, data=b""),),
        )
    return LoadedFile(path=path, format=FileFormat.TAR_GZ_ARCHIVE, streams=tuple(streams))
