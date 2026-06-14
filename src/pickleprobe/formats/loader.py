"""Input format detection and pickle stream extraction."""

from __future__ import annotations

import io
import zipfile
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

# Common PyTorch zip layouts (torch.save legacy and zip-serialization).
_PYTORCH_PICKLE_PATHS = (
    "archive/data.pkl",
    "data.pkl",
    "pickle.pkl",
)


class FileFormat(Enum):
    RAW_PICKLE = auto()
    PYTORCH_ZIP = auto()


@dataclass(frozen=True)
class PickleStream:
    """One pickle byte stream extracted from a file."""

    name: str
    data: bytes


@dataclass(frozen=True)
class LoadedFile:
    """A file loaded and split into analyzable pickle streams."""

    path: Path
    format: FileFormat
    streams: tuple[PickleStream, ...]


def detect_format(data: bytes) -> FileFormat:
    if len(data) >= 4 and data[:2] == b"PK":
        return FileFormat.PYTORCH_ZIP
    return FileFormat.RAW_PICKLE


def extract_streams(data: bytes, *, label: str = "raw") -> tuple[PickleStream, ...]:
    fmt = detect_format(data)
    if fmt is FileFormat.PYTORCH_ZIP:
        return _extract_from_zip(data)
    return (PickleStream(name=label, data=data),)


def load_file(path: Path) -> LoadedFile:
    data = path.read_bytes()
    fmt = detect_format(data)
    if fmt is FileFormat.PYTORCH_ZIP:
        streams = _extract_from_zip(data)
    else:
        streams = (PickleStream(name="raw", data=data),)
    return LoadedFile(path=path, format=fmt, streams=streams)


def _extract_from_zip(data: bytes) -> tuple[PickleStream, ...]:
    streams: list[PickleStream] = []
    seen: set[str] = set()

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()

        # Prefer known PyTorch pickle paths first (stable ordering).
        for preferred in _PYTORCH_PICKLE_PATHS:
            if preferred in names and preferred not in seen:
                streams.append(PickleStream(name=preferred, data=zf.read(preferred)))
                seen.add(preferred)

        for name in sorted(names):
            if name.endswith("/") or name in seen:
                continue
            lower = name.lower()
            if lower.endswith((".pkl", ".pickle", ".pth")) or "pickle" in lower:
                streams.append(PickleStream(name=name, data=zf.read(name)))
                seen.add(name)

    if not streams:
        raise ValueError("zip archive contains no pickle members")
    return tuple(streams)
