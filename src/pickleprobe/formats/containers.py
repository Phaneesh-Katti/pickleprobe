"""Recursive container peeling (ZIP / gzip) for nested pickle extraction."""

from __future__ import annotations

import gzip
import io
import zipfile
from dataclasses import dataclass

from pickleprobe.formats.types import PickleStream


@dataclass(frozen=True)
class PeelLimits:
    max_depth: int = 4
    max_members: int = 32
    max_total_bytes: int = 64 * 1024 * 1024


def peel_pickle_streams(
    data: bytes,
    *,
    label: str = "raw",
    depth: int = 0,
    limits: PeelLimits | None = None,
) -> tuple[PickleStream, ...]:
    """Extract pickle byte streams, unwrapping nested ZIP/gzip layers."""
    lim = limits or PeelLimits()
    if depth > lim.max_depth or len(data) > lim.max_total_bytes:
        return (PickleStream(name=label, data=data),)

    # gzip wrapper (not pickle, but common transport)
    if len(data) >= 2 and data[:2] == b"\x1f\x8b":
        try:
            inner = gzip.decompress(data)
            inner_label = f"{label}|gzip"
            return peel_pickle_streams(inner, label=inner_label, depth=depth + 1, limits=lim)
        except OSError:
            pass

    # ZIP archive (PyTorch, picklescan nested samples)
    if len(data) >= 4 and data[:2] == b"PK":
        streams: list[PickleStream] = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                names = [n for n in zf.namelist() if not n.endswith("/")]
                pickle_names = [
                    n
                    for n in names
                    if n.lower().endswith((".pkl", ".pickle", ".pth", ".pt", ".bin"))
                    or "pickle" in n.lower()
                    or n.endswith("data.pkl")
                ]
                if not pickle_names:
                    pickle_names = names[: lim.max_members]
                for name in sorted(pickle_names)[: lim.max_members]:
                    member = zf.read(name)
                    nested_label = f"{label}|zip:{name}"
                    if member[:2] == b"PK" or member[:2] == b"\x1f\x8b":
                        streams.extend(
                            peel_pickle_streams(
                                member, label=nested_label, depth=depth + 1, limits=lim
                            )
                        )
                    elif _looks_like_pickle(member):
                        streams.append(PickleStream(name=nested_label, data=member))
        except zipfile.BadZipFile:
            return (PickleStream(name=label, data=data),)
        if streams:
            return tuple(streams)

    if _looks_like_pickle(data):
        return (PickleStream(name=label, data=data),)
    return (PickleStream(name=label, data=data),)


def _looks_like_pickle(data: bytes) -> bool:
    if not data:
        return False
    head = data[:32]
    if head.startswith((b"\x80", b"(", b"]", b"}", b"c", b"(")):
        return True
    if b"\n" in head[:16]:
        return True
    return False
