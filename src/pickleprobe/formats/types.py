"""Shared format types."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class PickleStream:
    """One pickle byte stream extracted from a file."""

    name: str
    data: bytes
