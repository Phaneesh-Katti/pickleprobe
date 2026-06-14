"""Load and query versioned security policy from YAML."""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from polyglot.domain.taint import SecurityTaint


@dataclass(frozen=True)
class PolicyRule:
    module: str
    name: str

    @property
    def qualified(self) -> str:
        return f"{self.module}.{self.name}"

    @property
    def pair(self) -> tuple[str, str]:
        return (self.module, self.name)


@dataclass
class SecurityPolicy:
    """Mutable view of loaded policy rules."""

    version: int = 1
    sinks: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    chain_primitives: frozenset[tuple[str, str]] = field(default_factory=frozenset)
    sensitive_attrs: frozenset[str] = field(default_factory=frozenset)
    extension_codes_suspicious: bool = True
    memo_warnings: dict[str, bool] = field(default_factory=dict)

    def classify_pair(self, module: str | None, name: str | None) -> SecurityTaint:
        if module is None or name is None:
            return SecurityTaint.INCONCLUSIVE
        pair = (module, name)
        if pair in self.sinks:
            return SecurityTaint.SINK
        if pair in self.chain_primitives:
            return SecurityTaint.SUSPICIOUS
        return SecurityTaint.CLEAN

    def is_sink_pair(self, pair: tuple[str, str]) -> bool:
        return pair in self.sinks

    def is_sensitive_attr(self, attr: str) -> bool:
        return attr in self.sensitive_attrs


def _parse_rules(items: list[Any]) -> frozenset[tuple[str, str]]:
    out: set[tuple[str, str]] = set()
    for item in items or []:
        if isinstance(item, dict) and "module" in item and "name" in item:
            out.add((str(item["module"]), str(item["name"])))
    return frozenset(out)


def load_policy(path: Path | None = None) -> SecurityPolicy:
    """Load policy from YAML file or bundled default."""
    if path is None:
        raw = resources.files("polyglot.policy").joinpath("default.yaml").read_text(encoding="utf-8")
    else:
        raw = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(raw) or {}
    return SecurityPolicy(
        version=int(doc.get("version", 1)),
        sinks=_parse_rules(doc.get("sinks", [])),
        chain_primitives=_parse_rules(doc.get("chain_primitives", [])),
        sensitive_attrs=frozenset(str(x) for x in doc.get("sensitive_attrs", [])),
        extension_codes_suspicious=bool(doc.get("extension_codes_suspicious", True)),
        memo_warnings=dict(doc.get("memo_warnings") or {}),
    )


@lru_cache(maxsize=4)
def get_policy(path: str | None = None) -> SecurityPolicy:
    return load_policy(Path(path) if path else None)
