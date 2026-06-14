"""Symbolic qualified-name algebra for multi-hop gadget resolution."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pickleprobe.domain.taint import SecurityTaint, join_security


@dataclass
class SymbolicValue:
    """Approximate runtime value for static gadget folding."""

    qualified: str | None = None
    module_hint: str | None = None
    bound_args: tuple[Any, ...] = ()
    security: SecurityTaint = SecurityTaint.CLEAN
    hop_depth: int = 0

    @classmethod
    def from_qualified(cls, qn: str | None, *, security: SecurityTaint | None = None) -> SymbolicValue:
        if not qn:
            return cls(security=security or SecurityTaint.INCONCLUSIVE)
        sec = security or SecurityTaint.CLEAN
        mod_hint = None
        if qn.startswith("<module:") and qn.endswith(">"):
            mod_hint = qn[8:-1]
        elif "." in qn and " " not in qn:
            mod_hint = qn.rpartition(".")[0]
        return cls(qualified=qn, module_hint=mod_hint, security=sec)

    @classmethod
    def from_module(cls, module: str) -> SymbolicValue:
        return cls(qualified=f"<module:{module}>", module_hint=module, security=SecurityTaint.SUSPICIOUS)

    def with_security(self, sec: SecurityTaint) -> SymbolicValue:
        return SymbolicValue(
            qualified=self.qualified,
            module_hint=self.module_hint,
            bound_args=self.bound_args,
            security=join_security(self.security, sec),
            hop_depth=self.hop_depth,
        )

    def bind_partial(self, extra_args: tuple[Any, ...]) -> SymbolicValue:
        return SymbolicValue(
            qualified=self.qualified,
            module_hint=self.module_hint,
            bound_args=self.bound_args + extra_args,
            security=self.security,
            hop_depth=self.hop_depth + 1,
        )

    def resolve_attr(self, attr: str, *, policy) -> SymbolicValue:
        if not isinstance(attr, str):
            return self.with_security(SecurityTaint.INCONCLUSIVE)
        mod = self.module_hint
        if mod and policy.is_sensitive_attr(attr):
            qn = f"{mod}.{attr}"
            pair = (mod, attr)
            sec = SecurityTaint.SINK if policy.is_sink_pair(pair) else SecurityTaint.SUSPICIOUS
            return SymbolicValue(
                qualified=qn,
                module_hint=mod,
                bound_args=self.bound_args,
                security=join_security(self.security, sec),
                hop_depth=self.hop_depth + 1,
            )
        if policy.is_sensitive_attr(attr):
            return self.with_security(SecurityTaint.SUSPICIOUS)
        return self
