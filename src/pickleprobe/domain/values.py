"""Stack cell representations, global references, and REDUCE events."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, FrozenSet

from pickleprobe.domain.taint import SecurityTaint


@dataclass(frozen=True)
class ValueRef:
    """Reference to the opcode that produced a stack value."""

    kind: str
    offset: int
    memo_key: int | None = None
    store_offset: int | None = None


def refs_union(*groups: FrozenSet[ValueRef]) -> FrozenSet[ValueRef]:
    out: set[ValueRef] = set()
    for group in groups:
        out.update(group)
    return frozenset(out)


class TaintKind(Enum):
    """How confidently we know a stack value (resolution axis)."""

    CONST = auto()
    MEMO = auto()
    DERIVED = auto()
    GLOBAL = auto()
    REDUCE = auto()
    UNKNOWN = auto()


@dataclass(frozen=True)
class GlobalReference:
    """A module.attr lookup materialized by the PVM."""

    module: str | None
    name: str | None
    taint: TaintKind
    opcode: str
    offset: int
    module_source_offset: int | None = None
    name_source_offset: int | None = None

    @property
    def is_resolved(self) -> bool:
        return self.module is not None and self.name is not None

    @property
    def qualified_name(self) -> str | None:
        if not self.is_resolved:
            return None
        return f"{self.module}.{self.name}"


@dataclass(frozen=True)
class ReduceEvent:
    """One REDUCE opcode: callable(*args) call site."""

    offset: int
    callable_qualified: str | None
    callable_security: SecurityTaint
    callable_producer_offset: int | None
    callable_producer_kind: str | None
    args: tuple[Any, ...] | None
    args_security: SecurityTaint
    invocation_security: SecurityTaint
    result_qualified: str | None
    result_security: SecurityTaint
    args_producer_refs: FrozenSet[ValueRef] = field(default_factory=frozenset)


@dataclass(frozen=True)
class MemoEvent:
    """Memo store or load with taint snapshot for graph construction."""

    offset: int
    opcode: str
    key: int
    kind: str  # "store" | "load"
    security: SecurityTaint = SecurityTaint.CLEAN
    qualified_name: str | None = None
    store_offset: int | None = None  # load: offset of PUT that populated key
    producer_refs: FrozenSet[ValueRef] = field(default_factory=frozenset)
    overwrote: bool = False
    prior_security: SecurityTaint | None = None
    load_before_store: bool = False


@dataclass(frozen=True)
class ExtensionReference:
    """Resolved EXT1/EXT2/EXT4 registry target."""

    code: int
    module: str | None
    name: str | None
    offset: int
    opcode: str

    @property
    def qualified_name(self) -> str | None:
        if self.module and self.name:
            return f"{self.module}.{self.name}"
        return None


@dataclass(frozen=True)
class BuildEvent:
    """One BUILD opcode: instance.__setstate__(state) or __dict__ update."""

    offset: int
    instance_qualified: str | None
    instance_security: SecurityTaint
    instance_producer_offset: int | None
    instance_producer_kind: str | None
    state_security: SecurityTaint
    state_producer_refs: FrozenSet[ValueRef] = field(default_factory=frozenset)
    invocation_security: SecurityTaint = SecurityTaint.CLEAN


@dataclass(frozen=True)
class NewObjEvent:
    """One NEWOBJ / NEWOBJ_EX opcode: cls.__new__(cls, *args)."""

    offset: int
    opcode: str
    class_qualified: str | None
    class_security: SecurityTaint
    class_producer_offset: int | None
    class_producer_kind: str | None
    args: tuple[Any, ...] | None
    args_security: SecurityTaint
    args_producer_refs: FrozenSet[ValueRef] = field(default_factory=frozenset)
    invocation_security: SecurityTaint = SecurityTaint.CLEAN


@dataclass(frozen=True)
class StackValue:
    """One cell on the simulated PVM stack."""

    value: Any
    taint: TaintKind
    security: SecurityTaint = SecurityTaint.CLEAN
    qualified_name: str | None = None
    producer_offset: int | None = None
    producer_kind: str | None = None
    source_refs: FrozenSet[ValueRef] = field(default_factory=frozenset)

    @classmethod
    def constant(cls, value: Any, *, opcode: str, offset: int) -> StackValue:
        ref = ValueRef(kind=opcode, offset=offset)
        return cls(
            value=value,
            taint=TaintKind.CONST,
            security=SecurityTaint.CLEAN,
            producer_offset=offset,
            producer_kind=opcode,
            source_refs=frozenset({ref}),
        )

    @classmethod
    def unknown(cls, value: Any = None) -> StackValue:
        return cls(
            value=value,
            taint=TaintKind.UNKNOWN,
            security=SecurityTaint.INCONCLUSIVE,
        )

    @classmethod
    def from_global(cls, ref: GlobalReference) -> StackValue:
        from pickleprobe.domain.security import classify_global

        security = classify_global(ref.module, ref.name)
        vref = ValueRef(kind=ref.opcode, offset=ref.offset)
        return cls(
            value=ref,
            taint=TaintKind.GLOBAL,
            security=security,
            qualified_name=ref.qualified_name,
            producer_offset=ref.offset,
            producer_kind=ref.opcode,
            source_refs=frozenset({vref}),
        )

    @classmethod
    def from_reduce(
        cls,
        value: Any,
        *,
        qualified_name: str | None,
        security: SecurityTaint,
        offset: int,
        resolution: TaintKind = TaintKind.REDUCE,
    ) -> StackValue:
        vref = ValueRef(kind="REDUCE", offset=offset)
        return cls(
            value=value,
            taint=resolution,
            security=security,
            qualified_name=qualified_name,
            producer_offset=offset,
            producer_kind="REDUCE",
            source_refs=frozenset({vref}),
        )

    @classmethod
    def from_newobj(
        cls,
        value: Any,
        *,
        qualified_name: str | None,
        security: SecurityTaint,
        offset: int,
        opcode: str,
    ) -> StackValue:
        vref = ValueRef(kind=opcode, offset=offset)
        return cls(
            value=value,
            taint=TaintKind.DERIVED,
            security=security,
            qualified_name=qualified_name,
            producer_offset=offset,
            producer_kind=opcode,
            source_refs=frozenset({vref}),
        )

    def as_str(self) -> str | None:
        if self.taint not in (TaintKind.CONST, TaintKind.MEMO, TaintKind.DERIVED):
            return None
        if isinstance(self.value, str):
            return self.value
        if isinstance(self.value, bytes):
            try:
                return self.value.decode("utf-8")
            except UnicodeDecodeError:
                return None
        return None
