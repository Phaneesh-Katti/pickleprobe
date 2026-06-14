"""Control-flow graph types for pickle opcode analysis."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any

from polyglot.domain.values import BuildEvent, GlobalReference, MemoEvent, NewObjEvent, ReduceEvent


class NodeKind(Enum):
    """Categories of CFG nodes."""

    OPCODE = auto()
    GLOBAL_LOOKUP = auto()
    REDUCE_INVOKE = auto()
    BUILD_INVOKE = auto()
    NEWOBJ_INVOKE = auto()
    MEMO_STORE = auto()
    MEMO_LOAD = auto()


class EdgeKind(Enum):
    """Relationship between CFG nodes."""

    FALLTHROUGH = auto()
    STACK_DATA = auto()
    CALLABLE_FLOW = auto()
    ARGS_FLOW = auto()
    INSTANCE_FLOW = auto()
    STATE_FLOW = auto()
    MEMO_FLOW = auto()


@dataclass(frozen=True)
class CFGNode:
    """One vertex in the analysis graph."""

    id: int
    kind: NodeKind
    offset: int
    opcode: str
    payload: dict[str, Any] = field(default_factory=dict)

    @property
    def global_ref(self) -> GlobalReference | None:
        ref = self.payload.get("global_ref")
        return ref if isinstance(ref, GlobalReference) else None

    @property
    def reduce_event(self) -> ReduceEvent | None:
        ev = self.payload.get("reduce_event")
        return ev if isinstance(ev, ReduceEvent) else None

    @property
    def build_event(self) -> BuildEvent | None:
        ev = self.payload.get("build_event")
        return ev if isinstance(ev, BuildEvent) else None

    @property
    def newobj_event(self) -> NewObjEvent | None:
        ev = self.payload.get("newobj_event")
        return ev if isinstance(ev, NewObjEvent) else None

    @property
    def memo_event(self) -> MemoEvent | None:
        ev = self.payload.get("memo_event")
        return ev if isinstance(ev, MemoEvent) else None


@dataclass(frozen=True)
class CFGEdge:
    """Directed edge between CFG nodes."""

    source: int
    target: int
    kind: EdgeKind


@dataclass
class CFG:
    """Accumulated control-flow graph for one pickle stream."""

    nodes: list[CFGNode] = field(default_factory=list)
    edges: list[CFGEdge] = field(default_factory=list)
    _next_id: int = field(default=0, repr=False)

    def add_node(
        self,
        kind: NodeKind,
        offset: int,
        opcode: str,
        **payload: Any,
    ) -> CFGNode:
        node = CFGNode(
            id=self._next_id,
            kind=kind,
            offset=offset,
            opcode=opcode,
            payload=dict(payload),
        )
        self._next_id += 1
        self.nodes.append(node)
        return node

    def add_edge(
        self,
        source: int,
        target: int,
        kind: EdgeKind = EdgeKind.FALLTHROUGH,
    ) -> None:
        self.edges.append(CFGEdge(source=source, target=target, kind=kind))

    @property
    def global_lookups(self) -> list[CFGNode]:
        return [n for n in self.nodes if n.kind is NodeKind.GLOBAL_LOOKUP]

    @property
    def reduce_invocations(self) -> list[CFGNode]:
        return [n for n in self.nodes if n.kind is NodeKind.REDUCE_INVOKE]

    @property
    def build_invocations(self) -> list[CFGNode]:
        return [n for n in self.nodes if n.kind is NodeKind.BUILD_INVOKE]

    @property
    def newobj_invocations(self) -> list[CFGNode]:
        return [n for n in self.nodes if n.kind is NodeKind.NEWOBJ_INVOKE]

    @property
    def memo_stores(self) -> list[CFGNode]:
        return [n for n in self.nodes if n.kind is NodeKind.MEMO_STORE]

    @property
    def memo_loads(self) -> list[CFGNode]:
        return [n for n in self.nodes if n.kind is NodeKind.MEMO_LOAD]
