"""Forward security-taint propagation over the pickle CFG."""

from __future__ import annotations

from dataclasses import dataclass, field

from pickleprobe.domain.cfg import CFG, EdgeKind, NodeKind
from pickleprobe.domain.taint import SecurityTaint, join_security


_DATAFLOW_EDGES = frozenset(
    {
        EdgeKind.STACK_DATA,
        EdgeKind.CALLABLE_FLOW,
        EdgeKind.ARGS_FLOW,
        EdgeKind.INSTANCE_FLOW,
        EdgeKind.STATE_FLOW,
        EdgeKind.MEMO_FLOW,
    }
)


@dataclass(frozen=True)
class ExploitPath:
    """One dataflow path from sources to a dangerous invoke."""

    sink_offset: int
    sink_kind: str
    sink_callable: str | None
    steps: tuple[tuple[str, int, str, int | None], ...]  # opcode, offset, edge, memo_key


@dataclass
class CfgTaintResult:
    """Result of graph-based taint propagation."""

    node_security: dict[int, SecurityTaint] = field(default_factory=dict)
    exploit_paths: list[ExploitPath] = field(default_factory=list)
    max_propagated: SecurityTaint = SecurityTaint.CLEAN


def propagate_cfg_taint(cfg: CFG) -> CfgTaintResult:
    """Fixed-point join of security taint along dataflow edges."""
    result = CfgTaintResult()
    node_sec: dict[int, SecurityTaint] = {}

    for node in cfg.nodes:
        seed = _seed_security(node)
        if seed is not None:
            node_sec[node.id] = seed

    incoming: dict[int, list[tuple[int, EdgeKind]]] = {n.id: [] for n in cfg.nodes}
    for edge in cfg.edges:
        if edge.kind in _DATAFLOW_EDGES:
            incoming[edge.target].append((edge.source, edge.kind))

    changed = True
    while changed:
        changed = False
        for node in cfg.nodes:
            if not incoming[node.id]:
                continue
            joined = node_sec.get(node.id, SecurityTaint.CLEAN)
            for src_id, _kind in incoming[node.id]:
                joined = join_security(joined, node_sec.get(src_id, SecurityTaint.CLEAN))
            if joined != node_sec.get(node.id, SecurityTaint.CLEAN):
                node_sec[node.id] = joined
                changed = True

    result.node_security = dict(node_sec)
    if node_sec:
        result.max_propagated = max(node_sec.values(), key=lambda t: _rank(t))

    result.exploit_paths = _find_sink_paths(cfg, node_sec)
    return result


def _rank(taint: SecurityTaint) -> int:
    return {
        SecurityTaint.CLEAN: 0,
        SecurityTaint.INCONCLUSIVE: 1,
        SecurityTaint.SUSPICIOUS: 2,
        SecurityTaint.SINK: 3,
    }[taint]


def _seed_security(node: object) -> SecurityTaint | None:
    from pickleprobe.domain.cfg import CFGNode

    if not isinstance(node, CFGNode):
        return None
    if node.kind is NodeKind.GLOBAL_LOOKUP:
        ref = node.global_ref
        if ref and ref.module and ref.name:
            from pickleprobe.domain.security import classify_global

            return classify_global(ref.module, ref.name)
        return SecurityTaint.INCONCLUSIVE
    if node.kind is NodeKind.REDUCE_INVOKE:
        ev = node.reduce_event
        return ev.invocation_security if ev else None
    if node.kind is NodeKind.BUILD_INVOKE:
        ev = node.build_event
        return ev.invocation_security if ev else None
    if node.kind is NodeKind.NEWOBJ_INVOKE:
        ev = node.newobj_event
        return ev.invocation_security if ev else None
    if node.kind is NodeKind.MEMO_STORE:
        ev = node.memo_event
        return ev.security if ev else SecurityTaint.CLEAN
    if node.kind is NodeKind.MEMO_LOAD:
        ev = node.memo_event
        return ev.security if ev else SecurityTaint.INCONCLUSIVE
    return None


def _find_sink_paths(cfg: CFG, node_sec: dict[int, SecurityTaint]) -> list[ExploitPath]:
    paths: list[ExploitPath] = []
    sinks = [
        n
        for n in cfg.nodes
        if n.kind in (NodeKind.REDUCE_INVOKE, NodeKind.BUILD_INVOKE, NodeKind.NEWOBJ_INVOKE)
        and node_sec.get(n.id, SecurityTaint.CLEAN) is SecurityTaint.SINK
    ]

    back: dict[int, list[tuple[int, EdgeKind]]] = {n.id: [] for n in cfg.nodes}
    for edge in cfg.edges:
        if edge.kind in _DATAFLOW_EDGES:
            back[edge.source].append((edge.target, edge.kind))

    for sink in sinks:
        callable_name = None
        if sink.reduce_event:
            callable_name = sink.reduce_event.callable_qualified
        elif sink.build_event:
            callable_name = sink.build_event.instance_qualified
        elif sink.newobj_event:
            callable_name = sink.newobj_event.class_qualified

        steps: list[tuple[str, int, str, int | None]] = [(sink.opcode, sink.offset, "SINK", None)]
        frontier = [sink.id]
        visited = {sink.id}
        found_source = False

        while frontier:
            nid = frontier.pop()
            for pred_id, kind in _predecessors(cfg, nid):
                if pred_id in visited:
                    continue
                visited.add(pred_id)
                pred = cfg.nodes[pred_id]
                memo_key = None
                if pred.memo_event is not None:
                    memo_key = pred.memo_event.key
                steps.append((pred.opcode, pred.offset, kind.name, memo_key))
                if pred.kind in (
                    NodeKind.GLOBAL_LOOKUP,
                    NodeKind.MEMO_STORE,
                    NodeKind.OPCODE,
                ):
                    found_source = True
                frontier.append(pred_id)

        if found_source and len(steps) > 1:
            path_steps = tuple(reversed(steps))
            paths.append(
                ExploitPath(
                    sink_offset=sink.offset,
                    sink_kind=sink.opcode,
                    sink_callable=callable_name,
                    steps=path_steps,
                )
            )
    return paths


def _predecessors(cfg: CFG, node_id: int) -> list[tuple[int, EdgeKind]]:
    return [(e.source, e.kind) for e in cfg.edges if e.target == node_id and e.kind in _DATAFLOW_EDGES]
