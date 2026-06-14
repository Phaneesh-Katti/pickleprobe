"""Build a CFG from pickle bytecode via PVM emulation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import BinaryIO

import pickletools

from pickleprobe.analysis.gadget_resolver import refine_emulation
from pickleprobe.analysis.cfg_taint import CfgTaintResult, ExploitPath, propagate_cfg_taint
from pickleprobe.domain.cfg import CFG, EdgeKind, NodeKind
from pickleprobe.domain.policy import configure_policy, get_policy
from pickleprobe.domain.taint import SecurityTaint
from pickleprobe.domain.values import (
    BuildEvent,
    ExtensionReference,
    GlobalReference,
    MemoEvent,
    NewObjEvent,
    ReduceEvent,
    TaintKind,
    ValueRef,
)
from pickleprobe.formats.loader import FileFormat, LoadedFile, load_file, read_archive_member
from pickleprobe.pvm.emulator import EmulationResult, PvmEmulator


@dataclass
class AnalysisReport:
    """Static analysis result for one pickle byte stream."""

    cfg: CFG
    stream_name: str = "raw"
    global_refs: list[GlobalReference] = field(default_factory=list)
    reduce_events: list[ReduceEvent] = field(default_factory=list)
    build_events: list[BuildEvent] = field(default_factory=list)
    newobj_events: list[NewObjEvent] = field(default_factory=list)
    extension_refs: list[ExtensionReference] = field(default_factory=list)
    memo_events: list[MemoEvent] = field(default_factory=list)
    memo_warnings: list[str] = field(default_factory=list)
    cfg_taint: CfgTaintResult | None = None
    exploit_paths: list[ExploitPath] = field(default_factory=list)
    emulation_errors: list[str] = field(default_factory=list)
    max_protocol: int = -1
    raw_size: int = 0
    gadget_hop_cap: int = 0
    gadget_iterations: int = 0
    stack_unreliable_from: int | None = None

    @property
    def resolved_globals(self) -> list[GlobalReference]:
        return [r for r in self.global_refs if r.is_resolved]

    @property
    def sink_invocations(self) -> list[ReduceEvent]:
        return [e for e in self.reduce_events if e.invocation_security is SecurityTaint.SINK]

    @property
    def suspicious_invocations(self) -> list[ReduceEvent]:
        return [
            e
            for e in self.reduce_events
            if e.invocation_security is SecurityTaint.SUSPICIOUS
        ]

    @property
    def risky_builds(self) -> list[BuildEvent]:
        return [
            e
            for e in self.build_events
            if e.invocation_security in (SecurityTaint.SINK, SecurityTaint.SUSPICIOUS)
        ]

    @property
    def has_findings(self) -> bool:
        return bool(
            self.sink_invocations
            or self.suspicious_invocations
            or self.risky_builds
            or any(e.invocation_security is SecurityTaint.SUSPICIOUS for e in self.newobj_events)
        )


@dataclass
class FileAnalysisResult:
    """Analysis of a file that may contain multiple pickle streams."""

    path: Path
    format: FileFormat
    streams: list[AnalysisReport] = field(default_factory=list)

    @property
    def primary(self) -> AnalysisReport:
        return self.streams[0]


class PickleAnalyzer:
    """Coordinate format loading, PVM emulation, and CFG construction."""

    def __init__(
        self,
        emulator: PvmEmulator | None = None,
        *,
        policy_path: str | Path | None = None,
    ) -> None:
        self._emulator = emulator or PvmEmulator()
        self._policy_path = Path(policy_path) if policy_path else None

    def analyze(self, data: bytes | BinaryIO, *, stream_name: str = "raw") -> AnalysisReport:
        configure_policy(self._policy_path)
        raw = data if isinstance(data, bytes) else data.read()
        if not isinstance(raw, bytes):
            raise TypeError("expected bytes or binary stream")

        emulation = self._emulator.emulate(raw)
        emulation, _metrics, hop_cap, hop_iters = refine_emulation(emulation)
        cfg = self._build_cfg(raw, emulation)
        cfg_taint = propagate_cfg_taint(cfg)
        memo_warnings = self._memo_warnings(emulation.memo_events, emulation.memo_overwrites)

        return AnalysisReport(
            cfg=cfg,
            stream_name=stream_name,
            global_refs=list(emulation.global_refs),
            extension_refs=list(emulation.extension_refs),
            reduce_events=list(emulation.reduce_events),
            build_events=list(emulation.build_events),
            newobj_events=list(emulation.newobj_events),
            memo_events=list(emulation.memo_events),
            memo_warnings=memo_warnings,
            cfg_taint=cfg_taint,
            exploit_paths=list(cfg_taint.exploit_paths),
            emulation_errors=list(emulation.errors),
            max_protocol=emulation.max_protocol,
            raw_size=len(raw),
            gadget_hop_cap=hop_cap,
            gadget_iterations=hop_iters,
            stack_unreliable_from=emulation.stack_unreliable_from,
        )

    def analyze_file(self, path: Path) -> FileAnalysisResult:
        loaded = load_file(path)
        reports = [
            self.analyze(stream.data, stream_name=stream.name)
            for stream in loaded.streams
        ]
        return FileAnalysisResult(path=loaded.path, format=loaded.format, streams=reports)

    def analyze_archive_member(self, path: Path, member_name: str) -> AnalysisReport:
        """Analyze one pickle inside a ``.tar.gz`` without extracting the full archive."""
        configure_policy(self._policy_path)
        data = read_archive_member(path, member_name)
        stream_name = f"{path.name}|{member_name}"
        return self.analyze(data, stream_name=stream_name)

    def analyze_target(self, path: Path, *, member: str | None = None) -> list[AnalysisReport]:
        """Analyze a file or a single archive member; returns one report per pickle stream."""
        if member is not None:
            return [self.analyze_archive_member(path, member)]
        return list(self.analyze_file(path).streams)

    def _build_cfg(self, data: bytes, emulation: EmulationResult) -> CFG:
        cfg = CFG()
        prev_node_id: int | None = None
        producer_index: dict[tuple[str, int], int] = {}

        reduce_by_offset = {e.offset: e for e in emulation.reduce_events}
        build_by_offset = {e.offset: e for e in emulation.build_events}
        newobj_by_offset = {e.offset: e for e in emulation.newobj_events}
        memo_by_offset = {e.offset: e for e in emulation.memo_events}
        memo_store_index: dict[tuple[int, int], int] = {}

        _MEMO_STORE_OPS = frozenset({"PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE"})
        _MEMO_LOAD_OPS = frozenset({"GET", "BINGET", "LONG_BINGET"})

        for opcode, arg, pos in pickletools.genops(data):
            if pos is None:
                pos = -1

            node = cfg.add_node(
                NodeKind.OPCODE,
                offset=pos,
                opcode=opcode.name,
                arg=arg,
            )

            if prev_node_id is not None:
                cfg.add_edge(prev_node_id, node.id, EdgeKind.FALLTHROUGH)
            prev_node_id = node.id

            if opcode.name not in (
                "GLOBAL", "STACK_GLOBAL", "REDUCE", "BUILD", "NEWOBJ", "NEWOBJ_EX",
                "PUT", "BINPUT", "LONG_BINPUT", "MEMOIZE", "GET", "BINGET", "LONG_BINGET",
            ):
                producer_index[(opcode.name, pos)] = node.id

            if opcode.name in _MEMO_STORE_OPS:
                ev = memo_by_offset.get(pos)
                if ev and ev.kind == "store":
                    store = cfg.add_node(
                        NodeKind.MEMO_STORE,
                        offset=pos,
                        opcode=ev.opcode,
                        memo_event=ev,
                        memo_key=ev.key,
                    )
                    cfg.add_edge(node.id, store.id, EdgeKind.STACK_DATA)
                    for ref in ev.producer_refs:
                        pkey = (ref.kind, ref.offset)
                        if pkey in producer_index:
                            cfg.add_edge(producer_index[pkey], store.id, EdgeKind.STACK_DATA)
                    memo_store_index[(ev.key, ev.offset)] = store.id
                    producer_index[("MEMO_STORE", pos)] = store.id
                    producer_index[(ev.opcode, pos)] = store.id
                    prev_node_id = store.id

            elif opcode.name in _MEMO_LOAD_OPS:
                ev = memo_by_offset.get(pos)
                if ev and ev.kind == "load":
                    load = cfg.add_node(
                        NodeKind.MEMO_LOAD,
                        offset=pos,
                        opcode=ev.opcode,
                        memo_event=ev,
                        memo_key=ev.key,
                    )
                    cfg.add_edge(node.id, load.id, EdgeKind.STACK_DATA)
                    if ev.store_offset is not None:
                        sid = memo_store_index.get((ev.key, ev.store_offset))
                        if sid is not None:
                            cfg.add_edge(sid, load.id, EdgeKind.MEMO_FLOW)
                    producer_index[("MEMO_LOAD", pos)] = load.id
                    producer_index[(ev.opcode, pos)] = load.id
                    prev_node_id = load.id

            if opcode.name == "GLOBAL":
                ref = self._find_global_ref(emulation, pos, "GLOBAL")
                lookup = cfg.add_node(
                    NodeKind.GLOBAL_LOOKUP,
                    offset=pos,
                    opcode="GLOBAL",
                    global_ref=ref,
                )
                cfg.add_edge(node.id, lookup.id, EdgeKind.STACK_DATA)
                producer_index[("GLOBAL", pos)] = lookup.id
                prev_node_id = lookup.id

            elif opcode.name == "STACK_GLOBAL":
                ref = self._find_global_ref(emulation, pos, "STACK_GLOBAL")
                lookup = cfg.add_node(
                    NodeKind.GLOBAL_LOOKUP,
                    offset=pos,
                    opcode="STACK_GLOBAL",
                    global_ref=ref,
                )
                cfg.add_edge(node.id, lookup.id, EdgeKind.STACK_DATA)
                self._link_stack_global_memo_inputs(cfg, lookup.id, ref, producer_index)
                producer_index[("STACK_GLOBAL", pos)] = lookup.id
                prev_node_id = lookup.id

            elif opcode.name == "REDUCE":
                event = reduce_by_offset.get(pos)
                if event is None:
                    continue
                invoke = cfg.add_node(
                    NodeKind.REDUCE_INVOKE,
                    offset=pos,
                    opcode="REDUCE",
                    reduce_event=event,
                )
                cfg.add_edge(node.id, invoke.id, EdgeKind.STACK_DATA)
                self._link_reduce_producers(cfg, invoke.id, event, producer_index)
                producer_index[("REDUCE", pos)] = invoke.id
                prev_node_id = invoke.id

            elif opcode.name == "BUILD":
                event = build_by_offset.get(pos)
                if event is None:
                    continue
                invoke = cfg.add_node(
                    NodeKind.BUILD_INVOKE,
                    offset=pos,
                    opcode="BUILD",
                    build_event=event,
                )
                cfg.add_edge(node.id, invoke.id, EdgeKind.STACK_DATA)
                self._link_build_producers(cfg, invoke.id, event, producer_index)
                producer_index[("BUILD", pos)] = invoke.id
                prev_node_id = invoke.id

            elif opcode.name in ("NEWOBJ", "NEWOBJ_EX"):
                event = newobj_by_offset.get(pos)
                if event is None:
                    continue
                invoke = cfg.add_node(
                    NodeKind.NEWOBJ_INVOKE,
                    offset=pos,
                    opcode=opcode.name,
                    newobj_event=event,
                )
                cfg.add_edge(node.id, invoke.id, EdgeKind.STACK_DATA)
                self._link_newobj_producers(cfg, invoke.id, event, producer_index)
                producer_index[(opcode.name, pos)] = invoke.id
                prev_node_id = invoke.id

        return cfg

    @staticmethod
    def _link_reduce_producers(
        cfg: CFG,
        invoke_id: int,
        event: ReduceEvent,
        producer_index: dict[tuple[str, int], int],
    ) -> None:
        kind = event.callable_producer_kind
        offset = event.callable_producer_offset
        if kind and offset is not None:
            key = (kind, offset)
            if key in producer_index:
                cfg.add_edge(producer_index[key], invoke_id, EdgeKind.CALLABLE_FLOW)

        for ref in event.args_producer_refs:
            key = (ref.kind, ref.offset)
            if key in producer_index:
                cfg.add_edge(producer_index[key], invoke_id, EdgeKind.ARGS_FLOW)

    @staticmethod
    def _link_build_producers(
        cfg: CFG,
        invoke_id: int,
        event: BuildEvent,
        producer_index: dict[tuple[str, int], int],
    ) -> None:
        kind = event.instance_producer_kind
        offset = event.instance_producer_offset
        if kind and offset is not None:
            key = (kind, offset)
            if key in producer_index:
                cfg.add_edge(producer_index[key], invoke_id, EdgeKind.INSTANCE_FLOW)

        for ref in event.state_producer_refs:
            key = (ref.kind, ref.offset)
            if key in producer_index:
                cfg.add_edge(producer_index[key], invoke_id, EdgeKind.STATE_FLOW)

    @staticmethod
    def _link_newobj_producers(
        cfg: CFG,
        invoke_id: int,
        event: NewObjEvent,
        producer_index: dict[tuple[str, int], int],
    ) -> None:
        kind = event.class_producer_kind
        offset = event.class_producer_offset
        if kind and offset is not None:
            key = (kind, offset)
            if key in producer_index:
                cfg.add_edge(producer_index[key], invoke_id, EdgeKind.CALLABLE_FLOW)

        for ref in event.args_producer_refs:
            key = (ref.kind, ref.offset)
            if key in producer_index:
                cfg.add_edge(producer_index[key], invoke_id, EdgeKind.ARGS_FLOW)

    @staticmethod
    def _find_global_ref(
        emulation: EmulationResult,
        offset: int,
        opcode: str,
    ) -> GlobalReference:
        for ref in emulation.global_refs:
            if ref.offset == offset and ref.opcode == opcode:
                return ref
        return GlobalReference(
            module=None,
            name=None,
            taint=TaintKind.UNKNOWN,
            opcode=opcode,
            offset=offset,
        )

    @staticmethod
    def _link_stack_global_memo_inputs(
        cfg: CFG,
        lookup_id: int,
        ref: GlobalReference,
        producer_index: dict[tuple[str, int], int],
    ) -> None:
        for source_offset in (ref.module_source_offset, ref.name_source_offset):
            if source_offset is None:
                continue
            for key in (("MEMO_LOAD", source_offset),):
                if key in producer_index:
                    cfg.add_edge(producer_index[key], lookup_id, EdgeKind.ARGS_FLOW)
                    continue
            for op in ("GET", "BINGET", "LONG_BINGET"):
                key = (op, source_offset)
                if key in producer_index:
                    cfg.add_edge(producer_index[key], lookup_id, EdgeKind.ARGS_FLOW)

    @staticmethod
    def _memo_warnings(events: list[MemoEvent], overwrites: list[str]) -> list[str]:
        policy = get_policy()
        flags = policy.memo_warnings
        warnings: list[str] = list(overwrites)
        for ev in events:
            if ev.kind == "load" and ev.load_before_store and flags.get("get_before_put", True):
                warnings.append(f"GET memo key {ev.key} before PUT (@{ev.offset})")
            if ev.kind == "store" and ev.overwrote and flags.get("overwrite_put", True):
                if not any(f"memo key {ev.key}" in w for w in warnings):
                    warnings.append(f"PUT overwrote memo key {ev.key} (@{ev.offset})")
        return warnings
