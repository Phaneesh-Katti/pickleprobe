"""Fixed-point multi-hop gadget resolution with adaptive hop limits."""

from __future__ import annotations

from dataclasses import dataclass, replace

import re

from pickleprobe.domain.policy import get_policy
from pickleprobe.domain.security import classify_invocation
from pickleprobe.domain.symbolic import SymbolicValue
from pickleprobe.domain.taint import SecurityTaint, join_security
from pickleprobe.domain.values import BuildEvent, NewObjEvent, ReduceEvent
from pickleprobe.pvm.emulator import EmulationResult


@dataclass(frozen=True)
class GadgetMetrics:
    """Bytecode complexity signals used to size resolution depth."""

    reduce_count: int
    memo_event_count: int
    global_lookup_count: int
    build_count: int
    newobj_count: int
    max_stack_depth: int

    @classmethod
    def from_emulation(cls, emulation: EmulationResult) -> GadgetMetrics:
        return cls(
            reduce_count=len(emulation.reduce_events),
            memo_event_count=len(emulation.memo_events),
            global_lookup_count=len(emulation.global_refs),
            build_count=len(emulation.build_events),
            newobj_count=len(emulation.newobj_events),
            max_stack_depth=emulation.max_stack_depth,
        )


def max_resolution_hops(metrics: GadgetMetrics) -> int:
    """Variable hop cap from observed bytecode complexity (not a fixed constant)."""
    # REDUCE chains dominate; memo adds transport hops; globals seed lookups.
    dynamic = (
        metrics.reduce_count * 2
        + metrics.memo_event_count // 2
        + metrics.global_lookup_count
        + metrics.build_count
        + metrics.newobj_count // 2
    )
    stack_bonus = min(8, metrics.max_stack_depth // 3)
    return min(48, max(8, dynamic + stack_bonus))


def _symbolic_step(callable_sym: SymbolicValue, args: tuple | None) -> SymbolicValue:
    policy = get_policy()
    qn = _canonical_qn(callable_sym.qualified)

    if qn in ("builtins.__import__",) and args and len(args) >= 1:
        mod = args[0]
        if isinstance(mod, str):
            return SymbolicValue.from_module(mod)

    if qn in ("importlib.import_module",) and args and len(args) >= 1:
        mod = args[0]
        if isinstance(mod, str):
            return SymbolicValue.from_module(mod)

    if qn in ("builtins.getattr",) and args and len(args) == 2:
        base = args[0]
        attr = args[1]
        if isinstance(base, SymbolicValue):
            return base.resolve_attr(attr, policy=policy)
        if isinstance(base, str) and base.startswith("<module:") and base.endswith(">"):
            return SymbolicValue.from_module(base[8:-1]).resolve_attr(attr, policy=policy)

    if qn == "functools.partial" and args and len(args) >= 1:
        inner = args[0]
        if isinstance(inner, SymbolicValue):
            extra = tuple(a for a in args[1:] if isinstance(a, (str, int, bytes)))
            bound = inner.bind_partial(extra)
            if bound.qualified:
                pair = _parse_pair(bound.qualified)
                if pair and policy.is_sink_pair(pair):
                    return bound.with_security(SecurityTaint.SINK)
            return bound
        if isinstance(inner, str) and "." in inner:
            sym = SymbolicValue.from_qualified(inner).bind_partial(tuple(args[1:]))
            if sym.qualified and (pair := _parse_pair(sym.qualified)) and policy.is_sink_pair(pair):
                return sym.with_security(SecurityTaint.SINK)
            return sym

    if qn == "operator.methodcaller" and args and len(args) >= 1:
        method = args[0]
        if isinstance(method, str) and policy.is_sensitive_attr(method):
            return callable_sym.with_security(SecurityTaint.SUSPICIOUS)

    if qn == "operator.attrgetter" and args and len(args) >= 1:
        attr = args[0]
        if isinstance(attr, str) and policy.is_sensitive_attr(attr):
            return callable_sym.with_security(SecurityTaint.SUSPICIOUS)

    if qn and (pair := _parse_pair(qn)) and policy.is_sink_pair(pair):
        return callable_sym.with_security(SecurityTaint.SINK)

    return callable_sym


def _parse_pair(qualified: str) -> tuple[str, str] | None:
    if " " in qualified or "<" in qualified:
        return None
    module, dot, name = qualified.rpartition(".")
    if not dot:
        return None
    return module, name


def _callable_symbolic(ev: ReduceEvent, producer_syms: dict[tuple[str, int], SymbolicValue]) -> SymbolicValue:
    kind = ev.callable_producer_kind
    off = ev.callable_producer_offset
    if kind and off is not None:
        for key in ((kind, off), ("REDUCE", off), ("MEMO_LOAD", off), ("GET", off), ("BINGET", off)):
            if key in producer_syms:
                return producer_syms[key]

    if ev.callable_qualified:
        sec = ev.callable_security
        return SymbolicValue.from_qualified(ev.callable_qualified, security=sec)
    return SymbolicValue(security=SecurityTaint.INCONCLUSIVE)


_REDUCE_PLACEHOLDER = re.compile(r"^<reduce@(\d+)>$")


def _canonical_qn(qn: str | None) -> str | None:
    if not qn:
        return None
    if qn.startswith("__builtin__."):
        return "builtins." + qn.split(".", 1)[1]
    return qn


def _resolve_arg(arg: object, producer_syms: dict[tuple[str, int], SymbolicValue]) -> object:
    if isinstance(arg, SymbolicValue):
        return arg
    if isinstance(arg, str):
        m = _REDUCE_PLACEHOLDER.match(arg)
        if m:
            off = int(m.group(1))
            if ("REDUCE", off) in producer_syms:
                return producer_syms[("REDUCE", off)]
        if arg.startswith("<module:") and arg.endswith(">"):
            return SymbolicValue.from_module(arg[8:-1])
    return arg


def _normalize_args(
    args: tuple | None,
    producer_syms: dict[tuple[str, int], SymbolicValue],
) -> tuple | None:
    if args is None:
        return None
    out: list = []
    for a in args:
        a = _resolve_arg(a, producer_syms)
        if isinstance(a, SymbolicValue):
            out.append(a)
            continue
        from pickleprobe.domain.values import GlobalReference

        if isinstance(a, GlobalReference) and a.is_resolved:
            if a.name in ("__import__",) or a.module in ("builtins", "__builtin__"):
                out.append(a)
            else:
                out.append(SymbolicValue.from_qualified(a.qualified_name, security=SecurityTaint.CLEAN))
            continue
        if isinstance(a, str) and "." in a and " " not in a and not a.startswith("<"):
            out.append(SymbolicValue.from_qualified(a))
        else:
            out.append(a)
    return tuple(out)


def _wire_memo_producers(
    memo_events,
    memo_syms: dict[int, SymbolicValue],
    producer_syms: dict[tuple[str, int], SymbolicValue],
) -> None:
    for me in memo_events:
        if me.kind == "load":
            sym = memo_syms.get(me.key)
            if sym is not None:
                producer_syms[(me.opcode, me.offset)] = sym
                producer_syms[("MEMO", me.key)] = sym
        elif me.kind == "store":
            for ref in me.producer_refs:
                if ref.kind == "REDUCE" and ref.offset is not None:
                    sym = producer_syms.get(("REDUCE", ref.offset))
                    if sym is not None:
                        memo_syms[me.key] = sym
            if me.qualified_name:
                memo_syms[me.key] = SymbolicValue.from_qualified(me.qualified_name, security=me.security)


def refine_reduce_events(
    events: list[ReduceEvent],
    metrics: GadgetMetrics,
    *,
    memo_events=None,
    memo_load_values: dict[int, SymbolicValue] | None = None,
) -> tuple[list[ReduceEvent], int, int]:
    """Fixed-point gadget folding; returns (events, hop_cap, iterations_used)."""
    hop_cap = max_resolution_hops(metrics)
    if not events:
        return events, hop_cap, 0

    by_offset = {e.offset: e for e in events}
    order = sorted(by_offset.keys())
    producer_syms: dict[tuple[str, int], SymbolicValue] = {}
    memo_syms: dict[int, SymbolicValue] = dict(memo_load_values or {})
    if memo_events:
        _wire_memo_producers(memo_events, memo_syms, producer_syms)
    refined: dict[int, ReduceEvent] = dict(by_offset)

    iterations = 0
    for _ in range(hop_cap):
        iterations += 1
        changed = False
        if memo_events:
            _wire_memo_producers(memo_events, memo_syms, producer_syms)
        for off in order:
            ev = refined[off]
            callable_sym = _callable_symbolic(ev, producer_syms)
            norm_args = _normalize_args(ev.args, producer_syms)
            result_sym = _symbolic_step(callable_sym, norm_args)

            effective_qn = callable_sym.qualified or _canonical_qn(ev.callable_qualified)
            if result_sym.qualified:
                if (pair := _parse_pair(result_sym.qualified)) and get_policy().is_sink_pair(pair):
                    effective_qn = result_sym.qualified
                elif effective_qn in (None, "functools.partial") and result_sym.qualified:
                    effective_qn = result_sym.qualified
            inv = classify_invocation(
                effective_qn,
                norm_args,
                callable_security=join_security(callable_sym.security, ev.callable_security),
                args_security=ev.args_security,
            )
            if effective_qn and (pair := _parse_pair(effective_qn)) and get_policy().is_sink_pair(pair):
                inv = SecurityTaint.SINK
            inv = join_security(inv, result_sym.security)

            new_ev = replace(
                ev,
                invocation_security=inv,
                result_qualified=result_sym.qualified or ev.result_qualified,
                result_security=join_security(ev.result_security, result_sym.security),
            )
            if (
                new_ev.invocation_security != ev.invocation_security
                or new_ev.result_qualified != ev.result_qualified
                or new_ev.result_security != ev.result_security
            ):
                changed = True
            refined[off] = new_ev

            if ev.callable_producer_kind and ev.callable_producer_offset is not None:
                producer_syms[(ev.callable_producer_kind, ev.callable_producer_offset)] = callable_sym
            producer_syms[("REDUCE", off)] = result_sym
            for me in memo_events or ():
                if me.kind == "store" and any(
                    ref.kind == "REDUCE" and ref.offset == off for ref in me.producer_refs
                ):
                    memo_syms[me.key] = result_sym

        if not changed:
            break

    return [refined[o] for o in order], hop_cap, iterations


def refine_build_events(
    builds: list[BuildEvent],
    newobjs: list[NewObjEvent],
    reduce_syms: dict[int, SymbolicValue],
) -> list[BuildEvent]:
    """State-injection pass: BUILD + NEWOBJ coupling and dangerous state literals."""
    from pickleprobe.domain.security import classify_build

    policy = get_policy()
    instance_class: dict[tuple[str, int], str | None] = {}
    for nv in newobjs:
        if nv.class_producer_kind and nv.class_producer_offset is not None:
            instance_class[(nv.class_producer_kind, nv.class_producer_offset)] = nv.class_qualified
        instance_class[(nv.opcode, nv.offset)] = nv.class_qualified

    out: list[BuildEvent] = []
    for ev in builds:
        class_qn = ev.instance_qualified
        kind = ev.instance_producer_kind
        off = ev.instance_producer_offset
        if kind and off is not None and (cq := instance_class.get((kind, off))):
            class_qn = cq or class_qn

        sec = classify_build(
            class_qn,
            instance_security=ev.instance_security,
            state_security=ev.state_security,
            state_value=ev.state_value,
        )
        if off is not None and off in reduce_syms and reduce_syms[off].security is SecurityTaint.SINK:
            sec = join_security(sec, SecurityTaint.SINK)
        if class_qn and (pair := _parse_pair(class_qn)) and policy.is_sink_pair(pair):
            sec = SecurityTaint.SINK
        out.append(replace(ev, instance_qualified=class_qn, invocation_security=sec))
    return out


def refine_emulation(emulation: EmulationResult) -> tuple[EmulationResult, GadgetMetrics, int, int]:
    """Run gadget + BUILD refinement passes on emulation output."""
    metrics = GadgetMetrics.from_emulation(emulation)
    memo_syms: dict[int, SymbolicValue] = {}
    for me in emulation.memo_events:
        if me.kind == "load" and me.qualified_name:
            memo_syms[me.key] = SymbolicValue.from_qualified(me.qualified_name, security=me.security)
        elif me.kind == "store" and me.qualified_name:
            memo_syms[me.key] = SymbolicValue.from_qualified(me.qualified_name, security=me.security)

    reduces, hop_cap, iters = refine_reduce_events(
        emulation.reduce_events,
        metrics,
        memo_events=emulation.memo_events,
        memo_load_values=memo_syms,
    )
    reduce_syms = {e.offset: SymbolicValue.from_qualified(e.result_qualified, security=e.result_security) for e in reduces}
    builds = refine_build_events(emulation.build_events, emulation.newobj_events, reduce_syms)

    emulation.reduce_events = reduces
    emulation.build_events = builds
    emulation.gadget_hop_cap = hop_cap
    emulation.gadget_iterations = iters
    return emulation, metrics, hop_cap, iters
