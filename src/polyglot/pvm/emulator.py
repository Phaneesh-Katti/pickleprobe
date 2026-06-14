"""Value-aware PVM stack and memo emulation with REDUCE and security taint."""

from __future__ import annotations

import copyreg
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Iterator

from pickletools import genops, markobject

from polyglot.domain.memo import (
    memo_load_resolution,
    obfuscation_note_for_stack_global,
    overwrite_forensics,
    security_on_memo_load,
)
from polyglot.domain.security import (
    SecurityTaint,
    classify_build,
    classify_extension,
    classify_global,
    classify_invocation,
    classify_newobj,
    join_security,
    simulate_reduce_result,
)
from polyglot.domain.values import (
    BuildEvent,
    ExtensionReference,
    GlobalReference,
    MemoEvent,
    NewObjEvent,
    ReduceEvent,
    StackValue,
    TaintKind,
    ValueRef,
    refs_union,
)

_LITERAL_OPCODES = frozenset(
    {
        "INT",
        "LONG",
        "FLOAT",
        "STRING",
        "BINSTRING",
        "SHORT_BINSTRING",
        "BINBYTES",
        "SHORT_BINBYTES",
        "BYTEARRAY8",
        "BINBYTES8",
        "UNICODE",
        "BINUNICODE",
        "BINUNICODE8",
        "SHORT_BINUNICODE",
        "BININT",
        "BININT1",
        "BININT2",
        "LONG1",
        "LONG4",
        "BINFLOAT",
        "NONE",
        "NEWTRUE",
        "NEWFALSE",
        "EMPTY_TUPLE",
        "EMPTY_LIST",
        "EMPTY_DICT",
        "EMPTY_SET",
        "FROZENSET",
        "NEXT_BUFFER",
        "READONLY_BUFFER",
    }
)

_MEMO_LOAD_OPCODES = frozenset({"GET", "BINGET", "LONG_BINGET"})

_NOOP_OPCODES = frozenset({"PROTO", "FRAME", "STOP", "POP_MARK", "MEMOIZE"})


@dataclass
class EmulationResult:
    """Output of a single pickle stream emulation pass."""

    global_refs: list[GlobalReference] = field(default_factory=list)
    extension_refs: list[ExtensionReference] = field(default_factory=list)
    reduce_events: list[ReduceEvent] = field(default_factory=list)
    build_events: list[BuildEvent] = field(default_factory=list)
    newobj_events: list[NewObjEvent] = field(default_factory=list)
    memo_events: list[MemoEvent] = field(default_factory=list)
    memo_overwrites: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    max_protocol: int = -1


class PvmEmulator:
    """Simulate PVM stack/memo state; record global lookups and REDUCE call sites."""

    def emulate(self, data: bytes | BinaryIO) -> EmulationResult:
        result = EmulationResult()
        stack: list[StackValue] = []
        memo: dict[int, StackValue] = {}
        memo_stored: dict[int, int] = {}  # key -> offset of last PUT
        mark_stack: list[int] = []

        try:
            for opcode, arg, pos in genops(data):
                if pos is None:
                    pos = -1

                result.max_protocol = max(result.max_protocol, opcode.proto)

                if opcode.name in _NOOP_OPCODES:
                    if opcode.name == "MEMOIZE" and stack:
                        self._store_memo(
                            memo, memo_stored, len(memo), stack, pos, "MEMOIZE", result
                        )
                    continue

                if opcode.name == "MARK":
                    mark_stack.append(pos)
                    stack.append(StackValue(value=markobject, taint=TaintKind.UNKNOWN))
                    continue

                if opcode.name in ("PUT", "BINPUT", "LONG_BINPUT"):
                    self._store_memo(memo, memo_stored, arg, stack, pos, opcode.name, result)
                    continue

                if opcode.name in ("GET", "BINGET", "LONG_BINGET"):
                    self._load_memo(memo, memo_stored, arg, stack, pos, opcode.name, result)
                    continue

                if opcode.name == "GLOBAL":
                    ref = self._global_from_arg(arg, opcode.name, pos)
                    result.global_refs.append(ref)
                    stack.append(StackValue.from_global(ref))
                    continue

                if opcode.name == "STACK_GLOBAL":
                    ref, mod_cell, name_cell = self._global_from_stack_detail(stack, opcode.name, pos)
                    result.global_refs.append(ref)
                    note = obfuscation_note_for_stack_global(mod_cell, name_cell, ref)
                    if note:
                        result.errors.append(note)
                    stack.append(StackValue.from_global(ref))
                    continue

                if opcode.name == "POP":
                    if stack and stack[-1].value is markobject:
                        self._pop_to_mark(stack, mark_stack)
                    elif stack:
                        stack.pop()
                    continue

                if opcode.name == "DUP":
                    if stack:
                        stack.append(stack[-1])
                    continue

                if opcode.name in _LITERAL_OPCODES:
                    stack.append(self._literal_value(opcode.name, arg, pos))
                    continue

                if opcode.name in ("TUPLE1", "TUPLE2", "TUPLE3"):
                    n = int(opcode.name[-1])
                    self._make_tuple(stack, n, opcode.name, pos)
                    continue

                if opcode.name == "TUPLE":
                    self._make_tuple_from_mark(stack, mark_stack, pos)
                    continue

                if opcode.name == "LIST":
                    self._make_list_from_mark(stack, mark_stack, pos)
                    continue

                if opcode.name == "DICT":
                    self._make_dict_from_mark(stack, mark_stack)
                    continue

                if opcode.name == "SETITEM":
                    self._setitem(stack, pos)
                    continue

                if opcode.name == "SETITEMS":
                    self._bulk_dict(stack, mark_stack, pos)
                    continue

                if opcode.name == "APPEND":
                    self._append(stack, pos)
                    continue

                if opcode.name == "APPENDS":
                    self._bulk_list(stack, mark_stack, pos)
                    continue

                if opcode.name == "ADDITEMS":
                    self._bulk_set(stack, mark_stack, pos)
                    continue

                if opcode.name in ("EXT1", "EXT2", "EXT4"):
                    self._extension(stack, pos, opcode.name, arg, result)
                    continue

                if opcode.name == "INST":
                    self._inst(stack, mark_stack, pos, result)
                    continue

                if opcode.name == "OBJ":
                    self._obj(stack, mark_stack, pos)
                    continue

                if opcode.name == "PERSID":
                    stack.append(self._persid_cell(arg, pos))
                    continue

                if opcode.name == "BINPERSID":
                    self._binpersid(stack, pos)
                    continue

                if opcode.name == "REDUCE":
                    self._reduce(stack, pos, result)
                    continue

                if opcode.name == "BUILD":
                    self._build(stack, pos, result)
                    continue

                if opcode.name in ("NEWOBJ", "NEWOBJ_EX"):
                    self._newobj(stack, pos, opcode.name, result)
                    continue

                self._apply_generic_effect(stack, opcode, result)

        except Exception as exc:  # noqa: BLE001
            result.errors.append(str(exc))

        return result

    @staticmethod
    def _literal_value(opcode_name: str, arg: object, offset: int) -> StackValue:
        if opcode_name == "NEWTRUE":
            return StackValue.constant(True, opcode=opcode_name, offset=offset)
        if opcode_name == "NEWFALSE":
            return StackValue.constant(False, opcode=opcode_name, offset=offset)
        if opcode_name in ("EMPTY_TUPLE", "EMPTY_LIST", "EMPTY_DICT", "EMPTY_SET", "FROZENSET"):
            empty = {
                "EMPTY_TUPLE": (),
                "EMPTY_LIST": [],
                "EMPTY_DICT": {},
                "EMPTY_SET": set(),
                "FROZENSET": frozenset(),
            }[opcode_name]
            return StackValue.constant(empty, opcode=opcode_name, offset=offset)
        if opcode_name in ("NEXT_BUFFER", "READONLY_BUFFER"):
            return StackValue.constant(f"<{opcode_name}>", opcode=opcode_name, offset=offset)
        return StackValue.constant(arg, opcode=opcode_name, offset=offset)

    @staticmethod
    def _parse_global_arg(arg: object) -> tuple[str | None, str | None, TaintKind]:
        if not isinstance(arg, str) or not arg.strip():
            return None, None, TaintKind.UNKNOWN
        module, sep, name = arg.partition(" ")
        if not sep:
            return None, None, TaintKind.UNKNOWN
        return module, name, TaintKind.CONST

    def _global_from_arg(self, arg: object, opcode: str, offset: int) -> GlobalReference:
        module, name, taint = self._parse_global_arg(arg)
        return GlobalReference(
            module=module,
            name=name,
            taint=taint,
            opcode=opcode,
            offset=offset,
        )

    def _global_from_stack(self, stack: list[StackValue], opcode: str, offset: int) -> GlobalReference:
        ref, _, _ = self._global_from_stack_detail(stack, opcode, offset)
        return ref

    def _global_from_stack_detail(
        self, stack: list[StackValue], opcode: str, offset: int
    ) -> tuple[GlobalReference, StackValue, StackValue]:
        if len(stack) < 2:
            empty = StackValue.unknown()
            return (
                GlobalReference(
                    module=None,
                    name=None,
                    taint=TaintKind.UNKNOWN,
                    opcode=opcode,
                    offset=offset,
                ),
                empty,
                empty,
            )

        name_cell = stack.pop()
        module_cell = stack.pop()
        module = module_cell.as_str()
        name = name_cell.as_str()

        if module is not None and name is not None:
            taint = TaintKind.CONST
            if module_cell.taint is TaintKind.MEMO or name_cell.taint is TaintKind.MEMO:
                taint = TaintKind.MEMO
            elif module_cell.taint is not TaintKind.CONST or name_cell.taint is not TaintKind.CONST:
                taint = TaintKind.DERIVED
        else:
            taint = TaintKind.UNKNOWN

        ref = GlobalReference(
            module=module,
            name=name,
            taint=taint,
            opcode=opcode,
            offset=offset,
            module_source_offset=module_cell.producer_offset
            if module_cell.producer_kind in _MEMO_LOAD_OPCODES
            else None,
            name_source_offset=name_cell.producer_offset
            if name_cell.producer_kind in _MEMO_LOAD_OPCODES
            else None,
        )
        return ref, module_cell, name_cell

    @staticmethod
    def _store_memo(
        memo: dict[int, StackValue],
        memo_stored: dict[int, int],
        key: object,
        stack: list[StackValue],
        offset: int,
        opcode: str,
        result: EmulationResult,
    ) -> None:
        if not isinstance(key, int):
            result.errors.append(f"invalid memo key: {key!r}")
            return
        if not stack:
            result.errors.append(f"PUT with empty stack at memo key {key}")
            return
        if stack[-1].value is markobject:
            result.errors.append(f"cannot PUT markobject into memo key {key}")
            return
        overwrote = key in memo
        prior = memo.get(key)
        cell = stack[-1]
        memo[key] = cell
        memo_stored[key] = offset
        result.memo_events.append(
            MemoEvent(
                offset=offset,
                opcode=opcode,
                key=key,
                kind="store",
                security=cell.security,
                qualified_name=cell.qualified_name,
                producer_refs=cell.source_refs,
                overwrote=overwrote,
                prior_security=prior.security if prior else None,
            )
        )
        msg = overwrite_forensics(key, offset, prior, cell)
        if msg:
            result.memo_overwrites.append(msg)

    @staticmethod
    def _load_memo(
        memo: dict[int, StackValue],
        memo_stored: dict[int, int],
        key: object,
        stack: list[StackValue],
        offset: int,
        opcode: str,
        result: EmulationResult,
    ) -> None:
        if not isinstance(key, int):
            result.errors.append(f"invalid memo key: {key!r}")
            return
        load_before_store = key not in memo
        store_offset = memo_stored.get(key)
        if load_before_store:
            result.memo_events.append(
                MemoEvent(
                    offset=offset,
                    opcode=opcode,
                    key=key,
                    kind="load",
                    security=SecurityTaint.INCONCLUSIVE,
                    load_before_store=True,
                )
            )
            result.errors.append(f"memo key {key} never stored (GET at {offset})")
            stack.append(StackValue.unknown())
            return

        cell = memo[key]
        load_ref = ValueRef(
            kind=opcode,
            offset=offset,
            memo_key=key,
            store_offset=store_offset,
        )
        result.memo_events.append(
            MemoEvent(
                offset=offset,
                opcode=opcode,
                key=key,
                kind="load",
                security=security_on_memo_load(cell),
                qualified_name=cell.qualified_name,
                store_offset=store_offset,
                producer_refs=refs_union(cell.source_refs, frozenset({load_ref})),
            )
        )
        stack.append(
            StackValue(
                value=cell.value,
                taint=memo_load_resolution(cell),
                security=security_on_memo_load(cell),
                qualified_name=cell.qualified_name,
                producer_offset=offset,
                producer_kind=opcode,
                source_refs=refs_union(cell.source_refs, frozenset({load_ref})),
            )
        )

    @staticmethod
    def _pop_to_mark(stack: list[StackValue], mark_stack: list[int]) -> None:
        while stack and stack[-1].value is not markobject:
            stack.pop()
        if stack and stack[-1].value is markobject:
            stack.pop()
        if mark_stack:
            mark_stack.pop()

    @staticmethod
    def _items_above_mark(stack: list[StackValue]) -> list[StackValue]:
        items: list[StackValue] = []
        for cell in reversed(stack):
            if cell.value is markobject:
                break
            items.append(cell)
        return list(reversed(items))

    def _make_tuple(self, stack: list[StackValue], n: int, opcode: str, offset: int) -> None:
        if len(stack) < n:
            return
        cells = stack[-n:]
        del stack[-n:]
        stack.append(self._derived_cell(tuple(c.value for c in cells), cells, opcode, offset))

    def _make_tuple_from_mark(self, stack: list[StackValue], mark_stack: list[int], offset: int) -> None:
        items = self._items_above_mark(stack)
        self._pop_to_mark(stack, mark_stack)
        stack.append(self._derived_cell(tuple(c.value for c in items), items, "TUPLE", offset))

    def _make_list_from_mark(self, stack: list[StackValue], mark_stack: list[int], offset: int) -> None:
        items = self._items_above_mark(stack)
        self._pop_to_mark(stack, mark_stack)
        stack.append(self._derived_cell([c.value for c in items], items, "LIST", offset))

    def _make_dict_from_mark(self, stack: list[StackValue], mark_stack: list[int]) -> None:
        items = self._items_above_mark(stack)
        offset = mark_stack[-1] if mark_stack else None
        self._pop_to_mark(stack, mark_stack)
        if len(items) % 2:
            values: dict[object, object] = {}
        else:
            values = {}
            for i in range(0, len(items), 2):
                values[items[i].value] = items[i + 1].value
        stack.append(self._derived_cell(values, items, "DICT", offset))

    def _bulk_dict(self, stack: list[StackValue], mark_stack: list[int], offset: int) -> None:
        items = self._items_above_mark(stack)
        self._pop_to_mark(stack, mark_stack)
        if not stack:
            return
        container = stack.pop()
        if not isinstance(container.value, dict):
            stack.append(StackValue.unknown())
            return
        new_dict = dict(container.value)
        if len(items) % 2 == 0:
            for i in range(0, len(items), 2):
                new_dict[items[i].value] = items[i + 1].value
        all_sources = [container, *items]
        stack.append(
            self._derived_cell(new_dict, all_sources, "SETITEMS", offset)
        )

    def _bulk_list(self, stack: list[StackValue], mark_stack: list[int], offset: int) -> None:
        items = self._items_above_mark(stack)
        self._pop_to_mark(stack, mark_stack)
        if not stack:
            return
        container = stack.pop()
        if not isinstance(container.value, list):
            stack.append(StackValue.unknown())
            return
        new_list = list(container.value)
        new_list.extend(c.value for c in items)
        stack.append(self._derived_cell(new_list, [container, *items], "APPENDS", offset))

    def _bulk_set(self, stack: list[StackValue], mark_stack: list[int], offset: int) -> None:
        items = self._items_above_mark(stack)
        self._pop_to_mark(stack, mark_stack)
        if not stack:
            return
        container = stack.pop()
        if not isinstance(container.value, set):
            stack.append(StackValue.unknown())
            return
        new_set = set(container.value)
        new_set.update(c.value for c in items)
        stack.append(self._derived_cell(new_set, [container, *items], "ADDITEMS", offset))

    @staticmethod
    def _append(stack: list[StackValue], offset: int) -> None:
        if len(stack) < 2:
            return
        item = stack.pop()
        container = stack.pop()
        if not isinstance(container.value, list):
            stack.append(StackValue.unknown())
            return
        new_list = list(container.value)
        new_list.append(item.value)
        source_refs = refs_union(
            container.source_refs,
            item.source_refs,
            frozenset({ValueRef("APPEND", offset)}),
        )
        stack.append(
            StackValue(
                value=new_list,
                taint=PvmEmulator._merge_resolution((container.taint, item.taint)),
                security=join_security(container.security, item.security),
                producer_offset=offset,
                producer_kind="APPEND",
                source_refs=source_refs,
            )
        )

    def _extension(
        self,
        stack: list[StackValue],
        offset: int,
        opcode_name: str,
        code: object,
        result: EmulationResult,
    ) -> None:
        if not isinstance(code, int):
            result.errors.append(f"{opcode_name} at {offset}: bad code {code!r}")
            stack.append(StackValue.unknown())
            return
        module, name = self._resolve_extension_code(code)
        ref = ExtensionReference(code=code, module=module, name=name, offset=offset, opcode=opcode_name)
        result.extension_refs.append(ref)
        security = classify_extension(module, name)
        qn = ref.qualified_name
        stack.append(
            StackValue(
                value=qn or f"<ext:{code}>",
                taint=TaintKind.GLOBAL if qn else TaintKind.UNKNOWN,
                security=security,
                qualified_name=qn,
                producer_offset=offset,
                producer_kind=opcode_name,
                source_refs=frozenset({ValueRef(opcode_name, offset)}),
            )
        )

    @staticmethod
    def _resolve_extension_code(code: int) -> tuple[str | None, str | None]:
        try:
            entry = copyreg._inverted_registry.get(code)
            if entry and len(entry) >= 2:
                return str(entry[0]), str(entry[1])
        except Exception:  # noqa: BLE001
            pass
        return None, None

    def _inst(self, stack: list[StackValue], mark_stack: list[int], offset: int, result: EmulationResult) -> None:
        items = self._items_above_mark(stack)
        self._pop_to_mark(stack, mark_stack)
        module = name = None
        args_cells = items
        if len(items) >= 2:
            mod_s = items[0].as_str()
            name_s = items[1].as_str()
            if mod_s and name_s:
                module, name = mod_s, name_s
                args_cells = items[2:]
                ref = GlobalReference(
                    module=module,
                    name=name,
                    taint=TaintKind.CONST,
                    opcode="INST",
                    offset=offset,
                )
                result.global_refs.append(ref)
        qn = f"{module}.{name}" if module and name else None
        security = classify_global(module, name) if qn else SecurityTaint.INCONCLUSIVE
        stack.append(
            self._derived_cell(
                qn or f"<inst@{offset}>",
                items,
                "INST",
                offset,
            )
        )
        stack[-1] = StackValue(
            value=stack[-1].value,
            taint=stack[-1].taint,
            security=security,
            qualified_name=qn,
            producer_offset=offset,
            producer_kind="INST",
            source_refs=stack[-1].source_refs,
        )

    def _obj(self, stack: list[StackValue], mark_stack: list[int], offset: int) -> None:
        items = self._items_above_mark(stack)
        self._pop_to_mark(stack, mark_stack)
        stack.append(self._derived_cell(f"<obj@{offset}>", items, "OBJ", offset))

    @staticmethod
    def _persid_cell(arg: object, offset: int) -> StackValue:
        return StackValue(
            value=f"<persid:{arg!r}>",
            taint=TaintKind.UNKNOWN,
            security=SecurityTaint.INCONCLUSIVE,
            producer_offset=offset,
            producer_kind="PERSID",
            source_refs=frozenset({ValueRef("PERSID", offset)}),
        )

    @staticmethod
    def _binpersid(stack: list[StackValue], offset: int) -> None:
        if not stack:
            return
        cell = stack.pop()
        stack.append(
            StackValue(
                value=f"<persid:{cell.value!r}>",
                taint=TaintKind.DERIVED,
                security=join_security(cell.security, SecurityTaint.INCONCLUSIVE),
                producer_offset=offset,
                producer_kind="BINPERSID",
                source_refs=refs_union(cell.source_refs, frozenset({ValueRef("BINPERSID", offset)})),
            )
        )

    @staticmethod
    def _derived_cell(
        value: Any,
        sources: list[StackValue],
        opcode: str | None = None,
        offset: int | None = None,
    ) -> StackValue:
        source_refs = refs_union(*(c.source_refs for c in sources))
        if opcode is not None and offset is not None:
            source_refs = refs_union(
                source_refs,
                frozenset({ValueRef(kind=opcode, offset=offset)}),
            )
        return StackValue(
            value=value,
            taint=PvmEmulator._merge_resolution(c.taint for c in sources),
            security=join_security(*(c.security for c in sources)),
            producer_offset=offset,
            producer_kind=opcode,
            source_refs=source_refs,
        )

    @staticmethod
    def _setitem(stack: list[StackValue], offset: int) -> None:
        if len(stack) < 3:
            return
        value = stack.pop()
        key = stack.pop()
        container = stack.pop()
        if isinstance(container.value, dict):
            new_dict = dict(container.value)
            new_dict[key.value] = value.value
            source_refs = refs_union(
                container.source_refs,
                key.source_refs,
                value.source_refs,
                frozenset({ValueRef(kind="SETITEM", offset=offset)}),
            )
            stack.append(
                StackValue(
                    value=new_dict,
                    taint=PvmEmulator._merge_resolution(
                        (container.taint, key.taint, value.taint)
                    ),
                    security=join_security(
                        container.security, key.security, value.security
                    ),
                    producer_offset=container.producer_offset,
                    producer_kind=container.producer_kind,
                    source_refs=source_refs,
                )
            )
        else:
            stack.append(StackValue.unknown())

    def _reduce(self, stack: list[StackValue], offset: int, result: EmulationResult) -> None:
        if len(stack) < 2:
            result.errors.append(f"REDUCE at {offset}: stack underflow")
            return

        args_cell = stack.pop()
        callable_cell = stack.pop()

        callable_qn = callable_cell.qualified_name or self._qualified_from_cell(callable_cell)
        args_tuple = self._fold_args(args_cell)

        invocation_security = classify_invocation(
            callable_qn,
            args_tuple,
            callable_security=callable_cell.security,
            args_security=args_cell.security,
        )

        result_qn, result_security = simulate_reduce_result(
            callable_qn,
            args_tuple,
            callable_cell.security,
        )
        invocation_security = join_security(invocation_security, result_security)

        event = ReduceEvent(
            offset=offset,
            callable_qualified=callable_qn,
            callable_security=callable_cell.security,
            callable_producer_offset=callable_cell.producer_offset,
            callable_producer_kind=callable_cell.producer_kind,
            args=args_tuple,
            args_security=args_cell.security,
            invocation_security=invocation_security,
            result_qualified=result_qn,
            result_security=result_security,
            args_producer_refs=args_cell.source_refs,
        )
        result.reduce_events.append(event)

        stack.append(
            StackValue.from_reduce(
                value=result_qn or f"<reduce@{offset}>",
                qualified_name=result_qn,
                security=result_security,
                offset=offset,
            )
        )

    def _build(self, stack: list[StackValue], offset: int, result: EmulationResult) -> None:
        if len(stack) < 2:
            result.errors.append(f"BUILD at {offset}: stack underflow")
            return

        state_cell = stack.pop()
        instance_cell = stack.pop()

        instance_qn = instance_cell.qualified_name or self._qualified_from_cell(instance_cell)
        invocation_security = classify_build(
            instance_qn,
            instance_security=instance_cell.security,
            state_security=state_cell.security,
            state_value=state_cell.value,
        )

        event = BuildEvent(
            offset=offset,
            instance_qualified=instance_qn,
            instance_security=instance_cell.security,
            instance_producer_offset=instance_cell.producer_offset,
            instance_producer_kind=instance_cell.producer_kind,
            state_security=state_cell.security,
            state_producer_refs=state_cell.source_refs,
            invocation_security=invocation_security,
        )
        result.build_events.append(event)

        stack.append(
            StackValue(
                value=f"<build@{offset}:{instance_qn}>",
                taint=TaintKind.DERIVED,
                security=invocation_security,
                qualified_name=instance_qn,
                producer_offset=offset,
                producer_kind="BUILD",
                source_refs=refs_union(
                    instance_cell.source_refs,
                    state_cell.source_refs,
                    frozenset({ValueRef("BUILD", offset)}),
                ),
            )
        )

    def _newobj(
        self,
        stack: list[StackValue],
        offset: int,
        opcode_name: str,
        result: EmulationResult,
    ) -> None:
        if opcode_name == "NEWOBJ_EX":
            if len(stack) < 3:
                result.errors.append(f"NEWOBJ_EX at {offset}: stack underflow")
                return
            kwargs_cell = stack.pop()
            args_cell = stack.pop()
            class_cell = stack.pop()
            _ = kwargs_cell
        else:
            if len(stack) < 2:
                result.errors.append(f"NEWOBJ at {offset}: stack underflow")
                return
            args_cell = stack.pop()
            class_cell = stack.pop()

        class_qn = class_cell.qualified_name or self._qualified_from_cell(class_cell)
        args_tuple = self._fold_args(args_cell)
        invocation_security = classify_newobj(
            class_qn,
            args_tuple,
            class_security=class_cell.security,
            args_security=args_cell.security,
        )

        event = NewObjEvent(
            offset=offset,
            opcode=opcode_name,
            class_qualified=class_qn,
            class_security=class_cell.security,
            class_producer_offset=class_cell.producer_offset,
            class_producer_kind=class_cell.producer_kind,
            args=args_tuple,
            args_security=args_cell.security,
            args_producer_refs=args_cell.source_refs,
            invocation_security=invocation_security,
        )
        result.newobj_events.append(event)

        stack.append(
            StackValue.from_newobj(
                value=f"<newobj@{offset}:{class_qn}>",
                qualified_name=class_qn,
                security=invocation_security,
                offset=offset,
                opcode=opcode_name,
            )
        )

    @staticmethod
    def _qualified_from_cell(cell: StackValue) -> str | None:
        if isinstance(cell.value, GlobalReference):
            return cell.value.qualified_name
        if isinstance(cell.value, str) and "." in cell.value and " " not in cell.value:
            return cell.value
        return cell.qualified_name

    @staticmethod
    def _fold_args(args_cell: StackValue) -> tuple[Any, ...] | None:
        if not isinstance(args_cell.value, tuple):
            if args_cell.taint is TaintKind.UNKNOWN:
                return None
            return (args_cell.value,)
        return args_cell.value

    @staticmethod
    def _merge_resolution(taints: Any) -> TaintKind:
        kinds = list(taints)
        if not kinds:
            return TaintKind.CONST
        if any(t is TaintKind.UNKNOWN for t in kinds):
            return TaintKind.UNKNOWN
        if any(t is TaintKind.REDUCE for t in kinds):
            return TaintKind.DERIVED
        if any(t is TaintKind.DERIVED for t in kinds):
            return TaintKind.DERIVED
        if any(t is TaintKind.MEMO for t in kinds):
            return TaintKind.MEMO
        if any(t is TaintKind.GLOBAL for t in kinds):
            return TaintKind.GLOBAL
        return TaintKind.CONST

    @staticmethod
    def _apply_generic_effect(stack: list[StackValue], opcode: object, result: EmulationResult) -> None:
        before = opcode.stack_before
        after = opcode.stack_after

        num_pop = len(before)
        if num_pop and before[-1].name == "stackslice":
            result.errors.append(f"unhandled opcode with stackslice: {opcode.name}")
            return

        if len(stack) < num_pop:
            result.errors.append(
                f"{opcode.name}: stack underflow (need {num_pop}, have {len(stack)})"
            )
            return

        if num_pop:
            popped = stack[-num_pop:]
            del stack[-num_pop:]
            merged_sec = join_security(*(c.security for c in popped))
        else:
            merged_sec = SecurityTaint.CLEAN

        if after:
            stack.extend(
                StackValue(
                    value=None,
                    taint=TaintKind.UNKNOWN,
                    security=merged_sec if merged_sec is not SecurityTaint.CLEAN else SecurityTaint.INCONCLUSIVE,
                )
                for _ in after
            )
