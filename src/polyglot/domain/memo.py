"""Memo taint precision rules — security vs resolution axis."""

from __future__ import annotations

from polyglot.domain.taint import SecurityTaint, join_security
from polyglot.domain.values import GlobalReference, StackValue, TaintKind


def security_on_memo_load(stored: StackValue) -> SecurityTaint:
    """Inherit stored security; memo mechanism does not escalate risk."""
    return stored.security


def memo_load_resolution(stored: StackValue) -> TaintKind:
    """Track that value came via memo without losing prior resolution hints."""
    if stored.taint is TaintKind.CONST:
        return TaintKind.MEMO
    return stored.taint


def obfuscation_note_for_stack_global(
    module_cell: StackValue,
    name_cell: StackValue,
    resolved: GlobalReference,
) -> str | None:
    """Flag memo-fed lookups only when the resolved target is non-CLEAN."""
    if module_cell.taint is not TaintKind.MEMO and name_cell.taint is not TaintKind.MEMO:
        return None
    from polyglot.domain.security import classify_global

    level = classify_global(resolved.module, resolved.name)
    if level is SecurityTaint.CLEAN:
        return None
    qn = resolved.qualified_name or "unresolved"
    return f"memo-fed STACK_GLOBAL at {resolved.offset}: {qn} ({level.name})"


def overwrite_forensics(
    key: int,
    offset: int,
    prior: StackValue | None,
    new_cell: StackValue,
) -> str | None:
    """Content-aware overwrite message when security changes."""
    if prior is None:
        return None
    if prior.security is new_cell.security:
        return None
    prior_qn = prior.qualified_name or repr(prior.value)[:40]
    new_qn = new_cell.qualified_name or repr(new_cell.value)[:40]
    return (
        f"memo key {key} @{offset}: {prior.security.name} → {new_cell.security.name}"
        f" ({prior_qn!r} → {new_qn!r})"
    )


def join_slot_security(current: SecurityTaint, incoming: SecurityTaint) -> SecurityTaint:
    """Lattice join for memo slot fixed-point (cycles)."""
    return join_security(current, incoming)
