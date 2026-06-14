"""Security taint lattice, policy-backed rules, and gadget simulation."""

from __future__ import annotations

from enum import Enum, auto
from typing import Any

from polyglot.domain.taint import SecurityTaint, join_security
from polyglot.domain.policy import SecurityPolicy, get_policy


def _policy() -> SecurityPolicy:
    return get_policy()


def classify_global(module: str | None, name: str | None) -> SecurityTaint:
    return _policy().classify_pair(module, name)


def classify_invocation(
    callable_qualified: str | None,
    args: tuple[Any, ...] | None,
    *,
    callable_security: SecurityTaint,
    args_security: SecurityTaint,
) -> SecurityTaint:
    policy = _policy()
    base = join_security(callable_security, args_security)

    pair = _parse_qualified(callable_qualified) if callable_qualified else None
    if pair and policy.is_sink_pair(pair):
        return SecurityTaint.SINK

    if callable_qualified == "builtins.getattr" and args and len(args) >= 2:
        attr = args[1]
        if isinstance(attr, str) and policy.is_sensitive_attr(attr):
            return join_security(base, SecurityTaint.SUSPICIOUS)

    if callable_security is SecurityTaint.SINK:
        return SecurityTaint.SINK

    if callable_qualified is None and base is SecurityTaint.CLEAN:
        return SecurityTaint.INCONCLUSIVE

    return base


def simulate_reduce_result(
    callable_qualified: str | None,
    args: tuple[Any, ...] | None,
    callable_security: SecurityTaint,
) -> tuple[str | None, SecurityTaint]:
    policy = _policy()

    if callable_qualified == "builtins.getattr" and args and len(args) == 2:
        attr = args[1]
        if not isinstance(attr, str):
            return None, join_security(callable_security, SecurityTaint.INCONCLUSIVE)
        obj = args[0]
        module_hint = _module_hint(obj)
        if module_hint and policy.is_sensitive_attr(attr):
            result_qn = f"{module_hint}.{attr}"
            if policy.is_sink_pair((module_hint, attr)) or policy.is_sensitive_attr(attr):
                return result_qn, SecurityTaint.SINK
        if policy.is_sensitive_attr(attr):
            return None, SecurityTaint.SUSPICIOUS

    if callable_qualified == "builtins.__import__" and args and len(args) >= 1:
        mod = args[0]
        if isinstance(mod, str):
            return f"<module:{mod}>", SecurityTaint.SUSPICIOUS

    if callable_qualified == "importlib.import_module" and args and len(args) >= 1:
        mod = args[0]
        if isinstance(mod, str):
            return f"<module:{mod}>", SecurityTaint.SUSPICIOUS

    if callable_qualified == "operator.methodcaller" and args and len(args) >= 1:
        method = args[0]
        if isinstance(method, str) and policy.is_sensitive_attr(method):
            return None, SecurityTaint.SUSPICIOUS

    if callable_qualified == "operator.attrgetter" and args and len(args) >= 1:
        attr = args[0]
        if isinstance(attr, str) and policy.is_sensitive_attr(attr):
            return None, SecurityTaint.SUSPICIOUS

    if callable_qualified == "functools.partial" and args and len(args) >= 1:
        inner_qn = _qualified_from_arg(args[0])
        if inner_qn:
            pair = _parse_qualified(inner_qn)
            if pair and policy.is_sink_pair(pair):
                return inner_qn, SecurityTaint.SINK
        if callable_security is SecurityTaint.SINK:
            return inner_qn, SecurityTaint.SINK

    if callable_qualified == "builtins.setattr" and args and len(args) >= 3:
        attr = args[1]
        if isinstance(attr, str) and policy.is_sensitive_attr(attr):
            return None, SecurityTaint.SUSPICIOUS

    if callable_qualified and _parse_qualified(callable_qualified):
        pair = _parse_qualified(callable_qualified)
        if pair and policy.is_sink_pair(pair):
            return callable_qualified, SecurityTaint.SINK

    return None, callable_security


def classify_extension(module: str | None, name: str | None) -> SecurityTaint:
    policy = _policy()
    if module is None or name is None:
        return SecurityTaint.SUSPICIOUS if policy.extension_codes_suspicious else SecurityTaint.INCONCLUSIVE
    return policy.classify_pair(module, name)


def classify_newobj(
    class_qualified: str | None,
    args: tuple[Any, ...] | None,
    *,
    class_security: SecurityTaint,
    args_security: SecurityTaint,
) -> SecurityTaint:
    policy = _policy()
    base = join_security(class_security, args_security)
    pair = _parse_qualified(class_qualified) if class_qualified else None
    if pair and policy.is_sink_pair(pair):
        return SecurityTaint.SINK
    if class_security is SecurityTaint.SINK:
        return SecurityTaint.SINK
    if class_qualified is None and base is SecurityTaint.CLEAN:
        return SecurityTaint.INCONCLUSIVE
    return base


def classify_build(
    instance_qualified: str | None,
    *,
    instance_security: SecurityTaint,
    state_security: SecurityTaint,
    state_value: Any = None,
) -> SecurityTaint:
    policy = _policy()
    base = join_security(instance_security, state_security)
    if instance_security is SecurityTaint.SINK:
        return SecurityTaint.SINK
    if state_security in (SecurityTaint.SINK, SecurityTaint.SUSPICIOUS):
        return join_security(base, state_security)
    if isinstance(state_value, dict):
        for key, val in state_value.items():
            if isinstance(key, str) and key in ("__reduce__", "__reduce_ex__", "__setstate__"):
                return join_security(base, SecurityTaint.SUSPICIOUS)
            if isinstance(val, str):
                pair = _parse_qualified(val)
                if pair and policy.is_sink_pair(pair):
                    return SecurityTaint.SINK
    if instance_qualified is None and base is SecurityTaint.CLEAN:
        return SecurityTaint.INCONCLUSIVE
    return base


def _parse_qualified(qualified: str) -> tuple[str, str] | None:
    if " " in qualified or "<" in qualified:
        return None
    module, dot, name = qualified.rpartition(".")
    if not dot:
        return None
    return module, name


def _qualified_from_value(obj: Any) -> str | None:
    from polyglot.domain.values import GlobalReference

    if isinstance(obj, GlobalReference):
        return obj.qualified_name
    if isinstance(obj, str) and "." in obj and " " not in obj:
        return obj
    return None


def _qualified_from_arg(obj: Any) -> str | None:
    return _qualified_from_value(obj)


def _module_hint(obj: Any) -> str | None:
    from polyglot.domain.values import GlobalReference

    if isinstance(obj, GlobalReference) and obj.module:
        return obj.module
    if isinstance(obj, str) and obj in ("os", "posix", "nt"):
        return obj
    if isinstance(obj, str) and obj.startswith("<module:") and obj.endswith(">"):
        return obj[8:-1]
    return None
