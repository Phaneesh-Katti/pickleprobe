"""Tests for YAML security policy loading."""

from __future__ import annotations

from polyglot.domain.policy import load_policy
from polyglot.domain.security import SecurityTaint, classify_global


def test_default_policy_loads() -> None:
    policy = load_policy()
    assert policy.version >= 1
    assert ("os", "system") in policy.sinks
    assert ("builtins", "getattr") in policy.chain_primitives


def test_classify_uses_policy() -> None:
    assert classify_global("os", "system") is SecurityTaint.SINK
    assert classify_global("builtins", "getattr") is SecurityTaint.SUSPICIOUS
    assert classify_global("datetime", "datetime") is SecurityTaint.CLEAN
