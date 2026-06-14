"""SARIF 2.1.0 emission for CI integrations (GitHub Code Scanning, etc.)."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

from pickleprobe.analysis.analyzer import AnalysisReport, FileAnalysisResult
from pickleprobe.domain.taint import SecurityTaint

_TOOL_NAME = "pickleprobe"
_TOOL_VERSION = "0.1.0"
_RULE_SINK = "pickle-sink-invocation"
_RULE_SUSPICIOUS = "pickle-suspicious-invocation"
_RULE_BUILD = "pickle-risky-build"


def _level(security: SecurityTaint) -> str:
    if security is SecurityTaint.SINK:
        return "error"
    if security is SecurityTaint.SUSPICIOUS:
        return "warning"
    return "note"


def _report_results(report: AnalysisReport, file_path: str) -> list[dict]:
    results: list[dict] = []
    uri = Path(file_path).as_uri()

    for ev in report.sink_invocations:
        results.append(
            {
                "ruleId": _RULE_SINK,
                "level": "error",
                "message": {
                    "text": (
                        f"SINK REDUCE: {ev.callable_qualified or '<unresolved>'}"
                        f"{ev.args or ''}"
                    ),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"byteOffset": ev.offset},
                        },
                    }
                ],
                "properties": {
                    "stream": report.stream_name,
                    "callable": ev.callable_qualified,
                    "result": ev.result_qualified,
                },
            }
        )

    for ev in report.suspicious_invocations:
        if ev.invocation_security is not SecurityTaint.SUSPICIOUS:
            continue
        results.append(
            {
                "ruleId": _RULE_SUSPICIOUS,
                "level": "warning",
                "message": {
                    "text": (
                        f"SUSPICIOUS REDUCE: {ev.callable_qualified or '<unresolved>'}"
                        f"{ev.args or ''}"
                    ),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"byteOffset": ev.offset},
                        },
                    }
                ],
                "properties": {
                    "stream": report.stream_name,
                    "callable": ev.callable_qualified,
                },
            }
        )

    for ev in report.risky_builds:
        results.append(
            {
                "ruleId": _RULE_BUILD,
                "level": _level(ev.invocation_security),
                "message": {
                    "text": (
                        f"Risky BUILD on {ev.instance_qualified or '<unresolved>'}"
                        f" ({ev.invocation_security.name})"
                    ),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"byteOffset": ev.offset},
                        },
                    }
                ],
                "properties": {"stream": report.stream_name},
            }
        )

    return results


def file_results_to_sarif(results: Iterable[FileAnalysisResult]) -> dict:
    """Build a SARIF log dict from one or more file analysis results."""
    sarif_results: list[dict] = []
    for file_result in results:
        path_str = str(file_result.path)
        for report in file_result.streams:
            sarif_results.extend(_report_results(report, path_str))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": "https://github.com/Phaneesh-Katti/pickleprobe",
                        "rules": [
                            {
                                "id": _RULE_SINK,
                                "name": "PickleSinkInvocation",
                                "shortDescription": {"text": "Policy sink invoked via REDUCE"},
                                "defaultConfiguration": {"level": "error"},
                            },
                            {
                                "id": _RULE_SUSPICIOUS,
                                "name": "PickleSuspiciousInvocation",
                                "shortDescription": {
                                    "text": "Suspicious pickle gadget or chain primitive",
                                },
                                "defaultConfiguration": {"level": "warning"},
                            },
                            {
                                "id": _RULE_BUILD,
                                "name": "PickleRiskyBuild",
                                "shortDescription": {
                                    "text": "BUILD with dangerous instance or state",
                                },
                                "defaultConfiguration": {"level": "warning"},
                            },
                        ],
                    }
                },
                "results": sarif_results,
            }
        ],
    }
