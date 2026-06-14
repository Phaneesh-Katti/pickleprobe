"""Command-line interface for PickleProbe."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pickleprobe.analysis.analyzer import FileAnalysisResult, PickleAnalyzer


def _report_to_dict(report: object) -> dict:
    from pickleprobe.analysis.analyzer import AnalysisReport

    assert isinstance(report, AnalysisReport)
    return {
        "stream_name": report.stream_name,
        "raw_size": report.raw_size,
        "max_protocol": report.max_protocol,
        "emulation_errors": report.emulation_errors,
        "global_refs": [
            {
                "offset": ref.offset,
                "opcode": ref.opcode,
                "module": ref.module,
                "name": ref.name,
                "qualified_name": ref.qualified_name,
                "resolved": ref.is_resolved,
                "resolution": ref.taint.name,
            }
            for ref in report.global_refs
        ],
        "reduce_events": [
            {
                "offset": ev.offset,
                "callable": ev.callable_qualified,
                "callable_security": ev.callable_security.name,
                "callable_producer": {
                    "kind": ev.callable_producer_kind,
                    "offset": ev.callable_producer_offset,
                },
                "args": list(ev.args) if ev.args is not None else None,
                "args_security": ev.args_security.name,
                "args_producers": [
                    {"kind": r.kind, "offset": r.offset} for r in sorted(
                        ev.args_producer_refs, key=lambda r: (r.offset, r.kind)
                    )
                ],
                "invocation_security": ev.invocation_security.name,
                "result": ev.result_qualified,
                "result_security": ev.result_security.name,
            }
            for ev in report.reduce_events
        ],
        "build_events": [
            {
                "offset": ev.offset,
                "instance": ev.instance_qualified,
                "instance_security": ev.instance_security.name,
                "state_security": ev.state_security.name,
                "invocation_security": ev.invocation_security.name,
            }
            for ev in report.build_events
        ],
        "newobj_events": [
            {
                "offset": ev.offset,
                "opcode": ev.opcode,
                "class": ev.class_qualified,
                "class_security": ev.class_security.name,
                "args": list(ev.args) if ev.args is not None else None,
                "invocation_security": ev.invocation_security.name,
            }
            for ev in report.newobj_events
        ],
        "findings": {
            "sink_invocations": len(report.sink_invocations),
            "suspicious_invocations": len(report.suspicious_invocations),
            "risky_builds": len(report.risky_builds),
            "memo_warnings": report.memo_warnings,
        },
        "exploit_paths": [
            {
                "sink_offset": p.sink_offset,
                "sink_kind": p.sink_kind,
                "sink_callable": p.sink_callable,
                "steps": [
                    {
                        "opcode": s[0],
                        "offset": s[1],
                        "edge": s[2],
                        "memo_key": s[3],
                    }
                    for s in p.steps
                ],
            }
            for p in report.exploit_paths
        ],
        "cfg_taint_max": (
            report.cfg_taint.max_propagated.name if report.cfg_taint else "CLEAN"
        ),
        "cfg": {
            "node_count": len(report.cfg.nodes),
            "edge_count": len(report.cfg.edges),
            "global_lookup_count": len(report.cfg.global_lookups),
            "reduce_invoke_count": len(report.cfg.reduce_invocations),
            "build_invoke_count": len(report.cfg.build_invocations),
            "newobj_invoke_count": len(report.cfg.newobj_invocations),
        },
    }


def _file_result_to_dict(result: FileAnalysisResult) -> dict:
    return {
        "path": str(result.path),
        "format": result.format.name,
        "stream_count": len(result.streams),
        "streams": [_report_to_dict(r) for r in result.streams],
    }


def _print_human(report: object, *, stream_label: str | None = None) -> None:
    from pickleprobe.analysis.analyzer import AnalysisReport
    from pickleprobe.domain.taint import SecurityTaint

    assert isinstance(report, AnalysisReport)

    if stream_label:
        print(f"Stream: {stream_label}")
    print(f"Size: {report.raw_size} bytes  |  Max protocol: {report.max_protocol}")
    print(
        f"CFG: {len(report.cfg.nodes)} nodes, {len(report.cfg.edges)} edges"
        f"  ({len(report.cfg.reduce_invocations)} REDUCE invokes)"
    )
    print()

    if report.global_refs:
        print("Global lookups:")
        for ref in report.global_refs:
            status = ref.qualified_name or "<unresolved>"
            print(f"  @{ref.offset:4d}  {ref.opcode:14s}  {status}")
        print()

    if report.reduce_events:
        print("REDUCE invocations:")
        for ev in report.reduce_events:
            callee = ev.callable_qualified or "<unresolved>"
            args_repr = ev.args if ev.args is not None else "<?>"
            prod = ""
            if ev.callable_producer_kind and ev.callable_producer_offset is not None:
                prod = f"  producer={ev.callable_producer_kind}@{ev.callable_producer_offset}"
            print(
                f"  @{ev.offset:4d}  {callee}({args_repr})"
                f"  security={ev.invocation_security.name}{prod}"
            )
        print()

    if report.build_events:
        print("BUILD invocations:")
        for ev in report.build_events:
            inst = ev.instance_qualified or "<unresolved>"
            print(
                f"  @{ev.offset:4d}  BUILD({inst})"
                f"  security={ev.invocation_security.name}"
            )
        print()

    if report.newobj_events:
        print("NEWOBJ invocations:")
        for ev in report.newobj_events:
            cls = ev.class_qualified or "<unresolved>"
            args_repr = ev.args if ev.args is not None else "<?>"
            print(
                f"  @{ev.offset:4d}  {ev.opcode}({cls}, {args_repr})"
                f"  security={ev.invocation_security.name}"
            )
        print()

    sinks = report.sink_invocations
    suspicious = [
        e
        for e in report.suspicious_invocations
        if e.invocation_security is SecurityTaint.SUSPICIOUS
    ]
    if sinks:
        print(f"Findings: {len(sinks)} SINK invocation(s)")
        for ev in sinks:
            print(f"  CRITICAL @{ev.offset}: {ev.callable_qualified}{ev.args}")
    if suspicious:
        print(f"Findings: {len(suspicious)} SUSPICIOUS invocation(s)")
        for ev in suspicious:
            print(f"  WARN @{ev.offset}: {ev.callable_qualified}{ev.args}")
    if not sinks and not suspicious:
        print("Findings: no SINK or SUSPICIOUS invocations")

    if report.exploit_paths:
        print()
        print("Exploit paths (CFG dataflow):")
        for path in report.exploit_paths:
            parts = []
            for op, off, edge, memo_key in path.steps:
                label = f"{op}@{off}"
                if memo_key is not None:
                    label += f"[memo:{memo_key}]"
                parts.append(label)
            chain = " → ".join(parts)
            print(f"  @{path.sink_offset} {path.sink_callable}: {chain}")

    if report.memo_warnings:
        print()
        print("Memo warnings:")
        for w in report.memo_warnings:
            print(f"  - {w}")

    if report.emulation_errors:
        print()
        print("Emulation warnings:")
        for err in report.emulation_errors:
            print(f"  - {err}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pickleprobe",
        description="Static analyzer for Python pickle bytecode",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a pickle byte stream")
    analyze.add_argument("path", type=Path, help="Path to pickle file")
    analyze.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON",
    )
    analyze.add_argument(
        "--policy",
        type=Path,
        default=None,
        help="Path to custom security policy YAML (default: bundled default.yaml)",
    )

    args = parser.parse_args(argv)

    if args.command == "analyze":
        analyzer = PickleAnalyzer(policy_path=args.policy)
        result = analyzer.analyze_file(args.path)
        exit_code = 0
        for report in result.streams:
            if report.sink_invocations:
                exit_code = 2
            elif report.has_findings and exit_code == 0:
                exit_code = 1

        if args.json:
            print(json.dumps(_file_result_to_dict(result), indent=2))
        else:
            print(f"File: {result.path}  ({result.format.name})")
            if len(result.streams) > 1:
                print(f"Streams: {len(result.streams)}")
                print()
            for report in result.streams:
                label = report.stream_name if len(result.streams) > 1 else None
                _print_human(report, stream_label=label)
                if len(result.streams) > 1:
                    print("---")
        return exit_code

    return 1


if __name__ == "__main__":
    sys.exit(main())
