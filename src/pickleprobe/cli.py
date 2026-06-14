"""Command-line interface for PickleProbe."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from pickleprobe.analysis.analyzer import FileAnalysisResult, PickleAnalyzer
from pickleprobe.analysis.batch import ScanSummaryRow, iter_scan_targets, summarize_reports
from pickleprobe.reporting.sarif import file_results_to_sarif


def _json_arg(value: object) -> object:
    from pickleprobe.domain.values import GlobalReference

    if isinstance(value, GlobalReference):
        return {
            "module": value.module,
            "name": value.name,
            "qualified_name": value.qualified_name,
            "resolved": value.is_resolved,
        }
    if isinstance(value, tuple):
        return [_json_arg(v) for v in value]
    if isinstance(value, list):
        return [_json_arg(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _json_arg(v) for k, v in value.items()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


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
                "args": list(_json_arg(ev.args)) if ev.args is not None else None,
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
                "args": list(_json_arg(ev.args)) if ev.args is not None else None,
                "invocation_security": ev.invocation_security.name,
            }
            for ev in report.newobj_events
        ],
        "stack_unreliable_from": report.stack_unreliable_from,
        "gadget_hop_cap": report.gadget_hop_cap,
        "gadget_iterations": report.gadget_iterations,
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


def _verdict_line(exit_code: int) -> str:
    if exit_code == 0:
        return "Verdict: CLEAN (exit 0)"
    if exit_code == 2:
        return "Verdict: SINK detected (exit 2)"
    return "Verdict: SUSPICIOUS (exit 1)"


def _exit_code_note(exit_code: int) -> str:
    if exit_code == 0:
        return "No policy violations; shell exit 0."
    return (
        "Analysis finished successfully — non-zero exit is intentional for CI/scripts "
        "(see README: 0=clean, 1=suspicious, 2=sink)."
    )


def _exit_code_for_reports(reports: list) -> int:
    code = 0
    for report in reports:
        if report.sink_invocations:
            code = 2
        elif report.has_findings and code == 0:
            code = 1
    return code


def _exit_code_for_result(result: FileAnalysisResult) -> int:
    return _exit_code_for_reports(result.streams)


def _print_scan_summary(rows: list[ScanSummaryRow]) -> None:
    print(f"{'target':<56} {'sinks':>5} {'warn':>5} {'bytes':>10} {'exit':>4}")
    for row in rows:
        if row.error:
            print(f"{row.target:<56} {'ERR':>5} {'':>5} {'':>10} {'':>4}  {row.error}")
            continue
        print(
            f"{row.target:<56} {row.sinks:>5} {row.suspicious:>5} "
            f"{row.bytes_analyzed:>10} {row.exit_code:>4}"
        )
    worst = max((r.exit_code for r in rows if not r.error), default=0)
    print()
    print(_verdict_line(worst))
    print(_exit_code_note(worst))


def _run_streaming_scan(
    analyzer: PickleAnalyzer,
    root: Path,
    *,
    recursive: bool,
    archive_members: bool,
    limit: int | None,
    max_member_bytes: int | None,
    progress: bool,
) -> tuple[list[ScanSummaryRow], list[FileAnalysisResult], int]:
    rows: list[ScanSummaryRow] = []
    file_results: list[FileAnalysisResult] = []
    exit_code = 0
    index = 0

    for target in iter_scan_targets(
        root,
        recursive=recursive,
        archive_members=archive_members,
        limit=limit,
        max_member_bytes=max_member_bytes,
    ):
        index += 1
        try:
            reports = analyzer.analyze_target(target.path, member=target.member)
            sinks, suspicious, risky_builds, nbytes = summarize_reports(reports)
            code = _exit_code_for_reports(reports)
            row = ScanSummaryRow(
                target=target.label,
                sinks=sinks,
                suspicious=suspicious,
                risky_builds=risky_builds,
                streams=len(reports),
                exit_code=code,
                bytes_analyzed=nbytes,
            )
            if target.member is None:
                from pickleprobe.formats.loader import load_file

                loaded = load_file(target.path)
                file_results.append(
                    FileAnalysisResult(path=target.path, format=loaded.format, streams=reports)
                )
            else:
                from pickleprobe.formats.loader import FileFormat

                file_results.append(
                    FileAnalysisResult(
                        path=target.path,
                        format=FileFormat.TAR_GZ_ARCHIVE,
                        streams=reports,
                    )
                )
        except OSError as exc:
            row = ScanSummaryRow(
                target=target.label,
                sinks=0,
                suspicious=0,
                risky_builds=0,
                streams=0,
                exit_code=0,
                bytes_analyzed=0,
                error=str(exc),
            )
            code = 0
        except Exception as exc:  # noqa: BLE001 — batch scan should continue
            row = ScanSummaryRow(
                target=target.label,
                sinks=0,
                suspicious=0,
                risky_builds=0,
                streams=0,
                exit_code=0,
                bytes_analyzed=0,
                error=str(exc),
            )
            code = 0

        rows.append(row)
        exit_code = max(exit_code, code)
        if progress:
            prefix = f"[{index}] "
            if row.error:
                print(f"{prefix}{row.target}  ERROR  {row.error}", flush=True)
            else:
                print(
                    f"{prefix}{row.target}  sinks={row.sinks} suspicious={row.suspicious} "
                    f"bytes={row.bytes_analyzed} exit={row.exit_code}",
                    flush=True,
                )

    return rows, file_results, exit_code


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

    analyze.add_argument(
        "--sarif",
        action="store_true",
        help="Emit SARIF 2.1.0 JSON (implies --json structure for single-file runs)",
    )

    analyze.add_argument(
        "--member",
        default=None,
        help="Analyze one member inside a .tar.gz archive (e.g. ours/call_system.pkl)",
    )

    scan = sub.add_parser("scan", help="Batch-analyze files in a directory or one file")
    scan.add_argument("path", type=Path, help="File or directory to scan")
    scan.add_argument(
        "-r",
        "--recursive",
        action="store_true",
        help="Recurse into subdirectories when path is a directory",
    )
    scan.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop after N targets (files or archive members)",
    )
    scan.add_argument(
        "--max-member-mb",
        type=int,
        default=64,
        help="Skip archive members larger than this many MiB (default: 64)",
    )
    scan.add_argument(
        "--no-archive-members",
        action="store_true",
        help="Treat .tar.gz as one blob instead of per-member scans",
    )
    scan.add_argument(
        "--progress",
        action="store_true",
        help="Print one result line per target as analysis completes",
    )
    scan.add_argument("--json", action="store_true", help="Emit machine-readable JSON summary")
    scan.add_argument("--sarif", action="store_true", help="Emit SARIF 2.1.0 JSON")
    scan.add_argument("--policy", type=Path, default=None, help="Custom security policy YAML")

    args = parser.parse_args(argv)

    if args.command == "analyze":
        analyzer = PickleAnalyzer(policy_path=args.policy)
        if args.member:
            reports = analyzer.analyze_target(args.path, member=args.member)
            from pickleprobe.formats.loader import FileFormat

            result = FileAnalysisResult(
                path=args.path, format=FileFormat.TAR_GZ_ARCHIVE, streams=reports
            )
        else:
            result = analyzer.analyze_file(args.path)
        exit_code = _exit_code_for_result(result)

        if args.sarif:
            print(json.dumps(file_results_to_sarif([result]), indent=2))
        elif args.json:
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
            print()
            print(_verdict_line(exit_code))
            print(_exit_code_note(exit_code))
        return exit_code

    if args.command == "scan":
        analyzer = PickleAnalyzer(policy_path=args.policy)
        max_bytes = None if args.max_member_mb <= 0 else args.max_member_mb * 1024 * 1024
        try:
            rows, file_results, exit_code = _run_streaming_scan(
                analyzer,
                args.path,
                recursive=args.recursive,
                archive_members=not args.no_archive_members,
                limit=args.limit,
                max_member_bytes=max_bytes,
                progress=args.progress,
            )
        except FileNotFoundError as exc:
            print(str(exc), file=sys.stderr)
            return 1

        if not rows:
            print(f"No targets under {args.path}", file=sys.stderr)
            return 1

        if args.sarif:
            print(json.dumps(file_results_to_sarif(file_results), indent=2))
        elif args.json:
            print(
                json.dumps(
                    {
                        "root": str(args.path),
                        "target_count": len(rows),
                        "exit_code": exit_code,
                        "targets": [
                            {
                                "target": r.target,
                                "sinks": r.sinks,
                                "suspicious": r.suspicious,
                                "risky_builds": r.risky_builds,
                                "bytes_analyzed": r.bytes_analyzed,
                                "exit_code": r.exit_code,
                                "error": r.error,
                            }
                            for r in rows
                        ],
                    },
                    indent=2,
                )
            )
        else:
            if not args.progress:
                print(f"Scanned {len(rows)} target(s) under {args.path}")
                print()
            _print_scan_summary(rows)
        return exit_code

    return 1


if __name__ == "__main__":
    sys.exit(main())
