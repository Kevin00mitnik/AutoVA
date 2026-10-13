"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from autova.engine import AssessmentEngine
from autova.reporting import target_directory_name
from autova.scope import Scope, ScopeError, load_scope, normalize_target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run AutoVA against a target you are authorized to assess.")
    parser.add_argument("--target", required=True, help="Exact hostname/IP; URL and wildcard forms are rejected.")
    parser.add_argument("--scope", help="Optional JSON scope file for preset targets and limits.")
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm you are authorized to scan this target (required when stdin is non-interactive).",
    )
    parser.add_argument("--output", default="reports", help="Report output directory (default: reports).")
    args = parser.parse_args(argv)

    try:
        target = normalize_target(args.target)
    except ScopeError as exc:
        print(f"Target error: {exc}", file=sys.stderr)
        return 2

    if args.scope:
        try:
            scope = load_scope(args.scope)
            if not scope.permits(target):
                raise ScopeError(f"Target {target!r} is not explicitly listed in {args.scope}.")
        except ScopeError as exc:
            print(f"Authorization/scope error: {exc}", file=sys.stderr)
            return 2
    elif args.yes:
        scope = Scope(frozenset({target}))
    else:
        if not sys.stdin.isatty():
            print(
                "Authorization confirmation required. Rerun with --yes only if you have permission "
                "to assess this exact target.",
                file=sys.stderr,
            )
            return 2
        try:
            answer = input(
                f"Only scan {target} if you have the owner's permission. "
                "This runs active security tools. Continue? [y/N] "
            )
        except EOFError:
            print("Authorization confirmation was not provided; scan cancelled.", file=sys.stderr)
            return 2
        if answer.strip().lower() not in {"y", "yes"}:
            print("Scan cancelled; no target was scanned.")
            return 2
        scope = Scope(frozenset({target}))

    try:
        report = AssessmentEngine(scope, Path(args.output)).scan(target)
    except (OSError, PermissionError) as exc:
        print(f"Assessment failed: {exc}", file=sys.stderr)
        return 1
    target_dir = Path(args.output) / target_directory_name(target)
    complete = report["risk"].get("assessment_status", "complete") == "complete"
    label = "Assessment complete" if complete else "Assessment incomplete; available results saved"
    risk = report["risk"]["overall"].upper()
    print(
        f"{label} for {target}: risk={risk} "
        f"findings={report['risk']['finding_count']}"
    )
    print(f"Reports: {target_dir / 'scan.json'}, {target_dir / 'vulnerabilities.json'}, {target_dir / 'report.html'}")
    return 0
