"""Command-line interface."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from autova.engine import AssessmentEngine
from autova.reporting import target_directory_name
from autova.scope import ScopeError, load_scope, normalize_target


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run a conservative assessment against one explicitly authorized target."
    )
    parser.add_argument("--target", required=True, help="Exact hostname/IP; URL and wildcard forms are rejected.")
    parser.add_argument("--scope", required=True, help="Authorization JSON file (see scope.example.json).")
    parser.add_argument("--output", default="reports", help="Report output directory (default: reports).")
    args = parser.parse_args(argv)

    try:
        target = normalize_target(args.target)
        scope = load_scope(args.scope)
        if not scope.permits(target):
            raise ScopeError(f"Target {target!r} is not explicitly listed in {args.scope}.")
    except ScopeError as exc:
        print(f"Authorization/scope error: {exc}", file=sys.stderr)
        return 2
    try:
        report = AssessmentEngine(scope, Path(args.output)).scan(target)
    except (OSError, PermissionError) as exc:
        print(f"Assessment failed: {exc}", file=sys.stderr)
        return 1
    target_dir = Path(args.output) / target_directory_name(target)
    print(
        f"Assessment complete for {target}: risk={report['risk']['overall']} "
        f"findings={report['risk']['finding_count']}"
    )
    print(f"Reports: {target_dir / 'scan.json'}, {target_dir / 'vulnerabilities.json'}, {target_dir / 'report.html'}")
    return 0
