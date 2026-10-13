"""Assessment pipeline orchestration and SQLite persistence."""

from __future__ import annotations

import json
import socket
import sqlite3
import ssl
import uuid
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from autova.reporting import write_reports
from autova.risk import make_finding, risk_summary
from autova.scope import Scope, normalize_target
from autova.terminal import TerminalReporter
from autova.tools import (
    ToolResult,
    ToolRunner,
    findings_from_tool,
    http_endpoint_fallback,
    result_category,
    tool_observations,
    tool_plans,
)


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY, target TEXT NOT NULL, started_at TEXT NOT NULL,
  completed_at TEXT NOT NULL, risk_summary_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS tool_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL REFERENCES scans(scan_id),
  name TEXT NOT NULL, status TEXT NOT NULL, command_json TEXT NOT NULL, returncode INTEGER,
  stdout TEXT NOT NULL, stderr TEXT NOT NULL, error TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL REFERENCES scans(scan_id),
  finding_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL, score INTEGER NOT NULL,
  source TEXT NOT NULL, asset TEXT NOT NULL, detail TEXT NOT NULL, evidence TEXT NOT NULL
);
"""


class AssessmentEngine:
    def __init__(
        self,
        scope: Scope,
        output_root: str | Path = "reports",
        runner: ToolRunner | None = None,
        console: TerminalReporter | None = None,
    ):
        self.scope = scope
        self.output_root = Path(output_root)
        self.runner = runner or ToolRunner(scope)
        self.console = console or TerminalReporter()

    def scan(self, target: str) -> dict[str, Any]:
        target = normalize_target(target)
        if not self.scope.permits(target):
            raise PermissionError(f"Target {target!r} is not explicitly listed in the authorized scope.")

        self.console.start(target)
        scan_id = uuid.uuid4().hex
        started_at = datetime.now(timezone.utc).isoformat()
        reconnaissance = self._reconnaissance(target)
        self.console.reconnaissance(reconnaissance["dns"], reconnaissance["tls"])
        findings = list(reconnaissance["findings"])
        tool_results = []
        tool_result_rows: dict[str, list[dict[str, str]]] = {}
        tool_display_status: dict[str, str] = {}
        for name, args in tool_plans(target, self.scope):
            category = result_category(name)
            self.console.tool_warning(category, target)
            result = self.runner.execute(name, args)
            tool_results.append(result)
            observations = tool_observations(result, target)
            display_status = "partial" if result.status == "timeout" and result.stdout.strip() else result.status
            if name == "httpx" and result.status != "ok":
                fallback = http_endpoint_fallback(target)
                observations.append(fallback)
                if fallback["result"].startswith("HTTPS "):
                    display_status = "fallback"
            tool_result_rows[name] = observations
            tool_display_status[name] = display_status
            tool_findings = findings_from_tool(result, target)
            findings.extend(tool_findings)
            self.console.tool_result(category, display_status, observations)
        summary = risk_summary(findings)
        recon_checks = [reconnaissance["dns"], reconnaissance["tls"]]
        successful_checks = (
            sum(item.status == "ok" for item in tool_results)
            + sum(item.get("status") == "ok" for item in recon_checks)
        )
        total_checks = len(tool_results) + len(recon_checks)
        incomplete_checks = total_checks - successful_checks
        summary["assessment_status"] = "complete" if incomplete_checks == 0 else "incomplete"
        summary["checks_completed"] = successful_checks
        summary["checks_total"] = total_checks
        if incomplete_checks and summary["overall"] == "none":
            summary["overall"] = "unknown"
        self.console.analysis(len(findings))
        self.console.risk(
            summary["overall"],
            summary["score"],
            summary["finding_count"],
            successful_checks=successful_checks,
            total_checks=total_checks,
        )
        completed_at = datetime.now(timezone.utc).isoformat()
        report: dict[str, Any] = {
            "tool_name": "AutoVA",
            "author": "Mohammed Arif Pallath",
            "scan_id": scan_id,
            "target": target,
            "started_at": started_at,
            "completed_at": completed_at,
            "scope": {
                "authorized": True,
                "rate_limit_rps": self.scope.rate_limit_rps,
                "max_ports": self.scope.max_ports,
                "matching_rule": "exact target only; discovered hosts are not scanned",
            },
            "pipeline": [
                "TARGET", "Reconnaissance", "Enumeration", "Vulnerability Analysis", "Risk Engine", "Report"
            ],
            "reconnaissance": {key: value for key, value in reconnaissance.items() if key != "findings"},
            "tools": [
                {
                    "name": item.name, "status": item.status, "command": item.command,
                    "returncode": item.returncode, "error": item.error,
                    "results": tool_result_rows[item.name],
                    "display_status": tool_display_status[item.name],
                }
                for item in tool_results
            ],
            "risk": summary,
            "findings": findings,
        }
        self._persist(scan_id, target, started_at, completed_at, summary, tool_results, findings)
        report_dir = write_reports(self.output_root, target, report, findings)
        self.console.reports(report_dir)
        return report

    def _reconnaissance(self, target: str) -> dict[str, Any]:
        findings = []
        try:
            addresses = sorted({
                item[4][0] for item in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
            })
            dns: dict[str, Any] = {"status": "ok", "addresses": addresses}
        except socket.gaierror as exc:
            addresses = []
            dns = {"status": "error", "addresses": [], "error": str(exc)}
        if not addresses:
            findings.append(make_finding(
                title="DNS resolution failed", severity="info", source="dns", asset=target,
                detail=dns.get("error", "No addresses were returned."),
            ))
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname=target) as tls_socket:
                    cert = tls_socket.getpeercert()
                    cipher = tls_socket.cipher()
                    tls = {
                        "status": "ok", "version": tls_socket.version(),
                        "cipher": cipher[0] if cipher else None,
                        "certificate_subject": cert.get("subject", []),
                        "certificate_not_after": cert.get("notAfter"),
                    }
        except (OSError, ssl.SSLError) as exc:
            tls = {"status": "error", "error": str(exc)}
            findings.append(make_finding(
                title="TLS handshake unavailable", severity="info", source="tls",
                asset=target, detail=str(exc),
            ))
        return {"dns": dns, "tls": tls, "findings": findings}

    def _persist(
        self, scan_id: str, target: str, started_at: str, completed_at: str,
        summary: dict[str, Any], results: list[ToolResult], findings: list[dict[str, Any]],
    ) -> None:
        self.output_root.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.output_root / "assessments.sqlite3")) as db:
            with db:
                db.executescript(SCHEMA)
                db.execute(
                    "INSERT INTO scans VALUES (?, ?, ?, ?, ?)",
                    (scan_id, target, started_at, completed_at, json.dumps(summary)),
                )
                db.executemany(
                    """INSERT INTO tool_runs
                    (scan_id,name,status,command_json,returncode,stdout,stderr,error)
                    VALUES (?,?,?,?,?,?,?,?)""",
                    [
                        (scan_id, r.name, r.status, json.dumps(r.command), r.returncode, r.stdout, r.stderr, r.error)
                        for r in results
                    ],
                )
                db.executemany(
                    """INSERT INTO findings
                    (scan_id,finding_id,title,severity,score,source,asset,detail,evidence)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
                    [
                        (
                            scan_id, f["id"], f["title"], f["severity"], f["score"],
                            f["source"], f["asset"], f["detail"], f["evidence"],
                        )
                        for f in findings
                    ],
                )
