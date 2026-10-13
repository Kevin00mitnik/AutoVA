"""Compact, optionally colored terminal output for assessment runs."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import TextIO


class TerminalReporter:
    def __init__(self, stream: TextIO | None = None, *, color: bool | None = None) -> None:
        self.stream = stream or sys.stdout
        if color is None:
            color = bool(getattr(self.stream, "isatty", lambda: False)()) and "NO_COLOR" not in os.environ
        self.color = color

    def _paint(self, text: str, code: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.color else text

    def start(self, target: str) -> None:
        print(self._paint("+--------------------------------------------------------------+", "36"), file=self.stream)
        print(self._paint("|  AutoVA  |  AUTHORIZED SECURITY ASSESSMENT                   |", "1;36"), file=self.stream)
        print(self._paint("|  Created by Mohammed Arif Pallath                            |", "36"), file=self.stream)
        print(self._paint("+--------------------------------------------------------------+", "36"), file=self.stream)
        print(f"TARGET  {target}", file=self.stream)
        print(self._paint("NOTICE  Active network checks run only for this authorized target.", "1;33"), file=self.stream)
        print(self._paint("RECON   DNS and TLS checks", "36"), file=self.stream)

    def reconnaissance(self, dns: dict, tls: dict) -> None:
        addresses = ", ".join(dns.get("addresses", [])) or dns.get("error", "no addresses")
        self._status_line("RECON", "DNS", dns.get("status", "unknown"), addresses)
        tls_detail = tls.get("version") or tls.get("error", "no TLS details")
        self._status_line("RECON", "TLS", tls.get("status", "unknown"), tls_detail)
        print(self._paint("ENUM    Results grouped by finding type", "36"), file=self.stream)

    def tool_warning(self, category: str, target: str) -> None:
        print(
            self._paint(
                f"NOTICE: Checking {category.lower()} on {target} may send network traffic.",
                "33",
            ),
            file=self.stream,
        )
        print(self._paint(f"CHECKING {category}...", "1;36"), file=self.stream)

    def tool_result(self, category: str, status: str, rows: list[dict[str, str]]) -> None:
        color = {"ok": "32", "fallback": "32", "partial": "33", "missing": "33", "timeout": "33", "error": "31"}.get(status, "36")
        status_text = {"fallback": "BACKUP CHECK", "partial": "PARTIAL"}.get(status, status.upper())
        print(
            self._paint(f"\n{category}  ·  {status_text}", f"1;{color}"),
            file=self.stream,
        )
        first_width, second_width = 29, 76
        border = f"+{'-' * (first_width + 2)}+{'-' * (second_width + 2)}+"
        print(border, file=self.stream)
        print(f"| {'RESULT':<{first_width}} | {'DETAILS':<{second_width}} |", file=self.stream)
        print(border, file=self.stream)
        visible_rows = rows[:20]
        for row in visible_rows:
            result = _fit(row.get("result", ""), first_width)
            details = _fit(row.get("details", ""), second_width)
            print(f"| {result:<{first_width}} | {details:<{second_width}} |", file=self.stream)
        if len(rows) > len(visible_rows):
            remaining = len(rows) - len(visible_rows)
            print(
                f"| {_fit('More results', first_width):<{first_width}} | "
                f"{_fit(f'{remaining} more row(s) are in scan.json', second_width):<{second_width}} |",
                file=self.stream,
            )
        print(border, file=self.stream)

    def analysis(self, finding_count: int) -> None:
        self._status_line("ANALYSIS", "Vulnerability review", "done", f"{finding_count} finding(s) normalized")

    def risk(
        self,
        level: str,
        score: int,
        finding_count: int,
        *,
        successful_checks: int | None = None,
        total_checks: int | None = None,
    ) -> None:
        color = "31" if level in ("critical", "high") else "33" if level in ("medium", "unknown") else "32"
        risk_label = "INCOMPLETE" if level == "unknown" else level.upper()
        coverage = ""
        if successful_checks is not None and total_checks is not None:
            coverage = f" | checks completed {successful_checks}/{total_checks}"
        print(
            self._paint(
                f"RISK    {risk_label} | score {score}/10 | {finding_count} finding(s){coverage}",
                f"1;{color}",
            ),
            file=self.stream,
        )

    def reports(self, target_dir: Path) -> None:
        print(self._paint("REPORT  Generated files", "32"), file=self.stream)
        for name in ("scan.json", "vulnerabilities.json", "report.html"):
            print(f"        {target_dir / name}", file=self.stream)

    def _status_line(self, category: str, name: str, status: str, detail: str) -> None:
        status_color = {
            "ok": "32",
            "done": "32",
            "missing": "33",
            "timeout": "33",
            "error": "31",
        }.get(status, "36")
        badge = self._paint(f"{status.upper():<8}", status_color)
        print(f"{category:<8} {name:<22} {badge} {detail}", file=self.stream)


def _fit(value: str, width: int) -> str:
    value = " ".join(str(value).split())
    if len(value) > width:
        return value[: width - 1] + "…"
    return value
