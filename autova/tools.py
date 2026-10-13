"""Rate-spaced, timeout-bounded wrappers for optional external tools."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Callable
from urllib.parse import urlsplit

from autova.risk import make_finding
from autova.scope import Scope


@dataclass
class ToolResult:
    name: str
    status: str
    command: list[str]
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""


class ToolRunner:
    def __init__(
        self,
        scope: Scope,
        *,
        which: Callable[[str], str | None] = shutil.which,
        run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
        timeout: int = 120,
    ) -> None:
        self.scope, self.which, self.run = scope, which, run
        self.clock, self.sleep, self.timeout = clock, sleep, timeout
        self._last_run: float | None = None

    def execute(self, name: str, args: list[str]) -> ToolResult:
        executable = self.which(name)
        command = [executable or name, *args]
        if executable is None:
            return ToolResult(name, "missing", command, error=f"{name} is not installed or not on PATH.")

        interval = 1.0 / self.scope.rate_limit_rps
        now = self.clock()
        if self._last_run is not None and interval > now - self._last_run:
            self.sleep(interval - (now - self._last_run))
        self._last_run = self.clock()
        try:
            completed = self.run(
                command, capture_output=True, text=True, check=False, timeout=self.timeout
            )
        except subprocess.TimeoutExpired as exc:
            return ToolResult(
                name, "timeout", command, stdout=_as_text(exc.stdout), stderr=_as_text(exc.stderr),
                error=f"Timed out after {self.timeout} seconds.",
            )
        except OSError as exc:
            return ToolResult(name, "error", command, error=f"Could not start {name}: {exc}")
        ok = completed.returncode == 0
        return ToolResult(
            name, "ok" if ok else "error", command, completed.returncode,
            completed.stdout, completed.stderr, "" if ok else f"Exited with status {completed.returncode}.",
        )


def _as_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def tool_plans(target: str, scope: Scope) -> list[tuple[str, list[str]]]:
    rate = max(1, int(scope.rate_limit_rps))
    return [
        ("nmap", ["-Pn", "-sT", "-sV", "--top-ports", str(scope.max_ports), "--max-rate", str(rate), "-oX", "-", target]),
        ("subfinder", ["-d", target, "-silent"]),
        ("httpx", ["-u", f"http://{target}", "-silent", "-json", "-rate", str(rate), "-timeout", "5", "-retries", "0"]),
        (
            "whatweb",
            ["--aggression=1", "--no-errors", "--log-json=-", "--wait=1", "--max-redirects=0", f"http://{target}"],
        ),
        ("nikto", ["-host", f"http://{target}", "-Pause", "1", "-maxtime", "120s"]),
        (
            "nuclei",
            [
                "-u", f"http://{target}", "-silent", "-jsonl", "-rl", str(rate),
                "-timeout", "5", "-retries", "0", "-disable-redirects", "-no-interactsh",
            ],
        ),
    ]


def findings_from_tool(result: ToolResult, target: str) -> list[dict[str, Any]]:
    if result.name == "nmap" and result.stdout:
        return _nmap_findings(result.stdout, target)
    if result.name == "nuclei" and result.stdout:
        return _nuclei_findings(result.stdout, target)
    if result.name == "subfinder" and result.stdout:
        return [
            make_finding(
                title="Discovered hostname (not scanned)", severity="info", source="subfinder",
                asset=target,
                detail="Discovery is recorded for awareness; exact-target authorization does not cover this host.",
                evidence=host,
            )
            for host in sorted(set(line.strip() for line in result.stdout.splitlines()))
            if host and host.lower().rstrip(".") != target.lower().rstrip(".")
        ]
    return []


def _nmap_findings(output: str, target: str) -> list[dict[str, Any]]:
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return []
    findings = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        service = port.find("service")
        port_id = f"{port.get('protocol', 'tcp')}/{port.get('portid', 'unknown')}"
        findings.append(
            make_finding(
                title=f"Open port {port_id}", severity="info", source="nmap", asset=target,
                detail=f"Service identified as {service.get('name', 'unknown') if service is not None else 'unknown'}.",
                evidence=port_id, identifier=f"nmap:{port_id}",
            )
        )
    return findings


def _nuclei_findings(output: str, target: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line in output.splitlines():
        try:
            item: dict[str, Any] = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        matched = str(item.get("matched-at", ""))
        if matched and (urlsplit(matched).hostname or "").lower() != target.lower():
            continue
        template = str(item.get("template-id", "nuclei-finding"))
        findings.append(
            make_finding(
                title=str(info.get("name") or template),
                severity=str(info.get("severity", "unknown")),
                source="nuclei", asset=target, detail=str(info.get("description", "")),
                evidence=matched, identifier=f"nuclei:{template}",
            )
        )
    return findings
