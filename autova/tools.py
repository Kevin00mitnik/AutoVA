"""Rate-spaced, timeout-bounded wrappers for optional external tools."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
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
        tool_timeouts: dict[str, int] | None = None,
    ) -> None:
        self.scope, self.which, self.run = scope, which, run
        self.clock, self.sleep, self.timeout = clock, sleep, timeout
        self.tool_timeouts = tool_timeouts or {
            "nmap": 60,
            "subfinder": 30,
            "httpx": 20,
            "whatweb": 30,
            "nikto": 45,
            "nuclei": 60,
        }
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
                command,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.tool_timeouts.get(name, self.timeout),
            )
        except subprocess.TimeoutExpired as exc:
            timeout = self.tool_timeouts.get(name, self.timeout)
            return ToolResult(
                name, "timeout", command, stdout=_as_text(exc.stdout), stderr=_as_text(exc.stderr),
                error=f"Timed out after {timeout} seconds.",
            )
        except OSError as exc:
            return ToolResult(name, "error", command, error=f"Could not start {name}: {exc}")
        ok = completed.returncode == 0
        partial_error = _nmap_incomplete_reason(completed.stdout) if ok and name == "nmap" else None
        return ToolResult(
            name,
            "partial" if partial_error else "ok" if ok else "error",
            command,
            completed.returncode,
            completed.stdout,
            completed.stderr,
            partial_error or ("" if ok else f"Exited with status {completed.returncode}."),
        )


def _as_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def tool_plans(target: str, scope: Scope) -> list[tuple[str, list[str]]]:
    rate = max(1, int(scope.rate_limit_rps))
    https_target = f"https://{target}"
    return [
        (
            "nmap",
            [
                "-n", "-Pn", "-sT", "-T4", "--top-ports", str(scope.max_ports),
                "--max-retries", "1", "--initial-rtt-timeout", "1s",
                "--max-rtt-timeout", "5s", "--host-timeout", "45s",
                "--max-rate", str(rate), "-oX", "-", target,
            ],
        ),
        ("subfinder", ["-d", target, "-silent"]),
        (
            "httpx",
            [
                "-u", https_target, "-silent", "-json", "-status-code", "-title",
                "-tech-detect", "-web-server", "-rate", str(rate), "-timeout", "5", "-retries", "0",
            ],
        ),
        (
            "whatweb",
            [
                "--aggression=1", "--no-errors", "--log-json=-", "--wait=1",
                "--max-redirects=0", "--max-threads=5", https_target,
            ],
        ),
        (
            "nikto",
            ["-host", https_target, "-Pause", "1", "-timeout", "5", "-maxtime", "30s", "-nointeractive"],
        ),
        (
            "nuclei",
            [
                "-u", https_target, "-silent", "-jsonl", "-rl", str(rate),
                "-timeout", "5", "-retries", "0", "-disable-redirects",
                "-no-interactsh", "-duc", "-tags", "misconfig,exposure,cve",
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


def tool_observations(result: ToolResult, target: str) -> list[dict[str, str]]:
    """Extract readable, target-only observations for live output and JSON reports."""
    partial = result.status in {"partial", "timeout"} and bool(result.stdout.strip())
    if result.status != "ok" and not partial:
        if result.status == "missing":
            return [{
                "result": "Scanner unavailable",
                "details": "The optional scanner program for this result category is not installed.",
            }]
        detail = _hide_scanner_names(result.error or "The check did not complete successfully.")
        diagnostic = result.stderr.strip() or result.stdout.strip()
        if diagnostic:
            detail += f" | {_hide_scanner_names(diagnostic.splitlines()[0])}"
        return [{"result": result.status.upper(), "details": detail}]
    if partial:
        result = ToolResult(
            result.name,
            "ok",
            result.command,
            result.returncode,
            result.stdout,
            result.stderr,
            result.error,
        )
    if result.name == "nmap":
        rows = _nmap_observations(result.stdout)
        return _with_partial_note(rows, result) if partial else rows
    if result.name == "subfinder":
        hosts = sorted(set(line.strip() for line in result.stdout.splitlines() if line.strip()))
        hosts = [host for host in hosts if host.lower().rstrip(".") != target.lower().rstrip(".")]
        rows = [
            {"result": "Discovered host (not scanned)", "details": host}
            for host in hosts
        ] or [{"result": "No additional hostnames", "details": "No subdomains were reported."}]
        return _with_partial_note(rows, result) if partial else rows
    if result.name == "httpx":
        rows = _httpx_observations(result.stdout, target)
        return _with_partial_note(rows, result) if partial else rows
    if result.name == "whatweb":
        rows = _whatweb_observations(result.stdout, target)
        return _with_partial_note(rows, result) if partial else rows
    if result.name == "nikto":
        observations = []
        for line in result.stdout.splitlines():
            detail = line.strip().lstrip("+").strip()
            if not detail:
                continue
            label = "Directory or file path" if detail.startswith("/") else "Web server finding"
            observations.append({"result": label, "details": detail})
        rows = observations or [{"result": "No web issues reported", "details": "No web issues were reported."}]
        return _with_partial_note(rows, result) if partial else rows
    if result.name == "nuclei":
        observations = [
            {"result": f"{item['severity'].upper()} finding", "details": item["title"]}
            for item in findings_from_tool(result, target)
        ]
        rows = observations or [{"result": "No template matches", "details": "No vulnerability templates matched."}]
        return _with_partial_note(rows, result) if partial else rows
    return [{"result": "Tool output", "details": "No structured observations are available."}]


def result_category(name: str) -> str:
    return {
        "nmap": "OPEN PORTS",
        "subfinder": "SUBDOMAINS",
        "httpx": "WEB RESPONSE",
        "whatweb": "TECHNOLOGIES",
        "nikto": "WEB PATHS & FINDINGS",
        "nuclei": "VULNERABILITY FINDINGS",
    }.get(name, "ASSESSMENT RESULTS")


def _with_partial_note(rows: list[dict[str, str]], result: ToolResult) -> list[dict[str, str]]:
    rows = [row for row in rows if not row["result"].startswith("No ")]
    rows.append({
        "result": "Partial results",
        "details": _hide_scanner_names(
            result.error or "The time limit was reached; results may be incomplete."
        ),
    })
    return rows


def _nmap_incomplete_reason(output: str) -> str | None:
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return None
    finished = root.find(".//runstats/finished")
    if finished is not None and finished.get("exit") not in (None, "success"):
        return finished.get("errormsg") or "Port scan did not finish."
    return None


def _hide_scanner_names(text: str) -> str:
    import re

    replacements = {
        "nmap": "port scanner",
        "subfinder": "subdomain scanner",
        "httpx": "HTTP probe",
        "whatweb": "technology checker",
        "nikto": "web checker",
        "nuclei": "vulnerability checker",
    }
    for name, category in replacements.items():
        text = re.sub(rf"\b{re.escape(name)}\b", category, text, flags=re.IGNORECASE)
    return text


def http_endpoint_fallback(target: str, timeout: float = 8.0) -> dict[str, str]:
    """Make one exact-host HTTPS request when the optional HTTP probe CLI is incompatible."""
    opener = build_opener(HTTPRedirectHandlerNoRedirect)
    host = f"[{target}]" if ":" in target else target
    request = Request(
        f"https://{host}/",
        headers={"User-Agent": "AutoVA/0.1 (authorized assessment)"},
        method="GET",
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            return {
                "result": f"HTTPS {response.status}",
                "details": (
                    f"HTTP endpoint responded; server: {response.headers.get('Server', 'not disclosed')} "
                    "(built-in exact-host fallback)"
                ),
            }
    except HTTPError as exc:
        exc.close()
        return {
            "result": f"HTTPS {exc.code}",
            "details": "The host responded with an HTTP status (built-in exact-host fallback).",
        }
    except (OSError, URLError, TimeoutError) as exc:
        return {
            "result": "HTTP endpoint unavailable",
            "details": f"Built-in exact-host request could not complete: {exc}",
        }


class HTTPRedirectHandlerNoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _nmap_observations(output: str) -> list[dict[str, str]]:
    try:
        root = ET.fromstring(output)
    except ET.ParseError:
        return [{"result": "Could not read scan output", "details": "Nmap did not return valid XML."}]
    rows = []
    for port in root.findall(".//port"):
        state_node = port.find("state")
        state = state_node.get("state", "unknown") if state_node is not None else "unknown"
        if state != "open":
            continue
        service = port.find("service")
        service_details = []
        if service is not None:
            service_details.append(service.get("name", "unknown"))
            if service.get("product"):
                product = service.get("product", "")
                if service.get("version"):
                    product += f" {service.get('version')}"
                service_details.append(product)
        rows.append({
            "result": f"{port.get('protocol', 'tcp')}/{port.get('portid', '?')} open",
            "details": " · ".join(service_details) or "Service not identified",
        })
    if rows:
        return rows
    host_status = root.find(".//host/status")
    if host_status is not None and host_status.get("state") == "down":
        return [{"result": "Host unreachable", "details": "The target did not respond to the port check."}]
    counts = [
        f"{extra.get('count', '?')} {extra.get('state', 'unknown')}"
        for extra in root.findall(".//extraports")
    ]
    if counts:
        return [{"result": "No open ports identified", "details": f"Port responses: {', '.join(counts)}."}]
    finished = root.find(".//runstats/finished")
    if finished is not None and finished.get("exit") != "success":
        reason = finished.get("errormsg") or finished.get("exit") or "scan did not finish"
        return [{"result": "Port check incomplete", "details": reason}]
    return [{"result": "No port results", "details": "No open ports were reported in the available scan output."}]


def _httpx_observations(output: str, target: str) -> list[dict[str, str]]:
    rows = []
    for item in _json_records(output):
        host = str(item.get("host") or item.get("input") or item.get("url") or "")
        if host:
            parsed_host = urlsplit(host if "://" in host else f"//{host}").hostname
            if parsed_host and parsed_host.lower() != target.lower():
                continue
        url = str(item.get("url") or item.get("input") or target)
        status = item.get("status_code", item.get("status-code"))
        title = str(item.get("title", "")).strip()
        tech = item.get("tech") or []
        details = []
        if status is not None:
            details.append(f"HTTP {status}")
        if title:
            details.append(f"title: {title}")
        if item.get("webserver"):
            details.append(f"server: {item['webserver']}")
        if tech:
            details.append(f"technologies: {', '.join(map(str, tech))}")
        rows.append({"result": url, "details": " | ".join(details) or "HTTP service responded."})
    return rows or [{"result": "No HTTP response", "details": "No HTTP endpoint was reported."}]


def _whatweb_observations(output: str, target: str) -> list[dict[str, str]]:
    rows = []
    for item in _json_records(output):
        host = str(item.get("target") or item.get("url") or "")
        if host:
            parsed_host = urlsplit(host if "://" in host else f"//{host}").hostname
            if parsed_host and parsed_host.lower() != target.lower():
                continue
        if item.get("http_status"):
            rows.append({"result": "HTTP status", "details": str(item["http_status"])})
        plugins = item.get("plugins") or {}
        if isinstance(plugins, dict):
            for name, metadata in plugins.items():
                version = metadata.get("version") if isinstance(metadata, dict) else None
                rows.append({
                    "result": "Technology",
                    "details": f"{name} {version}".strip() if version else str(name),
                })
    return rows or [{"result": "No technologies detected", "details": "WhatWeb returned no plugin observations."}]


def _json_records(output: str) -> list[dict[str, Any]]:
    try:
        document = json.loads(output)
    except json.JSONDecodeError:
        document = None
    if isinstance(document, dict):
        return [document]
    if isinstance(document, list):
        return [record for record in document if isinstance(record, dict)]
    records = []
    for line in output.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(record, dict):
            records.append(record)
    return records


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
