import json
import subprocess
import unittest

from autova.risk import make_finding, risk_summary
from autova.scope import Scope
from autova.tools import ToolResult, ToolRunner, findings_from_tool, tool_observations, tool_plans


class RiskToolsTests(unittest.TestCase):
    def test_severity_risk_summary(self):
        findings = [
            make_finding(title="High", severity="high", source="test", asset="example.com"),
            make_finding(title="Info", severity="info", source="test", asset="example.com"),
        ]
        summary = risk_summary(findings)
        self.assertEqual((summary["overall"], summary["score"], summary["finding_count"]), ("high", 8, 2))

    def test_missing_and_failed_tools_are_explicit(self):
        scope = Scope(frozenset({"example.com"}), 0.5, 100)
        self.assertEqual(ToolRunner(scope, which=lambda _: None).execute("nmap", []).status, "missing")

        def failed(*args, **kwargs):
            return subprocess.CompletedProcess(args[0], 2, "", "failed")

        result = ToolRunner(scope, which=lambda _: "nmap", run=failed).execute("nmap", [])
        self.assertEqual((result.status, result.returncode), ("error", 2))

    def test_runner_spaces_tool_processes_to_configured_rate(self):
        now = [0.0]
        delays = []

        def sleep(seconds):
            delays.append(seconds)
            now[0] += seconds

        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, "", "")

        runner = ToolRunner(
            Scope(frozenset({"example.com"}), 0.5, 100),
            which=lambda name: name,
            run=run,
            clock=lambda: now[0],
            sleep=sleep,
        )
        runner.execute("httpx", [])
        runner.execute("httpx", [])
        self.assertEqual(delays, [2.0])

    def test_plans_are_capped_and_discoveries_are_not_scanned(self):
        scope = Scope(frozenset({"example.com"}), 0.5, 100)
        args = dict(tool_plans("example.com", scope))["nmap"]
        self.assertIn("100", args)
        self.assertEqual(args[args.index("--max-rate") + 1], "1")
        findings = findings_from_tool(
            ToolResult("subfinder", "ok", [], stdout="example.com\nother.example.com\n"),
            "example.com",
        )
        self.assertEqual(len(findings), 1)
        self.assertIn("does not cover this host", findings[0]["detail"])

    def test_nuclei_only_accepts_exact_reported_host(self):
        lines = [
            {"template-id": "xss", "matched-at": "https://example.com/a", "info": {"name": "XSS", "severity": "high"}},
            {"template-id": "other", "matched-at": "https://elsewhere.test/", "info": {"severity": "critical"}},
        ]
        results = findings_from_tool(
            ToolResult("nuclei", "ok", [], stdout="\n".join(json.dumps(x) for x in lines)),
            "example.com",
        )
        self.assertEqual(len(results), 1)
        self.assertEqual((results[0]["severity"], results[0]["id"]), ("high", "nuclei:xss"))

    def test_each_tool_has_readable_result_observations(self):
        fixtures = [
            (
                "nmap",
                '<nmaprun><host><ports><port protocol="tcp" portid="443">'
                '<state state="open"/><service name="https" product="nginx" version="1.2"/>'
                '</port></ports></host></nmaprun>',
                "tcp/443 open",
            ),
            (
                "httpx",
                json.dumps({"url": "https://example.com", "status_code": 200, "title": "Example"}),
                "HTTP 200",
            ),
            (
                "whatweb",
                json.dumps({"target": "https://example.com", "http_status": 200, "plugins": {"nginx": {"version": "1.2"}}}),
                "nginx 1.2",
            ),
            ("subfinder", "example.com\napi.example.com\n", "api.example.com"),
            ("nikto", "+ Server: nginx/1.2\n", "nginx/1.2"),
            (
                "nuclei",
                json.dumps({"template-id": "exposure", "matched-at": "https://example.com/x", "info": {"name": "Exposure", "severity": "medium"}}),
                "MEDIUM finding",
            ),
        ]
        for tool_name, output, expected in fixtures:
            with self.subTest(tool=tool_name):
                rows = tool_observations(ToolResult(tool_name, "ok", [], stdout=output), "example.com")
                self.assertTrue(any(expected in (row["result"] + " " + row["details"]) for row in rows))

    def test_failed_tool_table_includes_diagnostic(self):
        rows = tool_observations(
            ToolResult("httpx", "error", [], returncode=2, stderr="unknown flag: -json"),
            "example.com",
        )
        self.assertEqual(rows[0]["result"], "ERROR")
        self.assertIn("unknown flag: -json", rows[0]["details"])


if __name__ == "__main__":
    unittest.main()
