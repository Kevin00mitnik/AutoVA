import json
import subprocess
import unittest

from autova.risk import make_finding, risk_summary
from autova.scope import Scope
from autova.tools import ToolResult, ToolRunner, findings_from_tool, tool_plans


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


if __name__ == "__main__":
    unittest.main()
