import json
import io
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from autova.engine import AssessmentEngine
from autova.scope import Scope
from autova.terminal import TerminalReporter
from autova.tools import ToolResult


class FakeRunner:
    def __init__(self):
        self.calls = []

    def execute(self, name, args):
        self.calls.append((name, args))
        return ToolResult(name, "missing", [name, *args], error=f"{name} unavailable")


class EngineTests(unittest.TestCase):
    def test_rejects_unauthorized_target_before_recon_or_tools(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner()
            engine = AssessmentEngine(Scope(frozenset({"example.com"})), directory, runner)
            with patch.object(engine, "_reconnaissance") as reconnaissance:
                with self.assertRaises(PermissionError):
                    engine.scan("outside.example")
            reconnaissance.assert_not_called()
            self.assertEqual(runner.calls, [])

    def test_pipeline_persists_db_and_generates_expected_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner()
            stream = io.StringIO()
            engine = AssessmentEngine(
                Scope(frozenset({"example.com"})),
                directory,
                runner,
                TerminalReporter(stream),
            )
            engine._reconnaissance = lambda target: {
                "dns": {"status": "ok", "addresses": ["192.0.2.10"]},
                "tls": {"status": "error", "error": "not tested"},
                "findings": [],
            }
            with patch("autova.engine.http_endpoint_fallback") as fallback:
                fallback.return_value = {
                    "result": "HTTP endpoint unavailable",
                    "details": "Test fallback; no network request was made.",
                }
                report = engine.scan("EXAMPLE.COM")
            target_dir = Path(directory) / "example.com"
            self.assertTrue((target_dir / "scan.json").is_file())
            self.assertTrue((target_dir / "vulnerabilities.json").is_file())
            self.assertTrue((target_dir / "report.html").is_file())
            saved = json.loads((target_dir / "scan.json").read_text(encoding="utf-8"))
            self.assertEqual(saved["pipeline"][0], "TARGET")
            self.assertEqual(len(saved["tools"]), 6)
            self.assertIn("results", saved["tools"][0])
            self.assertEqual(report["target"], "example.com")
            self.assertEqual(report["tool_name"], "AutoVA")
            self.assertEqual(report["author"], "Mohammed Arif Pallath")
            self.assertTrue(all(tool["status"] == "missing" for tool in report["tools"]))
            self.assertEqual(report["risk"]["overall"], "unknown")
            self.assertEqual(report["risk"]["assessment_status"], "incomplete")
            self.assertEqual(report["risk"]["checks_total"], 8)
            output = stream.getvalue()
            self.assertIn("NOTICE: Checking open ports", output)
            self.assertIn("OPEN PORTS", output)
            self.assertIn("ANALYSIS", output)
            self.assertIn("RISK    INCOMPLETE", output)
            self.assertIn("report.html", output)
            self.assertNotIn("nmap", output.lower())
            self.assertNotIn("subfinder", output.lower())
            self.assertNotIn("httpx", output.lower())
            self.assertNotIn("whatweb", output.lower())
            self.assertNotIn("nikto", output.lower())
            self.assertNotIn("nuclei", output.lower())
            db = sqlite3.connect(Path(directory) / "assessments.sqlite3")
            try:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM tool_runs").fetchone()[0], 6)
            finally:
                db.close()

    def test_http_probe_failure_uses_exact_host_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = FakeRunner()
            runner.execute = lambda name, args: ToolResult(
                name, "error" if name == "httpx" else "missing",
                [name, *args], returncode=2, stderr="incompatible CLI",
                error="Exited with status 2.",
            )
            stream = io.StringIO()
            with patch("autova.engine.http_endpoint_fallback") as fallback:
                fallback.return_value = {
                    "result": "HTTPS 200",
                    "details": "built-in exact-host fallback",
                }
                engine = AssessmentEngine(
                    Scope(frozenset({"example.com"})),
                    directory,
                    runner,
                    TerminalReporter(stream),
                )
                engine._reconnaissance = lambda target: {
                    "dns": {"status": "ok", "addresses": ["192.0.2.10"]},
                    "tls": {"status": "ok", "version": "TLSv1.3"},
                    "findings": [],
                }
                report = engine.scan("example.com")
            fallback.assert_called_once_with("example.com")
            http_result = next(tool for tool in report["tools"] if tool["name"] == "httpx")
            self.assertEqual(http_result["status"], "error")
            self.assertEqual(http_result["display_status"], "fallback")
            self.assertIn("HTTPS 200", stream.getvalue())
            self.assertNotIn("httpx", stream.getvalue().lower())


if __name__ == "__main__":
    unittest.main()
