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
            output = stream.getvalue()
            self.assertIn("WARNING: nmap", output)
            self.assertIn("NMAP RESULTS", output)
            self.assertIn("ANALYSIS", output)
            self.assertIn("RISK", output)
            self.assertIn("report.html", output)
            db = sqlite3.connect(Path(directory) / "assessments.sqlite3")
            try:
                self.assertEqual(db.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)
                self.assertEqual(db.execute("SELECT COUNT(*) FROM tool_runs").fetchone()[0], 6)
            finally:
                db.close()


if __name__ == "__main__":
    unittest.main()
