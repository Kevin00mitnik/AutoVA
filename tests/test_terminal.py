import io
import unittest
from pathlib import Path

from autova.terminal import TerminalReporter


class TerminalReporterTests(unittest.TestCase):
    def test_groups_output_and_warns_before_tool_use(self):
        stream = io.StringIO()
        reporter = TerminalReporter(stream)
        reporter.start("example.com")
        reporter.reconnaissance(
            {"status": "ok", "addresses": ["192.0.2.10"]},
            {"status": "ok", "version": "TLSv1.3"},
        )
        reporter.tool_warning("OPEN PORTS", "example.com")
        reporter.tool_result(
            "OPEN PORTS",
            "ok",
            [{"result": "tcp/443 open", "details": "https"}],
        )
        reporter.analysis(2)
        reporter.risk("high", 8, 2, successful_checks=5, total_checks=6)
        reporter.reports(Path("reports") / "example.com")

        output = stream.getvalue()
        self.assertIn("Created by Mohammed Arif Pallath", output)
        self.assertIn("NOTICE: Checking open ports", output)
        self.assertIn("CHECKING OPEN PORTS", output)
        self.assertIn("OPEN PORTS", output)
        self.assertIn("tcp/443 open", output)
        self.assertIn("| RESULT", output)
        self.assertNotIn("| TOOL", output)
        self.assertNotIn("nmap", output.lower())
        self.assertNotIn("nuclei", output.lower())
        self.assertIn("ENUM", output)
        self.assertIn("ANALYSIS", output)
        self.assertIn("RISK    HIGH", output)
        self.assertIn("checks completed 5/6", output)
        self.assertIn("reports\\example.com\\report.html", output)
        self.assertNotIn("\033[", output)

    def test_color_can_be_forced(self):
        stream = io.StringIO()
        TerminalReporter(stream, color=True).start("example.com")
        self.assertIn("\033[", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
