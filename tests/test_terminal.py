import io
import unittest
from pathlib import Path

from autova.terminal import TerminalReporter


class TerminalReporterTests(unittest.TestCase):
    def test_groups_output_and_warns_before_tool_use(self):
        stream = io.StringIO()
        reporter = TerminalReporter(stream)
        reporter.start("example.com")
        reporter.tool_warning("nmap", "example.com")
        reporter.tool_result("nmap", "missing", 0, "not installed")
        reporter.analysis(2)
        reporter.risk("high", 8, 2)
        reporter.reports(Path("reports") / "example.com")

        output = stream.getvalue()
        self.assertIn("Author: Mohammed Arif Pallath", output)
        self.assertIn("WARNING [nmap]", output)
        self.assertIn("ENUM", output)
        self.assertIn("ANALYSIS", output)
        self.assertIn("RISK    HIGH", output)
        self.assertIn("reports\\example.com\\report.html", output)
        self.assertNotIn("\033[", output)

    def test_color_can_be_forced(self):
        stream = io.StringIO()
        TerminalReporter(stream, color=True).start("example.com")
        self.assertIn("\033[", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
