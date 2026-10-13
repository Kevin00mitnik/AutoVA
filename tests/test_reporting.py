import json
import tempfile
import unittest

from autova.reporting import write_reports
from autova.risk import risk_summary


class ReportingTests(unittest.TestCase):
    def test_writes_json_reports_and_escaped_html(self):
        with tempfile.TemporaryDirectory() as directory:
            finding = {
                "id": "x", "title": "<script>alert(1)</script>", "severity": "high",
                "score": 8, "source": "test", "asset": "example.com", "detail": "", "evidence": "",
            }
            report = {
                "target": "example.com", "completed_at": "now",
                "risk": risk_summary([finding]), "tools": [],
            }
            output = write_reports(directory, "example.com", report, [finding])
            self.assertEqual(json.loads((output / "scan.json").read_text(encoding="utf-8"))["target"], "example.com")
            self.assertEqual(json.loads((output / "vulnerabilities.json").read_text(encoding="utf-8")), [finding])
            html = (output / "report.html").read_text(encoding="utf-8")
            self.assertNotIn("<script>alert(1)</script>", html)
            self.assertIn("&lt;script&gt;", html)


if __name__ == "__main__":
    unittest.main()
