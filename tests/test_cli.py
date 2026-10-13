import io
import unittest
from unittest.mock import patch

from autova.cli import main


class FakeEngine:
    def __init__(self, scope, output):
        self.scope = scope
        self.output = output

    def scan(self, target):
        return {"target": target, "risk": {"overall": "none", "finding_count": 0}}


class CliTests(unittest.TestCase):
    def test_target_only_requires_interactive_confirmation_when_noninteractive(self):
        stderr = io.StringIO()
        with patch("autova.cli.sys.stdin", io.StringIO("")), patch("autova.cli.sys.stderr", stderr):
            self.assertEqual(main(["--target", "example.com"]), 2)
        self.assertIn("Authorization confirmation required", stderr.getvalue())

    def test_yes_runs_target_without_scope_file(self):
        stdout = io.StringIO()
        with patch("autova.cli.AssessmentEngine", FakeEngine), patch("autova.cli.sys.stdout", stdout):
            result = main(["--target", "EXAMPLE.com.", "--yes"])
        self.assertEqual(result, 0)
        self.assertIn("Assessment complete for example.com", stdout.getvalue())
        self.assertIn("reports\\example.com\\scan.json", stdout.getvalue())

    def test_interactive_confirmation_declines_by_default(self):
        stdout = io.StringIO()
        stdin = io.StringIO("n\n")
        with patch("autova.cli.sys.stdin", stdin), patch("autova.cli.sys.stdout", stdout):
            stdin.isatty = lambda: True
            self.assertEqual(main(["--target", "example.com"]), 2)
        self.assertIn("Scan cancelled", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
