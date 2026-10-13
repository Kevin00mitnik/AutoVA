import json
import tempfile
import unittest
from pathlib import Path

from autova.scope import ScopeError, load_scope, normalize_target


class ScopeTests(unittest.TestCase):
    def test_requires_explicit_authorization_and_exact_host(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.json"
            path.write_text(json.dumps({"authorized": False, "targets": ["example.com"]}), encoding="utf-8")
            with self.assertRaises(ScopeError):
                load_scope(path)
            path.write_text(json.dumps({"authorized": True, "targets": ["example.com"]}), encoding="utf-8")
            scope = load_scope(path)
            self.assertTrue(scope.permits("EXAMPLE.com."))
            self.assertFalse(scope.permits("sub.example.com"))

    def test_rejects_url_wildcard_cidr_and_excessive_rate(self):
        for target in ("*.example.com", "https://example.com", "example.com/path", "192.0.2.0/24"):
            with self.subTest(target=target), self.assertRaises(ScopeError):
                normalize_target(target)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "scope.json"
            path.write_text(
                json.dumps({"authorized": True, "targets": ["example.com"], "rate_limit_rps": 10}),
                encoding="utf-8",
            )
            with self.assertRaises(ScopeError):
                load_scope(path)


if __name__ == "__main__":
    unittest.main()
