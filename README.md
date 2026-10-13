# AutoVA

AutoVA is a small assessment pipeline that coordinates DNS and TLS reconnaissance with Nmap, Subfinder, httpx, WhatWeb, Nikto, and Nuclei; normalizes findings; assigns a severity-based risk summary; persists results in SQLite; and emits JSON and HTML reports.

## Authorized targets only

Every run requires an explicit JSON scope file containing `"authorized": true` and the **exact** target hostname or IP. URLs, wildcards, and CIDRs are rejected. Passive Subfinder discoveries are recorded as observations only; discovered hosts are never scanned. Obtain the asset owner's permission before enabling authorization.

Copy `scope.example.json` to `scope.json`, replace the target with one you are authorized to assess, and explicitly change `authorized` to `true`:

```json
{
  "authorized": true,
  "targets": ["example.com"],
  "rate_limit_rps": 0.5,
  "max_ports": 100
}
```

The configured rate paces starts of external tool processes; scanner-native rate flags are capped at 1 request per second (these tools accept integer rates), and port enumeration is capped at 1,000 ports. Every external process has a timeout. Missing tools, timeouts, and failures are explicit in the report, not reported as successful stages. External scanners use conservative options; no scan is run unless the target first passes the explicit scope check.

## Install and run

Python 3.10+ is recommended. Install the Python dependency and whichever external tools you intend to use (`nmap`, `subfinder`, ProjectDiscovery `httpx`, `whatweb`, `nikto`, `nuclei`):

```sh
python -m pip install -r requirements.txt
python3 scanner.py --target example.com --scope scope.json
```

Outputs:

* `reports/<target>/scan.json` — scope, pipeline, reconnaissance, tool statuses, findings, and risk
* `reports/<target>/vulnerabilities.json` — normalized findings
* `reports/<target>/report.html` — escaped HTML report
* `reports/assessments.sqlite3` — persisted scans, tool runs, and findings

Run core tests without performing network scans:

```sh
python -m unittest discover -s tests -v
```
