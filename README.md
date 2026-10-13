# AutoVA

**AutoVA** is a small assessment pipeline by **Mohammed Arif Pallath**. It coordinates DNS and TLS reconnaissance with Nmap, Subfinder, httpx, WhatWeb, Nikto, and Nuclei; normalizes findings; assigns a severity-based risk summary; persists results in SQLite; and emits JSON and HTML reports.

The CLI prints a compact, color-aware terminal summary grouped by reconnaissance, enumeration, analysis, risk, and reports. Before each scanner invocation it displays a warning identifying the tool and authorized target. Colors are automatically disabled for non-interactive output and when `NO_COLOR` is set.

## Authorized targets only

Only scan systems you own or have explicit permission to assess. The normal command asks you to confirm authorization before starting active tools:

```sh
python AutoVA.py --target example.com
```

Answer `y` only if you are authorized to scan that exact host. To run non-interactively, pass `--yes` to confirm authorization. The target must be one hostname or IP; URLs, wildcards, and CIDRs are rejected. Passive Subfinder discoveries are recorded as observations only; discovered hosts are never scanned.

For repeatable runs or custom conservative limits, use an optional scope file. It is not created automatically: copy `scope.example.json` to `scope.json`, replace the example target, and set `"authorized": true`, then run:

```sh
python AutoVA.py --target example.com --scope scope.json
```

The configured rate paces starts of external tool processes; scanner-native rate flags are capped at 1 request per second (these tools accept integer rates), and port enumeration is capped at 1,000 ports. Every external process has a timeout. Missing tools, timeouts, and failures are explicit in the report, not reported as successful stages. External scanners use conservative options; no scan runs until you confirm authorization interactively or pass `--yes`.

## Install and run

Python 3.10+ is recommended. On Kali or another externally-managed Linux Python installation, do not install packages into the system Python with `pip`. Create and activate a virtual environment first:

```sh
sudo apt update
sudo apt install -y python3-venv
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python AutoVA.py --target example.com
```

The last command prompts you to confirm permission to assess the target. No scope file is needed for this normal, interactive workflow. If virtual-environment creation reports that `venv` or `ensurepip` is unavailable, install Kali's `python3-full` package and retry. Do not use `--break-system-packages`; `python3-xyz` in the Kali error message is a placeholder, not a package to install.

On Windows, create/activate the environment with `py -m venv .venv` and `.venv\Scripts\Activate.ps1`, then run the same `python -m pip install -r requirements.txt` and `python AutoVA.py --target example.com` commands.

Install the external scanner programs separately if you want to use them (`nmap`, `subfinder`, ProjectDiscovery `httpx`, `whatweb`, `nikto`, `nuclei`). AutoVA reports tools it cannot find and still writes a report for the stages it could run.

Outputs:

* `reports/<target>/scan.json` — scope, pipeline, reconnaissance, tool statuses, findings, and risk
* `reports/<target>/vulnerabilities.json` — normalized findings
* `reports/<target>/report.html` — escaped HTML report
* `reports/assessments.sqlite3` — persisted scans, tool runs, and findings

Run core tests without performing network scans:

```sh
python -m unittest discover -s tests -v
```
