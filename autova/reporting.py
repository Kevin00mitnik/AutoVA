"""JSON and HTML report generation."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, select_autoescape

from autova.tools import result_category


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>AutoVA: {{ report.target }}</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:70rem;margin:2rem auto;padding:0 1rem;color:#17202a}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccd1d1;padding:.5rem;text-align:left;vertical-align:top}
th{background:#f2f4f4}code{overflow-wrap:anywhere}.severity{text-transform:uppercase;font-weight:700}</style></head>
<body><h1>AutoVA assessment</h1><p><strong>Target:</strong> {{ report.target }} · <strong>Completed:</strong> {{ report.completed_at }}</p>
<p><strong>Assessment status:</strong> {{ report.risk.assessment_status|default('complete') }} · <strong>Overall risk:</strong> {{ report.risk.overall }} ({{ report.risk.score }}/10) · {{ report.risk.finding_count }} findings</p>
<h2>Findings</h2>{% if findings %}<table><thead><tr><th>Severity</th><th>Finding</th><th>Source</th><th>Evidence</th></tr></thead><tbody>
{% for finding in findings %}<tr><td class="severity">{{ finding.severity }}</td><td>{{ finding.title }}<br>{{ finding.detail }}</td><td>{{ source_category(finding.source) }}</td><td><code>{{ finding.evidence }}</code></td></tr>{% endfor %}
</tbody></table>{% else %}<p>No findings recorded.</p>{% endif %}
<h2>Assessment categories</h2><table><thead><tr><th>Category</th><th>Status</th><th>Details</th></tr></thead><tbody>
{% for tool in report.tools %}<tr><td>{{ result_category(tool.name) }}</td><td>{{ tool.display_status|default(tool.status) }}</td><td>
{% for item in tool.results %}<div><strong>{{ item.result }}</strong>: {{ item.details }}</div>{% endfor %}
</td></tr>{% endfor %}
</tbody></table><p>Authorized scope only. Discovered hosts were not scanned.</p></body></html>"""


def target_directory_name(target: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.-]", "_", target)


def write_reports(
    output_root: str | Path, target: str, report: dict[str, Any], findings: list[dict[str, Any]]
) -> Path:
    directory = Path(output_root) / target_directory_name(target)
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "scan.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (directory / "vulnerabilities.json").write_text(json.dumps(findings, indent=2) + "\n", encoding="utf-8")
    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    (directory / "report.html").write_text(
        env.from_string(TEMPLATE).render(
            report=report,
            findings=findings,
            result_category=result_category,
            source_category=lambda source: result_category(source) if source in {
                "nmap", "subfinder", "httpx", "whatweb", "nikto", "nuclei"
            } else source.upper(),
        ),
        encoding="utf-8",
    )
    return directory
