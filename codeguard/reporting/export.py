"""Export a scan as JSON or as a self-contained HTML report."""
from html import escape

from codeguard.schemas import ScanResult

SEVERITY_COLORS = {
    "Critical": "#7a0019", "High": "#c0392b", "Medium": "#d68910",
    "Low": "#2e86c1", "Informational": "#6c757d",
}


def to_json(result: ScanResult) -> str:
    return result.model_dump_json(indent=2)


def to_html(result: ScanResult) -> str:
    """Every value from the scan is HTML-escaped: findings can contain attacker-controlled text."""
    per_file = result.kind == "repository"  # a project report must say which file each finding is in
    rows = []
    for f in result.findings:
        color = SEVERITY_COLORS.get(f.severity.value, "#333")
        cwe = (f'<a href="{escape(f.cwe_link)}">CWE-{f.cwe}</a>' if f.cwe and f.cwe_link else "—")
        ml = f"{f.ml_score:.2f}" if f.ml_score is not None else "—"
        rows.append(
            "<tr>"
            f'<td><span class="sev" style="background:{color}">{escape(f.severity.value)}</span></td>'
            f"<td>{escape(f.rule_id)}<br><small>{escape(f.rule_name)}</small></td>"
            f"<td>{escape(f.category)}<br><small>{cwe}</small></td>"
            + (f"<td>{escape(f.file)}</td>" if per_file else "")
            + f"<td>{f.line}</td>"
            f"<td>{escape(f.evidence)}"
            + (f"<pre>{escape(f.code_snippet)}</pre>" if f.code_snippet else "")
            + (f"<p><b>Suggested action:</b> {escape(f.recommendation)}</p>" if f.recommendation else "")
            + "</td>"
            f"<td>{escape(f.source)}{'' if f.confirmed else '<br><small>unconfirmed</small>'}</td>"
            f"<td>{ml}</td>"
            "</tr>"
        )
    counts = " · ".join(f"{escape(k)}: {v}" for k, v in result.summary.by_severity.items())
    engines = " · ".join(f"{escape(k)}: {escape(v.status)}" for k, v in result.engines.items())
    file_th = "<th>File</th>" if per_file else ""
    body = "\n".join(rows) or f'<tr><td colspan="{8 if per_file else 7}">No findings.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CodeGuard AI report – {escape(result.filename)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 24px; color: #1d1d1f; background: #fff; }}
table {{ border-collapse: collapse; width: 100%; font-size: 14px; }}
th, td {{ border-bottom: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #f4f6f8; }}
pre {{ background: #f7f7f7; padding: 8px; overflow-x: auto; font-size: 12px; }}
.sev {{ color: #fff; padding: 2px 8px; border-radius: 10px; font-size: 12px; white-space: nowrap; }}
.note {{ color: #555; font-size: 13px; }}
</style></head><body>
<h1>CodeGuard AI security report</h1>
<p><b>File:</b> {escape(result.filename)} · <b>Scan ID:</b> {escape(result.scan_id)} ·
<b>Date:</b> {result.created_at:%Y-%m-%d %H:%M UTC} · <b>Lines:</b> {result.lines_of_code}</p>
<p><b>Findings:</b> {result.summary.total} ({counts})</p>
<p><b>Engines:</b> {engines}</p>
<table><thead><tr><th>Severity</th><th>Rule</th><th>Category</th>{file_th}<th>Line</th><th>Evidence</th>
<th>Source</th><th>ML score</th></tr></thead><tbody>
{body}
</tbody></table>
<p class="note">ML scores show how much a function resembles vulnerable training examples; they are not
the probability that the code is exploitable. A clean report does not prove the code is secure.</p>
</body></html>
"""
