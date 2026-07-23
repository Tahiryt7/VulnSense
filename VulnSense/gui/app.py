from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from tempfile import mkstemp
from typing import Dict, List, Optional

from flask import Flask, after_this_request, flash, redirect, render_template_string, request, send_file, url_for

from core.report_generator import ReportGenerator
from core.risk_engine import BusinessContext, RiskEngine, ScoredFinding
from core.scanner import Scanner

RISK_LEVELS = ("Critical", "High", "Medium", "Low")

PAGE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <title>VulnSense Web</title>
    <style>
        :root {
            --bg: #0f1b2d;
            --panel: #16233a;
            --line: #2a4366;
            --accent: #3fa9f5;
            --text: #e9f2ff;
            --muted: #9ab1cb;
            --critical: #ff6b6b;
            --high: #ffb347;
            --medium: #ffd166;
            --low: #7bd389;
        }
        * { box-sizing: border-box; }
        body {
            margin: 0;
            background: radial-gradient(1200px 600px at 80% -20%, #1d3658 0%, var(--bg) 60%);
            color: var(--text);
            font-family: "Segoe UI", Tahoma, sans-serif;
        }
        .layout {
            display: grid;
            grid-template-columns: 350px 1fr;
            gap: 16px;
            padding: 16px;
            min-height: 100vh;
        }
        .panel {
            background: var(--panel);
            border: 1px solid var(--line);
            border-radius: 12px;
            padding: 16px;
        }
        h1 { margin: 0 0 12px; font-size: 26px; }
        h2 { margin: 0 0 10px; font-size: 16px; color: var(--muted); }
        .field { margin-bottom: 12px; }
        label { display: block; margin-bottom: 6px; font-size: 13px; color: var(--muted); }
        input[type="text"], select {
            width: 100%;
            padding: 10px;
            border-radius: 8px;
            border: 1px solid var(--line);
            background: #0f1b2d;
            color: var(--text);
        }
        .checks label { display: flex; gap: 8px; align-items: center; color: var(--text); }
        .btn {
            width: 100%;
            padding: 10px;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            font-weight: 700;
            margin-top: 8px;
        }
        .btn-primary { background: var(--accent); color: #fff; }
        .btn-secondary { background: #2a4366; color: #fff; }
        .cards {
            display: grid;
            grid-template-columns: repeat(4, minmax(120px, 1fr));
            gap: 10px;
            margin-bottom: 12px;
        }
        .card { border-radius: 10px; padding: 12px; background: #13233b; border: 1px solid var(--line); }
        .card .label { font-size: 12px; color: var(--muted); }
        .card .count { font-size: 24px; margin-top: 5px; font-weight: 700; }
        .critical { color: var(--critical); }
        .high { color: var(--high); }
        .medium { color: var(--medium); }
        .low { color: var(--low); }
        table {
            width: 100%;
            border-collapse: collapse;
            background: #102038;
            border-radius: 10px;
            overflow: hidden;
            border: 1px solid var(--line);
        }
        th, td {
            padding: 10px;
            text-align: left;
            border-bottom: 1px solid var(--line);
            vertical-align: top;
            font-size: 13px;
        }
        th { background: #0f1b2d; color: #dbe9ff; }
        .mono { font-family: Consolas, "Courier New", monospace; }
        details {
            background: #102038;
            border: 1px solid var(--line);
            border-radius: 10px;
            margin-top: 10px;
            padding: 10px;
        }
        details summary { cursor: pointer; color: #dbe9ff; font-weight: 600; }
        .flash {
            background: #3a1f2f;
            border: 1px solid #7a3355;
            color: #ffd6e6;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 12px;
        }
        @media (max-width: 980px) {
            .layout { grid-template-columns: 1fr; }
            .cards { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
        }
    </style>
</head>
<body>
    <div class="layout">
        <section class="panel">
            <h1>VulnSense</h1>
            <h2>Context-Aware Web Assessment</h2>
            <form method="post" action="{{ url_for('scan') }}">
                <div class="field">
                    <label>Target URL</label>
                    <input type="text" name="target_url" value="{{ form.target_url }}" placeholder="https://example.com" required />
                </div>
                <button class="btn btn-primary" type="submit">Run Assessment</button>
            </form>
            <form method="get" action="{{ url_for('export_pdf') }}">
                <button class="btn btn-secondary" type="submit" {% if not findings %}disabled{% endif %}>Export PDF Report</button>
            </form>
            <p style="margin-top:12px;color:var(--muted);font-size:12px;">
                Use only on systems you own or are explicitly authorized to test.
            </p>
        </section>

        <section class="panel">
            {% with messages = get_flashed_messages() %}
                {% if messages %}
                    {% for msg in messages %}
                        <div class="flash">{{ msg }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}

            <div class="cards">
                <div class="card"><div class="label">Critical</div><div class="count critical">{{ counts.Critical }}</div></div>
                <div class="card"><div class="label">High</div><div class="count high">{{ counts.High }}</div></div>
                <div class="card"><div class="label">Medium</div><div class="count medium">{{ counts.Medium }}</div></div>
                <div class="card"><div class="label">Low</div><div class="count low">{{ counts.Low }}</div></div>
            </div>

            <table>
                <thead>
                    <tr>
                        <th>Risk</th>
                        <th>Finding</th>
                        <th>Category</th>
                        <th>OWASP</th>
                        <th>Score</th>
                    </tr>
                </thead>
                <tbody>
                {% for item in findings %}
                    <tr>
                        <td>{{ item.risk_level }}</td>
                        <td>{{ item.finding.title }}</td>
                        <td>{{ item.finding.category }}</td>
                        <td>{{ item.finding.owasp_category }}</td>
                        <td class="mono">{{ item.contextual_score }}/10</td>
                    </tr>
                    <tr>
                        <td colspan="5">
                            <details>
                                <summary>Details and Recommendation</summary>
                                <p><strong>Description:</strong> {{ item.finding.description }}</p>
                                <p><strong>Justification:</strong> {{ item.justification }}</p>
                                <p><strong>Recommendation:</strong> {{ item.finding.recommendation }}</p>
                            </details>
                        </td>
                    </tr>
                {% endfor %}
                {% if not findings %}
                    <tr><td colspan="5" style="color:var(--muted);">Run an assessment to populate findings.</td></tr>
                {% endif %}
                </tbody>
            </table>
        </section>
    </div>
</body>
</html>
"""


class VulnSenseWebApp:
    def __init__(self) -> None:
        self.flask_app = Flask(__name__)
        self.flask_app.secret_key = os.environ.get("VULNSENSE_SECRET_KEY", "vulnsense-dev-key")
        self.report_generator = ReportGenerator()
        self.last_target_url: str = ""
        self.last_context: Optional[BusinessContext] = None
        self.last_scored_findings: List[ScoredFinding] = []
        self._register_routes()

    def _register_routes(self) -> None:
        @self.flask_app.get("/")
        def index():
            return render_template_string(
                PAGE_TEMPLATE,
                form=self._default_form_values(),
                findings=self.last_scored_findings,
                counts=self._risk_counts(self.last_scored_findings),
            )

        @self.flask_app.post("/scan")
        def scan():
            form_data = self._extract_form_values(request.form)
            target_url = form_data["target_url"].strip()
            if not target_url:
                flash("Target URL is required.")
                return redirect(url_for("index"))

            context = self._default_context()

            try:
                findings = Scanner(target_url).run_full_scan()
                scored = RiskEngine(context).score(findings)
                self.last_target_url = target_url
                self.last_context = context
                self.last_scored_findings = scored
            except Exception as exc:
                flash(f"Assessment failed safely: {exc}")

            return render_template_string(
                PAGE_TEMPLATE,
                form=form_data,
                findings=self.last_scored_findings,
                counts=self._risk_counts(self.last_scored_findings),
            )

        @self.flask_app.get("/export")
        def export_pdf():
            if not self.last_scored_findings or self.last_context is None or not self.last_target_url:
                flash("Run an assessment before exporting a report.")
                return redirect(url_for("index"))

            fd, temp_path = mkstemp(prefix="vulnsense-report-", suffix=".pdf")
            os.close(fd)
            output_path = Path(temp_path)
            self.report_generator.generate_pdf(output_path, self.last_target_url, self.last_context, self.last_scored_findings)

            @after_this_request
            def cleanup_file(_response):
                try:
                    output_path.unlink(missing_ok=True)
                except Exception:
                    pass
                return _response

            timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            return send_file(
                output_path,
                as_attachment=True,
                download_name=f"vulnsense-report-{timestamp}.pdf",
                mimetype="application/pdf",
            )

    def run(self, host: str = "127.0.0.1", port: int = 5050, debug: bool = False) -> None:
        self.flask_app.run(host=host, port=port, debug=debug)

    def _default_form_values(self) -> Dict[str, object]:
        return {
            "target_url": self.last_target_url or "https://example.com",
        }

    def _extract_form_values(self, form_data) -> Dict[str, object]:
        return {
            "target_url": form_data.get("target_url", "").strip(),
        }

    def _default_context(self) -> BusinessContext:
        return BusinessContext(
            handles_customer_data=True,
            internet_facing=True,
            environment="production",
            business_criticality="medium",
        )

    def _risk_counts(self, scored_findings: List[ScoredFinding]) -> Dict[str, int]:
        counts = {level: 0 for level in RISK_LEVELS}
        for item in scored_findings:
            counts[item.risk_level] = counts.get(item.risk_level, 0) + 1
        return counts


def create_app() -> Flask:
    return VulnSenseWebApp().flask_app


def run_server() -> None:
    VulnSenseWebApp().run()
