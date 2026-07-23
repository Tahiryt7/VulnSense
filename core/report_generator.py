from __future__ import annotations

from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from .risk_engine import BusinessContext, ScoredFinding


class ReportGenerator:
    def __init__(self, title: str = "VulnSense Context-Aware Assessment Report"):
        self.title = title
        self.styles = getSampleStyleSheet()
        self.styles.add(
            ParagraphStyle(
                name="ReportTitle",
                parent=self.styles["Title"],
                alignment=TA_CENTER,
                textColor=colors.HexColor("#0f1b2d"),
                fontSize=22,
                leading=26,
                spaceAfter=12,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="SectionHeading",
                parent=self.styles["Heading2"],
                textColor=colors.HexColor("#0f1b2d"),
                spaceAfter=10,
            )
        )
        self.styles.add(
            ParagraphStyle(
                name="BodySmall",
                parent=self.styles["BodyText"],
                fontSize=9,
                leading=12,
            )
        )

    def generate_pdf(
        self,
        output_path: str | Path,
        target_url: str,
        context: BusinessContext,
        scored_findings: Sequence[ScoredFinding],
    ) -> Path:
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)

        document = SimpleDocTemplate(
            str(output),
            pagesize=LETTER,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36,
            title=self.title,
        )

        story = []
        story.extend(self._build_cover(target_url, context))
        story.append(Spacer(1, 0.2 * inch))
        story.extend(self._build_summary(scored_findings))
        story.append(PageBreak())
        story.extend(self._build_detail_sections(scored_findings))
        story.append(Spacer(1, 0.25 * inch))
        story.append(
            Paragraph(
                "Disclaimer: This report is intended for authorized security assessment only. "
                "Use it only on systems you own or have explicit permission to test.",
                self.styles["BodySmall"],
            )
        )

        document.build(story)
        return output

    def _build_cover(self, target_url: str, context: BusinessContext) -> list:
        context_rows = [
            ["Target", target_url],
            ["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Customer Data", "Yes" if context.handles_customer_data else "No"],
            ["Internet Facing", "Yes" if context.internet_facing else "No"],
            ["Environment", context.environment.title()],
            ["Business Criticality", context.business_criticality.title()],
        ]
        table = Table(context_rows, colWidths=[1.7 * inch, 4.8 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.whitesmoke),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#0f1b2d")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#3fa9f5")),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("LEADING", (0, 0), (-1, -1), 12),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#dcecff")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f5f9ff")]),
                ]
            )
        )
        return [
            Paragraph(self.title, self.styles["ReportTitle"]),
            Paragraph(
                "Context-aware vulnerability assessment that re-scores technical findings using business exposure.",
                self.styles["BodyText"],
            ),
            Spacer(1, 0.2 * inch),
            table,
        ]

    def _build_summary(self, scored_findings: Sequence[ScoredFinding]) -> list:
        counts = Counter(item.risk_level for item in scored_findings)
        rows = [["Risk Level", "Count"]]
        for level in ("Critical", "High", "Medium", "Low"):
            rows.append([level, str(counts.get(level, 0))])
        table = Table(rows, colWidths=[3.2 * inch, 1.0 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f1b2d")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#3fa9f5")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f9ff")]),
                ]
            )
        )

        owasp_counts = Counter(item.finding.owasp_category for item in scored_findings)
        owasp_rows = [["OWASP Category", "Count"]]
        for category in sorted(owasp_counts.keys()):
            owasp_rows.append([category, str(owasp_counts[category])])
        owasp_table = Table(owasp_rows, colWidths=[4.8 * inch, 0.8 * inch])
        owasp_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f1b2d")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#3fa9f5")),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("BACKGROUND", (0, 1), (-1, -1), colors.whitesmoke),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f9ff")]),
                ]
            )
        )
        return [
            Paragraph("Executive Summary", self.styles["SectionHeading"]),
            table,
            Spacer(1, 0.15 * inch),
            Paragraph("OWASP Top 10 Mapping", self.styles["Heading3"]),
            owasp_table,
        ]

    def _build_detail_sections(self, scored_findings: Sequence[ScoredFinding]) -> list:
        story = [Paragraph("Finding Details", self.styles["SectionHeading"])]
        for item in scored_findings:
            story.append(Paragraph(item.finding.title, self.styles["Heading3"]))
            rows = [
                ["Risk Level", item.risk_level],
                ["Category", item.finding.category],
                ["OWASP Category", item.finding.owasp_category],
                ["Base Severity", str(item.finding.base_severity)],
                ["Contextual Score", f"{item.contextual_score}/10"],
                ["Description", item.finding.description],
                ["Justification", item.justification],
                ["Recommendation", item.finding.recommendation],
            ]
            table = Table(rows, colWidths=[1.5 * inch, 5.1 * inch], repeatRows=0)
            table.setStyle(self._detail_table_style(item.risk_level))
            story.append(table)
            story.append(Spacer(1, 0.15 * inch))
        return story

    def _detail_table_style(self, risk_level: str) -> TableStyle:
        fill_colors = {
            "Critical": colors.HexColor("#ffe1e1"),
            "High": colors.HexColor("#fff0d9"),
            "Medium": colors.HexColor("#fff9db"),
            "Low": colors.HexColor("#e6f5ea"),
        }
        accent = fill_colors.get(risk_level, colors.whitesmoke)
        return TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#dcecff")),
                ("BACKGROUND", (1, 0), (1, 4), accent),
                ("BACKGROUND", (1, 5), (1, -1), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#3fa9f5")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9.5),
                ("LEADING", (0, 0), (-1, -1), 12),
                ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#f7fbff")]),
            ]
        )
