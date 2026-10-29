"""Report generation module for AI-Powered Log Analyzer.

Produces sanitized CSV exports and human-readable text / markdown reports
summarizing detection findings, evidence, limitations, and recommendations.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from typing import List, Optional

from src.analyzer import AnalysisResult
from src.detectors import Finding


def _sanitize_csv_cell(value: str) -> str:
    """Sanitize cell against CSV / Formula Injection (=, +, -, @, tab, CR).

    Args:
        value: The string value to sanitize.

    Returns:
        Safe string with leading single-quote if formula characters present.
    """
    if not value:
        return ""
    str_val = str(value)
    # If the string starts with formula triggers, prepend a single quote
    if str_val and str_val[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + str_val
    return str_val


def generate_csv_report(findings: List[Finding]) -> str:
    """Generate RFC 4180 compliant CSV string of findings with formula escaping.

    Args:
        findings: List of Finding instances.

    Returns:
        CSV text formatted string.
    """
    output = io.StringIO()
    writer = csv.writer(output, quoting=csv.QUOTE_MINIMAL, lineterminator="\n")

    # Header
    headers = [
        "Finding ID",
        "Category",
        "Severity",
        "Rule Name",
        "Summary",
        "Source IP",
        "Timestamp",
        "Confidence",
        "Recommended Step",
        "Limitations",
        "Evidence Count",
        "Evidence",
    ]
    writer.writerow(headers)

    for f in findings:
        evidence_str = " | ".join(f.evidence)
        row = [
            _sanitize_csv_cell(f.finding_id),
            _sanitize_csv_cell(f.category),
            _sanitize_csv_cell(f.severity),
            _sanitize_csv_cell(f.rule_name),
            _sanitize_csv_cell(f.summary),
            _sanitize_csv_cell(f.source_ip or "N/A"),
            _sanitize_csv_cell(f.timestamp or "N/A"),
            _sanitize_csv_cell(f.confidence),
            _sanitize_csv_cell(f.recommended_step),
            _sanitize_csv_cell(f.limitations),
            str(len(f.evidence)),
            _sanitize_csv_cell(evidence_str),
        ]
        writer.writerow(row)

    return output.getvalue()


def generate_text_report(
    analysis_result: AnalysisResult,
    ai_summary: Optional[str] = None,
) -> str:
    """Generate a structured, human-readable text/markdown report.

    Args:
        analysis_result: Complete analysis output with metrics and findings.
        ai_summary: Optional AI or deterministic executive summary text.

    Returns:
        Formatted human-readable report string.
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    metrics = analysis_result.metrics
    # Treat filename strictly as display text, escaping markdown/brackets
    safe_filename = analysis_result.filename.replace("\n", " ").replace("\r", " ")

    lines = [
        "=" * 70,
        " AI-POWERED LOG ANALYZER - INVESTIGATION REPORT",
        "=" * 70,
        f"Generated At      : {now_utc}",
        f"Analyzed File     : {safe_filename}",
        f"Total Lines       : {metrics.total_lines:,}",
        f"Critical Events   : {metrics.critical_count}",
        f"Errors Detected   : {metrics.error_count}",
        f"Warnings Detected : {metrics.warning_count}",
        f"Failed Logins     : {metrics.failed_auth_count}",
        f"Repeated IPs Leads: {metrics.repeated_login_count}",
        f"Total Findings    : {len(analysis_result.findings)}",
        "-" * 70,
        "",
    ]

    if ai_summary:
        lines.extend([
            "EXECUTIVE SUMMARY & ANALYSIS",
            "-" * 40,
            ai_summary.strip(),
            "",
            "-" * 70,
            "",
        ])

    lines.extend([
        "DETAILED FINDINGS",
        "-" * 40,
    ])

    if not analysis_result.findings:
        lines.append("No suspicious patterns or anomalies detected in the provided log data.")
    else:
        for idx, f in enumerate(analysis_result.findings, start=1):
            lines.extend([
                f"[{idx}] Finding: {f.finding_id} | Severity: {f.severity} | Category: {f.category}",
                f"    Rule Name       : {f.rule_name}",
                f"    Summary         : {f.summary}",
                f"    Source IP       : {f.source_ip or 'N/A'}",
                f"    Timestamp(s)    : {f.timestamp or 'N/A'}",
                f"    Confidence      : {f.confidence}",
                f"    Investigation   : {f.recommended_step}",
                f"    Known Limit     : {f.limitations}",
                "    Evidence Lines  :",
            ])
            for ev in f.evidence[:5]:
                # Truncate evidence display safely
                lines.append(f"      * {ev[:200]}")
            if len(f.evidence) > 5:
                lines.append(f"      * ... and {len(f.evidence) - 5} more evidence entry(ies).")
            lines.append("")

    lines.extend([
        "-" * 70,
        "DEFENSIVE TRIAGE & RECOMMENDED NEXT STEPS",
        "-" * 40,
        "1. Prioritize investigating Critical failures and repeated authentication leads.",
        "2. Cross-reference source IP addresses against edge firewall and network telemetry.",
        "3. Confirm whether any repeated failed authentication was followed by a valid session.",
        "4. Review application error logs around identified timestamps for root-cause exceptions.",
        "",
        "-" * 70,
        "LIMITATIONS AND DISCLAIMER",
        "-" * 40,
        "NOTE: This report is generated by a heuristic log analyzer for educational and defensive",
        "triage purposes. It is NOT proof of an intrusion or malicious attack. Findings must be",
        "independently validated by security personnel in conjunction with complete system context.",
        "=" * 70,
    ])

    return "\n".join(lines)
