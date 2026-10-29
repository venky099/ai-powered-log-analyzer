"""Unit tests for src/report_generator.py."""

import csv
import io
from src.analyzer import LogAnalyzer
from src.detectors import Finding
from src.report_generator import (
    _sanitize_csv_cell,
    generate_csv_report,
    generate_text_report,
)


def test_sanitize_csv_cell_formula_injection():
    """Formula trigger characters (=, +, -, @) should be prepended with a single quote."""
    assert _sanitize_csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert _sanitize_csv_cell("+12345") == "'+12345"
    assert _sanitize_csv_cell("-secret") == "'-secret"
    assert _sanitize_csv_cell("@SUM(A1:A10)") == "'@SUM(A1:A10)"
    assert _sanitize_csv_cell("Normal text") == "Normal text"
    assert _sanitize_csv_cell("") == ""


def test_generate_csv_report_empty():
    """Empty findings list should generate CSV with headers only."""
    csv_text = generate_csv_report([])
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 1
    assert "Finding ID" in rows[0]
    assert "Severity" in rows[0]


def test_generate_csv_report_content():
    """Findings should be serialized properly in CSV."""
    f = Finding(
        finding_id="FINDING-0001",
        category="AUTHENTICATION",
        severity="HIGH",
        rule_name="Rule-Repeated-Failed-Logins",
        summary="Repeated failed logins from 192.168.1.10",
        evidence=["Line 1: FAILED LOGIN", "Line 2: FAILED LOGIN"],
        source_ip="192.168.1.10",
        timestamp="2026-10-29 09:00:00",
        recommended_step="Check edge firewall",
        confidence="SUSPICIOUS",
        limitations="Could be user error",
    )
    csv_text = generate_csv_report([f])
    reader = csv.reader(io.StringIO(csv_text))
    rows = list(reader)
    assert len(rows) == 2
    data_row = rows[1]
    assert data_row[0] == "FINDING-0001"
    assert data_row[1] == "AUTHENTICATION"
    assert data_row[2] == "HIGH"
    assert data_row[5] == "192.168.1.10"


def test_generate_text_report_elements():
    """Text report should include all required metadata sections."""
    sample = (
        "2026-10-29 09:00:00 ERROR Connection lost\n"
        "2026-10-29 09:01:00 WARNING High load\n"
    )
    analyzer = LogAnalyzer()
    res = analyzer.analyze_text(sample, filename="app_errors.log")

    report = generate_text_report(res, ai_summary="AI detected connection issues.")

    assert "AI-POWERED LOG ANALYZER - INVESTIGATION REPORT" in report
    assert "app_errors.log" in report
    assert "Total Lines" in report
    assert "AI detected connection issues." in report
    assert "LIMITATIONS AND DISCLAIMER" in report
    assert "DEFENSIVE TRIAGE & RECOMMENDED NEXT STEPS" in report


def test_generate_text_report_unicode():
    """Unicode characters should be rendered without crashing."""
    sample = "2026-10-29 09:00:00 ERROR 🚀 Rocket subsystem failed: \u26a0\ufe0f Unicode alert\n"
    analyzer = LogAnalyzer()
    res = analyzer.analyze_text(sample, filename="unicode_\u2728.log")

    report = generate_text_report(res)
    assert "Rocket subsystem failed" in report
