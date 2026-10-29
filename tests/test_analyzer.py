"""Unit tests for src/analyzer.py."""

from src.analyzer import LogAnalyzer


def test_analyzer_empty_string():
    """Analyzing empty text should yield zero metrics and empty findings."""
    analyzer = LogAnalyzer()
    result = analyzer.analyze_text("", filename="empty.log")

    assert result.metrics.total_lines == 0
    assert result.metrics.error_count == 0
    assert len(result.findings) == 0


def test_analyzer_metrics_calculation():
    """Metrics should accurately tally line counts and event types."""
    sample = (
        "2026-10-29 09:00:00 INFO Startup\n"
        "2026-10-29 09:01:00 WARNING High latency\n"
        "2026-10-29 09:02:00 ERROR Query failed\n"
        "2026-10-29 09:03:00 CRITICAL Core dumped\n"
        "2026-10-29 09:04:00 FAILED LOGIN from 192.168.1.1\n"
        "2026-10-29 09:04:05 FAILED LOGIN from 192.168.1.1\n"
    )
    analyzer = LogAnalyzer(failed_login_threshold=2)
    result = analyzer.analyze_text(sample)

    assert result.metrics.total_lines == 6
    assert result.metrics.critical_count == 1
    assert result.metrics.error_count == 1
    assert result.metrics.warning_count == 1
    assert result.metrics.failed_auth_count == 2
    assert result.metrics.repeated_login_count == 1
    assert result.metrics.unique_ip_count == 1


def test_analyzer_filtering_by_severity():
    """Filtering findings by severity should return matching subset."""
    sample = (
        "2026-10-29 09:00:00 CRITICAL Fatal issue\n"
        "2026-10-29 09:01:00 WARNING Non-critical issue\n"
    )
    analyzer = LogAnalyzer()
    result = analyzer.analyze_text(sample)

    crit_findings = result.filter_findings(severity_filter="CRITICAL")
    assert len(crit_findings) == 1
    assert crit_findings[0].severity == "CRITICAL"

    low_findings = result.filter_findings(severity_filter="LOW")
    assert len(low_findings) == 1
    assert low_findings[0].severity == "LOW"


def test_analyzer_filtering_by_category_and_query():
    """Category filter and keyword search should narrow results."""
    sample = (
        "2026-10-29 09:00:00 ERROR MySQL connection refused on 10.0.0.5\n"
        "2026-10-29 09:01:00 WARNING Redis key expiration spike\n"
    )
    analyzer = LogAnalyzer()
    result = analyzer.analyze_text(sample)

    # Filter by category
    db_findings = result.filter_findings(category_filter="DATABASE")
    assert len(db_findings) == 1
    assert db_findings[0].category == "DATABASE"

    # Search by keyword
    search_res = result.filter_findings(search_query="MySQL")
    assert len(search_res) == 1
    assert "MySQL" in search_res[0].summary or any("MySQL" in e for e in search_res[0].evidence)


def test_analyzer_analyze_bytes():
    """Safe byte ingestion should mirror text ingestion."""
    raw = b"2026-10-29 09:00:00 ERROR Fatal service crash\n"
    analyzer = LogAnalyzer()
    result = analyzer.analyze_bytes(raw, filename="test.log")

    assert result.filename == "test.log"
    assert result.metrics.total_lines == 1
    assert len(result.findings) >= 1
