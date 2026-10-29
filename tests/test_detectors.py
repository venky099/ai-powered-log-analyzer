"""Unit tests for src/detectors.py."""

from src.detectors import DetectionEngine
from src.log_parser import parse_logs


def test_empty_entries_produce_no_findings():
    """Engine should handle empty entry lists gracefully without errors."""
    engine = DetectionEngine(failed_login_threshold=3)
    findings = engine.analyze([])
    assert findings == []


def test_informational_entries_no_findings():
    """Purely informational entries should not produce alerts."""
    content = (
        "2026-10-29 09:00:00 INFO Service started\n"
        "2026-10-29 09:00:10 INFO User alice successful login\n"
        "2026-10-29 09:00:20 INFO Job completed successfully\n"
    )
    entries = parse_logs(content)
    engine = DetectionEngine(failed_login_threshold=3)
    findings = engine.analyze(entries)
    assert len(findings) == 0


def test_critical_and_fatal_detection():
    """Critical and Fatal entries should trigger CRITICAL severity findings."""
    content = (
        "2026-10-29 09:00:00 CRITICAL Kernel panic in core-0\n"
        "2026-10-29 09:01:00 FATAL Out of memory killed process\n"
    )
    entries = parse_logs(content)
    engine = DetectionEngine(failed_login_threshold=3)
    findings = engine.analyze(entries)

    assert len(findings) == 2
    for f in findings:
        assert f.severity == "CRITICAL"
        assert f.category == "CRITICAL_FAILURE"
        assert "Rule-Critical-Fatal-Event" in f.rule_name


def test_error_and_warning_detection():
    """ERROR and WARNING events should trigger corresponding findings."""
    content = (
        "2026-10-29 09:00:00 ERROR Failed to write cache file\n"
        "2026-10-29 09:01:00 WARNING High disk usage on /data\n"
    )
    entries = parse_logs(content)
    engine = DetectionEngine(failed_login_threshold=3)
    findings = engine.analyze(entries)

    error_findings = [f for f in findings if f.category == "SYSTEM_ERROR"]
    warning_findings = [f for f in findings if f.category == "WARNING"]

    assert len(error_findings) == 1
    assert error_findings[0].severity == "HIGH"
    assert len(warning_findings) == 1
    assert warning_findings[0].severity == "LOW"


def test_repeated_failed_logins_same_ip():
    """Repeated failed logins from the same IP at or above threshold should trigger lead."""
    content = (
        "2026-10-29 09:00:01 FAILED LOGIN from 192.168.1.50 for user admin\n"
        "2026-10-29 09:00:05 FAILED LOGIN from 192.168.1.50 for user root\n"
        "2026-10-29 09:00:10 FAILED LOGIN from 192.168.1.50 for user test\n"
    )
    entries = parse_logs(content)
    engine = DetectionEngine(failed_login_threshold=3)
    findings = engine.analyze(entries)

    repeated = [f for f in findings if f.rule_name == "Rule-Repeated-Failed-Logins"]
    assert len(repeated) == 1
    assert repeated[0].source_ip == "192.168.1.50"
    assert repeated[0].severity == "HIGH"
    assert len(repeated[0].evidence) == 3
    # Check that limitation note is present
    assert "not definitive proof" in repeated[0].limitations.lower()


def test_events_from_different_ips():
    """Failures from different IPs should be counted separately."""
    content = (
        "2026-10-29 09:00:01 FAILED LOGIN from 192.168.1.50 for user admin\n"
        "2026-10-29 09:00:02 FAILED LOGIN from 192.168.1.50 for user admin\n"
        "2026-10-29 09:00:03 FAILED LOGIN from 10.0.0.1 for user bob\n"
    )
    entries = parse_logs(content)
    # Threshold is 3, so 192.168.1.50 (2 attempts) and 10.0.0.1 (1 attempt) should NOT trigger repeated rule
    engine = DetectionEngine(failed_login_threshold=3)
    findings = engine.analyze(entries)

    repeated = [f for f in findings if f.rule_name == "Rule-Repeated-Failed-Logins"]
    assert len(repeated) == 0

    isolated = [f for f in findings if f.rule_name == "Rule-Isolated-Auth-Failure"]
    # 2 isolated entries (or 1 per entry not grouped)
    assert len(isolated) == 3


def test_database_error_detection():
    """Database failures should be categorized under DATABASE."""
    content = "2026-10-29 09:00:01 ERROR PostgreSQL connection timeout during query\n"
    entries = parse_logs(content)
    engine = DetectionEngine()
    findings = engine.analyze(entries)

    db_findings = [f for f in findings if f.category == "DATABASE"]
    assert len(db_findings) == 1
    assert "Rule-Database-Connection-Error" in db_findings[0].rule_name
