"""Unit tests for src/log_parser.py."""

from src.log_parser import (
    classify_event_pattern,
    extract_severity,
    extract_timestamp,
    extract_valid_ipv4,
    parse_log_line,
    parse_logs,
    safe_read_bytes,
)


def test_safe_read_bytes_empty():
    """Empty bytes should produce an empty string."""
    assert safe_read_bytes(b"") == ""


def test_safe_read_bytes_crlf_normalization():
    """CRLF and CR endings should normalize to LF."""
    raw = b"line1\r\nline2\rline3\n"
    normalized = safe_read_bytes(raw)
    assert normalized == "line1\nline2\nline3\n"


def test_safe_read_bytes_utf8_bom():
    """UTF-8 BOM should be stripped cleanly."""
    raw = b"\xef\xbb\xbf2026-10-29 INFO Log with BOM"
    result = safe_read_bytes(raw)
    assert result == "2026-10-29 INFO Log with BOM"
    assert not result.startswith("\ufeff")


def test_safe_read_bytes_non_utf8_recovery():
    """Non-UTF8 bytes should not raise an exception."""
    raw = b"Error \xff\xfe in process"
    result = safe_read_bytes(raw)
    assert "Error" in result


def test_extract_valid_ipv4_success():
    """Valid IPv4 addresses should be extracted correctly."""
    assert extract_valid_ipv4("Failed login from 192.168.1.100") == "192.168.1.100"
    assert extract_valid_ipv4("Host 10.0.0.1 disconnected") == "10.0.0.1"


def test_extract_valid_ipv4_invalid_octets():
    """Invalid IP octets should be rejected."""
    assert extract_valid_ipv4("Connection attempt from 999.999.999.999") is None
    assert extract_valid_ipv4("Port 256.100.1.1 invalid") is None


def test_extract_valid_ipv4_version_string_rejection():
    """Version strings like v1.2.3.4 should not be extracted as valid IPs."""
    assert extract_valid_ipv4("Running software release v1.2.3.4 on server") is None
    assert extract_valid_ipv4("Module lib-1.2.3.4.so loaded") is None


def test_extract_timestamp_iso():
    """ISO 8601 formatted timestamps should be extracted."""
    line = "2026-10-29 09:10:01 INFO Service started"
    ts, remaining = extract_timestamp(line)
    assert ts == "2026-10-29 09:10:01"
    assert remaining == "INFO Service started"


def test_extract_timestamp_bracketed():
    """Bracketed timestamps should be extracted."""
    line = "[2026-10-29 09:10:01] ERROR Disk failure"
    ts, remaining = extract_timestamp(line)
    assert ts == "2026-10-29 09:10:01"
    assert remaining == "ERROR Disk failure"


def test_extract_timestamp_missing_or_malformed():
    """Malformed or missing timestamps should return None and preserve line."""
    line = "Random unformatted error without timestamp"
    ts, remaining = extract_timestamp(line)
    assert ts is None
    assert remaining == line


def test_extract_severity_normalization():
    """Recognized severities should normalize correctly."""
    assert extract_severity("FATAL: System crash")[0] == "FATAL"
    assert extract_severity("CRIT Server offline")[0] == "CRITICAL"
    assert extract_severity("CRITICAL System halt")[0] == "CRITICAL"
    assert extract_severity("ERROR Database disconnected")[0] == "ERROR"
    assert extract_severity("ERR Socket closed")[0] == "ERROR"
    assert extract_severity("WARN Response slow")[0] == "WARNING"
    assert extract_severity("WARNING Disk 90% full")[0] == "WARNING"
    assert extract_severity("INFO User login")[0] == "INFO"
    assert extract_severity("DEBUG Packet sent")[0] == "DEBUG"


def test_classify_event_pattern():
    """Authentication and database patterns should be classified."""
    assert classify_event_pattern("FAILED LOGIN for admin from 10.0.0.1") == "FAILED_LOGIN"
    assert classify_event_pattern("Authentication failed for user bob") == "FAILED_LOGIN"
    assert classify_event_pattern("User alice successful login") == "SUCCESS_LOGIN"
    assert classify_event_pattern("PostgreSQL connection refused by backend") == "DATABASE_ERROR"
    assert classify_event_pattern("Normal system heartbeat") is None


def test_parse_log_line_empty():
    """Empty lines should be parsed without errors."""
    entry = parse_log_line(1, "   ")
    assert entry.line_number == 1
    assert entry.event_type == "EMPTY"


def test_parse_log_line_oversized_safeguard():
    """Excessively long lines should be truncated defensively."""
    huge_line = "2026-10-29 09:00:00 INFO " + ("A" * 10_000)
    entry = parse_log_line(1, huge_line, max_line_length=100)
    assert len(entry.raw_text) == 100
    assert entry.severity == "INFO"


def test_parse_logs_multiline():
    """Multi-line content should return correct entries list."""
    content = "2026-10-29 09:00:00 INFO Start\n2026-10-29 09:01:00 ERROR Fail\n"
    entries = parse_logs(content)
    assert len(entries) == 2
    assert entries[0].severity == "INFO"
    assert entries[1].severity == "ERROR"


def test_parse_json_log_line():
    """Structured JSON log lines should parse fields accurately."""
    json_line = (
        '{"timestamp": "2026-10-29T10:15:30Z", "level": "ERROR", '
        '"message": "Database connection pool exhausted", "client_ip": "192.168.1.99"}'
    )
    entry = parse_log_line(1, json_line)
    assert entry.timestamp == "2026-10-29T10:15:30Z"
    assert entry.severity == "ERROR"
    assert "Database connection pool exhausted" in entry.message
    assert entry.ip_address == "192.168.1.99"
    assert entry.event_type == "DATABASE_ERROR"
    assert entry.metadata.get("level") == "ERROR"


def test_parse_json_bunyan_numeric_level():
    """Bunyan / Syslog numeric levels (e.g. 50=ERROR, 40=WARN) should be normalized."""
    json_line = '{"time": "2026-10-29T10:00:00Z", "level": 50, "msg": "Payment failed"}'
    entry = parse_log_line(1, json_line)
    assert entry.severity == "ERROR"
    assert entry.message == "Payment failed"


def test_parse_json_malformed_fallback():
    """Malformed JSON should fall back gracefully to text parsing without crashing."""
    broken_line = '{"timestamp": "2026-10-29 10:00:00", "level": "ERROR", broken json}'
    entry = parse_log_line(1, broken_line)
    assert entry.raw_text == broken_line
    assert entry.severity == "ERROR"
