"""Log parsing module for AI-Powered Log Analyzer.

This module provides safe, resilient parsing of raw log lines into structured
ParsedLogEntry objects. It handles invalid encodings, varying formats,
timestamp extraction, severity normalization, and IPv4 address validation.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class ParsedLogEntry:
    """Represents a single parsed log line with normalized metadata."""

    line_number: int
    raw_text: str
    timestamp: Optional[str] = None
    severity: Optional[str] = None
    ip_address: Optional[str] = None
    message: str = ""
    event_type: Optional[str] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Convert entry to dictionary for tabular views and serialization."""
        return {
            "line_number": self.line_number,
            "timestamp": self.timestamp or "N/A",
            "severity": self.severity or "UNKNOWN",
            "ip_address": self.ip_address or "N/A",
            "event_type": self.event_type or "GENERAL",
            "message": self.message,
            "raw_text": self.raw_text,
        }


# Compiled regex patterns for efficiency
_IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# Regex to avoid matching version numbers or numeric IDs like v1.2.3.4 or 1.2.3.4.5
_NON_IP_PREFIX_SUFFIX = re.compile(r"(?:[a-zA-Z0-9_\-\./])")

# Common timestamp patterns
_TIMESTAMP_PATTERNS = [
    # ISO-like: 2026-10-29 09:10:01, 2026-10-29T09:10:01, with optional milliseconds/timezone
    re.compile(
        r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
    ),
    # Syslog-like: Oct 29 09:10:01 or Oct  9 09:10:01
    re.compile(
        r"^(?P<ts>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    ),
    # Slash date: 29/10/2026 09:10:01 or 10/29/2026 09:10:01
    re.compile(
        r"^(?P<ts>\d{1,4}[/\-]\d{1,2}[/\-]\d{1,4}\s+\d{2}:\d{2}:\d{2})"
    ),
    # Bracketed timestamp: [2026-10-29 09:10:01] or [29/Oct/2026:09:10:01 +0000]
    re.compile(
        r"^\[(?P<ts>[^\]]+)\]"
    ),
]

# Severity keyword mappings
_SEVERITY_KEYWORDS = {
    "FATAL": "FATAL",
    "CRITICAL": "CRITICAL",
    "CRIT": "CRITICAL",
    "EMERGENCY": "CRITICAL",
    "ALERT": "CRITICAL",
    "ERROR": "ERROR",
    "ERR": "ERROR",
    "WARNING": "WARNING",
    "WARN": "WARNING",
    "INFO": "INFO",
    "NOTICE": "INFO",
    "DEBUG": "DEBUG",
    "TRACE": "DEBUG",
}

# Regex to find severity keyword near start or inside brackets
_SEVERITY_PATTERN = re.compile(
    r"\b(FATAL|CRITICAL|CRIT|EMERGENCY|ALERT|ERROR|ERR|WARNING|WARN|INFO|NOTICE|DEBUG|TRACE)\b",
    re.IGNORECASE,
)

# Authentication / Security event patterns
_FAILED_LOGIN_PATTERNS = [
    re.compile(r"failed\s+login", re.IGNORECASE),
    re.compile(r"authentication\s+failed", re.IGNORECASE),
    re.compile(r"login\s+failed", re.IGNORECASE),
    re.compile(r"invalid\s+(?:password|user|credentials)", re.IGNORECASE),
    re.compile(r"failed\s+password", re.IGNORECASE),
    re.compile(r"auth(?:entication)?\s+failure", re.IGNORECASE),
]

_SUCCESS_LOGIN_PATTERNS = [
    re.compile(r"successful\s+login", re.IGNORECASE),
    re.compile(r"login\s+successful", re.IGNORECASE),
    re.compile(r"accepted\s+password", re.IGNORECASE),
    re.compile(r"authentication\s+succeeded", re.IGNORECASE),
]


def safe_read_bytes(raw_bytes: bytes) -> str:
    """Safely decode raw bytes into normalized text, handling encodings and BOMs.

    Args:
        raw_bytes: The incoming raw byte content.

    Returns:
        Decoded text with normalized universal newlines (\\n).
    """
    if not raw_bytes:
        return ""

    # Check for byte-order marks
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        decoded = raw_bytes.decode("utf-8-sig", errors="replace")
    elif raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        decoded = raw_bytes.decode("utf-16", errors="replace")
    else:
        try:
            decoded = raw_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Fallback to Latin-1 / replace to avoid hard crash
            try:
                decoded = raw_bytes.decode("latin-1")
            except Exception:
                decoded = raw_bytes.decode("utf-8", errors="replace")

    # Normalize line endings: CRLF and CR -> LF
    normalized = decoded.replace("\r\n", "\n").replace("\r", "\n")
    return normalized


def extract_valid_ipv4(text: str) -> Optional[str]:
    """Extract and strictly validate an IPv4 address from text.

    Ensures that numeric patterns like version numbers (1.2.3.4.5),
    timestamps, or invalid octets (256.1.1.1) are rejected.

    Args:
        text: String to search.

    Returns:
        Validated IPv4 string or None.
    """
    candidates = _IPV4_PATTERN.findall(text)
    for cand in candidates:
        # Check that it is not part of a larger dotted version string or path
        pos = text.find(cand)
        if pos > 0 and text[pos - 1] in ".-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
            continue
        after_pos = pos + len(cand)
        if after_pos < len(text) and text[after_pos] in ".-_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ":
            continue

        try:
            ip_obj = ipaddress.IPv4Address(cand)
            # Avoid returning 0.0.0.0 or 255.255.255.255 if not meaningful
            return str(ip_obj)
        except ipaddress.AddressValueError:
            continue

    return None


def extract_timestamp(text: str) -> Tuple[Optional[str], str]:
    """Extract a timestamp from the start of a log line if present.

    Args:
        text: The line text.

    Returns:
        Tuple of (timestamp_string or None, remaining_text).
    """
    stripped = text.strip()
    for pattern in _TIMESTAMP_PATTERNS:
        match = pattern.search(stripped)
        if match:
            ts = match.group("ts").strip()
            # Remainder after the match
            remaining = stripped[match.end():].strip()
            # If remaining starts with separator like '-', ':', or whitespace
            remaining = re.sub(r"^[\s\-:\]|]+", "", remaining).strip()
            return ts, remaining

    return None, stripped


def extract_severity(text: str) -> Tuple[Optional[str], str]:
    """Extract recognized severity level from log line.

    Args:
        text: Log line or remainder after timestamp.

    Returns:
        Tuple of (normalized_severity or None, remaining_text).
    """
    match = _SEVERITY_PATTERN.search(text)
    if match:
        raw_word = match.group(1).upper()
        normalized = _SEVERITY_KEYWORDS.get(raw_word)
        if normalized:
            # We don't remove it from the message so full context remains,
            # but return the normalized severity
            return normalized, text

    return None, text


def classify_event_pattern(text: str) -> Optional[str]:
    """Classify common event types based on text patterns.

    Args:
        text: The log message text.

    Returns:
        Category string such as 'FAILED_LOGIN', 'SUCCESS_LOGIN', 'DATABASE_ERROR', etc.
    """
    for pat in _FAILED_LOGIN_PATTERNS:
        if pat.search(text):
            return "FAILED_LOGIN"

    for pat in _SUCCESS_LOGIN_PATTERNS:
        if pat.search(text):
            return "SUCCESS_LOGIN"

    if re.search(r"\b(?:database|sql|postgres(?:ql)?|mysql|sqlite|oracle|redis|mongodb|connection refused|deadlock)\b", text, re.IGNORECASE):
        if re.search(r"\b(?:error|fail|down|timeout|refused|exception|exhausted|closed|dropped)\b", text, re.IGNORECASE):
            return "DATABASE_ERROR"

    return None


def _try_parse_json_log(line_number: int, cleaned_line: str, bounded_line: str) -> Optional[ParsedLogEntry]:
    """Attempt to parse a structured JSON-lines log entry (e.g. Bunyan, ECS, Zap).

    Args:
        line_number: 1-based line number.
        cleaned_line: Stripped string line.
        bounded_line: Line bounded by max line length.

    Returns:
        ParsedLogEntry if valid JSON object, else None.
    """
    if not (cleaned_line.startswith("{") and cleaned_line.endswith("}")):
        return None
    try:
        data = json.loads(cleaned_line)
        if not isinstance(data, dict):
            return None
    except (json.JSONDecodeError, ValueError):
        return None

    # Timestamp extraction
    ts = None
    for key in ("timestamp", "@timestamp", "time", "ts", "datetime", "date"):
        if key in data and data[key]:
            ts = str(data[key])
            break

    # Severity / Level extraction
    sev = None
    for key in ("level", "severity", "log_level", "logLevel", "lvl"):
        if key in data and data[key] is not None:
            raw_lvl = str(data[key]).upper()
            if raw_lvl in ("60", "FATAL"):
                sev = "FATAL"
            elif raw_lvl in ("50", "ERROR", "ERR"):
                sev = "ERROR"
            elif raw_lvl in ("40", "WARN", "WARNING"):
                sev = "WARNING"
            elif raw_lvl in ("30", "INFO"):
                sev = "INFO"
            elif raw_lvl in ("20", "DEBUG", "TRACE"):
                sev = "DEBUG"
            else:
                norm_sev, _ = extract_severity(raw_lvl)
                sev = norm_sev
            break

    # Message extraction
    msg = ""
    for key in ("message", "msg", "error", "description", "event", "log"):
        if key in data and data[key]:
            msg = str(data[key])
            break
    if not msg:
        msg = cleaned_line

    # IP Address extraction
    ip = None
    for key in ("ip", "client_ip", "remote_addr", "remote_ip", "source_ip", "src_ip", "ip_address"):
        if key in data and data[key]:
            cand = str(data[key])
            ip = extract_valid_ipv4(cand)
            if ip:
                break
    if not ip:
        ip = extract_valid_ipv4(cleaned_line)

    # Event classification
    event_type = classify_event_pattern(msg)
    if not event_type:
        for key in ("event_type", "action", "event"):
            if key in data and data[key]:
                event_type = classify_event_pattern(str(data[key]))
                if event_type:
                    break

    return ParsedLogEntry(
        line_number=line_number,
        raw_text=bounded_line,
        timestamp=ts,
        severity=sev,
        ip_address=ip,
        message=msg,
        event_type=event_type,
        metadata=data,
    )


def parse_log_line(line_number: int, raw_line: str, max_line_length: int = 4096) -> ParsedLogEntry:
    """Parse a single raw log line into a structured ParsedLogEntry.

    Args:
        line_number: 1-based line number.
        raw_line: Raw string line.
        max_line_length: Safeguard against excessively long lines.

    Returns:
        ParsedLogEntry instance.
    """
    # Defensive truncation for line length to prevent denial-of-service / regex backtracking
    bounded_line = raw_line[:max_line_length] if len(raw_line) > max_line_length else raw_line
    cleaned_line = bounded_line.strip()

    if not cleaned_line:
        return ParsedLogEntry(
            line_number=line_number,
            raw_text=bounded_line,
            message="<EMPTY LINE>",
            event_type="EMPTY",
        )

    # 0. Check for JSON structured log entry
    json_entry = _try_parse_json_log(line_number, cleaned_line, bounded_line)
    if json_entry is not None:
        return json_entry

    # 1. Extract Timestamp
    ts, remaining = extract_timestamp(cleaned_line)

    # 2. Extract Severity
    sev, _ = extract_severity(remaining if ts else cleaned_line)

    # 3. Extract Valid IPv4
    ip = extract_valid_ipv4(cleaned_line)

    # 4. Classify event pattern
    event_type = classify_event_pattern(cleaned_line)

    # Message is the cleaned line or remaining after timestamp
    message = remaining if ts and remaining else cleaned_line

    return ParsedLogEntry(
        line_number=line_number,
        raw_text=bounded_line,
        timestamp=ts,
        severity=sev,
        ip_address=ip,
        message=message,
        event_type=event_type,
    )


def parse_logs(content: str, max_lines: int = 100_000, max_line_length: int = 4096) -> List[ParsedLogEntry]:
    """Parse multiple log lines from a content string safely.

    Args:
        content: Log text content.
        max_lines: Max number of lines to process to prevent resource exhaustion.
        max_line_length: Max length per line.

    Returns:
        List of ParsedLogEntry objects.
    """
    if not content:
        return []

    lines = content.splitlines()
    entries: List[ParsedLogEntry] = []

    for idx, line in enumerate(lines[:max_lines], start=1):
        # We parse each line safely
        entry = parse_log_line(idx, line, max_line_length=max_line_length)
        entries.append(entry)

    return entries
