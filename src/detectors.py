"""Detection engine module for AI-Powered Log Analyzer.

This module provides deterministic, rule-based detection for:
- Critical and fatal events
- Application and system errors
- Warnings and performance flags
- Failed authentications
- Repeated failed logins grouped by validated IP address
- Database and connection issues

All findings clearly distinguish evidence from hypotheses and include
recommended investigation steps and explicit limitations.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from src.log_parser import ParsedLogEntry


@dataclass
class Finding:
    """Represents a discrete detection result or investigation lead."""

    finding_id: str
    category: str  # e.g., AUTHENTICATION, SYSTEM_ERROR, CRITICAL_FAILURE, DATABASE, WARNING
    severity: str  # e.g., CRITICAL, HIGH, MEDIUM, LOW, INFO
    rule_name: str
    summary: str
    evidence: List[str] = field(default_factory=list)
    timestamp: Optional[str] = None
    source_ip: Optional[str] = None
    recommended_step: str = ""
    confidence: str = "PROBABLE"  # e.g., INFORMATIONAL, SUSPICIOUS, HIGH_CONFIDENCE
    limitations: str = ""

    def to_dict(self) -> dict:
        """Convert finding to dictionary for export and UI display."""
        return {
            "finding_id": self.finding_id,
            "category": self.category,
            "severity": self.severity,
            "rule_name": self.rule_name,
            "summary": self.summary,
            "source_ip": self.source_ip or "N/A",
            "timestamp": self.timestamp or "N/A",
            "confidence": self.confidence,
            "recommended_step": self.recommended_step,
            "limitations": self.limitations,
            "evidence_count": len(self.evidence),
            "evidence": "; ".join(self.evidence),
        }


class DetectionEngine:
    """Deterministic detection engine applying transparent rules to parsed log entries."""

    def __init__(self, failed_login_threshold: int = 3):
        """Initialize engine with configurable thresholds.

        Args:
            failed_login_threshold: Minimum number of failed logins from a single IP
                                    to trigger a repeated failure lead.
        """
        self.failed_login_threshold = max(1, failed_login_threshold)

    def analyze(self, entries: List[ParsedLogEntry]) -> List[Finding]:
        """Run all detection rules against parsed entries and return findings.

        Args:
            entries: List of parsed log lines.

        Returns:
            List of structured Finding objects.
        """
        findings: List[Finding] = []
        finding_counter = 1

        if not entries:
            return findings

        # Rule 1: CRITICAL and FATAL events
        critical_findings, finding_counter = self._detect_critical_events(entries, finding_counter)
        findings.extend(critical_findings)

        # Rule 2: Repeated Failed Logins grouped by IP
        repeated_login_findings, finding_counter = self._detect_repeated_failed_logins(
            entries, finding_counter
        )
        findings.extend(repeated_login_findings)

        # Rule 3: Isolated Failed Logins (below threshold or without IP)
        isolated_auth_findings, finding_counter = self._detect_isolated_auth_failures(
            entries, finding_counter, repeated_login_findings
        )
        findings.extend(isolated_auth_findings)

        # Rule 4: Database and Connection Errors
        db_findings, finding_counter = self._detect_database_errors(entries, finding_counter)
        findings.extend(db_findings)

        # Rule 5: General ERROR events
        error_findings, finding_counter = self._detect_general_errors(entries, finding_counter)
        findings.extend(error_findings)

        # Rule 6: WARNING events
        warning_findings, finding_counter = self._detect_warnings(entries, finding_counter)
        findings.extend(warning_findings)

        return findings

    def _detect_critical_events(
        self, entries: List[ParsedLogEntry], start_id: int
    ) -> tuple[List[Finding], int]:
        findings: List[Finding] = []
        cid = start_id

        for entry in entries:
            if entry.severity in ("CRITICAL", "FATAL"):
                f = Finding(
                    finding_id=f"FINDING-{cid:04d}",
                    category="CRITICAL_FAILURE",
                    severity="CRITICAL",
                    rule_name="Rule-Critical-Fatal-Event",
                    summary=f"Critical or Fatal event detected at line {entry.line_number}: {entry.message[:80]}",
                    evidence=[f"Line {entry.line_number} [{entry.timestamp or 'no timestamp'}]: {entry.raw_text}"],
                    timestamp=entry.timestamp,
                    source_ip=entry.ip_address,
                    recommended_step="Check system availability, examine application crash logs, and verify service health.",
                    confidence="HIGH_CONFIDENCE",
                    limitations="Log line flags an unhandled or fatal condition as reported by application logger.",
                )
                findings.append(f)
                cid += 1

        return findings, cid

    def _detect_repeated_failed_logins(
        self, entries: List[ParsedLogEntry], start_id: int
    ) -> tuple[List[Finding], int]:
        findings: List[Finding] = []
        cid = start_id

        # Group failed login entries by source IP
        ip_failures: Dict[str, List[ParsedLogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.event_type == "FAILED_LOGIN" and entry.ip_address:
                ip_failures[entry.ip_address].append(entry)

        for ip, failed_entries in ip_failures.items():
            count = len(failed_entries)
            if count >= self.failed_login_threshold:
                evidence_lines = [
                    f"Line {e.line_number} [{e.timestamp or 'no timestamp'}]: {e.raw_text}"
                    for e in failed_entries
                ]
                first_ts = failed_entries[0].timestamp
                last_ts = failed_entries[-1].timestamp
                ts_span = f"{first_ts} to {last_ts}" if first_ts and last_ts else first_ts

                f = Finding(
                    finding_id=f"FINDING-{cid:04d}",
                    category="AUTHENTICATION",
                    severity="HIGH",
                    rule_name="Rule-Repeated-Failed-Logins",
                    summary=(
                        f"Repeated failed logins detected ({count} attempts) from IP {ip}. "
                        "Investigation lead for credential stuffing or user misconfiguration."
                    ),
                    evidence=evidence_lines,
                    timestamp=ts_span,
                    source_ip=ip,
                    recommended_step=(
                        f"Review authentication history for IP {ip}. Check whether source belongs "
                        "to a legitimate user, proxy, VPN, or external scanner. Verify if any attempt succeeded."
                    ),
                    confidence="SUSPICIOUS",
                    limitations=(
                        "Repeated failed logins indicate repeated authentication errors, not definitive "
                        "proof of malicious intent. NAT gateways, proxies, or forgotten passwords can produce this pattern."
                    ),
                )
                findings.append(f)
                cid += 1

        return findings, cid

    def _detect_isolated_auth_failures(
        self, entries: List[ParsedLogEntry], start_id: int, repeated_findings: List[Finding]
    ) -> tuple[List[Finding], int]:
        findings: List[Finding] = []
        cid = start_id

        # Collect IPs that already triggered repeated findings to avoid duplicate noise
        flagged_ips = {f.source_ip for f in repeated_findings if f.source_ip}

        for entry in entries:
            if entry.event_type == "FAILED_LOGIN":
                if entry.ip_address in flagged_ips:
                    # Already part of repeated finding
                    continue

                f = Finding(
                    finding_id=f"FINDING-{cid:04d}",
                    category="AUTHENTICATION",
                    severity="MEDIUM",
                    rule_name="Rule-Isolated-Auth-Failure",
                    summary=f"Authentication failure at line {entry.line_number}" + (f" from IP {entry.ip_address}" if entry.ip_address else ""),
                    evidence=[f"Line {entry.line_number} [{entry.timestamp or 'no timestamp'}]: {entry.raw_text}"],
                    timestamp=entry.timestamp,
                    source_ip=entry.ip_address,
                    recommended_step="Check whether user subsequently logged in successfully or if account is locked.",
                    confidence="INFORMATIONAL",
                    limitations="Single or low-volume failed logins are common due to normal user typos.",
                )
                findings.append(f)
                cid += 1

        return findings, cid

    def _detect_database_errors(
        self, entries: List[ParsedLogEntry], start_id: int
    ) -> tuple[List[Finding], int]:
        findings: List[Finding] = []
        cid = start_id

        for entry in entries:
            if entry.event_type == "DATABASE_ERROR" and entry.severity not in ("CRITICAL", "FATAL"):
                f = Finding(
                    finding_id=f"FINDING-{cid:04d}",
                    category="DATABASE",
                    severity="HIGH" if entry.severity == "ERROR" else "MEDIUM",
                    rule_name="Rule-Database-Connection-Error",
                    summary=f"Database or backend storage issue at line {entry.line_number}: {entry.message[:80]}",
                    evidence=[f"Line {entry.line_number} [{entry.timestamp or 'no timestamp'}]: {entry.raw_text}"],
                    timestamp=entry.timestamp,
                    source_ip=entry.ip_address,
                    recommended_step="Verify database connectivity, connection pool limits, and recent schema migrations.",
                    confidence="HIGH_CONFIDENCE",
                    limitations="Indicates communication failure or query rejection; inspect database server metrics.",
                )
                findings.append(f)
                cid += 1

        return findings, cid

    def _detect_general_errors(
        self, entries: List[ParsedLogEntry], start_id: int
    ) -> tuple[List[Finding], int]:
        findings: List[Finding] = []
        cid = start_id

        for entry in entries:
            if entry.severity == "ERROR" and entry.event_type not in ("FAILED_LOGIN", "DATABASE_ERROR"):
                f = Finding(
                    finding_id=f"FINDING-{cid:04d}",
                    category="SYSTEM_ERROR",
                    severity="HIGH",
                    rule_name="Rule-General-Error-Event",
                    summary=f"Application error at line {entry.line_number}: {entry.message[:80]}",
                    evidence=[f"Line {entry.line_number} [{entry.timestamp or 'no timestamp'}]: {entry.raw_text}"],
                    timestamp=entry.timestamp,
                    source_ip=entry.ip_address,
                    recommended_step="Inspect stack trace and correlated service logs around this timestamp.",
                    confidence="HIGH_CONFIDENCE",
                    limitations="Severity is derived directly from log level stated in original log entry.",
                )
                findings.append(f)
                cid += 1

        return findings, cid

    def _detect_warnings(
        self, entries: List[ParsedLogEntry], start_id: int
    ) -> tuple[List[Finding], int]:
        findings: List[Finding] = []
        cid = start_id

        for entry in entries:
            if entry.severity == "WARNING" and entry.event_type != "FAILED_LOGIN":
                f = Finding(
                    finding_id=f"FINDING-{cid:04d}",
                    category="WARNING",
                    severity="LOW",
                    rule_name="Rule-General-Warning-Event",
                    summary=f"System warning at line {entry.line_number}: {entry.message[:80]}",
                    evidence=[f"Line {entry.line_number} [{entry.timestamp or 'no timestamp'}]: {entry.raw_text}"],
                    timestamp=entry.timestamp,
                    source_ip=entry.ip_address,
                    recommended_step="Monitor metric thresholds to prevent escalation into an error state.",
                    confidence="INFORMATIONAL",
                    limitations="Warnings typically do not halt execution but may indicate degraded performance.",
                )
                findings.append(f)
                cid += 1

        return findings, cid
