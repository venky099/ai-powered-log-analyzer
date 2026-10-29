"""Log Analyzer orchestration module.

Coordinates log parsing, rule detection, metric aggregation, and
filtering of findings.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from src.detectors import DetectionEngine, Finding
from src.log_parser import ParsedLogEntry, parse_logs, safe_read_bytes


@dataclass
class AnalysisMetrics:
    """Statistical summary of processed log file and detection results."""

    total_lines: int = 0
    non_empty_lines: int = 0
    critical_count: int = 0
    error_count: int = 0
    warning_count: int = 0
    failed_auth_count: int = 0
    repeated_login_count: int = 0
    unique_ip_count: int = 0
    total_findings: int = 0
    severity_breakdown: Dict[str, int] = field(default_factory=dict)
    category_breakdown: Dict[str, int] = field(default_factory=dict)


@dataclass
class AnalysisResult:
    """Comprehensive container for the output of a log analysis run."""

    entries: List[ParsedLogEntry]
    findings: List[Finding]
    metrics: AnalysisMetrics
    filename: str = "unnamed.log"

    def filter_findings(
        self,
        severity_filter: Optional[str] = None,
        category_filter: Optional[str] = None,
        search_query: Optional[str] = None,
    ) -> List[Finding]:
        """Filter findings based on severity, category, or search keywords.

        Args:
            severity_filter: Specific severity or "ALL".
            category_filter: Specific category or "ALL".
            search_query: Free text search across summary, rule, and evidence.

        Returns:
            Filtered list of Finding objects.
        """
        results = self.findings

        if severity_filter and severity_filter.upper() != "ALL":
            results = [f for f in results if f.severity.upper() == severity_filter.upper()]

        if category_filter and category_filter.upper() != "ALL":
            results = [f for f in results if f.category.upper() == category_filter.upper()]

        if search_query and search_query.strip():
            q = search_query.strip().lower()
            results = [
                f
                for f in results
                if (
                    q in f.summary.lower()
                    or q in f.rule_name.lower()
                    or (f.source_ip and q in f.source_ip.lower())
                    or any(q in ev.lower() for ev in f.evidence)
                )
            ]

        return results


class LogAnalyzer:
    """Orchestrates parsing, detection, and aggregation."""

    def __init__(self, failed_login_threshold: int = 3):
        """Initialize the analyzer with detection settings.

        Args:
            failed_login_threshold: Threshold for repeated failed login alert.
        """
        self.detector = DetectionEngine(failed_login_threshold=failed_login_threshold)

    def analyze_bytes(
        self, raw_bytes: bytes, filename: str = "uploaded.log", max_lines: int = 100_000
    ) -> AnalysisResult:
        """Safely parse and analyze raw bytes from an uploaded file.

        Args:
            raw_bytes: Content bytes.
            filename: Name of the uploaded file for display.
            max_lines: Max line limit for processing.

        Returns:
            AnalysisResult containing parsed entries, findings, and metrics.
        """
        text = safe_read_bytes(raw_bytes)
        return self.analyze_text(text, filename=filename, max_lines=max_lines)

    def analyze_text(
        self, content: str, filename: str = "log_content.log", max_lines: int = 100_000
    ) -> AnalysisResult:
        """Parse and analyze normalized text content.

        Args:
            content: Log text string.
            filename: Display filename.
            max_lines: Max line limit.

        Returns:
            AnalysisResult with findings and metrics.
        """
        entries = parse_logs(content, max_lines=max_lines)
        findings = self.detector.analyze(entries)
        metrics = self._calculate_metrics(entries, findings)

        return AnalysisResult(
            entries=entries,
            findings=findings,
            metrics=metrics,
            filename=filename,
        )

    def _calculate_metrics(
        self, entries: List[ParsedLogEntry], findings: List[Finding]
    ) -> AnalysisMetrics:
        """Compute aggregated counts and breakdown stats."""
        total_lines = len(entries)
        non_empty = sum(1 for e in entries if e.event_type != "EMPTY")

        # Counts from parsed lines
        crit_count = sum(1 for e in entries if e.severity in ("CRITICAL", "FATAL"))
        err_count = sum(1 for e in entries if e.severity == "ERROR")
        warn_count = sum(1 for e in entries if e.severity == "WARNING")
        failed_auth = sum(1 for e in entries if e.event_type == "FAILED_LOGIN")

        # Extract unique IPv4 addresses
        unique_ips = {e.ip_address for e in entries if e.ip_address}

        # Repeated failed login finding count
        repeated_logins = sum(
            1 for f in findings if f.rule_name == "Rule-Repeated-Failed-Logins"
        )

        # Breakdowns
        severity_counts = Counter(f.severity for f in findings)
        category_counts = Counter(f.category for f in findings)

        return AnalysisMetrics(
            total_lines=total_lines,
            non_empty_lines=non_empty,
            critical_count=crit_count,
            error_count=err_count,
            warning_count=warn_count,
            failed_auth_count=failed_auth,
            repeated_login_count=repeated_logins,
            unique_ip_count=len(unique_ips),
            total_findings=len(findings),
            severity_breakdown=dict(severity_counts),
            category_breakdown=dict(category_counts),
        )
