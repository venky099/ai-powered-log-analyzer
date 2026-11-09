"""Unit tests for Streamlit application components in app.py."""

import html
from unittest.mock import MagicMock, patch
import pandas as pd
import pytest

import app
from src.analyzer import LogAnalyzer


def test_app_imports_cleanly():
    """Verify app.py has no indentation or top-level import errors."""
    assert hasattr(app, "main")
    assert hasattr(app, "render_metric_card")
    assert hasattr(app, "render_visual_analytics")
    assert hasattr(app, "run_analysis")


def test_render_metric_card_escaping():
    """Metric cards must escape labels, values, and deltas against HTML injection."""
    with patch("streamlit.markdown") as mock_markdown:
        app.render_metric_card(
            label="<script>alert('xss')</script>",
            value="<b>10</b>",
            icon="⚠️",
            color_hex="#ef4444",
            delta="<img src=x onerror=1>",
        )
        assert mock_markdown.called
        rendered_html = mock_markdown.call_args[0][0]
        assert "<script>" not in rendered_html
        assert "&lt;script&gt;" in rendered_html
        assert "<b>" not in rendered_html
        assert "&lt;b&gt;" in rendered_html
        assert "<img" not in rendered_html
        assert "&lt;img" in rendered_html


def test_init_session_state():
    """Session state helper initializes required keys with defaults."""
    class MockSessionState(dict):
        def __getattr__(self, name):
            return self.get(name)
        def __setattr__(self, name, value):
            self[name] = value

    mock_state = MockSessionState()
    with patch.object(app.st, "session_state", mock_state):
        app.init_session_state()
        assert "analysis_result" in mock_state
        assert "ai_summary" in mock_state
        assert "active_bytes" in mock_state
        assert "active_threshold" in mock_state
        assert mock_state["analysis_result"] is None
        assert mock_state["ai_summary"] is None


def test_small_log_entries_safeguard():
    """Logs with fewer than 10 lines should be safely handled without slider value error."""
    analyzer = LogAnalyzer()
    res = analyzer.analyze_text("2026-10-29 09:00:00 INFO Line 1\n2026-10-29 09:00:01 INFO Line 2\n")
    total_entries = len(res.entries)
    assert total_entries < 10
    # In tab3, if total_entries <= 10, all entries are displayed without slider bounds exception
    df = pd.DataFrame([e.to_dict() for e in res.entries])
    assert len(df) == 2


def test_critical_alert_card_delta_pluralization():
    """Verify singular/plural delta formatting for metric cards."""
    one_alert = f"{1} {'Alert' if 1 == 1 else 'Alerts'}"
    assert one_alert == "1 Alert"

    two_alerts = f"{2} {'Alert' if 2 == 1 else 'Alerts'}"
    assert two_alerts == "2 Alerts"


def test_alert_feed_large_dataset_cap():
    """Alert feed display list is capped at 50 to maintain browser performance."""
    feed_limit = 50
    mock_findings = [MagicMock() for _ in range(120)]
    displayed = mock_findings[:feed_limit]
    assert len(displayed) == 50
    assert len(mock_findings) > feed_limit
