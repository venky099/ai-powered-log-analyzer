"""Unit tests for src/ai_summarizer.py with mocked Ollama HTTP API."""

from unittest.mock import MagicMock, patch
import pytest
import requests

from src.ai_summarizer import AISummaryResult, OllamaSummarizer
from src.analyzer import LogAnalyzer


@pytest.fixture
def sample_analysis_result():
    content = (
        "2026-10-29 09:00:00 ERROR Database failed\n"
        "2026-10-29 09:00:10 FAILED LOGIN from 192.168.1.50\n"
        "2026-10-29 09:00:15 FAILED LOGIN from 192.168.1.50\n"
        "2026-10-29 09:00:20 FAILED LOGIN from 192.168.1.50\n"
    )
    analyzer = LogAnalyzer(failed_login_threshold=3)
    return analyzer.analyze_text(content, filename="test_audit.log")


def test_ollama_offline_fallback(sample_analysis_result):
    """When Ollama is unreachable, return deterministic fallback without crashing."""
    summarizer = OllamaSummarizer(host="http://localhost:99999", timeout_seconds=1)

    with patch("requests.post", side_effect=requests.exceptions.ConnectionError("Connection refused")):
        res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

        assert not res.is_ai_generated
        assert "Deterministic Rule Engine (Fallback)" in res.model_name
        assert "Rule-Based Executive Summary" in res.summary_text
        assert "192.168.1.50" in res.summary_text
        assert "Limitations" in res.summary_text


def test_ollama_timeout_fallback(sample_analysis_result):
    """When Ollama times out, return deterministic fallback."""
    summarizer = OllamaSummarizer(host="http://localhost:11434", timeout_seconds=1)

    with patch("requests.post", side_effect=requests.exceptions.Timeout("Request timed out")):
        res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

        assert not res.is_ai_generated
        assert "timed out" in res.status_message.lower()
        assert "Rule-Based Executive Summary" in res.summary_text


def test_ollama_model_not_found_404(sample_analysis_result):
    """When Ollama returns 404 for a missing model, provide helpful guidance."""
    summarizer = OllamaSummarizer(model="llama3.2:1b")
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_resp.text = "model not found"

    with patch("requests.post", return_value=mock_resp):
        res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

        assert not res.is_ai_generated
        assert "ollama pull llama3.2:1b" in res.status_message


def test_ollama_successful_generation(sample_analysis_result):
    """When Ollama responds successfully, return AI generated narrative."""
    summarizer = OllamaSummarizer(model="llama3.2:1b")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "response": "### AI Security Assessment\nObserved repeated failed logins from 192.168.1.50. Recommend verifying IP ownership."
    }

    with patch("requests.post", return_value=mock_resp):
        res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

        assert res.is_ai_generated
        assert res.model_name == "llama3.2:1b"
        assert "Observed repeated failed logins" in res.summary_text


def test_check_ollama_status_offline():
    """Status check returns False when service is offline."""
    summarizer = OllamaSummarizer(host="http://localhost:11434")

    with patch("requests.get", side_effect=requests.exceptions.ConnectionError()):
        is_ok, msg = summarizer.check_ollama_status()
        assert not is_ok
        assert "Could not connect" in msg


def test_check_ollama_status_online_with_model():
    """Status check returns True when service is online and model exists."""
    summarizer = OllamaSummarizer(model="llama3.2:1b")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "models": [{"name": "llama3.2:1b:latest"}]
    }

    with patch("requests.get", return_value=mock_resp):
        is_ok, msg = summarizer.check_ollama_status()
        assert is_ok
        assert "ready" in msg
