"""Unit tests for src/ai_summarizer.py with Google Gemini API and fallback tests."""

from unittest.mock import MagicMock, patch
import pytest

from google.genai import errors
from src.ai_summarizer import AISummaryResult, GeminiSummarizer, OllamaSummarizer
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


def test_gemini_missing_api_key_fallback(sample_analysis_result):
    """When API key is not configured, return deterministic fallback without crashing."""
    with patch.dict("os.environ", {"GEMINI_API_KEY": ""}):
        with patch("src.ai_summarizer._load_env_file"):
            summarizer = GeminiSummarizer(api_key="")
            res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

            assert not res.is_ai_generated
            assert "Deterministic Rule Engine (Fallback)" in res.model_name
            assert "Rule-Based Executive Summary" in res.summary_text
            assert "192.168.1.50" in res.summary_text
            assert "not configured" in res.status_message.lower()


def test_gemini_successful_generation(sample_analysis_result):
    """When Gemini API responds successfully, return AI generated narrative."""
    summarizer = GeminiSummarizer(api_key="valid-test-key", model="gemini-3.8-flash")

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "### AI Security Assessment\nObserved repeated failed logins from 192.168.1.50. Recommend verifying IP ownership."
    mock_client.models.generate_content.return_value = mock_response

    with patch("google.genai.Client", return_value=mock_client):
        res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

        assert res.is_ai_generated
        assert res.model_name == "gemini-3.8-flash"
        assert "Observed repeated failed logins" in res.summary_text
        assert "Generated using Google Gemini" in res.status_message


def test_gemini_empty_response_fallback(sample_analysis_result):
    """When Gemini returns an empty response, return deterministic fallback."""
    summarizer = GeminiSummarizer(api_key="valid-test-key", model="gemini-3.8-flash")

    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.text = "   "
    mock_client.models.generate_content.return_value = mock_response

    with patch("google.genai.Client", return_value=mock_client):
        res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

        assert not res.is_ai_generated
        assert "empty response" in res.status_message.lower()
        assert "Rule-Based Executive Summary" in res.summary_text


def test_gemini_api_error_400(sample_analysis_result):
    """When Gemini returns a 400 invalid API key error, handle gracefully."""
    summarizer = GeminiSummarizer(api_key="bad-key", model="gemini-3.8-flash")

    mock_client = MagicMock()
    # Create APIError with code 400
    api_err = errors.APIError(400, "API key not valid. Please pass a valid API key.")
    mock_client.models.generate_content.side_effect = api_err

    with patch("google.genai.Client", return_value=mock_client):
        res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

        assert not res.is_ai_generated
        assert "400" in res.status_message
        assert "authentication" in res.status_message.lower() or "not valid" in res.status_message.lower()
        assert "Rule-Based Executive Summary" in res.summary_text


def test_gemini_api_error_404_model_not_found(sample_analysis_result):
    """When Gemini model is not found, provide helpful guidance."""
    summarizer = GeminiSummarizer(api_key="valid-key", model="unknown-model")

    mock_client = MagicMock()
    api_err = errors.APIError(404, "models/unknown-model is not found")
    mock_client.models.generate_content.side_effect = api_err

    with patch("google.genai.Client", return_value=mock_client):
        res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

        assert not res.is_ai_generated
        assert "unknown-model" in res.status_message
        assert "not found" in res.status_message.lower()


def test_gemini_api_error_429_quota(sample_analysis_result):
    """When Gemini quota or rate limit is reached, handle with fallback."""
    summarizer = GeminiSummarizer(api_key="valid-key", model="gemini-3.8-flash")

    mock_client = MagicMock()
    api_err = errors.APIError(429, "Resource has been exhausted (e.g. check quota).")
    mock_client.models.generate_content.side_effect = api_err

    with patch("google.genai.Client", return_value=mock_client):
        res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

        assert not res.is_ai_generated
        assert "429" in res.status_message or "quota" in res.status_message.lower()


def test_gemini_unexpected_exception(sample_analysis_result):
    """When unexpected network errors occur, return fallback."""
    summarizer = GeminiSummarizer(api_key="valid-key")

    with patch("google.genai.Client", side_effect=RuntimeError("Network unreachable")):
        res: AISummaryResult = summarizer.generate_summary(sample_analysis_result)

        assert not res.is_ai_generated
        assert "Network unreachable" in res.status_message


def test_check_gemini_status_unconfigured():
    """Status check returns False when API key is missing."""
    with patch.dict("os.environ", {"GEMINI_API_KEY": ""}):
        with patch("src.ai_summarizer._load_env_file"):
            summarizer = GeminiSummarizer(api_key="")
            is_ok, msg = summarizer.check_gemini_status()
            assert not is_ok
            assert "not configured" in msg.lower()


def test_check_gemini_status_configured_offline():
    """Status check returns True when API key is set without making network calls."""
    summarizer = GeminiSummarizer(api_key="test-key-12345", model="gemini-3.8-flash")
    is_ok, msg = summarizer.check_gemini_status(validate_online=False)
    assert is_ok
    assert "gemini-3.8-flash" in msg


def test_check_gemini_status_online_success():
    """Status check validates successfully when online check succeeds."""
    summarizer = GeminiSummarizer(api_key="test-key", model="gemini-3.8-flash")

    mock_client = MagicMock()
    with patch("google.genai.Client", return_value=mock_client):
        is_ok, msg = summarizer.check_gemini_status(validate_online=True)
        assert is_ok
        assert "connected successfully" in msg.lower()


def test_check_gemini_status_online_failure():
    """Status check returns False when online call fails."""
    summarizer = GeminiSummarizer(api_key="bad-key", model="gemini-3.8-flash")

    mock_client = MagicMock()
    mock_client.models.get.side_effect = errors.APIError(400, "Invalid API key")

    with patch("google.genai.Client", return_value=mock_client):
        is_ok, msg = summarizer.check_gemini_status(validate_online=True)
        assert not is_ok
        assert "400" in msg


def test_ollama_summarizer_alias_compatibility(sample_analysis_result):
    """Verify OllamaSummarizer alias preserves constructor compatibility and fallback."""
    with patch.dict("os.environ", {"GEMINI_API_KEY": ""}):
        with patch("src.ai_summarizer._load_env_file"):
            summarizer = OllamaSummarizer(host="http://localhost:11434", model="gemini-3.8-flash", api_key="")
            is_ok, msg = summarizer.check_ollama_status()
            assert not is_ok  # No key configured

            res = summarizer.generate_summary(sample_analysis_result)
            assert not res.is_ai_generated
            assert "Rule-Based Executive Summary" in res.summary_text
