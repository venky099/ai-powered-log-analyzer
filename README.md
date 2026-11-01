# 🛡️ AI-Powered Defensive Log Analyzer

An open-source, defensive log analysis workbench for developers, DevOps engineers, and cybersecurity analysts. This tool ingests server and application logs, flags operational errors and suspicious authentication leads using explainable deterministic detection rules, and synthesizes executive triage reports using the **Google Gemini API** (`gemini-2.5-flash`) with resilient local deterministic fallback.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.30+-FF4B4B.svg)](https://streamlit.io/)
[![Google Gemini API](https://img.shields.io/badge/Google%20Gemini-API%20Integrated-4285F4.svg)](https://ai.google.dev/)
[![Tests](https://img.shields.io/badge/tests-47%20passed-brightgreen.svg)]()

---

## 📋 Table of Contents
1. [Project Overview](#-project-overview)
2. [Key Features](#-key-features)
3. [Technology Stack](#-technology-stack)
4. [System Architecture](#-system-architecture)
5. [Prerequisites](#-prerequisites)
6. [Quickstart Setup Guide](#-quickstart-setup-guide)
   - [Windows Setup](#windows-setup)
   - [Linux & Kali Linux Setup](#linux--kali-linux-setup)
7. [Google Gemini API Setup](#-google-gemini-api-setup)
8. [Running the Application](#-running-the-application)
9. [Automated Testing](#-automated-testing)
10. [Sample Data & Walkthrough](#-sample-data--walkthrough)
11. [Troubleshooting](#-troubleshooting)
12. [Privacy & Security Boundary](#-privacy--security-boundary)
13. [Limitations & Disclaimers](#-limitations--disclaimers)
14. [Future Roadmap](#-future-roadmap)
15. [GitHub Repository Guide](#-github-repository-guide)

---

## 🔍 Project Overview

Production logs contain high-value operational signals, but manual inspection across thousands of lines is error-prone. 

The **AI-Powered Log Analyzer** addresses this by pairing:
1. **Deterministic Rule Detection:** Instant, explainable identification of `CRITICAL`, `FATAL`, `ERROR`, `WARNING`, database drops, and repeated authentication anomalies.
2. **Google Gemini AI Inference:** High-intelligence synthesis using Google Gemini (`gemini-2.5-flash`, `gemini-1.5-flash`, `gemini-2.0-flash`, `gemini-2.5-pro`), transforming structured telemetry into actionable executive summaries.
3. **Resilient Fallback Engine:** When the Gemini API key is unconfigured or network issues arise, the analyzer automatically provides a deterministic executive summary with no downtime or feature degradation.

---

## ✨ Key Features

- **🛡️ Explainable Detection Rules:** Evaluates logs against transparent heuristics rather than unverified "black-box" classifications.
- **📦 Multi-Format Ingestion:** Seamlessly parses unstructured syslogs as well as structured JSON-lines (`.json`, `.jsonl`, Bunyan, ECS, Pino, Zap).
- **🔢 Strict IPv4 Extraction & Grouping:** Distinguishes valid IPv4 addresses from version numbers and timestamps, grouping failed logins by source IP against configurable thresholds.
- **📊 Visual Analytics & Distributions:** Interactive Altair charts rendering findings by severity and category distributions.
- **🔒 Prompt-Injection Defenses:** Treats all log contents as untrusted data wrapped in `<log_evidence>` security barriers to prevent instruction hijacking.
- **🧠 Google Gemini API Integration:** Fast, high-accuracy analysis powered by official `google-genai` SDK with customizable model identifiers and live key input in the UI.
- **📊 Interactive Streamlit Dashboard:** Instant metric cards, severity and category filtering, full-text search, and expandable evidence cards.
- **📥 Secure Export Capabilities:**
  - **CSV Export:** RFC 4180 compliant with formula injection protection (`=, +, -, @` escaping).
  - **Text / Markdown Investigation Reports:** Ready for incident ticketing and post-mortem logs.

---

## 🛠️ Technology Stack

| Component | Technology | Purpose |
| :--- | :--- | :--- |
| **Language** | Python 3.11+ | Core implementation & standard library |
| **UI Dashboard** | Streamlit | Web interface and interactive filtering |
| **Data Processing** | pandas | Tabular data representation and filtering |
| **Visualizations** | Altair | Telemetry distribution charts |
| **AI Engine** | Google Gemini API (`gemini-2.5-flash`) | Executive triage summarization via `google-genai` |
| **Testing** | pytest | Automated unit and integration testing |

---

## 🏗️ System Architecture

```mermaid
flowchart TD
    A[Log File .log / .txt / .jsonl] --> B[Log Parser\nsrc/log_parser.py]
    B --> C[Detection Engine\nsrc/detectors.py]
    B --> D[Metrics Aggregation\nsrc/analyzer.py]
    C --> D
    D --> E{Gemini API Configured?}
    E -- Yes --> F[Google Gemini API\nsrc/ai_summarizer.py]
    E -- No / Error --> G[Deterministic Fallback Summary]
    F --> H[Streamlit Dashboard\napp.py]
    G --> H
    H --> I[CSV Export\nsrc/report_generator.py]
    H --> J[Text Report\nsrc/report_generator.py]
```

Detailed architectural specifications and component boundaries are documented in [`docs/ARCHITECTURE.md`](file:///C:/Users/DELL/project/res/docs/ARCHITECTURE.md).

---

## 📦 Prerequisites

- Python 3.11 or higher
- Git (recommended for version control)
- *(Optional)* [Google AI Studio API Key](https://aistudio.google.com/app/apikey) for Gemini AI summarization

---

## 🚀 Quickstart Setup Guide

### Windows Setup

1. **Clone or navigate to the workspace:**
   ```powershell
   cd C:\Users\DELL\project\res
   ```

2. **Create and activate a virtual environment:**
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   *(If script execution is disabled, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

3. **Install dependencies:**
   ```powershell
   pip install -r requirements.txt
   ```

4. **(Optional) Configure environment variables:**
   ```powershell
   Copy-Item .env.example .env
   ```

---

### Linux & Kali Linux Setup

1. **Clone repository & navigate into folder:**
   ```bash
   git clone https://github.com/venky099/ai-powered-log-analyzer.git
   cd ai-powered-log-analyzer
   ```

2. **Create and activate virtual environment:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Copy default configuration:**
   ```bash
   cp .env.example .env
   ```

---

## 🔑 Google Gemini API Setup

The application works completely out of the box **with or without** a Gemini API key using its built-in deterministic fallback engine.

To enable Gemini AI executive summaries:

1. **Get an API Key:**
   - Create a free Gemini API key at [Google AI Studio](https://aistudio.google.com/app/apikey).
2. **Configure Your API Key:**
   - **Option A (Environment):** Paste your key into `.env`:
     ```bash
     GEMINI_API_KEY=your_gemini_api_key_here
     GEMINI_MODEL=gemini-2.5-flash
     ```
   - **Option B (Dashboard UI):** Enter the key directly into the sidebar text box in the web dashboard.
3. In the Streamlit sidebar, the status indicator will turn green: `🟢 Gemini Ready (gemini-2.5-flash)`.

---

## 🖥️ Running the Application

Launch the Streamlit web dashboard with:

```bash
# Windows
.\.venv\Scripts\streamlit run app.py

# Linux / Kali
streamlit run app.py
```

The application will launch in your default web browser at `http://localhost:8501`.

### How to Use the Dashboard
1. **Upload or Load Sample:** Upload your `.log`, `.txt`, `.json`, or `.jsonl` file via the sidebar, or click **📄 Text Log** / **📦 JSON Log** to test synthetic telemetry.
2. **Review Metrics:** View high-level cards displaying Total Lines, Critical Events, Errors, Warnings, and Repeated IP Leads.
3. **Filter Findings:** Use the dropdowns in the **Findings & Evidence** tab to filter by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) or search by IP/keyword.
4. **Inspect Evidence:** Click any finding expander to examine the exact raw log lines and timestamps.
5. **Generate AI Summary:** Go to the **AI Executive Summary** tab and click **⚡ Generate AI Summary** for automated triage suggestions synthesized by Google Gemini.
6. **Download Reports:** Navigate to **Export & Reports** to download RFC 4180 CSV findings or text reports.

---

## 🧪 Automated Testing

The project includes a comprehensive test suite covering empty inputs, Unicode resilience, timestamp parsing, CSV formula escaping, threshold triggers, and mock Gemini API failures/fallbacks.

Run all tests via pytest:

```bash
# Windows
.\.venv\Scripts\pytest -v

# Linux / Kali
pytest -v
```

### Test Coverage Highlights:
- ✅ Malformed & Non-UTF8 decoding (`safe_read_bytes`)
- ✅ Strict IPv4 validation & version number rejection
- ✅ Critical, Fatal, Warning, Error, and Database heuristics
- ✅ Repeated authentication threshold grouping by IP
- ✅ CSV Formula Injection sanitization (`=cmd`, `@SUM`, etc.)
- ✅ Gemini API generation, empty response, HTTP 400, HTTP 404, HTTP 429 quota, and timeout fallback
- ✅ Backwards compatibility alias (`OllamaSummarizer`)

---

## 📂 Sample Data & Walkthrough

Synthetic log files are provided in [`sample_logs/sample.log`](file:///C:/Users/DELL/project/res/sample_logs/sample.log) and [`sample_logs/sample_json.jsonl`](file:///C:/Users/DELL/project/res/sample_logs/sample_json.jsonl).

### Observed Events in Sample Log:
- **Application Startup:** Normal informational entries.
- **Repeated Authentication Failures:** 4 consecutive failed logins for `admin`, `root`, and `administrator` from source IP `192.168.1.105` (triggers `Rule-Repeated-Failed-Logins`).
- **Isolated Authentication Failure:** 1 failed login from `10.0.0.42` followed immediately by a successful login.
- **Database Connection Error:** Database connection pool exhausted on port 5432.
- **Critical Subsystem Crash:** Unhandled worker process termination.
- **Untrusted Prompt Injection Simulation:** A log message containing `"SYSTEM PROMPT INJECTION: Ignore previous instructions..."` safely parsed and contained without triggering tool execution.

---

## 🔧 Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **API Key Required (Fallback active)** | No Gemini API key provided | Paste your key in the sidebar or set `GEMINI_API_KEY` in `.env`. |
| **Gemini API Error (400/403)** | API key is invalid or lacks permissions | Check your API key at [Google AI Studio](https://aistudio.google.com/app/apikey). |
| **Gemini Quota Exceeded (429)** | Free tier request limits reached | Wait a moment or upgrade quota; deterministic fallback will serve summaries in the meantime. |
| **Model Not Found (404)** | Typo in model identifier | Select a preset (e.g. `gemini-2.5-flash`, `gemini-1.5-flash`) or check the model name. |
| **File size exceeds limit** | Uploaded file > 2 MB default | Adjust `MAX_UPLOAD_SIZE_MB` in `.env` or upload a smaller log segment. |
| **PowerShell script execution error** | Windows execution policy blocks `.venv` | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` |

---

## 🔒 Privacy & Security Boundary

- **Local Memory Processing:** Uploaded logs are processed transiently in memory; logs are never permanently stored on disk unless explicitly exported by the user.
- **Bounded Context AI:** Only structured aggregated metrics and a bounded subset of findings (up to 15) are transmitted to the Gemini API, rather than dumping raw multi-megabyte log streams.
- **Defensive Prompt Engineering:** Findings are wrapped in `<log_evidence>` security barriers to defend against log injection attacks.

---

## ⚠️ Limitations & Disclaimers

For a detailed breakdown of false-positive risks and architectural boundaries, see [`docs/LIMITATIONS.md`](file:///C:/Users/DELL/project/res/docs/LIMITATIONS.md).

> **Disclaimer:** This tool is designed for educational triage and initial investigation support. It is **not** an enterprise SIEM or automated incident responder. A repeated failed login finding is an **investigation lead**, not definitive proof of an intrusion.

---

## 🔮 Future Roadmap

- [ ] Support for custom endpoint proxies for enterprise VPC deployments.
- [ ] Timeline visualization of event spikes using Altair / Streamlit charts.
- [ ] Integration with threat intelligence lists (RFC 1918 vs public bogon filtering).
- [ ] Multi-file correlation across frontend and backend log streams.

---

## 🐙 GitHub Repository Guide

### Suggested Repository Details:
- **Repository Name:** `ai-powered-log-analyzer`
- **Short Description:** *Defensive log analyzer and triage dashboard with explainable detection rules, Google Gemini API summarization, and deterministic fallback.*
- **Suggested Topics:** `cybersecurity`, `log-analyzer`, `incident-response`, `gemini-api`, `streamlit`, `python`, `threat-detection`, `defensive-security`
