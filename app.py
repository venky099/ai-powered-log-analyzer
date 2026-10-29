"""AI-Powered Log Analyzer - High-Performance Security Operations Dashboard.

A modern, defensive log analysis dashboard featuring glassmorphism cards,
cybersecurity typography (Plus Jakarta Sans & JetBrains Mono), visual Altair
distributions, structured JSON-lines support, and local Ollama AI summarization.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import altair as alt
import pandas as pd
import streamlit as st

from src.ai_summarizer import OllamaSummarizer
from src.analyzer import AnalysisResult, LogAnalyzer
from src.report_generator import generate_csv_report, generate_text_report

# Configuration defaults
DEFAULT_MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "2"))
DEFAULT_FAILED_LOGIN_THRESHOLD = int(os.getenv("FAILED_LOGIN_THRESHOLD", "3"))
DEFAULT_OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
DEFAULT_OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2:1b")
SAMPLE_LOG_PATH = Path(__file__).parent / "sample_logs" / "sample.log"
SAMPLE_JSON_PATH = Path(__file__).parent / "sample_logs" / "sample_json.jsonl"

# Page configuration
st.set_page_config(
    page_title="AI Log Analyzer | SOC Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


def inject_custom_styles():
    """Inject clean typography and modern dark theme CSS."""
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&family=Plus+Jakarta+Sans:wght@500;600;700;800&family=Space+Grotesk:wght@500;600;700&display=swap');

        /* Safe Global Typography */
        html, body, .stMarkdown, .stText, p, h1, h2, h3, h4, h5, h6, label {
            font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
        }

        /* Strictly protect icon fonts so icon ligatures (like 'upload') do not render as text */
        [data-testid="stIconMaterial"], 
        .material-symbols-rounded, 
        .material-icons,
        [class*="material-symbols"],
        [class*="material-icons"],
        span:empty,
        svg {
            font-family: 'Material Symbols Rounded', 'Material Icons', sans-serif !important;
        }

        code, pre, .stCode, [data-testid="stCodeBlock"], [data-testid="stCodeBlock"] * {
            font-family: 'JetBrains Mono', monospace !important;
        }

        /* Data Table Typography: High-Precision Monospace Grid */
        [data-testid="stDataFrame"], 
        [data-testid="stDataFrame"] *,
        .dvn-scroller,
        [data-testid="stTable"] {
            font-family: 'JetBrains Mono', 'Courier New', monospace !important;
            font-size: 0.82rem !important;
            letter-spacing: -0.01em !important;
        }

        /* Alert Feed Card Typography: High-Tech Security Font */
        .streamlit-expanderHeader {
            font-family: 'Space Grotesk', 'Inter', sans-serif !important;
            font-size: 0.93rem !important;
            font-weight: 600 !important;
            letter-spacing: -0.01em !important;
            color: #f8fafc !important;
        }

        .alert-meta-chip {
            font-family: 'JetBrains Mono', monospace !important;
            font-size: 0.78rem !important;
            background: rgba(15, 23, 42, 0.8) !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            border-radius: 6px !important;
            padding: 4px 8px !important;
            color: #cbd5e1 !important;
            display: inline-block !important;
            margin-bottom: 4px !important;
        }

        .alert-triage-box {
            font-family: 'Inter', sans-serif !important;
        }

        .alert-triage-title {
            font-family: 'Space Grotesk', sans-serif !important;
            font-size: 0.72rem !important;
            font-weight: 700 !important;
            letter-spacing: 0.06em !important;
            text-transform: uppercase !important;
            color: #94a3b8 !important;
        }

        .alert-triage-body {
            font-family: 'Inter', sans-serif !important;
            font-size: 0.88rem !important;
            line-height: 1.5 !important;
            color: #f1f5f9 !important;
            margin-top: 2px !important;
        }

        /* App Canvas */
        .stApp {
            background: linear-gradient(145deg, #070a12 0%, #0d1322 40%, #090e1a 100%);
            color: #e2e8f0;
        }

        /* Sidebar */
        [data-testid="stSidebar"] {
            background-color: #090d18 !important;
            border-right: 1px solid rgba(255, 255, 255, 0.07);
        }

        /* Modern Top Bar Card */
        .top-navbar {
            background: rgba(15, 23, 42, 0.7);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 14px;
            padding: 14px 20px;
            margin-bottom: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            backdrop-filter: blur(8px);
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        }

        .brand-title {
            font-size: 1.45rem;
            font-weight: 800;
            background: linear-gradient(135deg, #ffffff 30%, #38bdf8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin: 0;
            display: inline-block;
        }

        .badge-pill {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: rgba(56, 189, 248, 0.1);
            color: #38bdf8;
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-radius: 20px;
            padding: 3px 10px;
            font-size: 0.72rem;
            font-weight: 700;
            letter-spacing: 0.04em;
            text-transform: uppercase;
        }

        .badge-pill-success {
            background: rgba(16, 185, 129, 0.1);
            color: #10b981;
            border-color: rgba(16, 185, 129, 0.25);
        }

        /* Minimalist Metric Cards */
        .metric-card {
            background: linear-gradient(135deg, rgba(30, 41, 59, 0.4) 0%, rgba(15, 23, 42, 0.7) 100%);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 16px 18px;
            position: relative;
            overflow: hidden;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.3);
            transition: transform 0.2s ease, border-color 0.2s ease;
        }

        .metric-card:hover {
            transform: translateY(-2px);
            border-color: rgba(255, 255, 255, 0.18);
        }

        .metric-card-accent {
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
        }

        .metric-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 6px;
        }

        .metric-label {
            font-size: 0.72rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #94a3b8;
        }

        .metric-icon {
            font-size: 1.05rem;
            opacity: 0.85;
        }

        .metric-value {
            font-size: 1.85rem;
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            letter-spacing: -0.02em;
            color: #f8fafc;
            line-height: 1.1;
        }

        .metric-delta {
            font-size: 0.72rem;
            margin-top: 6px;
            font-weight: 600;
        }

        /* Chart Card Container */
        .chart-panel-card {
            background: rgba(15, 23, 42, 0.6);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 18px 20px 10px 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.2);
        }

        .chart-panel-title {
            font-size: 0.85rem;
            font-weight: 700;
            color: #cbd5e1;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Tabs Polish */
        .stTabs [data-baseweb="tab-list"] {
            gap: 6px;
            background-color: rgba(15, 23, 42, 0.6);
            padding: 5px;
            border-radius: 10px;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }

        .stTabs [data-baseweb="tab"] {
            border-radius: 8px;
            padding: 8px 18px;
            font-weight: 600;
            font-size: 0.85rem;
            color: #94a3b8;
            border: none !important;
            transition: all 0.2s ease;
        }

        .stTabs [aria-selected="true"] {
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%) !important;
            color: #38bdf8 !important;
            border: 1px solid rgba(56, 189, 248, 0.25) !important;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
        }

        /* Buttons */
        .stButton>button {
            border-radius: 8px;
            font-weight: 600;
            border: 1px solid rgba(255, 255, 255, 0.12);
            transition: all 0.2s ease;
        }

        .stButton>button:hover {
            transform: translateY(-1px);
            border-color: #38bdf8;
            box-shadow: 0 4px 12px rgba(56, 189, 248, 0.15);
        }

        /* Expanders */
        .streamlit-expanderHeader {
            background-color: rgba(15, 23, 42, 0.6) !important;
            border-radius: 8px !important;
            border: 1px solid rgba(255, 255, 255, 0.08) !important;
            font-weight: 600 !important;
            padding: 10px 14px !important;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def init_session_state():
    """Initialize Streamlit session state keys."""
    if "analysis_result" not in st.session_state:
        st.session_state.analysis_result = None
    if "ai_summary" not in st.session_state:
        st.session_state.ai_summary = None
    if "source_type" not in st.session_state:
        st.session_state.source_type = None


def run_analysis(content_bytes: bytes, filename: str, threshold: int):
    """Execute log analysis on uploaded or sample bytes."""
    analyzer = LogAnalyzer(failed_login_threshold=threshold)
    with st.spinner("Analyzing telemetry stream..."):
        result = analyzer.analyze_bytes(content_bytes, filename=filename)
        st.session_state.analysis_result = result
        st.session_state.ai_summary = None


def render_metric_card(label: str, value: str | int, icon: str, color_hex: str, delta: Optional[str] = None):
    """Render a compact glassmorphic metric card."""
    delta_html = f"<div class='metric-delta' style='color: {color_hex};'>{delta}</div>" if delta else "<div class='metric-delta' style='color: #64748b;'>Nominal</div>"
    card_html = f"""
    <div class="metric-card">
        <div class="metric-card-accent" style="background: {color_hex};"></div>
        <div class="metric-header">
            <span class="metric-label">{label}</span>
            <span class="metric-icon">{icon}</span>
        </div>
        <div class="metric-value">{value}</div>
        {delta_html}
    </div>
    """
    st.markdown(card_html, unsafe_allow_html=True)


def render_visual_analytics(result: AnalysisResult):
    """Render clean, horizontal Altair charts without awkward vertical label rotations."""
    st.markdown(
        """
        <div class="chart-panel-card">
            <div class="chart-panel-title">
                <span>📊</span> <span>Telemetry Distribution & Anomaly Spread</span>
            </div>
        """,
        unsafe_allow_html=True,
    )

    chart_col1, chart_col2 = st.columns(2)

    # 1. Severity Chart
    severity_counts = result.metrics.severity_breakdown
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_records = [
        {"Severity": s, "Findings": severity_counts.get(s, 0)}
        for s in sev_order
        if s in severity_counts or severity_counts.get(s, 0) > 0
    ]
    if not sev_records:
        sev_records = [{"Severity": s, "Findings": 0} for s in sev_order]

    sev_df = pd.DataFrame(sev_records)
    color_scale = alt.Scale(
        domain=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        range=["#ef4444", "#f97316", "#eab308", "#38bdf8", "#94a3b8"],
    )

    sev_chart = (
        alt.Chart(sev_df)
        .mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=32)
        .encode(
            x=alt.X(
                "Severity:N",
                sort=sev_order,
                title=None,
                axis=alt.Axis(
                    labelAngle=0,
                    labelColor="#cbd5e1",
                    labelFontSize=11,
                    labelFont="Plus Jakarta Sans",
                ),
            ),
            y=alt.Y(
                "Findings:Q",
                title=None,
                axis=alt.Axis(
                    tickMinStep=1,
                    format="d",
                    labelColor="#94a3b8",
                    gridColor="rgba(255, 255, 255, 0.05)",
                ),
            ),
            color=alt.Color("Severity:N", scale=color_scale, legend=None),
            tooltip=["Severity", "Findings"],
        )
        .properties(title="Findings by Severity Tier", height=210)
        .configure_view(strokeWidth=0)
        .configure_title(color="#e2e8f0", fontSize=12, font="Plus Jakarta Sans", anchor="start")
    )
    chart_col1.altair_chart(sev_chart, use_container_width=True)

    # 2. Category Chart
    cat_counts = result.metrics.category_breakdown
    if cat_counts:
        cat_df = pd.DataFrame([
            {"Category": k.replace("_", " ").title(), "Count": v}
            for k, v in sorted(cat_counts.items(), key=lambda x: x[1], reverse=True)
        ])
        cat_chart = (
            alt.Chart(cat_df)
            .mark_bar(cornerRadiusTopRight=4, cornerRadiusBottomRight=4, color="#818cf8", size=22)
            .encode(
                x=alt.X(
                    "Count:Q",
                    title=None,
                    axis=alt.Axis(
                        tickMinStep=1,
                        format="d",
                        labelColor="#94a3b8",
                        gridColor="rgba(255, 255, 255, 0.05)",
                    ),
                ),
                y=alt.Y(
                    "Category:N",
                    sort="-x",
                    title=None,
                    axis=alt.Axis(
                        labelAngle=0,
                        labelColor="#cbd5e1",
                        labelFontSize=11,
                        labelFont="Plus Jakarta Sans",
                    ),
                ),
                tooltip=["Category", "Count"],
            )
            .properties(title="Events by Detection Category", height=210)
            .configure_view(strokeWidth=0)
            .configure_title(color="#e2e8f0", fontSize=12, font="Plus Jakarta Sans", anchor="start")
        )
        chart_col2.altair_chart(cat_chart, use_container_width=True)

    st.markdown("</div>", unsafe_allow_html=True)


def main():
    """Main application layout and control flow."""
    inject_custom_styles()
    init_session_state()

    # Sidebar Header
    st.sidebar.markdown(
        """
        <div style="font-size: 1.15rem; font-weight: 800; color: #f8fafc; padding: 2px 0 12px 0; border-bottom: 1px solid rgba(255, 255, 255, 0.08); margin-bottom: 14px; display: flex; align-items: center; gap: 8px;">
            <span>🛡️</span> <span>Log Analyzer</span>
        </div>
        <div style="font-size: 0.72rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 6px;">
            Ingestion File
        </div>
        """,
        unsafe_allow_html=True,
    )

    uploaded_file = st.sidebar.file_uploader(
        "Upload Log",
        type=["log", "txt", "json", "jsonl"],
        label_visibility="collapsed",
    )

    # Sample Datasets & Clear
    st.sidebar.markdown(
        """
        <div style="font-size: 0.72rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.06em; text-transform: uppercase; margin: 10px 0 6px 0;">
            Sample Datasets
        </div>
        """,
        unsafe_allow_html=True,
    )
    col_s1, col_s2 = st.sidebar.columns(2)
    load_sample_text = col_s1.button("📄 Text Log", use_container_width=True)
    load_sample_json = col_s2.button("📦 JSON Log", use_container_width=True)
    clear_data = st.sidebar.button("🧹 Reset Workspace", use_container_width=True)

    if clear_data:
        st.session_state.analysis_result = None
        st.session_state.ai_summary = None
        st.session_state.source_type = None
        st.rerun()

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        """
        <div style="font-size: 0.72rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 6px;">
            Detection Rules
        </div>
        """,
        unsafe_allow_html=True,
    )
    failed_login_threshold = st.sidebar.slider(
        "Failed Login Threshold",
        min_value=1,
        max_value=10,
        value=DEFAULT_FAILED_LOGIN_THRESHOLD,
    )

    st.sidebar.markdown(
        """
        <div style="font-size: 0.72rem; font-weight: 700; color: #94a3b8; letter-spacing: 0.06em; text-transform: uppercase; margin: 10px 0 6px 0;">
            Local AI Engine
        </div>
        """,
        unsafe_allow_html=True,
    )
    ollama_host = st.sidebar.text_input("Ollama Endpoint", value=DEFAULT_OLLAMA_HOST)
    ollama_model = st.sidebar.text_input("Model Name", value=DEFAULT_OLLAMA_MODEL)

    summarizer = OllamaSummarizer(host=ollama_host, model=ollama_model)
    ollama_ok, _ = summarizer.check_ollama_status()

    if ollama_ok:
        st.sidebar.success(f"🟢 Ollama Ready ({ollama_model})")
    else:
        st.sidebar.info("⚪ Ollama Offline (Fallback active)")

    # Data ingestion handlers
    if load_sample_text and SAMPLE_LOG_PATH.exists():
        st.session_state.source_type = "sample.log"
        run_analysis(SAMPLE_LOG_PATH.read_bytes(), "sample.log", failed_login_threshold)
        st.rerun()

    if load_sample_json and SAMPLE_JSON_PATH.exists():
        st.session_state.source_type = "sample_json.jsonl"
        run_analysis(SAMPLE_JSON_PATH.read_bytes(), "sample_json.jsonl", failed_login_threshold)
        st.rerun()

    if uploaded_file is not None:
        file_bytes = uploaded_file.getvalue()
        if len(file_bytes) > DEFAULT_MAX_UPLOAD_MB * 1024 * 1024:
            st.error(f"File exceeds {DEFAULT_MAX_UPLOAD_MB} MB limit.")
            return
        elif len(file_bytes) == 0:
            st.warning("Uploaded file is empty.")
            return
        elif (
            st.session_state.analysis_result is None
            or st.session_state.analysis_result.filename != uploaded_file.name
        ):
            st.session_state.source_type = uploaded_file.name
            run_analysis(file_bytes, uploaded_file.name, failed_login_threshold)
            st.rerun()

    result: Optional[AnalysisResult] = st.session_state.analysis_result

    # Modern Top Navigation Bar
    active_filename = result.filename if result else "No File Loaded"
    status_badge = (
        '<span class="badge-pill badge-pill-success">● Telemetry Loaded</span>'
        if result
        else '<span class="badge-pill">● Waiting for Log</span>'
    )

    st.markdown(
        f"""
        <div class="top-navbar">
            <div style="display: flex; align-items: center; gap: 14px;">
                <h1 class="brand-title">AI Log Analyzer</h1>
                <span class="badge-pill">Air-Gapped & Private</span>
                {status_badge}
            </div>
            <div style="font-size: 0.82rem; color: #94a3b8; font-family: 'JetBrains Mono', monospace;">
                Target: <span style="color: #f1f5f9; font-weight: 600;">{active_filename}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if result is None:
        st.info("Upload a log file or click **📄 Text Log** / **📦 JSON Log** in the sidebar to begin.")
        return

    # Metrics Row
    m = result.metrics
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    with col1:
        render_metric_card("Lines", f"{m.total_lines:,}", "📄", "#38bdf8")
    with col2:
        render_metric_card("Critical", m.critical_count, "🚨", "#ef4444", delta=f"{m.critical_count} Alert" if m.critical_count else None)
    with col3:
        render_metric_card("Errors", m.error_count, "⚠️", "#f97316", delta=f"{m.error_count} Unhandled" if m.error_count else None)
    with col4:
        render_metric_card("Warnings", m.warning_count, "🔔", "#eab308")
    with col5:
        render_metric_card("Auth Fails", m.failed_auth_count, "🔒", "#00f2fe")
    with col6:
        render_metric_card("IP Leads", m.repeated_login_count, "🎯", "#a855f7", delta=f"{m.repeated_login_count} Flagged" if m.repeated_login_count else None)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Integrated Visual Analytics
    render_visual_analytics(result)

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # Tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "Findings & Evidence",
        "AI Executive Summary",
        "Raw Log Explorer",
        "Export & Reports",
    ])

    with tab1:
        filter_col1, filter_col2, filter_col3, view_col = st.columns([1.1, 1.1, 2.2, 1.2])
        all_severities = ["ALL"] + sorted(list({f.severity for f in result.findings}))
        all_categories = ["ALL"] + sorted(list({f.category for f in result.findings}))

        selected_sev = filter_col1.selectbox("Filter Severity", all_severities)
        selected_cat = filter_col2.selectbox("Filter Category", all_categories)
        search_query = filter_col3.text_input("Search Findings", placeholder="Filter by IP, rule, keyword...")
        view_mode = view_col.radio("View", ["Alert Feed", "Data Table"], horizontal=True, label_visibility="collapsed")

        filtered = result.filter_findings(
            severity_filter=selected_sev,
            category_filter=selected_cat,
            search_query=search_query,
        )

        st.markdown(
            f"<div style='font-size: 0.82rem; font-weight: 600; color: #94a3b8; margin: 4px 0 12px 0;'>"
            f"Showing <span style='color: #38bdf8; font-weight: 700;'>{len(filtered)}</span> of {len(result.findings)} detected findings"
            f"</div>",
            unsafe_allow_html=True,
        )

        if not filtered:
            st.info("No matching findings found.")
        elif view_mode == "Data Table":
            table_data = [
                {
                    "ID": f.finding_id,
                    "Severity": f.severity,
                    "Category": f.category,
                    "Summary": f.summary,
                    "Source IP": f.source_ip or "N/A",
                    "Timestamp": f.timestamp or "N/A",
                    "Rule": f.rule_name,
                }
                for f in filtered
            ]
            st.dataframe(pd.DataFrame(table_data), use_container_width=True, hide_index=True)
        else:
            # Unified Security Alert Feed
            for f in filtered:
                sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(f.severity, "⚪")
                sev_color = {
                    "CRITICAL": "#ef4444",
                    "HIGH": "#f97316",
                    "MEDIUM": "#eab308",
                    "LOW": "#38bdf8",
                    "INFO": "#94a3b8",
                }.get(f.severity, "#94a3b8")

                card_title = f"{sev_icon} [{f.severity}] {f.summary}  •  {f.finding_id}"
                with st.expander(card_title):
                    meta1, meta2, meta3, meta4 = st.columns(4)
                    meta1.markdown(f"<div class='alert-meta-chip'>🏷️ {f.category}</div>", unsafe_allow_html=True)
                    meta2.markdown(f"<div class='alert-meta-chip'>🛡️ {f.rule_name}</div>", unsafe_allow_html=True)
                    meta3.markdown(f"<div class='alert-meta-chip'>🌐 {f.source_ip or 'No IP'}</div>", unsafe_allow_html=True)
                    meta4.markdown(f"<div class='alert-meta-chip'>⏱️ {f.timestamp or 'No Timestamp'}</div>", unsafe_allow_html=True)

                    st.markdown(
                        f"""
                        <div class="alert-triage-box" style="background: rgba(15, 23, 42, 0.6); border-left: 3px solid {sev_color}; padding: 10px 14px; border-radius: 6px; margin: 10px 0;">
                            <div class="alert-triage-title">Recommended Triage</div>
                            <div class="alert-triage-body">{f.recommended_step}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    if f.limitations:
                        st.caption(f"ℹ️ Analysis Boundary: {f.limitations}")

                    st.markdown("**Supporting Telemetry Lines:**")
                    for ev in f.evidence:
                        st.code(ev, language="text")

    with tab2:
        generate_col, _ = st.columns([1, 3])
        if generate_col.button("⚡ Generate AI Summary", type="primary", use_container_width=True):
            with st.spinner("Synthesizing log findings..."):
                st.session_state.ai_summary = summarizer.generate_summary(result)

        if st.session_state.ai_summary:
            st.markdown(st.session_state.ai_summary.summary_text)

    with tab3:
        lines_to_show = st.slider("Display lines limit", 10, max(10, min(1000, len(result.entries))), min(50, len(result.entries)))
        st.dataframe(pd.DataFrame([e.to_dict() for e in result.entries[:lines_to_show]]), use_container_width=True, hide_index=True)

    with tab4:
        summary_val = st.session_state.ai_summary.summary_text if st.session_state.ai_summary else "N/A"
        csv_data = generate_csv_report(result.findings)
        txt_data = generate_text_report(result, ai_summary=summary_val)

        export_col1, export_col2 = st.columns(2)
        export_col1.download_button("📥 Download CSV Findings", csv_data, f"{result.filename}_findings.csv", "text/csv", use_container_width=True)
        export_col2.download_button("📄 Download Text Report", txt_data, f"{result.filename}_report.txt", "text/plain", use_container_width=True)


if __name__ == "__main__":
    main()
