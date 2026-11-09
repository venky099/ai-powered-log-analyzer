"""AI-Powered Log Analyzer - Streamlit dashboard for triaging log files.

Parses syslogs and structured JSON-lines, flags anomalies using deterministic
rules, and provides executive summaries via Google Gemini or local fallback.
"""

from __future__ import annotations

import html
import os
from pathlib import Path
from typing import Optional

import altair as alt
import pandas as pd
import streamlit as st

from dotenv import load_dotenv

# Ensure .env is loaded on startup
load_dotenv()

from src.ai_summarizer import GeminiSummarizer
from src.analyzer import AnalysisResult, LogAnalyzer
from src.report_generator import generate_csv_report, generate_text_report


# Configuration defaults
DEFAULT_MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "2"))
DEFAULT_FAILED_LOGIN_THRESHOLD = int(os.getenv("FAILED_LOGIN_THRESHOLD", "3"))
DEFAULT_GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
DEFAULT_GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_POPULAR_MODELS = [
    "gemini-2.5-flash",
    "gemini-2.0-flash",
    "gemini-1.5-flash",
    "gemini-2.5-pro",
    "gemini-3.8-flash",
    "Custom...",
]
SAMPLE_LOG_PATH = Path(__file__).parent / "sample_logs" / "sample.log"
SAMPLE_JSON_PATH = Path(__file__).parent / "sample_logs" / "sample_json.jsonl"

# Page configuration
st.set_page_config(
    page_title="AI Log Analyzer | SOC Workbench",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


STYLE_CSS_PATH = Path(__file__).parent / "assets" / "style.css"


def inject_custom_styles():
    """Inject modern dark theme CSS from assets/style.css."""
    if STYLE_CSS_PATH.is_file():
        css = STYLE_CSS_PATH.read_text(encoding="utf-8")
        st.markdown(f"<style>{css}</style>", unsafe_allow_html=True)


def init_session_state():
    """Initialize Streamlit session state keys."""
    if "analysis_result" not in st.session_state:
        st.session_state.analysis_result = None
    if "ai_summary" not in st.session_state:
        st.session_state.ai_summary = None
    if "active_bytes" not in st.session_state:
        st.session_state.active_bytes = None
    if "active_threshold" not in st.session_state:
        st.session_state.active_threshold = DEFAULT_FAILED_LOGIN_THRESHOLD


def run_analysis(content_bytes: bytes, filename: str, threshold: int):
    """Execute log analysis on uploaded or sample bytes."""
    analyzer = LogAnalyzer(failed_login_threshold=threshold)
    with st.spinner("Analyzing telemetry stream..."):
        result = analyzer.analyze_bytes(content_bytes, filename=filename)
        st.session_state.analysis_result = result
        st.session_state.ai_summary = None


def render_metric_card(label: str, value: str | int, icon: str, color_hex: str, delta: Optional[str] = None):
    """Render a compact glassmorphic metric card."""
    safe_label = html.escape(str(label))
    safe_value = html.escape(str(value))
    safe_delta = html.escape(str(delta)) if delta else "Nominal"
    delta_color = color_hex if delta else "#64748b"
    delta_html = f"<div class='metric-delta' style='color: {delta_color};'>{safe_delta}</div>"
    card_html = f"""
    <div class="metric-card">
        <div class="metric-card-accent" style="background: {color_hex};"></div>
        <div class="metric-header">
            <span class="metric-label">{safe_label}</span>
            <span class="metric-icon">{icon}</span>
        </div>
        <div class="metric-value">{safe_value}</div>
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
                    labelFont="sans-serif",
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
        .configure_title(color="#e2e8f0", fontSize=12, font="sans-serif", anchor="start")
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
                        labelFont="sans-serif",
                    ),
                ),
                tooltip=["Category", "Count"],
            )
            .properties(title="Events by Detection Category", height=210)
            .configure_view(strokeWidth=0)
            .configure_title(color="#e2e8f0", fontSize=12, font="sans-serif", anchor="start")
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
        st.session_state.active_bytes = None
        st.session_state.active_threshold = DEFAULT_FAILED_LOGIN_THRESHOLD
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
            Gemini AI Engine
        </div>
        """,
        unsafe_allow_html=True,
    )
    configured_env_key = os.getenv("GEMINI_API_KEY", "").strip()
    gemini_api_key = st.sidebar.text_input(
        "Gemini API Key",
        value=configured_env_key,
        type="password",
        help="Leave blank to use GEMINI_API_KEY from .env, or paste a new key here",
    )

    model_default_idx = (
        GEMINI_POPULAR_MODELS.index(DEFAULT_GEMINI_MODEL)
        if DEFAULT_GEMINI_MODEL in GEMINI_POPULAR_MODELS[:-1]
        else 0
    )
    selected_model = st.sidebar.selectbox(
        "Model Identifier",
        GEMINI_POPULAR_MODELS,
        index=model_default_idx,
    )
    if selected_model == "Custom...":
        gemini_model = st.sidebar.text_input("Custom Model", value=DEFAULT_GEMINI_MODEL)
    else:
        gemini_model = selected_model

    active_key = gemini_api_key.strip() or configured_env_key
    summarizer = GeminiSummarizer(api_key=active_key, model=gemini_model)
    gemini_ok, _ = summarizer.check_gemini_status(validate_online=False)

    if gemini_ok:
        st.sidebar.success(f"🟢 Gemini Ready ({gemini_model})")
    else:
        st.sidebar.info("⚪ API Key Required (Fallback active)")

    # Data ingestion handlers
    if load_sample_text and SAMPLE_LOG_PATH.exists():
        sample_bytes = SAMPLE_LOG_PATH.read_bytes()
        st.session_state.active_bytes = sample_bytes
        st.session_state.active_threshold = failed_login_threshold
        run_analysis(sample_bytes, "sample.log", failed_login_threshold)
        st.rerun()

    if load_sample_json and SAMPLE_JSON_PATH.exists():
        sample_json_bytes = SAMPLE_JSON_PATH.read_bytes()
        st.session_state.active_bytes = sample_json_bytes
        st.session_state.active_threshold = failed_login_threshold
        run_analysis(sample_json_bytes, "sample_json.jsonl", failed_login_threshold)
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
            or st.session_state.get("active_threshold") != failed_login_threshold
        ):
            st.session_state.active_bytes = file_bytes
            st.session_state.active_threshold = failed_login_threshold
            run_analysis(file_bytes, uploaded_file.name, failed_login_threshold)
            st.rerun()
    elif (
        st.session_state.get("active_bytes") is not None
        and st.session_state.get("analysis_result") is not None
        and st.session_state.get("active_threshold") != failed_login_threshold
    ):
        st.session_state.active_threshold = failed_login_threshold
        run_analysis(
            st.session_state.active_bytes,
            st.session_state.analysis_result.filename,
            failed_login_threshold,
        )
        st.rerun()

    result: Optional[AnalysisResult] = st.session_state.analysis_result

    # Modern Top Navigation Bar
    raw_filename = result.filename if result else "No File Loaded"
    active_filename = html.escape(raw_filename)
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
                <span class="badge-pill">Google Gemini Powered</span>
                {status_badge}
            </div>
            <div style="font-size: 0.82rem; color: #94a3b8; font-family: ui-monospace, SFMono-Regular, Menlo, monospace;">
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
                    safe_cat = html.escape(str(f.category))
                    safe_rule = html.escape(str(f.rule_name))
                    safe_ip = html.escape(str(f.source_ip or 'No IP'))
                    safe_ts = html.escape(str(f.timestamp or 'No Timestamp'))
                    safe_step = html.escape(str(f.recommended_step))

                    meta1.markdown(f"<div class='alert-meta-chip'>🏷️ {safe_cat}</div>", unsafe_allow_html=True)
                    meta2.markdown(f"<div class='alert-meta-chip'>🛡️ {safe_rule}</div>", unsafe_allow_html=True)
                    meta3.markdown(f"<div class='alert-meta-chip'>🌐 {safe_ip}</div>", unsafe_allow_html=True)
                    meta4.markdown(f"<div class='alert-meta-chip'>⏱️ {safe_ts}</div>", unsafe_allow_html=True)

                    st.markdown(
                        f"""
                        <div class="alert-triage-box" style="background: rgba(15, 23, 42, 0.6); border-left: 3px solid {sev_color}; padding: 10px 14px; border-radius: 6px; margin: 10px 0;">
                            <div class="alert-triage-title">Recommended Triage</div>
                            <div class="alert-triage-body">{safe_step}</div>
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
            with st.spinner(f"Synthesizing log findings with Gemini ({gemini_model})..."):
                st.session_state.ai_summary = summarizer.generate_summary(result)

        if st.session_state.ai_summary:
            st.markdown(st.session_state.ai_summary.summary_text)

    with tab3:
        total_entries = len(result.entries)
        if total_entries <= 10:
            st.dataframe(pd.DataFrame([e.to_dict() for e in result.entries]), use_container_width=True, hide_index=True)
        else:
            max_limit = min(1000, total_entries)
            default_limit = min(50, total_entries)
            lines_to_show = st.slider("Display lines limit", min_value=10, max_value=max_limit, value=default_limit)
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
