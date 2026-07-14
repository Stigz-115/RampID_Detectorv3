"""
RampID Detector – Streamlit Application
========================================

A pre-sales scoping tool for detecting LiveRamp / RampID usage on prospect websites.

Features:
  1. **Website Scanner** – Inspects a prospect's website for:
     - rlcdn.com network calls (LiveRamp's ID sync endpoint)
     - RampID identifiers in cookies and page content (XY/Xi + 4 digits + hash)
     - LiveRamp script references (ats.js, enabler.js, etc.)
     - Uses Playwright (full browser, JS rendering) or Requests (static HTML)

  2. **Web Research** – Searches the open web for public evidence of LiveRamp
     partnerships via press releases, case studies, and news articles.
     Supports DuckDuckGo (free) and Google Custom Search API.
"""

import streamlit as st
import re

from patterns import ScanResult, RampIDMatch, LIVERAMP_DOMAINS, RAMPID_KEYWORDS
from scanner import scan_website, normalize_url
from researcher import (
    ResearchReport, SearchResult,
    search_duckduckgo, search_google,
)


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title="RampID Detector",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------

st.markdown("""
<style>
    .main-header {
        font-size: 2rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.1rem;
        color: #888;
        margin-bottom: 1.5rem;
    }
    .confidence-high { color: #1a8a3a; font-weight: 700; }
    .confidence-medium { color: #c98a00; font-weight: 700; }
    .confidence-low { color: #cc6600; font-weight: 700; }
    .confidence-none { color: #888; font-weight: 700; }
    .result-card {
        background: #1a1a2e;
        border: 1px solid #333;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 0.75rem;
    }
    .match-value {
        font-family: monospace;
        font-size: 0.85rem;
        background: #0d1117;
        padding: 0.3rem 0.5rem;
        border-radius: 4px;
        border: 1px solid #333;
        word-break: break-all;
    }
    .signal-badge {
        display: inline-block;
        padding: 0.15rem 0.6rem;
        border-radius: 12px;
        font-size: 0.75rem;
        font-weight: 600;
        margin-right: 0.3rem;
    }
    .signal-found { background: #1a3a1a; color: #4caf50; }
    .signal-none { background: #3a1a1a; color: #f44336; }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

st.sidebar.markdown("## ⚙️ Settings")

# Scanner settings
st.sidebar.markdown("### Scanner")
scan_mode = st.sidebar.radio(
    "Scan Mode",
    options=["playwright", "requests"],
    format_func=lambda x: "Playwright (Full Browser)" if x == "playwright" else "Requests (Static HTML)",
    help="Playwright launches a headless browser to intercept network calls like Chrome Dev Tools. "
         "Requests is faster but only sees static HTML.",
)
scan_timeout = st.sidebar.slider(
    "Scan Timeout (seconds)",
    min_value=10, max_value=60, value=30, step=5,
)

# Research settings
st.sidebar.markdown("### Web Research")
search_engine = st.sidebar.radio(
    "Search Engine",
    options=["DuckDuckGo", "Google"],
    format_func=lambda x: f"{x} ({'Free' if x == 'DuckDuckGo' else 'API Key Required'})",
    help="DuckDuckGo is free with no setup. Google Custom Search requires an API key and CX ID.",
)

google_api_key = ""
google_cx_id = ""
if search_engine == "Google":
    google_api_key = st.sidebar.text_input("Google API Key", type="password")
    google_cx_id = st.sidebar.text_input("Google Custom Search Engine ID")

max_results = st.sidebar.slider(
    "Max Search Results",
    min_value=5, max_value=50, value=20, step=5,
)

# Info section
st.sidebar.markdown("---")
st.sidebar.markdown("### About")
st.sidebar.markdown("""
**RampID Detector** identifies LiveRamp / RampID usage on prospect websites for
pre-sales scoping.

**Detection signals:**
- `rlcdn.com` network calls
- RampID cookies (`XY`/`Xi` + 4 digits + hash)
- LiveRamp script references (ats.js, etc.)
- Public partnership evidence
""")


# ---------------------------------------------------------------------------
# Display helper functions (defined before tabs that use them)
# ---------------------------------------------------------------------------

def _display_scan_result(result: ScanResult):
    """Render a ScanResult in the UI."""
    if result.error:
        st.error(f"Scan error: {result.error}")
        return

    # Header with confidence
    conf_class = f"confidence-{result.confidence.lower()}"
    st.markdown(f"### Results: {result.url}")
    st.markdown(f"**Scan Mode:** {result.scan_mode} | **Page Title:** {result.page_title or 'N/A'}")
    st.markdown(f"**Confidence:** <span class='{conf_class}'>{result.confidence}</span>", unsafe_allow_html=True)
    st.markdown(f"**Summary:** {result.summary}")

    st.markdown("---")

    col_a, col_b, col_c, col_d = st.columns(4)

    with col_a:
        badge = "signal-found" if result.rlcdn_requests else "signal-none"
        label = "Found" if result.rlcdn_requests else "None"
        st.markdown(f"""
        <div class="result-card" style="text-align:center;">
            <div style="font-size:0.8rem;color:#888;">rlcdn.com Calls</div>
            <div style="font-size:1.8rem;font-weight:700;">{len(result.rlcdn_requests)}</div>
            <span class="signal-badge {badge}">{label}</span>
        </div>
        """, unsafe_allow_html=True)

    with col_b:
        badge = "signal-found" if result.rampid_matches else "signal-none"
        label = "Found" if result.rampid_matches else "None"
        st.markdown(f"""
        <div class="result-card" style="text-align:center;">
            <div style="font-size:0.8rem;color:#888;">RampID Identifiers</div>
            <div style="font-size:1.8rem;font-weight:700;">{len(result.rampid_matches)}</div>
            <span class="signal-badge {badge}">{label}</span>
        </div>
        """, unsafe_allow_html=True)

    with col_c:
        badge = "signal-found" if result.script_references else "signal-none"
        label = "Found" if result.script_references else "None"
        st.markdown(f"""
        <div class="result-card" style="text-align:center;">
            <div style="font-size:0.8rem;color:#888;">Script References</div>
            <div style="font-size:1.8rem;font-weight:700;">{len(result.script_references)}</div>
            <span class="signal-badge {badge}">{label}</span>
        </div>
        """, unsafe_allow_html=True)

    with col_d:
        badge = "signal-found" if result.cookie_matches else "signal-none"
        label = "Found" if result.cookie_matches else "None"
        st.markdown(f"""
        <div class="result-card" style="text-align:center;">
            <div style="font-size:0.8rem;color:#888;">Cookie Matches</div>
            <div style="font-size:1.8rem;font-weight:700;">{len(result.cookie_matches)}</div>
            <span class="signal-badge {badge}">{label}</span>
        </div>
        """, unsafe_allow_html=True)

    # --- rlcdn network calls ---
    if result.rlcdn_requests:
        st.markdown("### 🌐 rlcdn.com Network Calls")
        for i, req in enumerate(result.rlcdn_requests, 1):
            st.markdown(f"**{i}.** `{req.get('method', 'GET')}` — {req.get('resource_type', 'unknown')}")
            st.code(req["url"], language="text")

    # --- Other LiveRamp network calls ---
    if result.liveramp_requests:
        st.markdown("### 🔗 Other LiveRamp Domain Requests")
        for i, req in enumerate(result.liveramp_requests, 1):
            st.markdown(f"**{i}.** `{req.get('method', 'GET')}` — {req.get('resource_type', 'unknown')}")
            st.code(req["url"], language="text")

    # --- RampID identifiers ---
    if result.rampid_matches:
        st.markdown("### 🆔 RampID Identifiers Found")
        for i, match in enumerate(result.rampid_matches, 1):
            st.markdown(f"""
            <div class="result-card">
                <strong>{i}.</strong> <span class="signal-badge signal-found">{match.variant}</span>
                <span class="signal-badge signal-found">{match.length} chars</span>
                <span class="signal-badge signal-found">source: {match.source}</span>
                <div class="match-value" style="margin-top:0.5rem;">{match.value}</div>
            </div>
            """, unsafe_allow_html=True)

    # --- Script references ---
    if result.script_references:
        st.markdown("### 📜 LiveRamp Script References")
        for i, ref in enumerate(result.script_references, 1):
            st.markdown(f"**{i}.** {ref}")

    # --- Cookie matches ---
    if result.cookie_matches:
        st.markdown("### 🍪 Cookie Matches")
        for i, cookie in enumerate(result.cookie_matches, 1):
            note = cookie.get("note", "")
            rampids = cookie.get("rampids_found", [])
            st.markdown(f"""
            <div class="result-card">
                <strong>{i}.</strong> <code>{cookie.get('name', '?')}</code>
                <span style="color:#888;">domain: {cookie.get('domain', '?')}</span>
                {f'<br><em>{note}</em>' if note else ''}
                {f'<br>RampIDs: {", ".join(rampids)}' if rampids else ''}
                <div class="match-value" style="margin-top:0.5rem;">{cookie.get('value_preview', '')}</div>
            </div>
            """, unsafe_allow_html=True)

    # --- No signals found ---
    if not result.has_rampid:
        st.info("✅ No RampID / LiveRamp signals were detected on this website. "
                "The prospect may not be using LiveRamp, or their implementation may be "
                "behind a consent layer that blocks tracking scripts without user interaction.")


def _display_search_result(index: int, result: SearchResult):
    """Render a single SearchResult."""
    score_pct = int(result.relevance_score * 100)
    score_color = "#4caf50" if score_pct >= 50 else "#c98a00" if score_pct >= 30 else "#888"

    indicators_html = ""
    if result.indicators:
        indicators_html = " ".join(
            f'<span class="signal-badge signal-found">{ind}</span>'
            for ind in result.indicators
        )

    st.markdown(f"""
    <div class="result-card">
        <div style="display:flex;justify-content:space-between;align-items:start;">
            <div style="flex:1;">
                <strong>{index}. <a href="{result.url}" target="_blank" style="color:#4da6ff;text-decoration:none;">{result.title}</a></strong><br>
                <span style="color:#888;font-size:0.8rem;">{result.url}</span>
            </div>
            <div style="text-align:right;min-width:60px;">
                <span style="font-size:1.2rem;font-weight:700;color:{score_color};">{score_pct}%</span>
            </div>
        </div>
        <p style="margin-top:0.5rem;color:#aaa;font-size:0.9rem;">{result.snippet}</p>
        {f'<div style="margin-top:0.3rem;">{indicators_html}</div>' if indicators_html else ''}
    </div>
    """, unsafe_allow_html=True)


def _display_research_report(report: ResearchReport):
    """Render a ResearchReport in the UI."""
    if report.error and not report.results:
        st.error(f"Research error: {report.error}")
        return

    conf_class = f"confidence-{report.confidence.lower()}"
    st.markdown(f"### Research Report: {report.company}")
    st.markdown(f"**Search Engine:** {report.search_engine} | **Results:** {report.result_count}")
    st.markdown(f"**Partnership Evidence:** <span class='{conf_class}'>{report.confidence}</span>", unsafe_allow_html=True)
    st.markdown(f"**Summary:** {report.summary}")

    st.markdown("---")

    if not report.results:
        st.info("No results found. Try a different company name or search engine.")
        return

    # High confidence results first
    high = report.high_confidence_results
    if high:
        st.markdown(f"### ⭐ High-Relevance Results ({len(high)})")
        for i, r in enumerate(high, 1):
            _display_search_result(i, r)

    # Lower confidence results
    low = [r for r in report.results if r.relevance_score < 0.5]
    if low:
        with st.expander(f"Other Results ({len(low)})", expanded=False):
            for i, r in enumerate(low, 1):
                _display_search_result(i, r)


# ---------------------------------------------------------------------------
# Main content
# ---------------------------------------------------------------------------

st.markdown('<div class="main-header">🔍 RampID Detector</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Detect LiveRamp / RampID usage on prospect websites</div>', unsafe_allow_html=True)

tab_scan, tab_research, tab_combined = st.tabs(["🌐 Website Scanner", "🔎 Web Research", "🚀 Combined Scan"])


# ---------------------------------------------------------------------------
# Tab 1: Website Scanner
# ---------------------------------------------------------------------------

with tab_scan:
    col1, col2 = st.columns([3, 1])
    with col1:
        scan_url = st.text_input(
            "Website URL",
            placeholder="e.g., https://www.example.com",
            key="scan_url_input",
        )
    with col2:
        st.markdown("&nbsp;")
        scan_btn = st.button("🔍 Scan Website", type="primary", use_container_width=True)

    if scan_btn:
        if not scan_url.strip():
            st.warning("Please enter a website URL.")
        else:
            url = normalize_url(scan_url)
            st.info(f"Scanning **{url}** using **{scan_mode}** mode...")

            with st.spinner("Scanning website for RampID / LiveRamp signals..."):
                result = scan_website(url, mode=scan_mode, timeout_ms=scan_timeout * 1000)

            _display_scan_result(result)


# ---------------------------------------------------------------------------
# Tab 2: Web Research
# ---------------------------------------------------------------------------

with tab_research:
    col1, col2 = st.columns([3, 1])
    with col1:
        company_name = st.text_input(
            "Company Name",
            placeholder="e.g., Acme Corp",
            key="research_company_input",
        )
    with col2:
        st.markdown("&nbsp;")
        research_btn = st.button("🔎 Research", type="primary", use_container_width=True, key="research_btn")

    if research_btn:
        if not company_name.strip():
            st.warning("Please enter a company name.")
        elif search_engine == "Google" and (not google_api_key or not google_cx_id):
            st.warning("Google Custom Search requires both an API key and CX ID. Enter them in the sidebar or switch to DuckDuckGo.")
        else:
            st.info(f"Researching **{company_name}** via **{search_engine}**...")

            with st.spinner("Searching the web for LiveRamp partnership evidence..."):
                if search_engine == "DuckDuckGo":
                    report = search_duckduckgo(company_name, max_results=max_results)
                else:
                    report = search_google(company_name, google_api_key, google_cx_id, max_results=max_results)

            _display_research_report(report)


# ---------------------------------------------------------------------------
# Tab 3: Combined Scan
# ---------------------------------------------------------------------------

with tab_combined:
    st.markdown("""
    Run both the website scanner and web research in one shot.
    Enter a company name and website URL to get a comprehensive report.
    """)

    col1, col2 = st.columns(2)
    with col1:
        combined_company = st.text_input("Company Name", placeholder="e.g., Acme Corp", key="combined_company")
    with col2:
        combined_url = st.text_input("Website URL", placeholder="e.g., https://www.example.com", key="combined_url")

    combined_btn = st.button("🚀 Run Combined Scan", type="primary", use_container_width=True)

    if combined_btn:
        if not combined_company.strip() and not combined_url.strip():
            st.warning("Please enter at least a company name or website URL.")
        else:
            results_collected = {}

            # --- Website scan ---
            if combined_url.strip():
                st.markdown("### 🌐 Website Scan")
                with st.spinner("Scanning website..."):
                    url = normalize_url(combined_url)
                    scan_result = scan_website(url, mode=scan_mode, timeout_ms=scan_timeout * 1000)
                    _display_scan_result(scan_result)
                    results_collected["scan"] = scan_result

            # --- Web research ---
            if combined_company.strip():
                st.markdown("---")
                st.markdown("### 🔎 Web Research")
                if search_engine == "Google" and (not google_api_key or not google_cx_id):
                    st.warning("Google Custom Search requires API key and CX ID. Skipping research. Switch to DuckDuckGo in the sidebar.")
                else:
                    with st.spinner("Searching the web..."):
                        if search_engine == "DuckDuckGo":
                            report = search_duckduckgo(combined_company, max_results=max_results)
                        else:
                            report = search_google(combined_company, google_api_key, google_cx_id, max_results=max_results)
                        _display_research_report(report)
                        results_collected["research"] = report

            # --- Overall verdict ---
            if results_collected:
                st.markdown("---")
                st.markdown("## 📊 Overall Verdict")

                scan = results_collected.get("scan")
                research = results_collected.get("research")

                verdict_parts = []

                if scan:
                    if scan.has_rampid:
                        verdict_parts.append(f"✅ **Website:** RampID detected ({scan.confidence} confidence)")
                    else:
                        verdict_parts.append("❌ **Website:** No RampID signals detected")

                if research:
                    verdict_parts.append(f"📋 **Web Research:** Partnership evidence = {research.confidence}")

                for part in verdict_parts:
                    st.markdown(f"- {part}")

                # Overall recommendation
                scan_positive = scan.has_rampid if scan else False
                research_positive = research and research.confidence in ("High", "Medium") if research else False

                if scan_positive and research_positive:
                    st.success("🎯 **Strong prospect** – Both technical signals and public evidence indicate LiveRamp usage.")
                elif scan_positive:
                    st.info("💡 **Technical signals detected** – RampID is present on the website but limited public evidence found. May be a recent or private deployment.")
                elif research_positive:
                    st.info("💡 **Public evidence found** – Partnership mentions exist but no live RampID detected. Implementation may be partial, retired, or behind consent layers.")
                else:
                    st.warning("📭 **No signals found** – No RampID detected on website or in public sources. Prospect likely not using LiveRamp.")
