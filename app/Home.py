import streamlit as st
import database as db
import os
from styles import apply_custom_styles, get_icon_path, get_icon_base64
from auth import require_auth, get_current_user
from dotenv import load_dotenv
load_dotenv()
version = os.getenv('TIDE_VERSION', 'v1.0.0')

# Page Config
st.set_page_config(page_title="TIDE", page_icon=get_icon_path("tide.png"), layout="wide", initial_sidebar_state="expanded")
apply_custom_styles()

# Initialize database (ensures schema is up to date)
try:
    db.init_db()
except Exception as e:
    st.error(f"⚠️ Database initialization failed: {e}")

# Authentication Gate - must be authenticated to proceed
require_auth()

# Fetch Quick Stats
try:
    rule_health = db.get_rule_health_metrics()
    threat_metrics = db.get_threat_landscape_metrics()
except Exception as e:
    rule_health = {'total_rules': 0, 'enabled_rules': 0, 'avg_score': 0}
    threat_metrics = {'total_actors': 0, 'global_coverage_pct': 0, 'uncovered_ttps': 0}

# --- HERO SECTION ---
tide_icon_b64 = get_icon_base64("tide.png")
st.markdown(f"""
<div class="hero-section">
    <img src="data:image/png;base64,{tide_icon_b64}" class="hero-title" style="width: 72px; height: 72px;" alt="TIDE">
    <p class="hero-subtitle">TIDE</p>
    <p class="hero-tagline">Threat Informed Detection Engine</p>
    <div class="stat-row">
        <div class="stat-item">
            <div class="stat-value">{rule_health['enabled_rules']}</div>
            <div class="stat-label">Active Rules</div>
        </div>
        <div class="stat-item">
            <div class="stat-value">{threat_metrics['total_actors']}</div>
            <div class="stat-label">Tracked Actors</div>
        </div>
        <div class="stat-item">
            <div class="stat-value">{threat_metrics['global_coverage_pct']}%</div>
            <div class="stat-label">TTP Coverage</div>
        </div>
        <div class="stat-item">
            <div class="stat-value">{rule_health['avg_score']}</div>
            <div class="stat-label">Avg Quality</div>
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# --- WHAT IS TIDE ---
st.markdown('<p class="section-header">What is TIDE?</p>', unsafe_allow_html=True)
st.markdown("""
<p class="info-text">
TIDE is an open-source <b>Detection Engineering Platform</b> that bridges the gap between threat intelligence and detection capabilities. 
It automatically maps your SIEM detection rules against known adversary techniques (MITRE ATT&CK), identifies coverage gaps, 
and provides quality metrics to ensure your detection content is production-ready.
</p>
<p class="info-text">
By connecting to your existing tools—<b>Elastic SIEM</b>, <b>OpenCTI</b>, <b>GitLab</b>, and <b>MITRE ATT&CK</b>—TIDE creates a unified view 
of your security posture, helping you prioritize detection development based on real threat intelligence.
</p>
""", unsafe_allow_html=True)

# --- KEY FEATURES ---
st.markdown('<p class="section-header">Key Features</p>', unsafe_allow_html=True)

st.markdown("""
<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin-bottom: 20px;">
    <div class="feature-card">
        <div class="feature-title">Threat-Driven Coverage</div>
        <div class="feature-desc">
            Map detection rules to MITRE ATT&CK techniques. Visualize which adversary TTPs you can detect 
            and identify critical gaps based on your threat landscape.
        </div>
    </div>
    <div class="feature-card">
        <div class="feature-title">Rule Quality Scoring</div>
        <div class="feature-desc">
            Automated quality checks for field mappings, query syntax, metadata completeness, and performance. 
            Track validation status with 12-week review cycles.
        </div>
    </div>
    <div class="feature-card">
        <div class="feature-title">GitOps Promotion</div>
        <div class="feature-desc">
            Promote rules from Staging to Production with validation gates. 
            Full Git integration ensures version control and audit trails.
        </div>
    </div>
</div>
<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px;">
    <div class="feature-card">
        <div class="feature-title">Coverage Heatmap</div>
        <div class="feature-desc">
            Interactive MITRE ATT&CK matrix showing coverage per tactic. 
            Select specific threat actors to see targeted gap analysis.
        </div>
    </div>
    <div class="feature-card">
        <div class="feature-title">Automated Sync</div>
        <div class="feature-desc">
            Background workers continuously sync data from Elastic, OpenCTI, and MITRE. 
            Always up-to-date without manual intervention.
        </div>
    </div>
    <div class="feature-card">
        <div class="feature-title">Executive Dashboards</div>
        <div class="feature-desc">
            High-level metrics for security leadership. Track coverage trends, 
            rule health, and threat landscape evolution over time.
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

# --- HOW IT WORKS ---
st.markdown('<p class="section-header">How It Works</p>', unsafe_allow_html=True)

col_left, col_right = st.columns([1, 1])

with col_left:
    st.markdown("""
    <div class="workflow-step">
        <div class="step-number">1</div>
        <div class="step-content">
            <div class="step-title">Connect Your Tools</div>
            <div class="step-desc">Configure API connections to Elastic, OpenCTI, and GitLab in Settings.</div>
        </div>
    </div>
    <div class="workflow-step">
        <div class="step-number">2</div>
        <div class="step-content">
            <div class="step-title">Sync Threat Intel</div>
            <div class="step-desc">Pull threat actors and TTPs from OpenCTI or directly from MITRE ATT&CK.</div>
        </div>
    </div>
    <div class="workflow-step">
        <div class="step-number">3</div>
        <div class="step-content">
            <div class="step-title">Sync Detection Rules</div>
            <div class="step-desc">Import rules from Elastic SIEM. TIDE extracts MITRE mappings and calculates quality scores.</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_right:
    st.markdown("""
    <div class="workflow-step">
        <div class="step-number">4</div>
        <div class="step-content">
            <div class="step-title">Analyze Coverage</div>
            <div class="step-desc">View the Dashboard and Heatmap to see which adversary techniques you detect.</div>
        </div>
    </div>
    <div class="workflow-step">
        <div class="step-number">5</div>
        <div class="step-content">
            <div class="step-title">Prioritize Gaps</div>
            <div class="step-desc">Focus on uncovered TTPs used by threat actors targeting your sector.</div>
        </div>
    </div>
    <div class="workflow-step">
        <div class="step-number">6</div>
        <div class="step-content">
            <div class="step-title">Validate & Promote</div>
            <div class="step-desc">Use Rule Health to validate detection logic, then promote to production via GitOps.</div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# --- QUICK LINKS ---
st.markdown('<p class="section-header">Get Started</p>', unsafe_allow_html=True)

q1, q2, q3, q4 = st.columns(4)

with q1:
    st.page_link("pages/1_Dashboard.py", label="📊 Dashboard", use_container_width=True)
with q2:
    st.page_link("pages/2_Threat_Landscape.py", label="🏴‍☠️ Threat Landscape", use_container_width=True)
with q3:
    st.page_link("pages/4_Rule_health.py", label="🩺 Rule Health", use_container_width=True)
with q4:
    st.page_link("pages/9_Settings.py", label="⚙️ Settings", use_container_width=True)

# --- FOOTER ---
st.markdown(f"""
<div style="text-align: center; margin-top: 50px; padding: 20px; color: #64748b; font-size: 13px; border-top: 1px solid #334155;">
    <b>TIDE {version}</b> — Threat Informed Detection Engine<br/>
    <span style="font-size: 11px;">Built for Detection Engineers • Open Source</span>
</div>
""", unsafe_allow_html=True)