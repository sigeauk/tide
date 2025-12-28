import streamlit as st
import database as db
import os
from styles import apply_custom_styles
from auth import require_auth, get_current_user
from dotenv import load_dotenv
load_dotenv()
version = os.getenv('TIDE_VERSION', 'v1.0.0')

# Page Config
st.set_page_config(page_title="TIDE", page_icon="app/static/icons/tide.png", layout="wide", initial_sidebar_state="expanded")
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

# --- CUSTOM CSS ---
st.markdown("""
<style>
    .hero-section {
        text-align: center;
        padding: 40px 20px;
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 50%, #0f172a 100%);
        border-radius: 16px;
        border: 1px solid #334155;
        margin-bottom: 30px;
    }
    .hero-title {
        font-size: 72px;
        margin: 0;
    }
    .hero-subtitle {
        font-size: 24px;
        color: #60a5fa;
        margin: 10px 0 5px 0;
        font-weight: 600;
    }
    .hero-tagline {
        font-size: 16px;
        color: #94a3b8;
        margin: 0;
    }
    .stat-row {
        display: flex;
        justify-content: center;
        gap: 40px;
        margin-top: 25px;
    }
    .stat-item {
        text-align: center;
    }
    .stat-value {
        font-size: 28px;
        font-weight: 700;
        color: #f1f5f9;
    }
    .stat-label {
        font-size: 12px;
        color: #64748b;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .feature-card {
        background: #1e293b;
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 24px;
    }
    .feature-icon {
        font-size: 36px;
        margin-bottom: 12px;
    }
    .feature-title {
        font-size: 18px;
        font-weight: 700;
        color: #f1f5f9;
        margin-bottom: 8px;
    }
    .feature-desc {
        font-size: 14px;
        color: #94a3b8;
        line-height: 1.5;
        flex-grow: 1;
    }
    .section-header {
        font-size: 20px;
        font-weight: 600;
        color: #e2e8f0;
        margin: 30px 0 15px 0;
    }
    .info-text {
        color: #94a3b8;
        font-size: 15px;
        line-height: 1.7;
    }
    .workflow-step {
        display: flex;
        align-items: flex-start;
        gap: 15px;
        margin-bottom: 15px;
    }
    .step-number {
        background: #3b82f6;
        color: white;
        width: 28px;
        height: 28px;
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        font-size: 14px;
        flex-shrink: 0;
    }
    .step-content {
        flex: 1;
    }
    .step-title {
        font-weight: 600;
        color: #e2e8f0;
        margin-bottom: 2px;
    }
    .step-desc {
        font-size: 13px;
        color: #94a3b8;
    }
</style>
""", unsafe_allow_html=True)

# --- HERO SECTION ---
st.markdown(f"""
<div class="hero-section">
    <img src="app/static/icons/tide.png" class="hero-title" style="width: 72px; height: 72px;" alt="TIDE">
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
        <div class="feature-icon">🎯</div>
        <div class="feature-title">Threat-Driven Coverage</div>
        <div class="feature-desc">
            Map detection rules to MITRE ATT&CK techniques. Visualize which adversary TTPs you can detect 
            and identify critical gaps based on your threat landscape.
        </div>
    </div>
    <div class="feature-card">
        <div class="feature-icon">🩺</div>
        <div class="feature-title">Rule Quality Scoring</div>
        <div class="feature-desc">
            Automated quality checks for field mappings, query syntax, metadata completeness, and performance. 
            Track validation status with 12-week review cycles.
        </div>
    </div>
    <div class="feature-card">
        <div class="feature-icon">🚀</div>
        <div class="feature-title">GitOps Promotion</div>
        <div class="feature-desc">
            Promote rules from Staging to Production with validation gates. 
            Full Git integration ensures version control and audit trails.
        </div>
    </div>
</div>
<div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px;">
    <div class="feature-card">
        <div class="feature-icon">🧱</div>
        <div class="feature-title">Coverage Heatmap</div>
        <div class="feature-desc">
            Interactive MITRE ATT&CK matrix showing coverage per tactic. 
            Select specific threat actors to see targeted gap analysis.
        </div>
    </div>
    <div class="feature-card">
        <div class="feature-icon">🔄</div>
        <div class="feature-title">Automated Sync</div>
        <div class="feature-desc">
            Background workers continuously sync data from Elastic, OpenCTI, and MITRE. 
            Always up-to-date without manual intervention.
        </div>
    </div>
    <div class="feature-card">
        <div class="feature-icon">📊</div>
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