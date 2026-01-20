import streamlit as st
import database as db
import pandas as pd
import plotly.express as px
from styles import apply_custom_styles, render_sidebar_status, get_icon_path
from auth import require_auth

# Page Configuration
st.set_page_config(page_title="Dashboard | TIDE", page_icon=get_icon_path("tide.png"), layout="wide", initial_sidebar_state="expanded")
apply_custom_styles()
require_auth()

st.title("Security Posture Dashboard")

# --- 1. DATA FETCHING (Fail Gracefully) ---
try:
    # Fetch Threat Intel
    raw_threats, threat_sync = db.get_threat_data()
    df_threats = pd.DataFrame(raw_threats)
    
    # Fetch Rules
    raw_rules, rule_sync = db.get_latest_rules()
    df_rules = pd.DataFrame(raw_rules)
    
    # Fetch Coverage Set (The "Magic Layer")
    covered_ttps_set = db.get_all_covered_ttps()
    
except Exception as e:
    st.error(f"⚠️ Database connection failed: {e}")
    st.stop()

# --- 2. METRIC CALCULATIONS ---

# Get Rule Health Metrics (validation stats)
rule_health = db.get_rule_health_metrics()

# Get Threat Landscape Metrics
threat_metrics = db.get_threat_landscape_metrics()

# Calculated metrics
validated_pct = round((rule_health['validated_count'] / rule_health['total_rules'] * 100), 1) if rule_health['total_rules'] > 0 else 0
needs_review = rule_health['validation_expired_count'] + rule_health['never_validated_count']

# --- 3. UI LAYOUT ---

# === RULE HEALTH SECTION ===
st.markdown('<p class="section-header">Rule Health</p>', unsafe_allow_html=True)
m1, m2, m3, m4, m5, m6 = st.columns(6)

with m1:
    score_color = "metric-good" if rule_health['avg_score'] >= 70 else ("metric-warn" if rule_health['avg_score'] >= 50 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {score_color}">{rule_health["avg_score"]}</p>
        <p class="metric-label">Avg Quality</p>
        <p class="metric-sub">Range: {rule_health["min_score"]} - {rule_health["max_score"]}</p>
    </div>
    ''', unsafe_allow_html=True)

with m2:
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{rule_health["enabled_rules"]}</p>
        <p class="metric-label">Enabled Rules</p>
        <p class="metric-sub">📊 {rule_health["total_rules"]} total</p>
    </div>
    ''', unsafe_allow_html=True)

with m3:
    val_color = "metric-good" if validated_pct >= 80 else ("metric-warn" if validated_pct >= 50 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {val_color}">{validated_pct}%</p>
        <p class="metric-label">Validated</p>
        <p class="metric-sub">✅ {rule_health["validated_count"]} rules</p>
    </div>
    ''', unsafe_allow_html=True)

with m4:
    exp_color = "metric-good" if needs_review == 0 else ("metric-warn" if needs_review < 20 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {exp_color}">{needs_review}</p>
        <p class="metric-label">Needs Review</p>
        <p class="metric-sub">⚠️ {rule_health["validation_expired_count"]} expired</p>
    </div>
    ''', unsafe_allow_html=True)

with m5:
    lq_color = "metric-good" if rule_health['low_quality_count'] == 0 else ("metric-warn" if rule_health['low_quality_count'] < 20 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {lq_color}">{rule_health["low_quality_count"]}</p>
        <p class="metric-label">Low Quality</p>
        <p class="metric-sub">🌟 {rule_health["high_quality_count"]} high quality</p>
    </div>
    ''', unsafe_allow_html=True)

with m6:
    spaces_str = " | ".join([f"{k}: {v}" for k, v in list(rule_health['rules_by_space'].items())[:2]])
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{len(rule_health["rules_by_space"])}</p>
        <p class="metric-label">Spaces</p>
        <p class="metric-sub">{spaces_str if spaces_str else "No spaces"}</p>
    </div>
    ''', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# === THREAT LANDSCAPE SECTION ===
st.markdown('<p class="section-header">Threat Landscape</p>', unsafe_allow_html=True)
t1, t2, t3, t4, t5, t6 = st.columns(6)

with t1:
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{threat_metrics["total_actors"]}</p>
        <p class="metric-label">Tracked Actors</p>
        <p class="metric-sub">🌍 {len(threat_metrics["origin_breakdown"])} origins</p>
    </div>
    ''', unsafe_allow_html=True)

with t2:
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{threat_metrics["unique_ttps"]}</p>
        <p class="metric-label">Unique TTPs</p>
        <p class="metric-sub">📊 {threat_metrics["total_ttps"]} instances</p>
    </div>
    ''', unsafe_allow_html=True)

with t3:
    cov_color = "metric-good" if threat_metrics['global_coverage_pct'] >= 70 else ("metric-warn" if threat_metrics['global_coverage_pct'] >= 40 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {cov_color}">{threat_metrics["global_coverage_pct"]}%</p>
        <p class="metric-label">Global Coverage</p>
        <p class="metric-sub">✅ {threat_metrics["covered_ttps"]} covered</p>
    </div>
    ''', unsafe_allow_html=True)

with t4:
    gap_color = "metric-good" if threat_metrics['uncovered_ttps'] < 20 else ("metric-warn" if threat_metrics['uncovered_ttps'] < 50 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {gap_color}">{threat_metrics["uncovered_ttps"]}</p>
        <p class="metric-label">Coverage Gaps</p>
        <p class="metric-sub">⚠️ TTPs without rules</p>
    </div>
    ''', unsafe_allow_html=True)

with t5:
    fc_color = "metric-good" if threat_metrics['fully_covered_actors'] > threat_metrics['uncovered_actors'] else "metric-warn"
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {fc_color}">{threat_metrics["fully_covered_actors"]}</p>
        <p class="metric-label">Fully Covered</p>
        <p class="metric-sub">🛡️ {threat_metrics["partially_covered_actors"]} partial</p>
    </div>
    ''', unsafe_allow_html=True)

with t6:
    actor_name, actor_count = threat_metrics['max_ttps_actor']
    short_name = actor_name[:10] + "..." if len(str(actor_name)) > 10 else actor_name
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{actor_count}</p>
        <p class="metric-label">Most TTPs</p>
        <p class="metric-sub">🎯 {short_name}</p>
    </div>
    ''', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)
st.divider()

# Row 2: Deep Dive Charts
col_left, col_right = st.columns([2, 1])

with col_left:
    st.subheader("Rule Severity Distribution")
    if not df_rules.empty:
        # Group by Severity
        sev_counts = df_rules['severity'].value_counts().reset_index()
        sev_counts.columns = ['Severity', 'Count']
        
        # Custom color map for severity
        color_map = {
            'critical': "#df4a4a", 
            'high': '#ff9f1c', 
            'medium': '#ffd166', 
            'low': '#06d6a0',
            'informational': '#118ab2'
        }
        
        fig = px.bar(
            sev_counts, 
            x='Severity', 
            y='Count', 
            color='Severity',
            color_discrete_map=color_map,
            text_auto=True,
            title="Active Detection Rules by Severity"
        )
        fig.update_layout(height=350, showlegend=False)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No rules found. Please run a Sync.")

with col_right:
    st.subheader("Top Risky Actors")
    if not df_threats.empty:
        # FIXED: Use 'name' and 'ttp_count' (DuckDB schema)
        top_actors = df_threats[['name', 'ttp_count']].sort_values(by='ttp_count', ascending=False).head(8)
        
        st.dataframe(
            top_actors,
            column_config={
                "name": "Threat Group",
                "ttp_count": st.column_config.ProgressColumn(
                    "Known TTPs",
                    format="%d",
                    min_value=0,
                    # Safe max value calculation
                    max_value=int(df_threats['ttp_count'].max()) if not df_threats.empty else 100
                )
            },
            hide_index=True,
            use_container_width=True
        )
    else:
        st.info("No Threat Intel data. Go to Settings -> OpenCTI/MITRE to sync.")

# Row 3: Quality Assurance (The "Review" Queue)
st.divider()
st.subheader("Quality Assurance Needed")

if not df_rules.empty:
    # Filter for "Low Quality" rules that are enabled
    low_quality_rules = df_rules[
        (df_rules['quality_score'] < 50) & 
        (df_rules['enabled'] == 1)
    ].sort_values(by='quality_score', ascending=True)

    if not low_quality_rules.empty:
        st.warning(f"⚠️ Found {len(low_quality_rules)} active rules with low quality scores (<50).")
        st.dataframe(
            low_quality_rules[['name', 'author', 'severity', 'quality_score']],
            column_config={
                "quality_score": st.column_config.NumberColumn(
                    "Quality Score",
                    format="%d 📉"
                )
            },
            hide_index=True,
            use_container_width=True
        )
    else:
        st.success("✅ All active rules meet the quality standard (>50).")