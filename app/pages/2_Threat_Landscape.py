import streamlit as st
import pandas as pd
import math
import os
import sys
import base64
import numpy as np

current_dir = os.path.dirname(os.path.abspath(__file__)) # .../app/pages
parent_dir = os.path.dirname(current_dir)                # .../app
if parent_dir not in sys.path:
    sys.path.append(parent_dir)

import database as db
from cti_helper import get_iso_code
from styles import apply_custom_styles, render_sidebar_status, get_icon_path
from auth import require_auth

# 1. Page Config
st.set_page_config(page_title="Threat Landscape | TIDE", page_icon=get_icon_path("tide.png"), layout="wide")
apply_custom_styles()
require_auth()

st.title("Threat Landscape")

# --- GET METRICS ---
threat_metrics = db.get_threat_landscape_metrics()

# --- METRICS ROW ---
m1, m2, m3, m4, m5, m6 = st.columns(6)

with m1:
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{threat_metrics["total_actors"]}</p>
        <p class="metric-label">Tracked Actors</p>
        <p class="metric-sub">🌍 {len(threat_metrics["origin_breakdown"])} origins</p>
    </div>
    ''', unsafe_allow_html=True)

with m2:
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{threat_metrics["unique_ttps"]}</p>
        <p class="metric-label">Unique TTPs</p>
        <p class="metric-sub">📊 {threat_metrics["total_ttps"]} total instances</p>
    </div>
    ''', unsafe_allow_html=True)

with m3:
    cov_color = "metric-good" if threat_metrics['global_coverage_pct'] >= 70 else ("metric-warn" if threat_metrics['global_coverage_pct'] >= 40 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {cov_color}">{threat_metrics["global_coverage_pct"]}%</p>
        <p class="metric-label">Global Coverage</p>
        <p class="metric-sub">✅ {threat_metrics["covered_ttps"]} covered</p>
    </div>
    ''', unsafe_allow_html=True)

with m4:
    gap_color = "metric-good" if threat_metrics['uncovered_ttps'] < 20 else ("metric-warn" if threat_metrics['uncovered_ttps'] < 50 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {gap_color}">{threat_metrics["uncovered_ttps"]}</p>
        <p class="metric-label">Coverage Gaps</p>
        <p class="metric-sub">⚠️ TTPs without rules</p>
    </div>
    ''', unsafe_allow_html=True)

with m5:
    fc_color = "metric-good" if threat_metrics['fully_covered_actors'] > threat_metrics['uncovered_actors'] else "metric-warn"
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {fc_color}">{threat_metrics["fully_covered_actors"]}</p>
        <p class="metric-label">Fully Covered</p>
        <p class="metric-sub">🛡️ {threat_metrics["partially_covered_actors"]} partial</p>
    </div>
    ''', unsafe_allow_html=True)

with m6:
    actor_name, actor_count = threat_metrics['max_ttps_actor']
    short_name = actor_name[:12] + "..." if len(str(actor_name)) > 12 else actor_name
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{actor_count}</p>
        <p class="metric-label">Most TTPs</p>
        <p class="metric-sub">🎯 {short_name}</p>
    </div>
    ''', unsafe_allow_html=True)

# --- DATA MANAGEMENT ---
with st.expander("🗑️ Data Management", expanded=False):
    st.warning("⚠️ Threat actors are synced live from OpenCTI/MITRE. Clearing this data will remove all cached actors until the next sync.")
    col1, col2 = st.columns([1, 4])
    with col1:
        if st.button("🗑️ Clear Threat Actors", type="secondary", use_container_width=True):
            deleted = db.clear_threat_actors()
            st.success(f"✅ Cleared {deleted} threat actors. Run a sync to reload.")
            st.rerun()

st.markdown("<br>", unsafe_allow_html=True)

# 2. Fetch Data
try:
    threats, last_sync = db.get_threat_data()
    raw_covered = db.get_all_covered_ttps()
    covered_ttps = {str(t).strip().upper() for t in raw_covered if t}
except Exception as e:
    st.error(f"Database Error: {e}")
    threats = []
    covered_ttps = set()
    last_sync = "Never"

df_threats = pd.DataFrame(threats)

# --- PRE-CALCULATE COVERAGE ---
if not df_threats.empty:
    def calc_row_coverage(ttps_list):
        if ttps_list is None or len(ttps_list) == 0:
            return 0, 0, 0
        actor_ttps = {str(t).strip().upper() for t in ttps_list}
        total = len(actor_ttps)
        if total == 0: return 0, 0, 0
        covered = len(actor_ttps.intersection(covered_ttps))
        pct = int((covered / total) * 100)
        return total, covered, pct

    metrics = df_threats['ttps'].apply(calc_row_coverage)
    df_threats[['total_unique', 'covered_count', 'coverage_pct']] = pd.DataFrame(metrics.tolist(), index=df_threats.index)
else:
    df_threats['total_unique'] = 0
    df_threats['covered_count'] = 0
    df_threats['coverage_pct'] = 0

# 3. Sync Row & Last Sync (consistent with Rule Health)
col_sync_title, col_sync_cti, col_sync_mitre = st.columns([4, 1, 1])
with col_sync_title:
    st.subheader(f"Last Sync: {last_sync}")
with col_sync_cti:
    if st.button("🔄 Sync OpenCTI", key="btn_sync_cti", use_container_width=True):
        db.set_trigger("sync_opencti")
        with st.spinner("Syncing threat intel from OpenCTI..."):
            import time
            time.sleep(2)
        st.success("✅ Sync signal sent!")
        st.cache_data.clear()
        st.rerun()
with col_sync_mitre:
    if st.button("🔄 Sync MITRE", key="btn_sync_mitre", use_container_width=True):
        db.set_trigger("sync_mitre")
        with st.spinner("Syncing MITRE ATT&CK data..."):
            import time
            time.sleep(2)
        st.success("✅ Sync signal sent!")
        st.cache_data.clear()
        st.rerun()

st.divider()

# 4. Filters
with st.sidebar:
    st.header("Filters")
    search_term = st.text_input("Search Actor", placeholder="e.g. APT29, China...")

    if not df_threats.empty:
        if search_term:
            mask = (
                df_threats['name'].str.contains(search_term, case=False, na=False) | 
                df_threats.get('description', pd.Series()).str.contains(search_term, case=False, na=False) |
                df_threats.get('aliases', pd.Series()).str.contains(search_term, case=False, na=False)
            )
            df_threats = df_threats[mask]

# 5. PAGINATION
ITEMS_PER_PAGE = 24
if "threat_page" not in st.session_state:
    st.session_state.threat_page = 0

if df_threats.empty:
    st.info("No threat data found matching your filters.")
else:
    total_pages = math.ceil(len(df_threats) / ITEMS_PER_PAGE)
    if st.session_state.threat_page >= total_pages:
        st.session_state.threat_page = max(0, total_pages - 1)
    
    start_idx = st.session_state.threat_page * ITEMS_PER_PAGE
    end_idx = start_idx + ITEMS_PER_PAGE
    batch_threats = df_threats.iloc[start_idx:end_idx]

    c1, c2, c3 = st.columns([1, 8, 1])
    with c1:
        if st.button("Previous", disabled=(st.session_state.threat_page == 0)):
            st.session_state.threat_page -= 1
            st.rerun()
    with c2:
        st.markdown(f"<div style='text-align:center; color:#94a3b8; padding-top:5px;'>Page {st.session_state.threat_page + 1} of {total_pages}</div>", unsafe_allow_html=True)
    with c3:
        if st.button("Next", disabled=(st.session_state.threat_page == total_pages - 1)):
            st.session_state.threat_page += 1
            st.rerun()

    # 6. Render Grid
    rows = batch_threats.to_dict('records')
    cols = st.columns(3)
    
    for index, row in enumerate(rows):
        col_idx = index % 3
        with cols[col_idx]:
            actor_name = row.get('name', 'Unknown')
            aliases = row.get('aliases', '')
            desc = row.get('description', '')
            
            # --- FLAG GENERATION (DYNAMIC PATH) ---
            raw_origin = row.get('origin', '')
            text_to_check = f"{raw_origin} {actor_name} {desc}"
            
            iso_code = get_iso_code(text_to_check)
            
            flag_html = "🏴‍☠️" # Default

            if iso_code:
                # 1. Get current script directory (app/pages)
                # 2. Go up one level (app)
                # 3. Construct path safely
                app_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
                file_path = os.path.join(app_root, "static", "flags", "4x3", f"{iso_code}.svg")
                
                # Check existence & Embed
                if os.path.exists(file_path):
                    try:
                        with open(file_path, "rb") as f:
                            encoded = base64.b64encode(f.read()).decode()
                        flag_html = f'<img src="data:image/svg+xml;base64,{encoded}" class="flag-img" title="{iso_code}">'
                    except Exception:
                        flag_html = "🏴‍☠️"
            
            # Metrics
            coverage_pct = row['coverage_pct']
            detected_count = row['covered_count']
            total_count = row['total_unique']
            
            bar_color = "#22d3ee" 
            if coverage_pct > 75: bar_color = "#4ade80"
            if coverage_pct < 25: bar_color = "#f87171" 
            
            # Generate source pills
            sources = row.get('source', [])
            if isinstance(sources, np.ndarray):
                sources = sources.tolist()  # Convert numpy array to list
            if sources and isinstance(sources, list):
                source_pills = ''.join([f'<span class="source-pill">{src}</span>' for src in sources])
                source_html = f'<div class="source-pills">{source_pills}</div>'
            else:
                source_html = ''
            
            card_html = f"""
<div class="threat-card">
<div>
    <div class="threat-header">
        <div class="actor-name" title="{actor_name}">
            {flag_html}
            <span>{actor_name}</span>
        </div>
        <div style="font-size:1.2rem;">{'🛡️' if coverage_pct == 100 else ''}</div>
    </div>
    <div class="alias-text" title="{aliases}">
        {aliases if aliases else "Unknown Aliases"}
    </div>
    {source_html}
</div>

<div>
    <div class="coverage-meta">
        <span>Coverage</span>
        <span>{detected_count}/{total_count} ({coverage_pct}%)</span>
    </div>
    <div class="progress-track">
        <div class="progress-fill" style="width: {coverage_pct}%; background-color: {bar_color};"></div>
    </div>
</div>
</div>
            """
            st.markdown(card_html, unsafe_allow_html=True)
            
            with st.expander("Analyze TTPs"):
                st.markdown("**Description**")
                clean_desc = desc if desc else "No description available."
                st.caption(clean_desc[:300] + "..." if len(clean_desc) > 300 else clean_desc)
                
                st.divider()
                st.markdown(f"**Techniques ({total_count})**")
                
                raw_ttps = row.get('ttps', [])
                
                if raw_ttps is not None and len(raw_ttps) > 0:
                    actor_ttps = {str(t).strip().upper() for t in raw_ttps}
                    sorted_ttps = sorted(list(actor_ttps))
                    tags = []
                    for t in sorted_ttps:
                        if t in covered_ttps:
                            tags.append(f"<span class='ttp-tag tag-covered' title='Rule Exists'>✓ {t}</span>")
                        else:
                            tags.append(f"<span class='ttp-tag tag-missing' title='Gap'>✕ {t}</span>")
                    
                    st.markdown(f"<div class='ttp-grid'>{''.join(tags)}</div>", unsafe_allow_html=True)
                else:
                    st.info("No mapped techniques.")

    st.markdown("---")
    st.caption(f"Showing {len(batch_threats)} of {len(df_threats)} actors")