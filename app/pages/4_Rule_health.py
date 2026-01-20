import streamlit as st
import os
import pandas as pd
from datetime import datetime
import json
import math
import database as db
from styles import apply_custom_styles, get_icon_path
from auth import require_auth, get_current_user

# 1. Page Config
st.set_page_config(page_title="Rule Health | TIDE", page_icon=get_icon_path("tide.png"), layout="wide")
apply_custom_styles()
require_auth()
st.title("Detection Rule Health")

# Initialize session state for force refresh
if 'refresh_counter' not in st.session_state:
    st.session_state.refresh_counter = 0

VALIDATION_FILE = "data/checkedRule.json"

# --- METRICS DISPLAY ---
metrics = db.get_rule_health_metrics(VALIDATION_FILE)

# Metrics Row
m1, m2, m3, m4, m5, m6 = st.columns(6)

with m1:
    score_color = "metric-good" if metrics['avg_score'] >= 70 else ("metric-warn" if metrics['avg_score'] >= 50 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {score_color}">{metrics["avg_score"]}</p>
        <p class="metric-label">Avg Quality Score</p>
        <p class="metric-sub">Range: {metrics["min_score"]} - {metrics["max_score"]}</p>
    </div>
    ''', unsafe_allow_html=True)

with m2:
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{metrics["total_rules"]}</p>
        <p class="metric-label">Total Rules</p>
        <p class="metric-sub">✅ {metrics["enabled_rules"]} enabled</p>
    </div>
    ''', unsafe_allow_html=True)

with m3:
    validated_pct = round((metrics['validated_count'] / metrics['total_rules'] * 100), 1) if metrics['total_rules'] > 0 else 0
    val_color = "metric-good" if validated_pct >= 80 else ("metric-warn" if validated_pct >= 50 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {val_color}">{metrics["validated_count"]}</p>
        <p class="metric-label">Validated (12wk)</p>
        <p class="metric-sub">{validated_pct}% of total</p>
    </div>
    ''', unsafe_allow_html=True)

with m4:
    exp_color = "metric-good" if metrics['validation_expired_count'] == 0 else ("metric-warn" if metrics['validation_expired_count'] < 10 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {exp_color}">{metrics["validation_expired_count"]}</p>
        <p class="metric-label">Validation Expired</p>
        <p class="metric-sub">⚠️ {metrics["never_validated_count"]} never checked</p>
    </div>
    ''', unsafe_allow_html=True)

with m5:
    lq_color = "metric-good" if metrics['low_quality_count'] == 0 else ("metric-warn" if metrics['low_quality_count'] < 20 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {lq_color}">{metrics["low_quality_count"]}</p>
        <p class="metric-label">Low Quality (&lt;50)</p>
        <p class="metric-sub">🌟 {metrics["high_quality_count"]} high quality</p>
    </div>
    ''', unsafe_allow_html=True)

with m6:
    spaces_str = " | ".join([f"{k}: {v}" for k, v in list(metrics['rules_by_space'].items())[:3]])
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{len(metrics["rules_by_space"])}</p>
        <p class="metric-label">Spaces</p>
        <p class="metric-sub">{spaces_str if spaces_str else "No spaces"}</p>
    </div>
    ''', unsafe_allow_html=True)

# --- DATA MANAGEMENT ---
with st.expander("🗑️ Data Management", expanded=False):
    st.warning("⚠️ Detection rules are synced live from Elastic. Clearing this data will remove all cached rules until the next sync.")
    col1, col2 = st.columns([1, 4])
    with col1:
        if st.button("🗑️ Clear Detection Rules", type="secondary", use_container_width=True):
            deleted = db.clear_detection_rules()
            st.success(f"✅ Cleared {deleted} detection rules. Run a sync to reload.")
            st.rerun()

st.markdown("<br>", unsafe_allow_html=True)
st.divider()

# --- HELPERS ---
def load_validation_data():
    """Load validation data from JSON file"""
    if os.path.exists(VALIDATION_FILE):
        with open(VALIDATION_FILE, "r") as f:
            try:
                return json.load(f).get("rules", {})
            except:
                return {}
    return {}

def update_validation_json(rule_id, user_name):
    if os.path.exists(VALIDATION_FILE):
        with open(VALIDATION_FILE, "r") as f:
            try: data = json.load(f)
            except: data = {"rules": {}}
    else: data = {"rules": {}}

    if "rules" not in data: data["rules"] = {}
    data["rules"][str(rule_id)] = {
        "last_checked_on": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "checked_by": user_name
    }
    with open(VALIDATION_FILE, "w") as f: json.dump(data, f, indent=4)

def get_code_lang(elastic_lang):
    lang = str(elastic_lang).lower()
    if lang in ['esql', 'eql', 'sql', 'kuery', 'kql']: return 'sql'
    if lang in ['painless', 'json']: return 'json'
    return 'bash' 

def format_space_label(raw_space):
    if not raw_space: return "default"
    return raw_space.lower().capitalize()

# --- DIALOGS (POPUPS) ---

@st.experimental_dialog("Validate Rule")
def validate_modal(rule_name):
    st.write(f"Marking **{rule_name}** as valid.")
    
    # Get current user name from authentication
    user = get_current_user()
    user_name = user.get('name', user.get('preferred_username', '')) if user else ''
    
    # Use a form to allow Enter key submission
    with st.form(key=f"validate_form_{rule_name}"):
        st.text_input("Validated by:", value=user_name, disabled=True)
        submitted = st.form_submit_button("Confirm Validation", type="primary")
        
        if submitted:
            if user_name:
                update_validation_json(rule_name, user_name)
                st.success("Rule validated successfully!")
                st.rerun()
            else:
                st.warning("User name not available.")

@st.experimental_dialog("Rule Logic", width="large")
def view_logic_modal(rule_name, query, language, details, row):
    st.subheader(f"{rule_name}")
    
    # 1. Code Block
    st.caption("Query / Logic")
    st.code(query, language=language)
    
    # 2. Mappings Table
    mapping_results = details.get('results', [])
    if mapping_results:
        st.caption(f"**Field Mappings ({len(mapping_results)})**")
        map_df = pd.DataFrame(mapping_results, columns=["Index", "Field", "Exists", "Type"])
        st.dataframe(
            map_df, 
            hide_index=True, 
            use_container_width=True,
            column_config={
                "Index": st.column_config.TextColumn("Index Pattern", width="medium"),
                "Field": st.column_config.TextColumn("Field", width="medium"),
                "Exists": st.column_config.TextColumn("Valid", width="small"),
                "Type": st.column_config.TextColumn("Type", width="small")
            }
        )
    elif row.get('score_mapping', 0) == 0:
        st.error("⚠️ Field Mapping Issues: Index fields missing or not checked.")

    # 3. Stats - Quality Scores
    st.divider()
    st.caption("**Quality Scores**")
    q1, q2, q3, q4 = st.columns(4)
    q1.metric("Mapping", f"{row.get('score_mapping', 0)}/20")
    q2.metric("Field Type", f"{row.get('score_field_type', 0)}/11")
    q3.metric("Search Time", f"{row.get('score_search_time', 0)}/10")
    q4.metric("Language", f"{row.get('score_language', 0)}/9")
    
    # 4. Stats - Meta Scores
    st.caption("**Meta Scores**")
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Note", f"{row.get('score_note', 0)}/20")
    m2.metric("Override", f"{row.get('score_override', 0)}/5")
    m3.metric("Tactics", f"{row.get('score_tactics', 0)}/3")
    m4.metric("Techniques", f"{row.get('score_techniques', 0)}/7")
    m5.metric("Author", f"{row.get('score_author', 0)}/5")
    m6.metric("Highlights", f"{row.get('score_highlights', 0)}/10")


# 2. Fetch Data
def load_data():
    try:
        data, last_sync = db.get_latest_rules()
        return data, last_sync
    except Exception as e:
        st.error(f"Failed to load data: {e}")
        return [], "Error"

data, last_sync = load_data()
df_rules = pd.DataFrame(data)

# Add validation dates to dataframe for sorting
if not df_rules.empty:
    validation_data = load_validation_data()
    def get_validation_date(rule_name):
        rule_v = validation_data.get(str(rule_name), {})
        val_str = rule_v.get('last_checked_on', '')
        if val_str:
            try:
                return datetime.strptime(val_str[:10], "%Y-%m-%d")
            except:
                pass
        return datetime.min  # Never validated = oldest
    
    df_rules['validated_on'] = df_rules['name'].apply(get_validation_date)

# Sync Button
col_title, col_sync = st.columns([4, 1])
with col_title:
    st.subheader(f"Last Sync: {last_sync}")
with col_sync:
    if st.button("🔄 Sync", key="btn_sync_rules", use_container_width=True):
        st.session_state.refresh_counter += 1
        db.set_trigger("sync_elastic")
        with st.spinner("Syncing rules from Kibana..."):
            success = db.wait_for_sync(timeout=60)
            if success:
                st.success("✅ Sync completed!")
            else:
                st.warning("⚠️ Sync may still be running...")
        import time
        time.sleep(0.3)
        st.cache_data.clear()
        st.cache_resource.clear()
        st.rerun()

# 3. Sidebar - Initialize filter state
if 'filter_env' not in st.session_state:
    st.session_state.filter_env = 'All'
if 'filter_status' not in st.session_state:
    st.session_state.filter_status = 'All'

with st.sidebar:
    st.header("Filters")
    search = st.text_input("Search", placeholder="Rule name, Author, ID, MITRE (T1078)...")
    if not df_rules.empty:
        # Environment filter as radio
        if 'space' in df_rules.columns:
            unique_spaces = sorted(df_rules['space'].astype(str).unique())
            env_options = ['All'] + unique_spaces
            env_filter = st.radio("Environment", env_options, horizontal=True, key='filter_env')
            if env_filter != 'All':
                df_rules = df_rules[df_rules['space'] == env_filter]
        
        # Enabled filter
        enabled_options = ["All", "Enabled", "Disabled"]
        enabled_filter = st.radio("Status", enabled_options, horizontal=True, key='filter_status')
        if enabled_filter == "Enabled":
            df_rules = df_rules[df_rules['enabled'] == 1]
        elif enabled_filter == "Disabled":
            df_rules = df_rules[df_rules['enabled'] == 0]
        
        # Sort option
        sort_options = ["Score (Low→High)", "Score (High→Low)", "Validated (Oldest)", "Validated (Newest)", "Name (A→Z)"]
        sort_by = st.selectbox("Sort By", sort_options, index=0)
        
        # Combined search (name, rule_id, author, MITRE)
        if search:
            search_term = search.strip()
            def matches_search(row):
                # Check name, rule_id, author
                if search_term.lower() in str(row.get('name', '')).lower():
                    return True
                if search_term.lower() in str(row.get('rule_id', '')).lower():
                    return True
                if search_term.lower() in str(row.get('author', '')).lower():
                    return True
                # Check MITRE IDs
                mitre_ids = row.get('mitre_ids', [])
                if isinstance(mitre_ids, list):
                    if any(search_term.upper() in str(m).upper() for m in mitre_ids):
                        return True
                return False
            df_rules = df_rules[df_rules.apply(matches_search, axis=1)]
        
        # Apply sorting
        if sort_by == "Score (Low→High)":
            df_rules = df_rules.sort_values('score', ascending=True)
        elif sort_by == "Score (High→Low)":
            df_rules = df_rules.sort_values('score', ascending=False)
        elif sort_by == "Validated (Oldest)":
            df_rules = df_rules.sort_values('validated_on', ascending=True)
        elif sort_by == "Validated (Newest)":
            df_rules = df_rules.sort_values('validated_on', ascending=False)
        elif sort_by == "Name (A→Z)":
            df_rules = df_rules.sort_values('name', ascending=True)
    st.divider()

# 4. PAGINATION
ITEMS_PER_PAGE = 24
if "page_number" not in st.session_state: st.session_state.page_number = 0

if df_rules.empty:
    st.info("No rules match your filters.")
    total_pages = 0
else:
    total_pages = math.ceil(len(df_rules) / ITEMS_PER_PAGE)
    if st.session_state.page_number >= total_pages: st.session_state.page_number = max(0, total_pages - 1)

    start_idx = st.session_state.page_number * ITEMS_PER_PAGE
    end_idx = start_idx + ITEMS_PER_PAGE
    batch_rules = df_rules.iloc[start_idx:end_idx]

    c1, c2, c3 = st.columns([1, 6, 1])
    with c1:
        if st.button("Previous", disabled=(st.session_state.page_number == 0)):
            st.session_state.page_number -= 1
            st.rerun()
    with c2:
        st.markdown(f"<div style='text-align:center; color:#94a3b8;'>Page {st.session_state.page_number + 1} of {total_pages} ({len(df_rules)} Rules)</div>", unsafe_allow_html=True)
    with c3:
        if st.button("Next", disabled=(st.session_state.page_number == total_pages - 1)):
            st.session_state.page_number += 1
            st.rerun()

    # 5. Render Grid
    rows = batch_rules.to_dict('records')
    cols_per_row = 3
    cols = st.columns(cols_per_row)
    
    for index, row in enumerate(rows):
        target_col = cols[index % cols_per_row]
        
        with target_col:
            try: details = json.loads(row.get('raw_data', '{}'))
            except: details = {}
            
            # Logic & Formatting
            rule_id = row.get('rule_id', 'unknown_id')
            rule_name = row.get('name', 'Unknown')
            is_enabled = row.get('enabled', 0) == 1
            status_text = format_space_label(row.get('space', 'default'))
            dot_color = "#4ade80" if is_enabled else "#94a3b8"
            
            severity = row.get('severity', 'low').lower()
            severity_map = {'critical': '#f87171', 'high': '#fb923c', 'medium': '#facc15', 'low': '#4ade80'}
            sev_color = severity_map.get(severity, '#94a3b8')
            
            score = row.get('score', 0)
            score_color = "#f87171" 
            if score >= 50: score_color = "#facc15" 
            if score >= 80: score_color = "#4ade80" 
            
            author = row.get('author', 'Unknown')
            if len(author) > 20: author = "Multiple/Long"
            
            # Get MITRE technique IDs and generate pills HTML
            mitre_ids = row.get('mitre_ids', [])
            if isinstance(mitre_ids, list) and mitre_ids:
                # Generate pill HTML for each MITRE ID (max 4)
                mitre_pills = ''.join([f'<span class="mitre-pill">{mid}</span>' for mid in mitre_ids[:4]])
                if len(mitre_ids) > 4:
                    mitre_pills += f'<span class="mitre-pill">+{len(mitre_ids) - 4}</span>'
            else:
                mitre_pills = ''
            
            lang = details.get('language', 'kuery')
            hl_lang = get_code_lang(lang)
            query = details.get('query', '')
            
            # Validation Check
            val_date = "Never"
            val_by = "-"
            val_color = "#f87171" # Default Red (Never)
            
            if os.path.exists(VALIDATION_FILE):
                with open(VALIDATION_FILE, "r") as f:
                    v_data = json.load(f)
                    rule_v = v_data.get("rules", {}).get(str(rule_name))
                    if rule_v:
                        val_str = rule_v.get('last_checked_on', 'Unknown')[:10]
                        val_by = rule_v.get('checked_by', 'Unknown')
                        try:
                            weeks = (datetime.now() - datetime.strptime(val_str, "%Y-%m-%d")).days / 7
                            if weeks > 12: val_color = "#f87171" 
                            elif weeks > 11: val_color = "#fb923c"
                            else: val_color = "#4ade80" 
                            val_date = val_str
                        except: pass
            
            # --- RENDER CARD (HTML) ---
            mitre_html = f'<div class="mitre-pills">{mitre_pills}</div>' if mitre_pills else ''
            st.markdown(f"""
<div class="rule-card">
<div>
<div class="rule-header">
<div class="rule-name-container">
<div class="rule-name" title="{rule_name}">{rule_name}</div>
</div>
<div class="pill-stack">
<div class="status-pill"><span class="status-dot" style="background-color:{dot_color};"></span>{status_text}</div>
<div class="sev-pill" style="background-color:{sev_color};">{severity.upper()}</div>
{mitre_html}
</div>
</div>
<div class="score-meta">
<span>Quality Score</span>
<span style="color:{score_color}">{score}</span>
</div>
<div class="track">
<div class="fill" style="width: {score}%; background-color: {score_color};"></div>
</div>
</div>
<div class="meta-grid">
<div style="text-align:left;">
<div>Validated by: <span class="meta-val">{val_by}</span></div>
<div>On: <span class="meta-val" style="color:{val_color};">{val_date}</span></div>
</div>
<div style="text-align:right;">
<div>Author: <span class="meta-val">{author}</span></div>
<div>Lang: <span class="meta-val">{lang}</span></div>
</div>
</div>
</div>
""", unsafe_allow_html=True)
            
            # --- BUTTONS (Standard Streamlit, Side-by-Side with no gap) ---
            b1, b2 = st.columns([1, 1], gap="small")
            
            with b1:
                if st.button("✅ Validate", key=f"btn_{index}", use_container_width=True):
                    validate_modal(rule_name)
            
            with b2:
                if st.button("📋 View Logic", key=f"logic_{index}", use_container_width=True):
                    view_logic_modal(rule_name, query, hl_lang, details, row)

    st.markdown("---")
    st.caption(f"Showing {len(batch_rules)} of {len(df_rules)} rules")