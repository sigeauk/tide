import streamlit as st
import os
import pandas as pd
from datetime import datetime
import json
import math
import database as db
import elastic_helper as eh
from styles import apply_custom_styles
from auth import require_auth, get_current_user

# 1. Page Config
st.set_page_config(page_title="Promotion | TIDE", page_icon="🚀", layout="wide")
apply_custom_styles()
require_auth()
st.title("Rule Promotion")

# Initialize session state for force refresh
if 'refresh_counter' not in st.session_state:
    st.session_state.refresh_counter = 0

def sync_rules_from_elastic():
    """Force a sync of rules from Elastic to update the database."""
    try:
        df = eh.fetch_detection_rules(check_mappings=True)
        if not df.empty:
            audit_records = df.to_dict('records')
            db.save_audit_results(audit_records)
            return True
    except Exception as e:
        st.warning(f"Could not sync rules: {e}")
    return False

VALIDATION_FILE = "data/checkedRule.json"

# --- PAGE-SPECIFIC STYLES (extends global styles) ---
st.markdown("""
<style>
/* Promotion-specific score display styles */
.score-section.total {
    flex: 0 0 120px;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
}
.section-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}
.section-title {
    font-size: 0.75rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.section-score {
    font-size: 0.9rem;
    font-weight: 700;
}
.score-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
    margin-top: 8px;
}
.score-grid.meta {
    grid-template-columns: repeat(6, 1fr);
}
.score-item {
    text-align: center;
}
.score-label {
    font-size: 0.65rem;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.3px;
    margin-bottom: 2px;
}
.score-value {
    font-size: 0.9rem;
    font-weight: 700;
    color: #e2e8f0;
}
.score-value.good { color: #4ade80; }
.score-value.warn { color: #facc15; }
.score-value.bad { color: #f87171; }
.total-label {
    font-size: 0.7rem;
    color: #64748b;
    text-transform: uppercase;
    margin-bottom: 4px;
}
.total-value {
    font-size: 2rem;
    font-weight: 700;
}
.meta-row {
    display: flex;
    justify-content: space-between;
    font-size: 0.8rem;
    color: #64748b;
    margin-top: 16px;
    padding-top: 12px;
    border-top: 1px solid #334155;
}
.action-btn {
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid #334155;
    background: #1e293b;
    color: #e2e8f0;
    font-size: 0.8rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    text-align: center;
}
.action-btn:hover {
    background: #334155;
    border-color: #475569;
}
.action-btn.promote {
    border-color: #22c55e;
    color: #4ade80;
}
.action-btn.promote:hover {
    background: #166534;
}
.button-column {
    display: flex;
    flex-direction: column;
    gap: 8px;
    justify-content: center;
    min-width: 100px;
}
</style>
""", unsafe_allow_html=True)

# --- HELPERS ---
def get_code_lang(elastic_lang):
    lang = str(elastic_lang).lower()
    if lang in ['esql', 'eql', 'sql', 'kuery', 'kql']: return 'sql'
    if lang in ['painless', 'json']: return 'json'
    return 'bash' 

def get_score_class(value, thresholds=(80, 50)):
    """Return CSS class based on score thresholds"""
    if value >= thresholds[0]: return "good"
    if value >= thresholds[1]: return "warn"
    return "bad"

def save_validation(rule_name, checked_by):
    """Save validation record for a promoted rule"""
    try:
        # Load existing data
        if os.path.exists(VALIDATION_FILE):
            with open(VALIDATION_FILE, 'r') as f:
                data = json.load(f)
        else:
            data = {"uuid": 12334, "rules": {}}
        
        # Add/update the rule validation
        data["rules"][rule_name] = {
            "last_checked_on": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "checked_by": checked_by
        }
        
        # Save back
        with open(VALIDATION_FILE, 'w') as f:
            json.dump(data, f, indent=4)
        return True
    except Exception as e:
        return False

# --- DIALOGS (POPUPS) ---

@st.experimental_dialog("Promote Rule", width="large")
def promote_modal(rule_name, rule_id, raw_data, source_space="staging"):
    st.write(f"Promoting **{rule_name}** from Staging to Production.")
    st.warning("⚠️ Please verify the following before promoting:")
    
    # Get current user name from authentication
    user = get_current_user()
    user_name = user.get('name', user.get('preferred_username', '')) if user else ''
    
    with st.form(key=f"promote_form_{rule_id}"):
        st.text_input("Your Name:", value=user_name, disabled=True)
        
        st.markdown("**Verification Checklist:**")
        checked_mapping = st.checkbox("I have verified the field mappings are correct")
        checked_search_time = st.checkbox("I have verified the search time is acceptable")
        
        submitted = st.form_submit_button("🚀 Promote to Production", type="primary")
        
        if submitted:
            if not user_name:
                st.error("User name not available.")
            elif not checked_mapping:
                st.error("Please verify the field mappings.")
            elif not checked_search_time:
                st.error("Please verify the search time.")
            else:
                # Execute promotion logic
                with st.spinner("Promoting rule to production..."):
                    success, message = eh.promote_rule_to_production(
                        rule_data=raw_data,
                        source_space=source_space,
                        target_space="production"
                    )
                
                if success:
                    # Save validation record
                    save_validation(rule_name, user_name)
                    st.success(f"✅ {message}")
                    st.info(f"Validated and promoted by: {user_name} at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
                    
                    # Force sync to update the rules list
                    with st.spinner("Syncing rules from Elastic..."):
                        sync_rules_from_elastic()
                    
                    st.session_state.refresh_counter += 1
                else:
                    st.error(f"❌ Promotion failed: {message}")

@st.experimental_dialog(f"Quality", width="large")
def view_quality_modal(rule_name, query, language, hl_lang, details, row):
    # Get raw_data for author
    raw_data = row.get('raw_data', {})
    if isinstance(raw_data, str):
        try:
            raw_data = json.loads(raw_data)
        except:
            raw_data = {}
    
    # Author - parse from string representation of list
    author_raw = row.get('author', '') or raw_data.get('author', [])
    if isinstance(author_raw, str):
        try:
            import ast
            author_list = ast.literal_eval(author_raw)
            if isinstance(author_list, list):
                author_display = ", ".join(author_list) if author_list else "Not specified"
            else:
                author_display = str(author_list)
        except:
            author_display = author_raw if author_raw and author_raw != '[]' else "Not specified"
    elif isinstance(author_raw, list):
        author_display = ", ".join(author_raw) if author_raw else "Not specified"
    else:
        author_display = "Not specified"
    
    # Rule name (big, colored) and Author on same line
    st.markdown(f'<div style="margin-bottom: 8px;"><span style="font-size: 1.5rem; font-weight: 700; color: #22d3ee;">{rule_name}</span><span style="color: #64748b; margin-left: 12px;">by</span><span style="color: #e2e8f0; margin-left: 6px;">{author_display}</span></div>', unsafe_allow_html=True)
    
    st.divider()
    
    # 1. Quality Scores at top
    st.caption("**Quality Scores**")
    q1, q2, q3, q4 = st.columns(4)
    q1.metric("Mapping", f"{row.get('score_mapping', 0)}/20")
    q2.metric("Field Type", f"{row.get('score_field_type', 0)}/11")
    q3.metric("Search Time", f"{row.get('score_search_time', 0)}/10")
    q4.metric("Language", f"{row.get('score_language', 0)}/9")
    
    st.divider()
    
    # 2. Language and Search Time details inline
    search_time = row.get('search_time', 0)
    st.markdown(f'<div style="margin-bottom: 12px;"><span style="color:#94a3b8; margin-right:8px;">Language:</span><code style="background-color:#1e293b; color:#22d3ee; padding:4px 8px; border-radius:4px;">{language or "Not specified"}</code></div>', unsafe_allow_html=True)
    st.markdown(f'<div style="margin-bottom: 12px;"><span style="color:#94a3b8; margin-right:8px;">Search Time:</span><code style="background-color:#1e293b; color:#4ade80; padding:4px 8px; border-radius:4px;">{search_time} ms</code></div>' if search_time else '<div style="margin-bottom: 12px;"><span style="color:#94a3b8; margin-right:8px;">Search Time:</span><span style="color:#64748b;">Not measured</span></div>', unsafe_allow_html=True)
    
    st.divider()
    
    # 3. Code Block
    st.caption("**Query / Logic**")
    st.code(query, language=hl_lang)
    
    # 4. Mappings Table
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


@st.experimental_dialog("Meta", width="large")
def view_meta_modal(rule_name, row):
    # Get raw_data for additional fields
    raw_data = row.get('raw_data', {})
    if isinstance(raw_data, str):
        try:
            raw_data = json.loads(raw_data)
        except:
            raw_data = {}
    
    # Author - parse from string representation of list
    author_raw = row.get('author', '') or raw_data.get('author', [])
    if isinstance(author_raw, str):
        try:
            import ast
            author_list = ast.literal_eval(author_raw)
            if isinstance(author_list, list):
                author_display = ", ".join(author_list) if author_list else "Not specified"
            else:
                author_display = str(author_list)
        except:
            author_display = author_raw if author_raw and author_raw != '[]' else "Not specified"
    elif isinstance(author_raw, list):
        author_display = ", ".join(author_raw) if author_raw else "Not specified"
    else:
        author_display = "Not specified"
    
    # Rule name (big, colored) and Author on same line
    st.markdown(f'<div style="margin-bottom: 8px;"><span style="font-size: 1.5rem; font-weight: 700; color: #22d3ee;">{rule_name}</span><span style="color: #64748b; margin-left: 12px;">by</span><span style="color: #e2e8f0; margin-left: 6px;">{author_display}</span></div>', unsafe_allow_html=True)
    
    st.divider()
    
    # Meta Scores
    st.caption("**Meta Scores**")
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Note", f"{row.get('score_note', 0)}/20")
    m2.metric("Override", f"{row.get('score_override', 0)}/5")
    m3.metric("Tactics", f"{row.get('score_tactics', 0)}/3")
    m4.metric("Techniques", f"{row.get('score_techniques', 0)}/7")
    m5.metric("Author", f"{row.get('score_author', 0)}/5")
    m6.metric("Highlights", f"{row.get('score_highlights', 0)}/10")
    
    st.divider()
    
    # Extract tactics with their techniques (hierarchical) from threat array
    threat_hierarchy = []
    threats = raw_data.get('threat', []) if isinstance(raw_data, dict) else []
    if isinstance(threats, list):
        for t in threats:
            if isinstance(t, dict):
                tactic = t.get('tactic', {})
                if isinstance(tactic, dict) and tactic.get('name'):
                    tactic_entry = {
                        'id': tactic.get('id', ''),
                        'name': tactic.get('name', ''),
                        'techniques': []
                    }
                    for tech in t.get('technique', []):
                        if isinstance(tech, dict):
                            tactic_entry['techniques'].append({
                                'id': tech.get('id', ''),
                                'name': tech.get('name', '')
                            })
                    threat_hierarchy.append(tactic_entry)
    
    # MITRE ATT&CK hierarchical display
    st.markdown('<span style="color:#94a3b8; font-weight:600;">MITRE ATT&CK</span>', unsafe_allow_html=True)
    
    if threat_hierarchy:
        mitre_html = '<div style="margin-top:8px;">'
        for tactic in threat_hierarchy:
            # Tactic pill
            mitre_html += f'<div style="margin-bottom:12px;"><span style="background-color:#1e3a5f; color:#60a5fa; padding:6px 12px; border-radius:12px; font-size:0.9rem; font-weight:600; display:inline-block;">{tactic["name"]} ({tactic["id"]})</span>'
            # Techniques under this tactic
            if tactic['techniques']:
                mitre_html += '<div style="margin-left:24px; margin-top:8px; display:flex; flex-wrap:wrap; gap:6px;">'
                for tech in tactic['techniques']:
                    mitre_html += f'<span style="background-color:#3f1e5f; color:#c084fc; padding:4px 10px; border-radius:12px; font-size:0.85rem; display:inline-block;">{tech["id"]} - {tech["name"]}</span>'
                mitre_html += '</div>'
            mitre_html += '</div>'
        mitre_html += '</div>'
        st.markdown(mitre_html, unsafe_allow_html=True)
    else:
        st.markdown('<div style="color:#64748b; margin-top:8px;">No MITRE ATT&CK mappings defined</div>', unsafe_allow_html=True)
    
    st.divider()
    
    # Highlighted Fields inline
    investigation_fields_obj = raw_data.get('investigation_fields', {}) if isinstance(raw_data, dict) else {}
    if isinstance(investigation_fields_obj, dict):
        investigation_fields = investigation_fields_obj.get('field_names', [])
    else:
        investigation_fields = []
    if not investigation_fields:
        alert_suppression = raw_data.get('alert_suppression', {}) if isinstance(raw_data, dict) else {}
        if isinstance(alert_suppression, dict):
            investigation_fields = alert_suppression.get('group_by', [])
    
    if investigation_fields:
        fields_pills = " ".join([f'<code style="background-color:#1e293b; color:#22d3ee; padding:4px 8px; border-radius:4px; margin-right:6px; font-size:0.85rem; display:inline-block; margin-bottom:4px;">{field}</code>' for field in investigation_fields])
        st.markdown(f'<div style="margin-bottom: 12px;"><span style="color:#94a3b8; margin-right:8px;">Highlighted Fields:</span>{fields_pills}</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div style="margin-bottom: 12px;"><span style="color:#94a3b8; margin-right:8px;">Highlighted Fields:</span><span style="color:#64748b;">None configured</span></div>', unsafe_allow_html=True)
    
    # Timestamp Override inline
    override = row.get('timestamp_override', '') or raw_data.get('timestamp_override', '')
    if override and override != "❌":
        st.markdown(f'<div style="margin-bottom: 12px;"><span style="color:#94a3b8; margin-right:8px;">Timestamp Override:</span><code style="background-color:#1e293b; color:#4ade80; padding:4px 8px; border-radius:4px;">{override}</code></div>', unsafe_allow_html=True)
    else:
        st.markdown('<div style="margin-bottom: 12px;"><span style="color:#94a3b8; margin-right:8px;">Timestamp Override:</span><span style="color:#64748b;">Not configured</span></div>', unsafe_allow_html=True)
    
    st.divider()
    
    # Investigation Guide / Note in a container
    st.markdown('<span style="color:#94a3b8;">Investigation Guide</span>', unsafe_allow_html=True)
    note = row.get('note', '') or (raw_data.get('note', '') if isinstance(raw_data, dict) else '')
    if note:
        st.markdown(f'''
        <div style="background-color:#1e293b; border:1px solid #334155; border-radius:8px; padding:16px; margin-top:8px;">
            {note}
        </div>
        ''', unsafe_allow_html=True)
    else:
        st.info("No investigation guide has been added to this rule.")


# 2. Fetch Data - Only Staging Rules
def load_data():
    try:
        data, last_sync = db.get_latest_rules()
        return data, last_sync
    except Exception as e:
        st.error(f"Failed to load data: {e}")
        return [], "Error"

data, last_sync = load_data()
df_rules = pd.DataFrame(data)

# Filter to only Staging rules
if not df_rules.empty and 'space' in df_rules.columns:
    df_rules = df_rules[df_rules['space'].str.lower() == 'staging']

# Sync Button
col_title, col_sync = st.columns([4, 1])
with col_title:
    st.subheader(f"Last Sync: {last_sync}")
    st.caption("Showing rules from **Staging** environment ready for promotion")
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
if 'promo_filter_status' not in st.session_state:
    st.session_state.promo_filter_status = 'All'

with st.sidebar:
    st.header("Filters")
    search = st.text_input("Search", placeholder="Rule name, Author, ID, MITRE (T1078)...")
    
    if not df_rules.empty:
        # Enabled filter
        enabled_options = ["All", "Enabled", "Disabled"]
        enabled_filter = st.radio("Status", enabled_options, horizontal=True, key='promo_filter_status')
        if enabled_filter == "Enabled":
            df_rules = df_rules[df_rules['enabled'] == 1]
        elif enabled_filter == "Disabled":
            df_rules = df_rules[df_rules['enabled'] == 0]
        
        # Combined search (name, rule_id, author, MITRE)
        if search:
            search_term = search.strip()
            def matches_search(row):
                if search_term.lower() in str(row.get('name', '')).lower():
                    return True
                if search_term.lower() in str(row.get('rule_id', '')).lower():
                    return True
                if search_term.lower() in str(row.get('author', '')).lower():
                    return True
                mitre_ids = row.get('mitre_ids', [])
                if isinstance(mitre_ids, list):
                    if any(search_term.upper() in str(m).upper() for m in mitre_ids):
                        return True
                return False
            df_rules = df_rules[df_rules.apply(matches_search, axis=1)]
    st.divider()

# 4. PAGINATION
ITEMS_PER_PAGE = 10
if "promo_page_number" not in st.session_state: st.session_state.promo_page_number = 0

if df_rules.empty:
    st.info("No staging rules found. Rules in the Staging environment will appear here for promotion to Production.")
    total_pages = 0
else:
    total_pages = math.ceil(len(df_rules) / ITEMS_PER_PAGE)
    if st.session_state.promo_page_number >= total_pages: st.session_state.promo_page_number = max(0, total_pages - 1)

    start_idx = st.session_state.promo_page_number * ITEMS_PER_PAGE
    end_idx = start_idx + ITEMS_PER_PAGE
    batch_rules = df_rules.iloc[start_idx:end_idx]

    c1, c2, c3 = st.columns([1, 6, 1])
    with c1:
        if st.button("Previous", disabled=(st.session_state.promo_page_number == 0), key="promo_prev"):
            st.session_state.promo_page_number -= 1
            st.rerun()
    with c2:
        st.markdown(f"<div style='text-align:center; color:#94a3b8;'>Page {st.session_state.promo_page_number + 1} of {total_pages} ({len(df_rules)} Staging Rules)</div>", unsafe_allow_html=True)
    with c3:
        if st.button("Next", disabled=(st.session_state.promo_page_number == total_pages - 1), key="promo_next"):
            st.session_state.promo_page_number += 1
            st.rerun()

    # 5. Render Full-Width Cards
    rows = batch_rules.to_dict('records')
    
    for index, row in enumerate(rows):
        try: details = json.loads(row.get('raw_data', '{}'))
        except: details = {}
        
        # Logic & Formatting
        rule_id = row.get('rule_id', 'unknown_id')
        rule_name = row.get('name', 'Unknown')
        is_enabled = row.get('enabled', 0) == 1
        dot_color = "#4ade80" if is_enabled else "#94a3b8"
        enabled_text = "Enabled" if is_enabled else "Disabled"
        
        severity = row.get('severity', 'low').lower()
        severity_map = {'critical': '#f87171', 'high': '#fb923c', 'medium': '#facc15', 'low': '#4ade80'}
        sev_color = severity_map.get(severity, '#94a3b8')
        
        # Scores
        score = row.get('score', 0)
        quality_score = row.get('quality_score', 0)
        meta_score = row.get('meta_score', 0)
        score_mapping = row.get('score_mapping', 0)
        score_field_type = row.get('score_field_type', 0)
        score_search_time = row.get('score_search_time', 0)
        score_language = row.get('score_language', 0)
        score_note = row.get('score_note', 0)
        score_override = row.get('score_override', 0)
        score_tactics = row.get('score_tactics', 0)
        score_techniques = row.get('score_techniques', 0)
        score_author = row.get('score_author', 0)
        score_highlights = row.get('score_highlights', 0)
        
        score_color = "#f87171" 
        if score >= 50: score_color = "#facc15" 
        if score >= 80: score_color = "#4ade80" 
        
        author = row.get('author', 'Unknown')
        if len(author) > 30: author = author[:27] + "..."
        
        # Get MITRE technique IDs
        mitre_ids = row.get('mitre_ids', [])
        if isinstance(mitre_ids, list) and mitre_ids:
            mitre_pills = ''.join([f'<span class="mitre-pill">{mid}</span>' for mid in mitre_ids[:6]])
            if len(mitre_ids) > 6:
                mitre_pills += f'<span class="mitre-pill">+{len(mitre_ids) - 6}</span>'
        else:
            mitre_pills = ''
        
        lang = details.get('language', 'kuery')
        hl_lang = get_code_lang(lang)
        query = details.get('query', '')
        
        # Calculate quality and meta percentages for bars
        quality_max = 50  # mapping(20) + field_type(11) + search_time(10) + language(9)
        meta_max = 50  # note(20) + override(5) + tactics(3) + techniques(7) + author(5) + highlights(10)
        quality_pct = min(100, (quality_score / quality_max) * 100) if quality_max > 0 else 0
        meta_pct = min(100, (meta_score / meta_max) * 100) if meta_max > 0 else 0
        
        quality_color = "#f87171"
        if quality_pct >= 50: quality_color = "#facc15"
        if quality_pct >= 80: quality_color = "#4ade80"
        
        meta_color = "#f87171"
        if meta_pct >= 50: meta_color = "#facc15"
        if meta_pct >= 80: meta_color = "#4ade80"
        
        # --- RENDER CARD (HTML) ---
        st.markdown(f"""
<div class="promo-card">
<div class="promo-header">
<div class="promo-name">{rule_name}</div>
<div class="pill-row">
<div class="status-pill"><span class="status-dot" style="background-color:{dot_color};"></span>{enabled_text}</div>
<div class="sev-pill" style="background-color:{sev_color};">{severity.upper()}</div>
{mitre_pills}
</div>
</div>
<div class="card-body">
<div class="scores-container">
<div class="score-section">
<div class="section-header">
<span class="section-title">Quality Scores</span>
<span class="section-score" style="color:{quality_color}">{quality_score}/{quality_max}</span>
</div>
<div class="track">
<div class="fill" style="width: {quality_pct}%; background-color: {quality_color};"></div>
</div>
<div class="score-grid">
<div class="score-item">
<div class="score-label">Mapping</div>
<div class="score-value {get_score_class(score_mapping * 5, (80, 50))}">{score_mapping}/20</div>
</div>
<div class="score-item">
<div class="score-label">Field Type</div>
<div class="score-value {get_score_class(score_field_type * 9, (80, 50))}">{score_field_type}/11</div>
</div>
<div class="score-item">
<div class="score-label">Search Time</div>
<div class="score-value {get_score_class(score_search_time * 10, (80, 50))}">{score_search_time}/10</div>
</div>
<div class="score-item">
<div class="score-label">Language</div>
<div class="score-value">{score_language}/9</div>
</div>
</div>
</div>
<div class="score-section">
<div class="section-header">
<span class="section-title">Meta Scores</span>
<span class="section-score" style="color:{meta_color}">{meta_score}/{meta_max}</span>
</div>
<div class="track">
<div class="fill" style="width: {meta_pct}%; background-color: {meta_color};"></div>
</div>
<div class="score-grid meta">
<div class="score-item">
<div class="score-label">Note</div>
<div class="score-value {get_score_class(score_note * 5, (80, 50))}">{score_note}/20</div>
</div>
<div class="score-item">
<div class="score-label">Override</div>
<div class="score-value {get_score_class(score_override * 20, (80, 50))}">{score_override}/5</div>
</div>
<div class="score-item">
<div class="score-label">Tactics</div>
<div class="score-value {get_score_class(score_tactics * 33, (80, 50))}">{score_tactics}/3</div>
</div>
<div class="score-item">
<div class="score-label">Techniques</div>
<div class="score-value {get_score_class(score_techniques * 14, (80, 50))}">{score_techniques}/7</div>
</div>
<div class="score-item">
<div class="score-label">Author</div>
<div class="score-value {get_score_class(score_author * 20, (80, 50))}">{score_author}/5</div>
</div>
<div class="score-item">
<div class="score-label">Highlights</div>
<div class="score-value {get_score_class(score_highlights * 10, (80, 50))}">{score_highlights}/10</div>
</div>
</div>
</div>
<div class="score-section total">
<div class="total-label">Rule Score</div>
<div class="total-value" style="color:{score_color}">{score}</div>
</div>
</div>
</div>
<div class="meta-row">
<div>Author: <span class="meta-val">{author}</span></div>
<div>Language: <span class="meta-val">{lang}</span></div>
<div>Rule ID: <span class="meta-val" style="font-family: monospace; font-size: 0.75rem;">{rule_id[:20]}...</span></div>
</div>
</div>
""", unsafe_allow_html=True)
        
        # --- BUTTONS (below card for Streamlit interactivity) ---
        b1, b2, b3, b4 = st.columns([1, 1, 5, 1], gap="small")
        
        source_space = row.get('space_id', 'staging')
        with b1:
            if st.button("📊 Quality", key=f"quality_{index}", use_container_width=True):
                view_quality_modal(rule_name, query, lang, hl_lang, details, row)
        
        with b2:
            if st.button("📖 Meta", key=f"meta_{index}", use_container_width=True):
                view_meta_modal(rule_name, row)
        
        with b4:
            if st.button("🚀 Promote", key=f"promote_{index}", use_container_width=True):
                promote_modal(rule_name, rule_id, details, source_space)
        
        st.markdown("<div style='margin-bottom: 20px;'></div>", unsafe_allow_html=True)

    st.markdown("---")
    st.caption(f"Showing {len(batch_rules)} of {len(df_rules)} staging rules")