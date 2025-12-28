import streamlit as st
import pandas as pd
import database as db
from styles import apply_custom_styles, render_sidebar_status
from auth import require_auth

# Page Config
st.set_page_config(page_title="Coverage Matrix | TIDE", page_icon="🧱", layout="wide")
apply_custom_styles()
require_auth()

# --- 1. DEFINITIONS ---
TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation", 
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", 
    "Collection", "Command and Control", "Exfiltration", "Impact"
]

# --- FIX: MAP STIX SLUGS TO DISPLAY TITLES ---
SLUG_TO_TITLE = {
    "initial-access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege-escalation": "Privilege Escalation",
    "defense-evasion": "Defense Evasion",
    "credential-access": "Credential Access",
    "discovery": "Discovery",
    "lateral-movement": "Lateral Movement",
    "collection": "Collection",
    "command-and-control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
    "reconnaissance": "Reconnaissance",       # Optional Support
    "resource-development": "Resource Dev"    # Optional Support
}

# --- 2. CSS STYLING ---
st.markdown("""
<style>
    /* Main Grid Container */
    .matrix-container {
        display: grid;
        grid-template-columns: repeat(6, 1fr);
        gap: 12px;
        margin-top: 20px;
    }
    
    /* Column Styling */
    .tactic-column {
        background-color: #0d1117;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 8px;
        display: flex;
        flex-direction: column;
        gap: 4px;
    }
    
    /* Header Styling */
    .tactic-header {
        text-align: center;
        font-weight: 700;
        color: #8b949e;
        border-bottom: 1px solid #30363d;
        padding-bottom: 8px;
        margin-bottom: 8px;
        font-size: 0.85rem;
        letter-spacing: 0.5px;
    }
    
    /* Card Styling */
    .ttp-card {
        padding: 6px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        text-align: center;
        font-weight: 600;
        cursor: pointer;
        color: #fff;
        transition: all 0.2s ease;
        display: block;
    }
    .ttp-card:hover {
        transform: translateY(-2px);
        filter: brightness(1.2);
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    
    /* Status Colors */
    .status-gap { 
        background-color: rgba(185, 28, 28, 0.25); 
        border: 1px solid #7f1d1d; 
        color: #fca5a5;
    }
    .status-covered { 
        background-color: rgba(6, 95, 70, 0.4); 
        border: 1px solid #064e3b; 
        color: #6ee7b7;
    }
    .status-defense { 
        background-color: rgba(30, 58, 138, 0.3); 
        border: 1px solid #1e3a8a; 
        color: #93c5fd; 
        opacity: 0.7;
    }
</style>
""", unsafe_allow_html=True)

st.title("🧱 Coverage Matrix")

# --- METRICS CARDS CSS ---
st.markdown("""
<style>
    .metric-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
    }
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        color: #f1f5f9;
        margin: 0;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #94a3b8;
        margin-top: 4px;
    }
    .metric-sub {
        font-size: 0.75rem;
        color: #64748b;
        margin-top: 8px;
    }
    .metric-good { color: #4ade80; }
    .metric-warn { color: #facc15; }
    .metric-bad { color: #f87171; }
</style>
""", unsafe_allow_html=True)

# --- 3. LOAD DATA (Dynamic Map) ---
def load_tactic_map():
    # Tries to get map from DB. If empty, returns fallback.
    try:
        mapping = db.get_technique_map()
        if mapping: return mapping
    except AttributeError:
        pass
    return {}

def load_technique_names():
    # Get technique ID to name mapping
    try:
        return db.get_technique_names()
    except AttributeError:
        return {}

TTP_MAP = load_tactic_map()
TTP_NAMES = load_technique_names()

def get_tactic_for_ttp(ttp_id):
    # 1. Get raw value from DB (likely 'initial-access')
    raw_tactic = TTP_MAP.get(ttp_id.upper())
    
    if not raw_tactic:
        return "Other"
        
    # 2. Convert Slug to Title Case using our map
    #    If not found in map, it defaults to "Other"
    return SLUG_TO_TITLE.get(raw_tactic, "Other")

# Fetch Real Data
try:
    threats, _ = db.get_threat_data()
    raw_covered = db.get_all_covered_ttps()
    covered_ttps = {str(t).strip().upper() for t in raw_covered if t}
    df_threats = pd.DataFrame(threats)
except Exception as e:
    st.error(f"Data Fetch Error: {e}")
    st.stop()

# --- 4. SIDEBAR CONTROLS ---
with st.sidebar:
    st.header("Matrix Settings")
    
    # FIXED: 'name' instead of 'Actor'
    all_actors = sorted(df_threats['name'].unique()) if not df_threats.empty else []
    
    selected_actors = st.multiselect(
        "Select Adversaries", 
        all_actors,
        placeholder="e.g. APT29, Lazarus Group..."
    )
    
    show_defense = st.checkbox(
        "Show 'Defense in Depth'", 
        value=False, 
        help="Include rules for techniques NOT used by the selected actors."
    )

# --- 5. CALCULATE MATRIX ---
relevant_ttps = set()
actor_ttp_map = {} 

if selected_actors:
    mask = df_threats['name'].isin(selected_actors)
    subset = df_threats[mask]
    
    for _, row in subset.iterrows():
        actor = row['name']
        raw_list = row.get('ttps', [])
        
        for t in raw_list:
            t_id = str(t).strip().upper()
            relevant_ttps.add(t_id)
            if t_id not in actor_ttp_map: actor_ttp_map[t_id] = []
            actor_ttp_map[t_id].append(actor)

# --- 6. PREPARE DISPLAY DATA ---
matrix_data = {t: [] for t in TACTIC_ORDER + ["Other"]}

display_ttps = relevant_ttps.copy()
if show_defense:
    display_ttps.update(covered_ttps)

if not display_ttps:
    st.info("👈 Please select Threat Actors in the sidebar to generate the Matrix.")
    st.stop()

for ttp in display_ttps:
    is_relevant = ttp in relevant_ttps
    is_covered = ttp in covered_ttps
    
    # Get technique name for tooltip
    tech_name = TTP_NAMES.get(ttp, TTP_NAMES.get(ttp.upper(), "Unknown Technique"))
    
    # Classify Logic
    if is_relevant and not is_covered:
        s_class = "status-gap"
        status_text = "CRITICAL GAP: No rules found"
    elif is_relevant and is_covered:
        s_class = "status-covered"
        status_text = "COVERED: Rules exist"
    else:
        s_class = "status-defense"
        status_text = "Defense in Depth"
    
    # Mapping Logic (Now uses correct Title Case)
    tactic = get_tactic_for_ttp(ttp)
    if tactic not in matrix_data: tactic = "Other"
    
    actors = ", ".join(actor_ttp_map.get(ttp, []))
    # Use HTML entity for newline in title attribute, escape quotes
    final_tooltip = f"{tech_name} | {status_text} | Used by: {actors if actors else 'N/A'}"
    final_tooltip = final_tooltip.replace('"', '&quot;')
    
    matrix_data[tactic].append({
        "id": ttp,
        "name": tech_name,
        "class": s_class,
        "tooltip": final_tooltip
    })

# --- 7. METRICS ROW ---
gap_count = sum(1 for t in relevant_ttps if t not in covered_ttps)
covered_count = len(relevant_ttps) - gap_count
pct = int((covered_count/len(relevant_ttps)*100)) if relevant_ttps else 0

h1, h2, h3, h4, h5, h6 = st.columns(6)

with h1:
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{len(selected_actors)}</p>
        <p class="metric-label">Selected Actors</p>
        <p class="metric-sub">🎯 Focus group</p>
    </div>
    ''', unsafe_allow_html=True)

with h2:
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{len(relevant_ttps)}</p>
        <p class="metric-label">Adversary TTPs</p>
        <p class="metric-sub">📊 Techniques used</p>
    </div>
    ''', unsafe_allow_html=True)

with h3:
    gap_color = "metric-good" if gap_count == 0 else ("metric-warn" if gap_count < 10 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {gap_color}">{gap_count}</p>
        <p class="metric-label">Critical Gaps</p>
        <p class="metric-sub">⚠️ No detection</p>
    </div>
    ''', unsafe_allow_html=True)

with h4:
    cov_color = "metric-good" if covered_count == len(relevant_ttps) else ("metric-warn" if covered_count > 0 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {cov_color}">{covered_count}</p>
        <p class="metric-label">Covered TTPs</p>
        <p class="metric-sub">✅ Rules exist</p>
    </div>
    ''', unsafe_allow_html=True)

with h5:
    pct_color = "metric-good" if pct >= 80 else ("metric-warn" if pct >= 50 else "metric-bad")
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value {pct_color}">{pct}%</p>
        <p class="metric-label">Coverage</p>
        <p class="metric-sub">🛡️ Protection rate</p>
    </div>
    ''', unsafe_allow_html=True)

with h6:
    defense_count = len(covered_ttps - relevant_ttps) if show_defense else 0
    st.markdown(f'''
    <div class="metric-card">
        <p class="metric-value">{defense_count}</p>
        <p class="metric-label">Defense Depth</p>
        <p class="metric-sub">💪 Extra rules</p>
    </div>
    ''', unsafe_allow_html=True)

st.markdown("<br>", unsafe_allow_html=True)

# --- 8. RENDER GRID ---
active_tactics = [t for t in TACTIC_ORDER + ["Other"] if matrix_data[t]]
html_columns = []

for tactic in active_tactics:
    cards = sorted(matrix_data[tactic], key=lambda x: x['id'])
    cards_html = ""
    
    for c in cards:
        # Display styled card with tooltip
        cards_html += f'<div class="ttp-card {c["class"]}" title="{c["tooltip"]}">{c["id"]}</div>'
    
    col_html = f"""
<div class="tactic-column">
<div class="tactic-header">{tactic.upper()}</div>
{cards_html}
</div>"""
    html_columns.append(col_html)

# Final Grid Injection
grid_html = f"""
<div class="matrix-container" style="grid-template-columns: repeat({len(active_tactics)}, minmax(140px, 1fr));">
{''.join(html_columns)}
</div>
"""

st.markdown(grid_html, unsafe_allow_html=True)