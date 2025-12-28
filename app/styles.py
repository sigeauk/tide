import streamlit as st
import requests
import os
from datetime import datetime
from dotenv import dotenv_values

def apply_custom_styles():
    st.markdown("""
    <style>
        /* ========================================
           GLOBAL OVERRIDES
           ======================================== */
        header, div[data-testid="stHeader"] { display: none !important; visibility: hidden !important; }
        div[data-testid="stDecoration"] { display: none !important; visibility: hidden !important; height: 0px !important; }
        .block-container { padding-top: 1rem !important; }
        .stApp { background-color: #0e1117; color: #e0e0e0; }
        footer { visibility: hidden; }

        /* ========================================
           BUTTONS - Global consistent styling
           ======================================== */
        .stButton > button,
        div.stButton > button,
        div[data-testid="stPopover"] button,
        div[data-testid="stPopover"] > div:first-child > button,
        .stDownloadButton > button {
            background-color: #1e293b !important;
            color: white !important;
            border: 1px solid #334155 !important;
            border-radius: 6px !important;
            font-weight: 600 !important;
        }
        .stButton > button:hover,
        div.stButton > button:hover,
        div[data-testid="stPopover"] button:hover,
        div[data-testid="stPopover"] > div:first-child > button:hover,
        .stDownloadButton > button:hover {
            background-color: #22d3ee !important;
            color: black !important;
            border-color: #22d3ee !important;
        }
        .stButton > button:active,
        div.stButton > button:active {
            background-color: #0e7490 !important;
        }
        
        /* Column gaps - tighter for buttons, normal for cards */
        [data-testid="stHorizontalBlock"]:has(.stButton) {
            gap: 4px !important;
        }
        [data-testid="stHorizontalBlock"] {
            gap: 12px !important;
        }
        [data-testid="column"] {
            padding: 0 2px !important;
        }
        .stButton {
            margin: 0 !important;
        }

        /* ========================================
           CARD STYLES - Shared across pages
           ======================================== */
        .rule-card, .threat-card {
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 280px;
        }
        
        /* Rule Health Card Header */
        .rule-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 10px;
            margin-bottom: 12px;
            min-height: 90px;
        }
        .rule-name-container {
            flex: 1;
            min-width: 0;
            max-height: 85px;
            overflow: hidden;
        }
        .rule-name {
            font-size: 1.1rem;
            font-weight: 700;
            color: #f1f5f9;
            line-height: 1.3;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        /* ========================================
           PILLS - Status, Severity, MITRE
           ======================================== */
        .pill-stack { display: flex; flex-direction: column; align-items: flex-end; gap: 6px; flex-shrink: 0; }
        .pill-row { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .status-pill { font-size: 0.85rem; background: #0f172a; padding: 4px 12px; border-radius: 12px; border: 1px solid #334155; color: #94a3b8; white-space: nowrap; display: flex; align-items: center; gap: 6px; }
        .sev-pill { font-size: 0.75rem; font-weight: 700; padding: 3px 10px; border-radius: 12px; white-space: nowrap; color: white; }
        .status-dot { display: inline-block; width: 6px; height: 6px; border-radius: 50%; }
        .mitre-pills { display: flex; flex-wrap: wrap; gap: 4px; justify-content: flex-end; max-width: 150px; max-height: 28px; overflow: hidden; }
        .mitre-pill { font-size: 0.7rem; background: #1e3a5f; padding: 2px 6px; border-radius: 8px; color: #60a5fa; white-space: nowrap; }

        /* ========================================
           PROGRESS BAR
           ======================================== */
        .score-meta { display: flex; justify-content: space-between; font-size: 0.8rem; color: #cbd5e1; margin-bottom: 4px; }
        .track { background-color: #334155; height: 6px; border-radius: 3px; width: 100%; overflow: hidden; }
        .fill { height: 100%; border-radius: 3px; transition: width 0.5s ease; }

        /* ========================================
           METADATA & SCORES
           ======================================== */
        .meta-grid {
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            color: #64748b;
            margin-top: 15px;
            padding-top: 10px;
            border-top: 1px solid #334155;
        }
        .meta-val { color: #e2e8f0; font-weight: 500; }
        .meta-item { display: flex; flex-direction: column; }
        .meta-label { font-weight: 600; color: #58a6ff; margin-bottom: 1px; }
        
        .score-box { text-align: center; padding: 6px; border-radius: 6px; font-weight: bold; margin-bottom: 8px; font-size: 14px; }
        .sub-score-row { display: flex; gap: 10px; margin-bottom: 8px; }
        .sub-score { flex: 1; text-align: center; font-size: 12px; padding: 4px; border-radius: 4px; }

        /* ========================================
           METRIC CARDS
           ======================================== */
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
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        /* ========================================
           PROMOTION CARD STYLES
           ======================================== */
        .promo-card {
            background-color: #1e293b;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        .promo-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 20px;
            margin-bottom: 16px;
        }
        .promo-name {
            font-size: 1.25rem;
            font-weight: 700;
            color: #f1f5f9;
            line-height: 1.3;
            flex: 1;
        }
        .card-body {
            display: flex;
            gap: 16px;
            margin: 16px 0;
        }
        .scores-container {
            display: flex;
            gap: 16px;
            flex: 1;
        }
        .score-section {
            flex: 1;
            padding: 12px;
            background: #0f172a;
            border-radius: 8px;
            border: 1px solid #334155;
        }

        /* ========================================
           SCROLLABLE DESCRIPTION BOX
           ======================================== */
        .threat-desc-scroll {
            font-size: 12px;
            color: #8b949e;
            background-color: #0d1117;
            border: 1px solid #21262d;
            border-radius: 4px;
            padding: 6px;
            height: 100px;
            overflow-y: auto;
            margin-bottom: 8px;
            line-height: 1.4;
        }
        .threat-desc-scroll::-webkit-scrollbar { width: 4px; }
        .threat-desc-scroll::-webkit-scrollbar-track { background: #0d1117; }
        .threat-desc-scroll::-webkit-scrollbar-thumb { background: #30363d; border-radius: 2px; }

        /* ========================================
           COLORS
           ======================================== */
        .color-green { color: #4ade80 !important; border: 1px solid #4ade80; background-color: rgba(74, 222, 128, 0.1); }
        .color-amber { color: #fbbf24 !important; border: 1px solid #fbbf24; background-color: rgba(251, 191, 36, 0.1); }
        .color-red { color: #f87171 !important; border: 1px solid #f87171; background-color: rgba(248, 113, 113, 0.1); }
        .color-blue { color: #58a6ff !important; border: 1px solid #58a6ff; background-color: rgba(88, 166, 255, 0.1); }

        /* ========================================
           TTP TAGS
           ======================================== */
        .ttp-tag {
            display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px;
            font-family: monospace; margin-right: 4px; margin-bottom: 6px; border: 1px solid transparent;
        }
        .ttp-covered { background-color: rgba(74, 222, 128, 0.15); color: #4ade80; border-color: #4ade80; }
        .ttp-missing { background-color: rgba(248, 113, 113, 0.15); color: #f87171; border-color: #f87171; }

        /* ========================================
           STATUS SIDEBAR
           ======================================== */
        .status-row { margin-bottom: 5px; display: flex; align-items: center; justify-content: space-between; }
    </style>
    """, unsafe_allow_html=True)

# --- CONNECTOR STATUS LOGIC ---
def _check_service(name, url, headers=None):
    if not url: return False
    try:
        response = requests.get(url, headers=headers, verify=False, timeout=3)
        return response.status_code in [200, 401, 403]
    except Exception:
        return False

def _run_checks():
    env_path = os.environ.get("TIDE_ENV_PATH", ".env")
    config = dotenv_values(env_path) if os.path.exists(env_path) else {}
    
    es_url = config.get("ELASTIC_URL", "")
    es_key = config.get("ELASTIC_API_KEY", "")
    cti_url = config.get("OPENCTI_URL", "")
    cti_token = config.get("OPENCTI_TOKEN", "")
    gl_url = config.get("GITLAB_URL", "")
    gl_token = config.get("GITLAB_TOKEN", "")
    target_gl = f"{gl_url.rstrip('/')}/api/v4/version" if gl_url else ""

    return {
        "Elastic": _check_service("Elastic", es_url, headers={"Authorization": f"ApiKey {es_key}"}),
        "OpenCTI": _check_service("OpenCTI", cti_url, headers={"Authorization": f"Bearer {cti_token}"}),
        "GitLab": _check_service("GitLab", target_gl, headers={"PRIVATE-TOKEN": gl_token})
    }

def render_sidebar_status():
    with st.sidebar.container(border=True):
        st.subheader("Connector Status")
        
        if "connector_status" not in st.session_state:
            st.session_state["connector_status"] = {"Elastic": None, "OpenCTI": None, "GitLab": None}
            st.session_state["last_check"] = "Never"

        statuses = st.session_state["connector_status"]
        for service, is_up in statuses.items():
            if is_up is None: icon, color = "⚪", "gray"
            elif is_up: icon, color = "🟢", "#4ade80"
            else: icon, color = "🔴", "#f87171"
            
            st.markdown(f"""
                <div class="status-row">
                    <span style="font-weight:bold;">{service}</span>
                    <span style="color:{color};">{icon}</span>
                </div>""", unsafe_allow_html=True)
            
        if st.button("Check Connectivity", use_container_width=True):
            with st.spinner("Checking services..."):
                st.session_state["connector_status"] = _run_checks()
                st.session_state["last_check"] = datetime.now().strftime("%H:%M:%S")
            st.rerun()

        st.markdown(f"<div style='text-align:right; margin-top:10px; font-size:10px; color:#666;'>Last check: {st.session_state['last_check']}</div>", unsafe_allow_html=True)