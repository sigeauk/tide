import os
import streamlit as st
import importlib
from dotenv import dotenv_values

# Import get_icon_path early for page config
from styles import get_icon_path

# --- 1. CONFIG MUST BE FIRST ---
st.set_page_config(
    page_title="Settings | TIDE", 
    page_icon=get_icon_path("tide.png"), 
    layout="wide", 
    initial_sidebar_state="expanded"
)

# --- 2. LOCAL IMPORTS ---
import database as db
from styles import apply_custom_styles, render_sidebar_status
from auth import require_auth

# Apply styles
apply_custom_styles()
require_auth()

# --- 3. DYNAMIC IMPORTS WITH RELOAD ---
# We still keep these imports if you want to add status checks later,
# even though the heavy lifting is moving to the worker.
try:
    import elastic_helper
    importlib.reload(elastic_helper)
except ImportError:
    elastic_helper = None

try:
    import splunk_helper
    importlib.reload(splunk_helper)
except ImportError:
    splunk_helper = None

try:
    import cti_helper
    importlib.reload(cti_helper)
except ImportError:
    cti_helper = None

try:
    import gitlab_helper    
    importlib.reload(gitlab_helper)
except ImportError:
    gitlab_helper = None

# --- 4. APP LOGIC ---
ENV_PATH = os.environ.get("TIDE_ENV_PATH", ".env")

def load_env(path: str) -> dict:
    if os.path.exists(path):
        return dict(dotenv_values(path))
    return {}

def write_env(path: str, data: dict) -> None:
    lines = []
    for k, v in data.items():
        if v is None: v = ""
        lines.append(f"{k}={v}\n")
    with open(path, "w", encoding="utf-8") as fh:
        fh.writelines(lines)

config = load_env(ENV_PATH)
tabs = st.tabs(["Platform", "SIEM", "OpenCTI", "MITRE", "GitLab", "Sigma repo", "Elastic repo"])

# ==========================================
# 1. PLATFORM
# ==========================================
with tabs[0]:
    st.header("Platform Settings")
    with st.form("platform_settings_form"):
        st.subheader("Worker Settings")
        # Ensure value is int
        default_interval = int(config.get("SYNC_INTERVAL_MINUTES", 5))
        sync_interval = st.number_input("Sync Interval (Minutes)", min_value=1, value=default_interval)
        
        if st.form_submit_button("Save Platform Settings"):
            config["SYNC_INTERVAL_MINUTES"] = str(sync_interval)
            try:
                write_env(ENV_PATH, config)
                st.success("Platform settings saved to .env")
            except Exception as exc:
                st.error(f"Failed to save .env: {exc}")

# ==========================================
# 2. SIEM
# ==========================================
with tabs[1]:
    st.header("SIEM Configuration")
    
    # Elastic
    col_el_head, col_el_btn = st.columns([4, 1])
    with col_el_head: st.subheader("Elastic")
    with col_el_btn:
        if st.button("🔄 Sync Elastic", key="btn_sync_elastic", use_container_width=True):
            db.set_trigger("sync_elastic")
            with st.spinner("Syncing rules from Kibana..."):
                sync_success = db.wait_for_sync(timeout=60)
            if sync_success:
                st.success("✅ Sync completed!")
            else:
                st.warning("⚠️ Sync may still be in progress.")
            st.rerun()

    with st.form("elastic_form"):
        es_url = st.text_input("Kibana URL (e.g. http://kibana:5601)", value=config.get("ELASTIC_URL", "http://localhost:5601"))
        
        es_direct_url = st.text_input("Elasticsearch URL (e.g. http://elasticsearch:9200)", value=config.get("ELASTICSEARCH_URL", ""))
        
        es_api_key = st.text_input("API Key (Used for both)", value=config.get("ELASTIC_API_KEY", ""), type="password")

        kib_spaces = st.text_input("Kibana Spaces to query (e.g. production, staging)", value=config.get("KIBANA_SPACES", ""))
        
        if st.form_submit_button("Save Elastic Settings"):
            config["ELASTIC_URL"] = es_url
            config["ELASTICSEARCH_URL"] = es_direct_url
            config["ELASTIC_API_KEY"] = es_api_key
            config["KIBANA_SPACES"] = kib_spaces
            write_env(ENV_PATH, config)
            st.success("Saved!")
    
    st.divider()
    
    # Splunk
    col_sp_head, col_sp_btn = st.columns([4, 1])
    with col_sp_head: st.subheader("Splunk")
    with col_sp_btn:
        if st.button("🔄 Sync Splunk", key="btn_sync_splunk", use_container_width=True):
            db.set_trigger("sync_splunk")
            st.info("Signal sent (Worker implementation pending for Splunk).")

    with st.form("Splunk_form"):
        splunk_url = st.text_input("URL", value=config.get("SPLUNK_URL", "http://localhost:8089"))
        splunk_api_key = st.text_input("API Key", value=config.get("SPLUNK_API_KEY", ""), type="password")
        if st.form_submit_button("Save Splunk Settings"):
            config["SPLUNK_URL"] = splunk_url
            config["SPLUNK_API_KEY"] = splunk_api_key
            write_env(ENV_PATH, config)
            st.success("Saved!")

# ==========================================
# 3. OPENCTI
# ==========================================
with tabs[2]:
    st.header("OpenCTI Configuration")
    
    col_cti_head, col_cti_btn = st.columns([4, 1])
    with col_cti_head: st.subheader("OpenCTI Connection")
    with col_cti_btn:
        if st.button("🔄 Sync OpenCTI", key="btn_sync_opencti", use_container_width=True):
            # ✅ UPDATED: Now uses safe trigger pattern
            db.set_trigger("sync_opencti")
            st.success("Signal sent to Worker! Threat Intel sync starting...")

    with st.form("opencti_form"):
        cti_url = st.text_input("URL", value=config.get("OPENCTI_URL", ""))
        cti_token = st.text_input("API Token", value=config.get("OPENCTI_TOKEN", ""), type="password")
        if st.form_submit_button("Save OpenCTI Settings"):
            config["OPENCTI_URL"] = cti_url
            config["OPENCTI_TOKEN"] = cti_token
            write_env(ENV_PATH, config)
            st.success("Saved!")

# ==========================================
# 4. MITRE
# ==========================================
with tabs[3]:
    st.header("MITRE Configuration")
    
    col_mitre_head, col_mitre_btn = st.columns([4, 1])
    with col_mitre_head: st.subheader("MITRE ATT&CK Feeds")
    with col_mitre_btn:
        if st.button("🔄 Sync All Feeds", key="btn_sync_mitre", use_container_width=True):
            # ✅ UPDATED: Now uses safe trigger pattern
            db.set_trigger("sync_mitre")
            st.success("Signal sent to Worker! Feeds are updating in background...")

    with st.form("mitre_form"):
        mitre_ent = st.text_input("Enterprise", value=config.get("MITRE_SOURCE", "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"))
        mitre_mob = st.text_input("Mobile", value=config.get("MITRE_MOBILE_SOURCE", "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"))
        mitre_ics = st.text_input("ICS (Industrial)", value=config.get("MITRE_ICS_SOURCE", "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"))
        mitre_pre = st.text_input("Pre-Attack (Legacy)", value=config.get("MITRE_PRE_SOURCE", "https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json"))

        if st.form_submit_button("Save MITRE Settings"):
            config["MITRE_SOURCE"] = mitre_ent
            config["MITRE_MOBILE_SOURCE"] = mitre_mob
            config["MITRE_ICS_SOURCE"] = mitre_ics
            config["MITRE_PRE_SOURCE"] = mitre_pre
            write_env(ENV_PATH, config)
            st.success("MITRE settings saved!")

# ==========================================
# 5. GITLAB
# ==========================================
with tabs[4]:
    st.header("GitLab Configuration")
    col_gl_head, col_gl_btn = st.columns([4, 1])
    with col_gl_head: st.subheader("GitLab (Detection-as-Code)")
    with col_gl_btn:
        if st.button("🔄 Sync GitLab", key="btn_sync_gitlab", use_container_width=True):
            # ✅ UPDATED: Now uses safe trigger pattern
            db.set_trigger("sync_gitlab")
            st.success("Signal sent to Worker! Repo sync starting...")

    with st.form("gitlab_form"):
        gl_url = st.text_input("URL", value=config.get("GITLAB_URL", ""))
        gl_token = st.text_input("API Token", value=config.get("GITLAB_TOKEN", ""), type="password")
        gl_project_id = st.text_input("Project ID", value=config.get("GITLAB_PROJECT_ID", ""))
        
        if st.form_submit_button("Save GitLab Settings"):
            config["GITLAB_URL"] = gl_url
            config["GITLAB_TOKEN"] = gl_token
            config["GITLAB_PROJECT_ID"] = gl_project_id
            write_env(ENV_PATH, config)
            st.success("Saved!")

# ==========================================
# 6. SIGMA & ELASTIC REPO
# ==========================================
with tabs[5]:
    st.header("Sigma Repository")
    with st.form("sigma_form"):
        sigma_repo = st.text_input("Sigma Repo URL", value=config.get("SIGMA_REPO_URL", ""))
        if st.form_submit_button("Save"):
            config["SIGMA_REPO_URL"] = sigma_repo
            write_env(ENV_PATH, config)
            st.success("Saved!")

with tabs[6]:
    st.header("Elastic Repository")
    with st.form("elastic_repo_form"):
        elastic_repo = st.text_input("Elastic Repo URL", value=config.get("ELASTIC_REPO_URL", ""))
        if st.form_submit_button("Save"):
            config["ELASTIC_REPO_URL"] = elastic_repo
            write_env(ENV_PATH, config)
            st.success("Saved!")