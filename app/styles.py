import streamlit as st
import requests
import os
from datetime import datetime
from dotenv import dotenv_values

# ============================================================
# COLOR PALETTE - All colors in one place for VS Code swatches
# ============================================================

# --- Background Colors ---
COLOR_BG_PRIMARY = "#0e1117"      # App background
COLOR_BG_CARD = "#1e293b"         # Card backgrounds
COLOR_BG_DARK = "#0f172a"         # Gradient end, dark areas
COLOR_BG_DARKEST = "#0d1117"      # Matrix columns, scroll areas
COLOR_BG_PILL = "#0f172a"         # Status pill background
COLOR_BG_SECTION = "#0f172a"      # Score section background
COLOR_BG_MITRE_PILL = "#1e3a5f"   # MITRE technique pills

# --- Border Colors ---
COLOR_BORDER = "#334155"          # Primary borders
COLOR_BORDER_DARK = "#30363d"     # Matrix borders
COLOR_BORDER_SUBTLE = "#21262d"   # Subtle borders
COLOR_BORDER_HOVER = "#475569"    # Hover state borders

# --- Text Colors ---
COLOR_TEXT_PRIMARY = "#f1f5f9"    # Main text
COLOR_TEXT_SECONDARY = "#e2e8f0"  # Secondary text
COLOR_TEXT_MUTED = "#94a3b8"      # Labels, muted text
COLOR_TEXT_SUBTLE = "#64748b"     # Subtle text, dividers
COLOR_TEXT_DIM = "#8b949e"        # Dim headers
COLOR_TEXT_DARK = "#cbd5e1"       # Coverage meta text

# --- Status Colors ---
COLOR_SUCCESS = "#4ade80"         # Good/success states
COLOR_SUCCESS_DARK = "#059669"    # Covered border
COLOR_SUCCESS_LIGHT = "#34d399"   # Covered text
COLOR_SUCCESS_BG = "#166534"      # Success button hover
COLOR_SUCCESS_MATRIX = "#6ee7b7"  # Matrix covered text
COLOR_SUCCESS_BORDER_MATRIX = "#064e3b"  # Matrix covered border

COLOR_WARNING = "#facc15"         # Warning states
COLOR_WARNING_ALT = "#fbbf24"     # Amber variant

COLOR_DANGER = "#f87171"          # Bad/error states
COLOR_DANGER_DARK = "#991b1b"     # Missing border
COLOR_DANGER_LIGHT = "#fca5a5"    # Gap text
COLOR_DANGER_BORDER_MATRIX = "#7f1d1d"  # Matrix gap border

# --- Accent Colors ---
COLOR_INFO = "#60a5fa"            # Info, links
COLOR_ACCENT_CYAN = "#22d3ee"     # Button hover
COLOR_ACCENT_CYAN_DARK = "#0e7490"  # Button active
COLOR_ACCENT_BLUE = "#58a6ff"     # Accent blue
COLOR_ACCENT_BLUE_LIGHT = "#93c5fd"  # Defense matrix text
COLOR_ACCENT_BLUE_BORDER = "#1e3a8a"  # Defense matrix border
COLOR_QUERY_LABEL = "#0ea5e9"     # Query output label

# --- Severity Colors ---
COLOR_SEV_CRITICAL = "#dc2626"    # Critical severity
COLOR_SEV_HIGH = "#ea580c"        # High severity
COLOR_SEV_MEDIUM = "#eab308"      # Medium severity
COLOR_SEV_LOW = "#22c55e"         # Low severity
COLOR_SEV_INFO = "#06b6d4"        # Informational

# --- Chart Colors (used in plotly) ---
COLOR_CHART_CRITICAL = "#df4a4a"
COLOR_CHART_HIGH = "#ff9f1c"
COLOR_CHART_MEDIUM = "#ffd166"
COLOR_CHART_LOW = "#06d6a0"
COLOR_CHART_INFO = "#118ab2"


def apply_custom_styles():
    """Apply global custom styles to the Streamlit app."""
    st.markdown(f"""
    <style>
        /* ========================================
           GLOBAL OVERRIDES
           ======================================== */
        header, div[data-testid="stHeader"] {{ display: none !important; visibility: hidden !important; }}
        div[data-testid="stDecoration"] {{ display: none !important; visibility: hidden !important; height: 0px !important; }}
        .block-container {{ padding-top: 1rem !important; }}
        .stApp {{ background-color: {COLOR_BG_PRIMARY}; color: #e0e0e0; }}
        footer {{ visibility: hidden; }}

        /* ========================================
           BUTTONS - Global consistent styling
           ======================================== */
        .stButton > button,
        div.stButton > button,
        div[data-testid="stPopover"] button,
        div[data-testid="stPopover"] > div:first-child > button,
        .stDownloadButton > button {{
            background-color: {COLOR_BG_CARD} !important;
            color: white !important;
            border: 1px solid {COLOR_BORDER} !important;
            border-radius: 6px !important;
            font-weight: 600 !important;
        }}
        .stButton > button:hover,
        div.stButton > button:hover,
        div[data-testid="stPopover"] button:hover,
        div[data-testid="stPopover"] > div:first-child > button:hover,
        .stDownloadButton > button:hover {{
            background-color: {COLOR_ACCENT_CYAN} !important;
            color: black !important;
            border-color: {COLOR_ACCENT_CYAN} !important;
        }}
        .stButton > button:active,
        div.stButton > button:active {{
            background-color: {COLOR_ACCENT_CYAN_DARK} !important;
        }}
        
        /* Column gaps - tighter for buttons, normal for cards */
        [data-testid="stHorizontalBlock"]:has(.stButton) {{
            gap: 4px !important;
        }}
        [data-testid="stHorizontalBlock"] {{
            gap: 12px !important;
        }}
        [data-testid="column"] {{
            padding: 0 2px !important;
        }}
        .stButton {{
            margin: 0 !important;
        }}

        /* ========================================
           CARD STYLES - Shared across pages
           ======================================== */
        .rule-card, .threat-card {{
            background-color: {COLOR_BG_CARD};
            border: 1px solid {COLOR_BORDER};
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 280px;
        }}
        
        /* Rule Health Card Header */
        .rule-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 10px;
            margin-bottom: 12px;
            min-height: 90px;
        }}
        .rule-name-container {{
            flex: 1;
            min-width: 0;
            max-height: 85px;
            overflow: hidden;
        }}
        .rule-name {{
            font-size: 1.1rem;
            font-weight: 700;
            color: {COLOR_TEXT_PRIMARY};
            line-height: 1.3;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }}

        /* ========================================
           THREAT LANDSCAPE - Actor Cards
           ======================================== */
        .threat-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }}
        .actor-name {{
            font-size: 1.1rem;
            font-weight: 700;
            color: {COLOR_TEXT_PRIMARY};
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            max-width: 85%;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        .alias-text {{
            font-size: 0.8rem;
            color: {COLOR_TEXT_MUTED};
            font-style: italic;
            margin-bottom: 12px;
            height: 20px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }}
        .coverage-meta {{
            display: flex;
            justify-content: space-between;
            font-size: 0.8rem;
            color: {COLOR_TEXT_DARK};
            margin-bottom: 4px;
        }}
        .progress-track {{
            background-color: {COLOR_BORDER};
            height: 6px;
            border-radius: 3px;
            width: 100%;
            overflow: hidden;
        }}
        .progress-fill {{
            height: 100%;
            border-radius: 3px;
            transition: width 0.5s ease-in-out;
        }}
        .ttp-grid {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
            margin-top: 8px;
        }}
        .tag-covered {{
            background-color: rgba(16, 185, 129, 0.15);
            border-color: {COLOR_SUCCESS_DARK};
            color: {COLOR_SUCCESS_LIGHT};
        }}
        .tag-missing {{
            background-color: rgba(239, 68, 68, 0.15);
            border-color: {COLOR_DANGER_DARK};
            color: {COLOR_DANGER};
        }}
        .flag-img {{
            height: 18px;
            width: auto;
            border-radius: 2px;
            box-shadow: 0 0 3px rgba(0,0,0,0.5);
        }}
        .source-pills {{
            display: flex;
            flex-wrap: wrap;
            gap: 4px;
            margin-top: 8px;
        }}
        .source-pill {{
            font-size: 1rem;
            background: {COLOR_BG_MITRE_PILL};
            padding: 2px 6px;
            border-radius: 8px;
            color: {COLOR_INFO};
            white-space: nowrap;
        }}

        /* ========================================
           PILLS - Status, Severity, MITRE
           ======================================== */
        .pill-stack {{ display: flex; flex-direction: column; align-items: flex-end; gap: 6px; flex-shrink: 0; }}
        .pill-row {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
        .status-pill {{ font-size: 0.85rem; background: {COLOR_BG_PILL}; padding: 4px 12px; border-radius: 12px; border: 1px solid {COLOR_BORDER}; color: {COLOR_TEXT_MUTED}; white-space: nowrap; display: flex; align-items: center; gap: 6px; }}
        .sev-pill {{ font-size: 0.75rem; font-weight: 700; padding: 3px 10px; border-radius: 12px; white-space: nowrap; color: white; }}
        .status-dot {{ display: inline-block; width: 6px; height: 6px; border-radius: 50%; }}
        .mitre-pills {{ display: flex; flex-wrap: wrap; gap: 4px; justify-content: flex-end; max-width: 150px; max-height: 28px; overflow: hidden; }}
        .mitre-pill {{ font-size: 0.7rem; background: {COLOR_BG_MITRE_PILL}; padding: 2px 6px; border-radius: 8px; color: {COLOR_INFO}; white-space: nowrap; }}

        /* ========================================
           PROGRESS BAR
           ======================================== */
        .score-meta {{ display: flex; justify-content: space-between; font-size: 0.8rem; color: {COLOR_TEXT_DARK}; margin-bottom: 4px; }}
        .track {{ background-color: {COLOR_BORDER}; height: 6px; border-radius: 3px; width: 100%; overflow: hidden; }}
        .fill {{ height: 100%; border-radius: 3px; transition: width 0.5s ease; }}

        /* ========================================
           METADATA & SCORES
           ======================================== */
        .meta-grid {{
            display: flex;
            justify-content: space-between;
            font-size: 0.75rem;
            color: {COLOR_TEXT_SUBTLE};
            margin-top: 15px;
            padding-top: 10px;
            border-top: 1px solid {COLOR_BORDER};
        }}
        .meta-val {{ color: {COLOR_TEXT_SECONDARY}; font-weight: 500; }}
        .meta-item {{ display: flex; flex-direction: column; }}
        .meta-label {{ font-weight: 600; color: {COLOR_ACCENT_BLUE}; margin-bottom: 1px; }}
        
        .score-box {{ text-align: center; padding: 6px; border-radius: 6px; font-weight: bold; margin-bottom: 8px; font-size: 14px; }}
        .sub-score-row {{ display: flex; gap: 10px; margin-bottom: 8px; }}
        .sub-score {{ flex: 1; text-align: center; font-size: 12px; padding: 4px; border-radius: 4px; }}

        /* ========================================
           METRIC CARDS
           ======================================== */
        .metric-card {{
            background: linear-gradient(135deg, {COLOR_BG_CARD} 0%, {COLOR_BG_DARK} 100%);
            border: 1px solid {COLOR_BORDER};
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .metric-value {{
            font-size: 2.2rem;
            font-weight: 700;
            color: {COLOR_TEXT_PRIMARY};
            margin: 0;
        }}
        .metric-label {{
            font-size: 0.85rem;
            color: {COLOR_TEXT_MUTED};
            margin-top: 4px;
        }}
        .metric-sub {{
            font-size: 0.75rem;
            color: {COLOR_TEXT_SUBTLE};
            margin-top: 8px;
        }}
        .metric-good {{ color: {COLOR_SUCCESS}; }}
        .metric-warn {{ color: {COLOR_WARNING}; }}
        .metric-bad {{ color: {COLOR_DANGER}; }}
        
        .section-header {{
            font-size: 1.1rem;
            font-weight: 600;
            color: {COLOR_TEXT_MUTED};
            margin: 20px 0 10px 0;
            padding-bottom: 8px;
            border-bottom: 1px solid {COLOR_BORDER};
        }}

        /* ========================================
           PROMOTION CARD STYLES
           ======================================== */
        .promo-card {{
            background-color: {COLOR_BG_CARD};
            border: 1px solid {COLOR_BORDER};
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 12px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        .promo-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            gap: 20px;
            margin-bottom: 16px;
        }}
        .promo-name {{
            font-size: 1.25rem;
            font-weight: 700;
            color: {COLOR_TEXT_PRIMARY};
            line-height: 1.3;
            flex: 1;
        }}
        .card-body {{
            display: flex;
            gap: 16px;
            margin: 16px 0;
        }}
        .scores-container {{
            display: flex;
            gap: 16px;
            flex: 1;
        }}
        .score-section {{
            flex: 1;
            padding: 12px;
            background: {COLOR_BG_SECTION};
            border-radius: 8px;
            border: 1px solid {COLOR_BORDER};
        }}
        .score-section.total {{
            flex: 0 0 120px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
        }}
        .section-title {{
            font-size: 0.75rem;
            color: {COLOR_TEXT_MUTED};
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .section-score {{
            font-size: 0.9rem;
            font-weight: 700;
        }}
        .score-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 8px;
            margin-top: 8px;
        }}
        .score-grid.meta {{
            grid-template-columns: repeat(6, 1fr);
        }}
        .score-item {{
            text-align: center;
        }}
        .score-label {{
            font-size: 0.65rem;
            color: {COLOR_TEXT_SUBTLE};
            text-transform: uppercase;
            letter-spacing: 0.3px;
            margin-bottom: 2px;
        }}
        .score-value {{
            font-size: 0.9rem;
            font-weight: 700;
            color: {COLOR_TEXT_SECONDARY};
        }}
        .score-value.good {{ color: {COLOR_SUCCESS}; }}
        .score-value.warn {{ color: {COLOR_WARNING}; }}
        .score-value.bad {{ color: {COLOR_DANGER}; }}
        .total-label {{
            font-size: 0.7rem;
            color: {COLOR_TEXT_SUBTLE};
            text-transform: uppercase;
            margin-bottom: 4px;
        }}
        .total-value {{
            font-size: 2rem;
            font-weight: 700;
        }}
        .meta-row {{
            display: flex;
            justify-content: space-between;
            font-size: 0.8rem;
            color: {COLOR_TEXT_SUBTLE};
            margin-top: 16px;
            padding-top: 12px;
            border-top: 1px solid {COLOR_BORDER};
        }}
        .action-btn {{
            padding: 8px 12px;
            border-radius: 6px;
            border: 1px solid {COLOR_BORDER};
            background: {COLOR_BG_CARD};
            color: {COLOR_TEXT_SECONDARY};
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            text-align: center;
        }}
        .action-btn:hover {{
            background: {COLOR_BORDER};
            border-color: {COLOR_BORDER_HOVER};
        }}
        .action-btn.promote {{
            border-color: {COLOR_SEV_LOW};
            color: {COLOR_SUCCESS};
        }}
        .action-btn.promote:hover {{
            background: {COLOR_SUCCESS_BG};
        }}
        .button-column {{
            display: flex;
            flex-direction: column;
            gap: 8px;
            justify-content: center;
            min-width: 100px;
        }}

        /* ========================================
           COVERAGE MATRIX (HEATMAP)
           ======================================== */
        .matrix-container {{
            display: grid;
            grid-template-columns: repeat(6, 1fr);
            gap: 12px;
            margin-top: 20px;
        }}
        .tactic-column {{
            background-color: {COLOR_BG_DARKEST};
            border: 1px solid {COLOR_BORDER_DARK};
            border-radius: 6px;
            padding: 8px;
            display: flex;
            flex-direction: column;
            gap: 4px;
        }}
        .tactic-header {{
            text-align: center;
            font-weight: 700;
            color: {COLOR_TEXT_DIM};
            border-bottom: 1px solid {COLOR_BORDER_DARK};
            padding-bottom: 8px;
            margin-bottom: 8px;
            font-size: 0.85rem;
            letter-spacing: 0.5px;
        }}
        .ttp-card {{
            padding: 6px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            text-align: center;
            font-weight: 600;
            cursor: pointer;
            color: #fff;
            transition: all 0.2s ease;
            display: block;
        }}
        .ttp-card:hover {{
            transform: translateY(-2px);
            filter: brightness(1.2);
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        .status-gap {{ 
            background-color: rgba(185, 28, 28, 0.25); 
            border: 1px solid {COLOR_DANGER_BORDER_MATRIX}; 
            color: {COLOR_DANGER_LIGHT};
        }}
        .status-covered {{ 
            background-color: rgba(6, 95, 70, 0.4); 
            border: 1px solid {COLOR_SUCCESS_BORDER_MATRIX}; 
            color: {COLOR_SUCCESS_MATRIX};
        }}
        .status-defense {{ 
            background-color: rgba(30, 58, 138, 0.3); 
            border: 1px solid {COLOR_ACCENT_BLUE_BORDER}; 
            color: {COLOR_ACCENT_BLUE_LIGHT}; 
            opacity: 0.7;
        }}

        /* ========================================
           SIGMA CONVERTER
           ======================================== */
        .level-pill {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 600;
            margin-right: 6px;
        }}
        .level-critical {{ background: {COLOR_SEV_CRITICAL}; color: white; }}
        .level-high {{ background: {COLOR_SEV_HIGH}; color: white; }}
        .level-medium {{ background: {COLOR_SEV_MEDIUM}; color: black; }}
        .level-low {{ background: {COLOR_SEV_LOW}; color: black; }}
        .level-informational {{ background: {COLOR_SEV_INFO}; color: black; }}
        .query-label {{
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: {COLOR_QUERY_LABEL};
            color: white;
            padding: 4px 12px;
            border-radius: 6px;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 12px;
        }}

        /* ========================================
           PRESENTATION PAGE
           ======================================== */
        h1 {{ color: {COLOR_INFO}; font-family: 'Helvetica Neue', sans-serif; }}

        /* ========================================
           SCROLLABLE DESCRIPTION BOX
           ======================================== */
        .threat-desc-scroll {{
            font-size: 12px;
            color: {COLOR_TEXT_DIM};
            background-color: {COLOR_BG_DARKEST};
            border: 1px solid {COLOR_BORDER_SUBTLE};
            border-radius: 4px;
            padding: 6px;
            height: 100px;
            overflow-y: auto;
            margin-bottom: 8px;
            line-height: 1.4;
        }}
        .threat-desc-scroll::-webkit-scrollbar {{ width: 4px; }}
        .threat-desc-scroll::-webkit-scrollbar-track {{ background: {COLOR_BG_DARKEST}; }}
        .threat-desc-scroll::-webkit-scrollbar-thumb {{ background: {COLOR_BORDER_DARK}; border-radius: 2px; }}

        /* ========================================
           COLORS - Utility classes
           ======================================== */
        .color-green {{ color: {COLOR_SUCCESS} !important; border: 1px solid {COLOR_SUCCESS}; background-color: rgba(74, 222, 128, 0.1); }}
        .color-amber {{ color: {COLOR_WARNING_ALT} !important; border: 1px solid {COLOR_WARNING_ALT}; background-color: rgba(251, 191, 36, 0.1); }}
        .color-red {{ color: {COLOR_DANGER} !important; border: 1px solid {COLOR_DANGER}; background-color: rgba(248, 113, 113, 0.1); }}
        .color-blue {{ color: {COLOR_ACCENT_BLUE} !important; border: 1px solid {COLOR_ACCENT_BLUE}; background-color: rgba(88, 166, 255, 0.1); }}

        /* ========================================
           TTP TAGS
           ======================================== */
        .ttp-tag {{
            display: inline-block; 
            padding: 2px 8px; 
            border-radius: 4px; 
            font-size: 12px;
            font-family: monospace; 
            margin-right: 4px; 
            margin-bottom: 6px; 
            border: 1px solid transparent;
        }}
        .ttp-covered {{ background-color: rgba(74, 222, 128, 0.15); color: {COLOR_SUCCESS}; border-color: {COLOR_SUCCESS}; }}
        .ttp-missing {{ background-color: rgba(248, 113, 113, 0.15); color: {COLOR_DANGER}; border-color: {COLOR_DANGER}; }}

        /* ========================================
           STATUS SIDEBAR
           ======================================== */
        .status-row {{ margin-bottom: 5px; display: flex; align-items: center; justify-content: space-between; }}

        /* ========================================
           HOME PAGE - Hero & Features
           ======================================== */
        .hero-section {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, {COLOR_BG_DARK} 0%, {COLOR_BG_CARD} 50%, {COLOR_BG_DARK} 100%);
            border-radius: 16px;
            border: 1px solid {COLOR_BORDER};
            margin-bottom: 30px;
        }}
        .hero-title {{
            font-size: 72px;
            margin: 0;
        }}
        .hero-subtitle {{
            font-size: 24px;
            color: {COLOR_INFO};
            margin: 10px 0 5px 0;
            font-weight: 600;
        }}
        .hero-tagline {{
            font-size: 16px;
            color: {COLOR_TEXT_MUTED};
            margin: 0;
        }}
        .stat-row {{
            display: flex;
            justify-content: center;
            gap: 40px;
            margin-top: 25px;
        }}
        .stat-item {{
            text-align: center;
        }}
        .stat-value {{
            font-size: 28px;
            font-weight: 700;
            color: {COLOR_TEXT_PRIMARY};
        }}
        .stat-label {{
            font-size: 12px;
            color: {COLOR_TEXT_SUBTLE};
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .feature-card {{
            background: {COLOR_BG_CARD};
            border: 1px solid {COLOR_BORDER};
            border-radius: 12px;
            padding: 24px;
        }}
        .feature-icon {{
            font-size: 36px;
            margin-bottom: 12px;
        }}
        .feature-title {{
            font-size: 18px;
            font-weight: 700;
            color: {COLOR_TEXT_PRIMARY};
            margin-bottom: 8px;
        }}
        .feature-desc {{
            font-size: 14px;
            color: {COLOR_TEXT_MUTED};
            line-height: 1.5;
            flex-grow: 1;
        }}
        .info-text {{
            color: {COLOR_TEXT_MUTED};
            font-size: 15px;
            line-height: 1.7;
        }}
        .workflow-step {{
            display: flex;
            align-items: flex-start;
            gap: 15px;
            margin-bottom: 15px;
        }}
        .step-number {{
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
        }}
        .step-content {{
            flex: 1;
        }}
        .step-title {{
            font-weight: 600;
            color: {COLOR_TEXT_SECONDARY};
            margin-bottom: 2px;
        }}
        .step-desc {{
            font-size: 13px;
            color: {COLOR_TEXT_MUTED};
        }}

        /* ========================================
           LOGIN PAGE
           ======================================== */
        .login-container {{
            max-width: 400px;
            margin: 100px auto;
            text-align: center;
        }}
        .login-title {{
            font-size: 48px;
            margin-bottom: 10px;
        }}
        .login-subtitle {{
            color: {COLOR_INFO};
            font-size: 24px;
            margin-bottom: 30px;
        }}
        .login-card {{
            background: {COLOR_BG_CARD};
            border: 1px solid {COLOR_BORDER};
            border-radius: 16px;
            padding: 40px;
        }}
        .login-message {{
            color: {COLOR_TEXT_MUTED};
            margin-bottom: 20px;
        }}
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
    """Render the connector status sidebar widget."""
    with st.sidebar.container(border=True):
        st.subheader("Connector Status")
        
        if "connector_status" not in st.session_state:
            st.session_state["connector_status"] = {"Elastic": None, "OpenCTI": None, "GitLab": None}
            st.session_state["last_check"] = "Never"

        statuses = st.session_state["connector_status"]
        for service, is_up in statuses.items():
            if is_up is None: 
                icon, color = "⚪", "gray"
            elif is_up: 
                icon, color = "🟢", COLOR_SUCCESS
            else: 
                icon, color = "🔴", COLOR_DANGER
            
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

        st.markdown(f"<div style='text-align:right; margin-top:10px; font-size:10px; color:{COLOR_TEXT_SUBTLE};'>Last check: {st.session_state['last_check']}</div>", unsafe_allow_html=True)