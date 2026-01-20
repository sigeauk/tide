import streamlit as st
import streamlit.components.v1 as components
import json
import os
import base64
from styles import apply_custom_styles, render_sidebar_status, get_icon_path, get_icon_base64
from auth import require_auth
import database as db
import cti_helper as cti
import pandas as pd

st.set_page_config(page_title="TIDE Ecosystem", page_icon=get_icon_path("tide.png"), layout="wide")
apply_custom_styles()
require_auth()

# get elastic stats
def load_rules():
    try:
        data, last_sync = db.get_latest_rules()
        return data, last_sync
    except Exception as e:
        return [], "Error"

data, last_sync = load_rules()
df_rules = pd.DataFrame(data)

# Handle empty DataFrame or missing columns
if not df_rules.empty and 'enabled' in df_rules.columns:
    enabled_rules = df_rules[df_rules['enabled'] == True]
else:
    enabled_rules = pd.DataFrame()

unique_techniques = set()
if not enabled_rules.empty and 'mitre_ids' in enabled_rules.columns:
    for mitre_list in enabled_rules['mitre_ids'].dropna():
        unique_techniques.update(mitre_list)

# get rule health metrics
rule_health = db.get_rule_health_metrics()
validated_pct = round((rule_health['validated_count'] / rule_health['total_rules'] * 100), 1) if rule_health['total_rules'] > 0 else 0
needs_review = rule_health['validation_expired_count'] + rule_health['never_validated_count']

# Determine overall health status
if rule_health['avg_score'] >= 70 and validated_pct >= 80:
    health_status = "Excellent"
elif rule_health['avg_score'] >= 50 and validated_pct >= 50:
    health_status = "Good"
else:
    health_status = "Needs Attention"

# get opencti stats
try:
    threats, last_sync = db.get_threat_data()
    threat_metrics = db.get_threat_landscape_metrics()
    total_ttps = threat_metrics['total_ttps']
except Exception as e:
    st.error(f"Database Error: {e}")
    threats = []
    threat_metrics = {'total_actors': 0, 'unique_ttps': 0, 'global_coverage_pct': 0, 'uncovered_ttps': 0}
    last_sync = "Error"
    total_ttps = 0


df_actors = pd.DataFrame(threats)

st.title("TIDE: Ecosystem Connectivity")
st.caption("Interact with the ecosystem: **Click** to view details, **Drag** to rearrange.")

# --- 2. CONFIGURATION ---
# Helper to get base64 image data for embedding in HTML
def get_static_base64(filename):
    """Get base64 encoded static file for use in HTML."""
    # Try Docker path first, then local
    docker_path = f"/app/app/static/{filename}"
    local_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", filename)
    
    for path in [docker_path, local_path]:
        if os.path.exists(path):
            try:
                with open(path, "rb") as f:
                    return base64.b64encode(f.read()).decode()
            except:
                pass
    return ""

# Define Nodes with base64-encoded images
nodes = {
    "feeds":   {"label": "Threat<br>&nbsp;  Feeds", "img_b64": "", "emoji": "📡", "top": "60%", "left": "10%",  "color": "#94a3b8"},
    "mitre":   {"label": "MITRE", "img_b64": get_static_base64("icons/mitre.png"), "emoji": "🎯", "top": "12%", "left": "60%", "color": "#f43f5e"},
    "opencti": {"label": "OpenCTI", "img_b64": get_static_base64("icons/opencti.png"), "emoji": "🧠", "top": "33%", "left": "30%", "color": "#150aee"},
    "sigma":   {"label": "Sigma", "img_b64": get_static_base64("icons/sigma.png"), "emoji": "📜", "top": "85%", "left": "30%", "color": "#aeba29"},
    "elastic": {"label": "Elastic", "img_b64": get_static_base64("icons/elastic.png"), "emoji": "⚡", "top": "60%", "left": "60%", "color": "#12dd5c"},
    "gitlab":  {"label": "GitLab", "img_b64": get_static_base64("icons/gitlab.png"), "emoji": "🦊", "top": "85%", "left": "90%", "color": "#f97316"},
    "tide":    {"label": "TIDE", "img_b64": get_static_base64("icons/tide.png"), "emoji": "🌊", "top": "33%", "left": "90%", "color": "#aeba29"},
}

links = [
    {"id": "feed-cti",      "src": "feeds",     "tgt": "opencti",   "color": "#94a3b8"},
    {"id": "cti-elast",     "src": "opencti",   "tgt": "elastic",   "color": "#150aee"},
    {"id": "cti-tide",      "src": "opencti",   "tgt": "tide",      "color": "#150aee"},
    {"id": "elast-cti",     "src": "elastic",   "tgt": "opencti",   "color": "#12dd5c"}, 
    {"id": "elast-git",     "src": "elastic",   "tgt": "gitlab",    "color": "#12dd5c"},
    {"id": "elast-tide",    "src": "elastic",   "tgt": "tide",      "color": "#12dd5c"},
    {"id": "git-tide",      "src": "gitlab",    "tgt": "tide",      "color": "#f97316"},
    {"id": "git-elast",     "src": "gitlab",    "tgt": "elastic",   "color": "#f97316"},
    {"id": "sig-cti",       "src": "sigma",     "tgt": "opencti",   "color": "#aeba29"},
    {"id": "sig-elast",     "src": "sigma",     "tgt": "elastic",   "color": "#aeba29"},
    {"id": "sig-git",       "src": "sigma",     "tgt": "gitlab",    "color": "#aeba29"},
    {"id": "mitre-cti",     "src": "mitre",     "tgt": "opencti",   "color": "#f43f5e"},
    {"id": "mitre-tide",    "src": "mitre",     "tgt": "tide",      "color": "#f43f5e"},
    {"id": "tide-git",      "src": "tide",      "tgt": "gitlab",    "color": "#3b82f6"},
    {"id": "tide-mitre",    "src": "tide",      "tgt": "mitre",     "color": "#3b82f6"},
    {"id": "tide-elastic",  "src": "tide",      "tgt": "elastic",   "color": "#3b82f6"},
    {"id": "tide-cti",      "src": "tide",      "tgt": "opencti",   "color": "#3b82f6"},
]

node_details = {
    "feeds": {
        "title": "External Threat Feeds",
        "desc": "Ingests raw intelligence from CrowdStrike, Mandiant, VirusTotal, and NVD.",
        "stats": "Status: Active | Rate: 120 events/min"
    },
    "opencti": {
        "title": "OpenCTI Intelligence Hub",
        "desc": "Aggregates feeds into structured data (STIX). Sends Indicators to Elastic for matching and TTPs to TIDE for mapping.",
        "stats": f"Actors: {threat_metrics['total_actors']} | TTPs: {threat_metrics['unique_ttps']} | Coverage: {threat_metrics['global_coverage_pct']}%"
    },
    "tide": {
        "title": "TIDE Orchestrator",
        "desc": "The central UI. It visualizes coverage gaps by mapping Active Rules (from Elastic) to Known TTPs (from OpenCTI).",
        "stats": f"Avg Score: {rule_health['avg_score']} | Validated: {validated_pct}% | Health: {health_status}"
    },
    "elastic": {
        "title": "Elastic SIEM",
        "desc": "Runs detection rules. Sends rules as 'Courses of Action' back to OpenCTI and backs up logic to GitLab.",
        "stats": f"Enabled: {len(enabled_rules)} | Techniques: {len(unique_techniques)} | Quality: {rule_health['avg_score']}/100"
    },
    "gitlab": {
        "title": "GitLab Version Control",
        "desc": "Source of Truth. Stores MITRE/Sigma repos and daily backups of Elastic Production rules.",
        "stats": f"Spaces: {len(rule_health['rules_by_space'])} | Rules Tracked: {rule_health['total_rules']}"
    },
    "sigma": {
        "title": "Sigma Rules",
        "desc": "Vendor-agnostic rule repository. Rules are converted to Elastic Query Language (ES|QL) and stored in GitLab.",
        "stats": "Available: 2,400+ | New: 5"
    },
    "mitre": {
        "title": "MITRE ATT&CK",
        "desc": "Global knowledge base of adversary tactics. The full repository is mirrored in GitLab for offline access.",
        "stats": f"Gaps: {threat_metrics['uncovered_ttps']} | Unique TTPs: {threat_metrics['unique_ttps']}"
    }
}

nodes_json = json.dumps(nodes)
links_json = json.dumps(links)
details_json = json.dumps(node_details)

# --- 3. HTML/JS COMPONENT ---
html_code = f"""
<!DOCTYPE html>
<html>
<head>
<style>
    body {{ margin: 0; background: transparent; font-family: 'Segoe UI', sans-serif; overflow: hidden; }}
    
    .container {{
        display: flex; flex-direction: column; height: 700px;
        background: #0e1117; 
        border: 1px solid #374151; border-radius: 12px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        user-select: none; 
    }}

    .circuit-board {{
        position: relative; flex-grow: 1;
        background: radial-gradient(circle at 50% 50%, #1f2937 0%, #0e1117 70%);
        overflow: hidden; border-bottom: 1px solid #374151;
        border-radius: 12px 12px 0 0;
    }}

    .details-panel {{
        height: 120px; background: rgba(17, 24, 39, 0.95); padding: 20px;
        display: flex; align-items: center; justify-content: space-between;
        color: white; transition: all 0.3s ease;
        border-top: 1px solid #374151;
        border-radius: 0 0 12px 12px;
    }}
    
    .d-content {{ width: 100%; }}
    .d-title {{ margin: 0 0 5px 0; font-size: 20px; font-weight: bold; color: #60a5fa; }}
    .d-desc {{ margin: 0; font-size: 14px; color: #9ca3af; line-height: 1.5; }}
    .d-stats {{ font-family: monospace; font-size: 12px; color: #34d399; margin-top: 10px; border-top: 1px solid #374151; padding-top: 10px; display: inline-block; width: 100%; }}
    .d-placeholder {{ color: #4b5563; font-style: italic; width: 100%; text-align: center; }}

    /* NODES */
    .node {{
        position: absolute; width: 100px; height: 100px;
        border-radius: 50%; display: flex; flex-direction: column; 
        align-items: center; justify-content: center;
        cursor: grab; z-index: 10;
        background: rgba(30, 41, 59, 0.9);
        border: 2px solid rgba(255,255,255,0.1);
        transition: box-shadow 0.3s, border-color 0.3s, transform 0.1s;
        backdrop-filter: blur(5px);
        box-shadow: 0 0 15px rgba(0,0,0,0.5);
    }}
    
    .node:active {{ cursor: grabbing; }}
    .node:hover {{ border-color: rgba(255,255,255,0.5); transform: scale(1.1); }}
    
    /* Active: Hovering */
    .node.active {{
        background: #1e293b; border-color: #fff;
        box-shadow: 0 0 25px currentColor;
        z-index: 20; transform: scale(1.1);
    }}

    /* Locked: Clicked (Keeps lines active) */
    .node.locked {{
        border-color: #60a5fa; /* Blue border to indicate locked state */
        box-shadow: 0 0 35px currentColor;
    }}

    /* IMAGE STYLES */
    .node-img {{
        width: 38px; height: 38px;
        object-fit: contain;
        margin-bottom: 5px;
        pointer-events: none;
    }}

    .node-emoji {{
        font-size: 32px;
        margin-bottom: 2px;
        pointer-events: none;
        display: none; 
    }}

    .node-label {{ font-size: 10px; font-weight: bold; color: #e5e7eb; text-transform: uppercase; letter-spacing: 1px; pointer-events: none; }}

    svg {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 1; }}

    .link-pulse {{
        fill: none; stroke-width: 4px; stroke-linecap: round;
        stroke-dasharray: 0, 15px; opacity: 0; transition: opacity 0.2s;
    }}
    .link-pulse.visible {{
        opacity: 1; animation: flow 0.6s linear infinite;
    }}
    @keyframes flow {{
        from {{ stroke-dashoffset: 15px; }} to {{ stroke-dashoffset: 0; }}
    }}

</style>
</head>
<body>

<div class="container">
    <div class="circuit-board" id="board">
        <svg id="svg-layer"></svg>
    </div>
    
    <div class="details-panel" id="panel">
        <div class="d-placeholder" id="placeholder">Hover to view details. Click to keep lines active.</div>
        <div class="d-content" id="content" style="display:none;">
            <h3 class="d-title" id="d-title"></h3>
            <p class="d-desc" id="d-desc"></p>
            <div class="d-stats" id="d-stats"></div>
        </div>
    </div>
</div>

<script>
    const NODES = {nodes_json};
    const LINKS = {links_json};
    const DETAILS = {details_json};

    const board = document.getElementById('board');
    const svgLayer = document.getElementById('svg-layer');
    
    const activeNodes = new Set(); // Currently lit up (hover or locked)
    const lockedNodes = new Set(); // Specifically clicked (persistent)
    
    let isDragging = false;
    let didMove = false;
    let currentDragNode = null;
    let dragOffsetX = 0;
    let dragOffsetY = 0;

    // 1. SETUP NODES
    Object.keys(NODES).forEach(key => {{
        const n = NODES[key];
        const el = document.createElement('div');
        el.className = 'node';
        el.id = key;
        el.style.top = n.top; 
        el.style.left = n.left;
        el.style.color = n.color;
        el.style.marginLeft = '-42px'; 
        el.style.marginTop = '-42px';  

        // Use base64 image if available, otherwise show emoji
        const hasImage = n.img_b64 && n.img_b64.length > 0;
        const imgSrc = hasImage ? 'data:image/png;base64,' + n.img_b64 : '';

        el.innerHTML = hasImage ? `
            <img src="${{imgSrc}}" class="node-img" onerror="this.style.display='none'; this.nextElementSibling.style.display='block';">
            <div class="node-emoji" style="display:none;">${{n.emoji}}</div>
            <div class="node-label">${{n.label}}</div>
        ` : `
            <div class="node-emoji">${{n.emoji}}</div>
            <div class="node-label">${{n.label}}</div>
        `;

        el.addEventListener('mousedown', (e) => startDrag(e, el, key));
        
        // Hover Logic
        el.addEventListener('mouseenter', () => handleHover(key, true));
        el.addEventListener('mouseleave', () => handleHover(key, false));

        board.appendChild(el);
        
        // Image Check - verify base64 image loaded correctly
        const img = el.querySelector('img');
        if (img && img.complete && img.naturalHeight === 0) {{
             img.style.display = 'none';
             const emoji = el.querySelector('.node-emoji');
             if (emoji) emoji.style.display = 'block';
        }}
    }});

    // 2. SETUP LINES
    LINKS.forEach(link => {{
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.classList.add('link-pulse');
        path.id = 'link-' + link.id;
        path.style.stroke = link.color;
        svgLayer.appendChild(path);
    }});

    // 3. DRAG & CLICK LOGIC
    function startDrag(e, el, key) {{
        isDragging = true;
        didMove = false; // Reset move tracker
        currentDragNode = el;
        const rect = el.getBoundingClientRect();
        dragOffsetX = e.clientX - rect.left;
        dragOffsetY = e.clientY - rect.top;
        document.addEventListener('mousemove', onDrag);
        document.addEventListener('mouseup', endDrag);
    }}

    function onDrag(e) {{
        if (!isDragging || !currentDragNode) return;
        didMove = true; // Mark as moved
        const boardRect = board.getBoundingClientRect();
        let newX = e.clientX - boardRect.left - dragOffsetX;
        let newY = e.clientY - boardRect.top - dragOffsetY;
        currentDragNode.style.left = (newX + 42) + 'px'; 
        currentDragNode.style.top = (newY + 42) + 'px';
        drawLines();
    }}

    function endDrag(e) {{
        if (!isDragging) return;
        
        // If we didn't drag, treat it as a CLICK
        if (!didMove && currentDragNode) {{
            toggleLock(currentDragNode.id);
        }}

        isDragging = false;
        currentDragNode = null;
        document.removeEventListener('mousemove', onDrag);
        document.removeEventListener('mouseup', endDrag);
    }}

    // 4. INTERACTION LOGIC
    function handleHover(key, isEnter) {{
        if (isEnter) {{
            // Always show on enter
            activeNodes.add(key);
            document.getElementById(key).classList.add('active');
            updateDetails(key);
        }} else {{
            // On leave, only remove if NOT locked
            if (!lockedNodes.has(key)) {{
                activeNodes.delete(key);
                document.getElementById(key).classList.remove('active');
                
                // If there are other locked nodes, show the most recent one
                // Otherwise clear details
                if (lockedNodes.size > 0) {{
                    const lastLocked = Array.from(lockedNodes).pop();
                    updateDetails(lastLocked);
                }} else {{
                    updateDetails(null);
                }}
            }}
        }}
        drawLines();
    }}

    function toggleLock(key) {{
        const el = document.getElementById(key);
        if (lockedNodes.has(key)) {{
            // Unlock
            lockedNodes.delete(key);
            el.classList.remove('locked');
            // If we are still hovering, keep active, else deactivate
            // (Simulate a mouse leave to check state)
            handleHover(key, false); 
        }} else {{
            // Lock
            lockedNodes.add(key);
            el.classList.add('locked');
            activeNodes.add(key); // Ensure it's active
            el.classList.add('active');
            updateDetails(key);
        }}
        drawLines();
    }}

    // 5. DRAWING & UPDATES
    function drawLines() {{
        LINKS.forEach(link => {{
            const path = document.getElementById('link-' + link.id);
            path.classList.remove('visible');
            path.setAttribute('d', ''); 
        }});

        LINKS.forEach(link => {{
            if (activeNodes.has(link.src)) {{
                updatePath(link);
            }}
        }});
    }}

    function updatePath(link) {{
        const p1 = getCenter(link.src);
        const p2 = getCenter(link.tgt);
        const path = document.getElementById('link-' + link.id);

        const dx = p2.x - p1.x;
        const dy = p2.y - p1.y;
        const dist = Math.sqrt(dx*dx + dy*dy);
        const curveIntensity = 40; 
        const mx = (p1.x + p2.x) / 2;
        const my = (p1.y + p2.y) / 2;
        const nx = (-dy / dist) * curveIntensity;
        const ny = (dx / dist) * curveIntensity;
        const cx = mx + nx;
        const cy = my + ny;

        const d = `M ${{p1.x}} ${{p1.y}} Q ${{cx}} ${{cy}} ${{p2.x}} ${{p2.y}}`;
        path.setAttribute('d', d);
        path.classList.add('visible');
    }}

    function updateDetails(key) {{
        const ph = document.getElementById('placeholder');
        const content = document.getElementById('content');
        
        if (!key) {{
            ph.style.display = 'block';
            content.style.display = 'none';
            return;
        }}

        const data = DETAILS[key];
        ph.style.display = 'none';
        content.style.display = 'block';
        
        document.getElementById('d-title').innerText = data.title;
        document.getElementById('d-title').style.color = NODES[key].color;
        document.getElementById('d-desc').innerText = data.desc;
        
        const outCount = LINKS.filter(l => l.src === key).length;
        document.getElementById('d-stats').innerText = `${{data.stats}} | Outgoing Connections: ${{outCount}}`;
    }}

    function getCenter(id) {{
        const el = document.getElementById(id);
        const r = el.getBoundingClientRect();
        const p = board.getBoundingClientRect();
        return {{
            x: (r.left - p.left) + r.width/2,
            y: (r.top - p.top) + r.height/2
        }};
    }}

    window.addEventListener('resize', drawLines);
    setTimeout(drawLines, 100);

</script>
</body>
</html>
"""

components.html(html_code, height=720)

st.markdown("### Ecosystem Status")
cols = st.columns(4)
cols[0].metric("System Health", "Optimal")
cols[1].metric("Active Feeds", "4")
cols[2].metric("Total Rules", "315")
cols[3].metric("Coverage Gap", "14")