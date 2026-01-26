import streamlit as st
import streamlit.components.v1 as components
import requests
import json
import collections
from auth import require_auth
from styles import get_icon_path, apply_custom_styles

# --- 1. CONFIGURATION & DATA CACHING ---
st.set_page_config(page_title="Attack Tree | TIDE", page_icon=get_icon_path("tide.png"), layout="wide")
apply_custom_styles()
require_auth()

@st.cache_data
def load_mitre_data():
    """Fetches and parses MITRE ATT&CK data from a local file."""
    file_path = "/opt/repos/mitre/enterprise-attack.json"
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
    except Exception as e:
        st.error(f"Failed to load MITRE data: {e}")
        return {}

    techniques = {}
    for obj in data.get('objects', []):
        if (obj.get('type') == 'attack-pattern' and not obj.get('revoked')):
            t_code = "Unknown"
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    t_code = ref.get('external_id')
                    break
            techniques[t_code] = {
                "name": obj.get('name'),
                "desc": obj.get('description', 'No description.')[:200] + "..."
            }
    return techniques

mitre_data = load_mitre_data()

# --- 2. SESSION STATE ---
if 'nodes' not in st.session_state:
    st.session_state.nodes = {} 
if 'links' not in st.session_state:
    st.session_state.links = [] 

# --- 3. PYTHON LAYOUT ENGINE ---
def calculate_positions(nodes, links):
    """
    Simple algorithm to assign Top/Left % based on tree depth.
    This replaces manual positioning.
    """
    # Build adjacency list to find children
    adj = collections.defaultdict(list)
    # Find all children to determine roots (nodes with no incoming edges)
    children = set()
    for src, tgt in links:
        adj[src].append(tgt)
        children.add(tgt)
    
    roots = [n for n in nodes if n not in children]
    
    levels = {} # {node_id: level}
    
    def bfs(node, level):
        levels[node] = level
        for child in adj[node]:
            bfs(child, level + 1)
            
    for root in roots:
        bfs(root, 0)
        
    # Default non-connected nodes to level 0
    for n in nodes:
        if n not in levels:
            levels[n] = 0

    # Calculate Coordinates
    layout_nodes = {}
    
    # Group by level to determine X spacing
    level_groups = collections.defaultdict(list)
    for n, lvl in levels.items():
        level_groups[lvl].append(n)
        
    for lvl, group in level_groups.items():
        count = len(group)
        for i, node_id in enumerate(group):
            # Y Position: simple increments based on level
            top_pos = 10 + (lvl * 20) 
            # X Position: Spread evenly across width
            left_pos = ((i + 1) / (count + 1)) * 100
            
            # Get Node Data
            n_data = nodes[node_id]
            
            color = "#f43f5e" if n_data['type'] == 'goal' else "#3b82f6"
            emoji = "🎯" if n_data['type'] == 'goal' else "🦠"
            
            layout_nodes[node_id] = {
                "label": n_data['label'],
                "img": "", # No image, use emoji
                "emoji": emoji,
                "top": f"{top_pos}%",
                "left": f"{left_pos}%",
                "color": color,
                "desc": n_data.get('desc', '')
            }
            
    return layout_nodes

# --- 4. UI: SIDEBAR ---
with st.sidebar:
    st.title("🛠️ Builder")
    
    # Add Goal
    new_goal = st.text_input("New Goal Name")
    if st.button("Add Goal"):
        if new_goal:
            nid = f"GOAL_{len(st.session_state.nodes)}"
            st.session_state.nodes[nid] = {
                "label": new_goal, "type": "goal", "desc": "Root Objective"
            }

    st.markdown("---")
    
    # Add Technique
    opts = [f"{k} : {v['name']}" for k,v in mitre_data.items()]
    sel = st.selectbox("Search MITRE", opts)
    if st.button("Add Technique"):
        code = sel.split(" : ")[0]
        st.session_state.nodes[code] = {
            "label": code, 
            "type": "tech",
            "desc": mitre_data[code]['name'] + "\n" + mitre_data[code]['desc']
        }

    st.markdown("---")
    
    # Link nodes
    st.subheader("🔗 Connections")
    node_keys = list(st.session_state.nodes.keys())
    if len(node_keys) > 1:
        p = st.selectbox("Parent", node_keys, key="link_parent")
        c = st.selectbox("Child", node_keys, key="link_child")
        if st.button("Add Connection"):
            if p != c and (p, c) not in st.session_state.links:
                st.session_state.links.append((p, c))
                st.rerun()
            elif p == c:
                st.warning("Cannot link a node to itself")
            else:
                st.warning("Connection already exists")
    
    st.markdown("---")
    
    # Delete connections
    st.subheader("🗑️ Delete Connection")
    if st.session_state.links:
        link_labels = [f"{src} → {tgt}" for src, tgt in st.session_state.links]
        link_to_delete = st.selectbox("Select Connection", link_labels, key="del_link")
        if st.button("Delete Connection", type="secondary"):
            idx = link_labels.index(link_to_delete)
            st.session_state.links.pop(idx)
            st.rerun()
    else:
        st.caption("No connections to delete")
    
    st.markdown("---")
    
    # Delete nodes
    st.subheader("🗑️ Delete Node")
    if st.session_state.nodes:
        node_to_delete = st.selectbox("Select Node", node_keys, key="del_node")
        if st.button("Delete Node", type="secondary"):
            # Remove node
            del st.session_state.nodes[node_to_delete]
            # Remove any links involving this node
            st.session_state.links = [
                (src, tgt) for src, tgt in st.session_state.links 
                if src != node_to_delete and tgt != node_to_delete
            ]
            st.rerun()
    else:
        st.caption("No nodes to delete")
    
    st.markdown("---")
            
    if st.button("🧹 Clear All", type="primary"):
        st.session_state.nodes = {}
        st.session_state.links = []
        st.rerun()

# --- 5. PREPARE JSON FOR JS ---
# Convert Python List of Tuples -> List of Dicts for JS
js_links = []
for i, (src, tgt) in enumerate(st.session_state.links):
    js_links.append({"id": f"link_{i}", "src": src, "tgt": tgt, "color": "#64748b"})

# Calculate Positions dynamically
js_nodes = calculate_positions(st.session_state.nodes, st.session_state.links)

# Extract details for the bottom panel
js_details = {}
for nid, data in js_nodes.items():
    js_details[nid] = {
        "title": data['label'],
        "desc": data['desc'],
        "stats": "Status: Active"
    }

# --- 6. RENDER CUSTOM HTML ---
html_code = f"""
<!DOCTYPE html>
<html>
<head>
<style>
    body {{ margin: 0; background: transparent; font-family: 'Segoe UI', sans-serif; overflow: hidden; }}
    
    /* CONTAINER */
    .container {{
        display: flex; flex-direction: column; height: 600px; /* Restored fixed height */
        background: #0e1117; 
        border: 1px solid #374151; border-radius: 12px;
        box-shadow: 0 10px 30px rgba(0,0,0,0.5);
        user-select: none; 
        overflow: hidden; /* Prevent content from spilling out */
    }}

    .circuit-board {{
        position: relative; flex-grow: 1;
        background: radial-gradient(circle at 50% 50%, #1f2937 0%, #0e1117 70%);
        overflow: auto; /* Ensure board content is scrollable */
        border-bottom: 1px solid #374151;
    }}

    .details-panel {{
        height: 100px; background: rgba(17, 24, 39, 0.95); padding: 15px;
        display: flex; align-items: center; justify-content: space-between;
        color: white; border-top: 1px solid #374151;
        overflow-y: auto; /* Ensure content is scrollable if it overflows */
        max-height: 120px; /* Prevent excessive height */
    }}
    .d-title {{ margin: 0 0 5px 0; font-size: 18px; font-weight: bold; color: #60a5fa; }}
    .d-desc {{ margin: 0; font-size: 13px; color: #9ca3af; line-height: 1.4; max-width: 80%; }}

    /* NODES */
    .node {{
        position: absolute; width: 80px; height: 80px;
        border-radius: 50%; display: flex; flex-direction: column; 
        align-items: center; justify-content: center;
        cursor: grab; z-index: 10;
        background: rgba(30, 41, 59, 0.9);
        border: 2px solid rgba(255,255,255,0.1);
        transition: box-shadow 0.3s, border-color 0.3s;
        backdrop-filter: blur(5px);
        box-shadow: 0 0 15px rgba(0,0,0,0.5);
    }}
    .node:active {{ cursor: grabbing; }}
    .node:hover {{ border-color: rgba(255,255,255,0.5); transform: scale(1.05); }}

    .node-emoji {{ font-size: 28px; margin-bottom: 2px; pointer-events: none; }}
    .node-label {{ font-size: 10px; font-weight: bold; color: #e5e7eb; text-align:center; pointer-events: none; }}

    /* LINKS */
    svg {{ position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; z-index: 1; }}
    .link-pulse {{
        fill: none; stroke-width: 2px; stroke-linecap: round;
        stroke-dasharray: 0, 10px; opacity: 0.4; transition: opacity 0.2s;
    }}
    .link-pulse.visible {{ opacity: 1; stroke-width: 3px; animation: flow 1s linear infinite; }}
    @keyframes flow {{ from {{ stroke-dashoffset: 20px; }} to {{ stroke-dashoffset: 0; }} }}

</style>
</head>
<body>

<div class="container">
    <div class="circuit-board" id="board">
        <svg id="svg-layer"></svg>
    </div>
    
    <div class="details-panel" id="panel">
        <div id="content" style="width:100%">
            <h3 class="d-title" id="d-title">Ready</h3>
            <p class="d-desc" id="d-desc">Add nodes from the sidebar to begin.</p>
        </div>
    </div>
</div>

<script>
    const NODES = {json.dumps(js_nodes)};
    const LINKS = {json.dumps(js_links)};
    const DETAILS = {json.dumps(js_details)};

    const board = document.getElementById('board');
    const svgLayer = document.getElementById('svg-layer');
    let isDragging = false;
    let currentDragNode = null;
    let dragOffsetX = 0, dragOffsetY = 0;

    // INITIALIZE NODES
    Object.keys(NODES).forEach(key => {{
        const n = NODES[key];
        const el = document.createElement('div');
        el.className = 'node';
        el.id = key;
        el.style.top = n.top; 
        el.style.left = n.left;
        el.style.borderColor = n.color; 
        // Centering offset
        el.style.marginLeft = '-40px'; 
        el.style.marginTop = '-40px';  

        el.innerHTML = `
            <div class="node-emoji">${{n.emoji}}</div>
            <div class="node-label">${{n.label}}</div>
        `;

        // DRAG EVENTS
        el.addEventListener('mousedown', (e) => {{
            isDragging = true;
            currentDragNode = el;
            const rect = el.getBoundingClientRect();
            dragOffsetX = e.clientX - rect.left;
            dragOffsetY = e.clientY - rect.top;
            
            // Show Details
            if(DETAILS[key]) {{
                document.getElementById('d-title').innerText = DETAILS[key].title;
                document.getElementById('d-desc').innerText = DETAILS[key].desc;
                document.getElementById('d-title').style.color = n.color;
            }}
            
            document.addEventListener('mousemove', onDrag);
            document.addEventListener('mouseup', endDrag);
        }});

        board.appendChild(el);
    }});

    // INITIALIZE LINKS
    LINKS.forEach(link => {{
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.classList.add('link-pulse');
        path.id = 'link-' + link.id;
        path.style.stroke = link.color;
        svgLayer.appendChild(path);
    }});

    function onDrag(e) {{
        if (!isDragging || !currentDragNode) return;
        const boardRect = board.getBoundingClientRect();
        let newX = e.clientX - boardRect.left - dragOffsetX;
        let newY = e.clientY - boardRect.top - dragOffsetY;
        
        currentDragNode.style.left = (newX + 40) + 'px'; 
        currentDragNode.style.top = (newY + 40) + 'px';
        drawLines();
    }}

    function endDrag() {{
        isDragging = false;
        currentDragNode = null;
        document.removeEventListener('mousemove', onDrag);
        document.removeEventListener('mouseup', endDrag);
    }}

    function getCenter(id) {{
        const el = document.getElementById(id);
        if(!el) return {{x:0, y:0}};
        const r = el.getBoundingClientRect();
        const p = board.getBoundingClientRect();
        return {{
            x: (r.left - p.left) + r.width/2,
            y: (r.top - p.top) + r.height/2
        }};
    }}

    function drawLines() {{
        LINKS.forEach(link => {{
            const p1 = getCenter(link.src);
            const p2 = getCenter(link.tgt);
            const path = document.getElementById('link-' + link.id);
            if(!path) return;

            // Bezier Curve Logic
            const dx = p2.x - p1.x;
            const dy = p2.y - p1.y;
            // Curvature based on distance
            const dist = Math.sqrt(dx*dx + dy*dy);
            const curve = Math.min(dist * 0.2, 100); 

            // Control Point (offset perpendicular to line)
            // Simple curve: just offset Y for hierarchy look
            const cx = (p1.x + p2.x) / 2; 
            const cy = (p1.y + p2.y) / 2;

            const d = `M ${{p1.x}} ${{p1.y}} Q ${{cx + 20}} ${{cy}} ${{p2.x}} ${{p2.y}}`;
            
            path.setAttribute('d', d);
            path.classList.add('visible');
        }});
    }}

    // Initial Draw & Resize Listener
    setTimeout(drawLines, 100);
    window.addEventListener('resize', drawLines);

</script>
</body>
</html>
"""

st.title("Interactive Attack Tree")
st.text("Build and visualize your attack tree using MITRE ATT&CK techniques. Use the sidebar to add goals and techniques, create connections, and see the relationships dynamically.")
st.caption("Add techniques from the sidebar. **Drag nodes** to arrange them.")
components.html(html_code, height=620)