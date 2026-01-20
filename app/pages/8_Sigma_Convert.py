import streamlit as st
from styles import apply_custom_styles, get_icon_path
from auth import require_auth
import sigma_helper as sigma

st.set_page_config(page_title="Sigma Convert | TIDE", page_icon=get_icon_path("tide.png"), layout="wide", initial_sidebar_state="expanded")
apply_custom_styles()
require_auth()

# --- HEADER (matching other pages) ---
st.title("Sigma Converter")

# --- Read URL Query Parameters ---
query_params = st.query_params
url_technique = query_params.get("technique", "")

# Initialize session state
if 'selected_rule_yaml' not in st.session_state:
    st.session_state.selected_rule_yaml = ""
if 'converted_query' not in st.session_state:
    st.session_state.converted_query = ""
if 'raw_query' not in st.session_state:
    st.session_state.raw_query = ""
if 'conversion_success' not in st.session_state:
    st.session_state.conversion_success = True

# Handle URL technique parameter - set filter value from URL
# Check if this is a new technique from URL (different from last one we processed)
if url_technique:
    last_url = st.session_state.get('last_url_technique', '')
    if last_url != url_technique:
        st.session_state.tech_filter = url_technique
        st.session_state.last_url_technique = url_technique
elif 'tech_filter' not in st.session_state:
    st.session_state.tech_filter = ""

# Load rules data
all_rules = sigma.load_all_rules()
categories = sigma.get_rule_categories()

# --- TOP ROW: 3 Columns (Conversion Settings | Rule Browser | Rules) ---
col_settings, col_browser, col_rules = st.columns([1, 1.2, 1.8])

# --- Column 1: Conversion Settings ---
with col_settings:
    st.markdown("##### ⚙️ Conversion Settings")
    
    backend = st.selectbox(
        "Target",
        options=list(sigma.get_available_backends().keys()),
        format_func=lambda x: sigma.get_available_backends().get(x, x),
        key="backend_select"
    )
    
    output_formats = sigma.get_output_formats(backend)
    output_format = st.selectbox(
        "Format",
        options=list(output_formats.keys()),
        format_func=lambda x: output_formats.get(x, x),
        key=f"output_format_{backend}"
    )
    
    pipelines = sigma.get_available_pipelines()
    pipeline = st.selectbox(
        "Pipeline",
        options=list(pipelines.keys()),
        format_func=lambda x: pipelines.get(x, x),
        key="pipeline_select"
    )

# --- Column 2: Rule Browser (Search & Filters) ---
with col_browser:
    st.markdown("##### 🔍 Rule Browser")
    
    search_query = st.text_input(
        "Search",
        placeholder="Search by title, description, technique...",
        key="rule_search"
    )
    
    technique_filter = st.text_input(
        "MITRE Technique",
        placeholder="e.g., T1059",
        key="tech_filter"
    )
    
    col_cat, col_lvl = st.columns(2)
    with col_cat:
        category_filter = st.selectbox(
            "Category",
            options=[""] + categories,
            format_func=lambda x: "All" if x == "" else x.title(),
            key="cat_filter"
        )
    with col_lvl:
        level_filter = st.selectbox(
            "Level",
            options=["", "critical", "high", "medium", "low", "informational"],
            format_func=lambda x: "All" if x == "" else x.title(),
            key="level_filter"
        )

# --- Column 3: Rules List ---
with col_rules:
    # Search with filters
    results = sigma.search_rules(
        query=search_query,
        technique_filter=technique_filter,
        category_filter=category_filter,
        level_filter=level_filter,
        limit=100
    )
    
    # Dynamic rule count
    total_rules = len(all_rules)
    filtered_count = len(results)
    
    if search_query or technique_filter or category_filter or level_filter:
        st.markdown(f"##### 📁 Rules ({filtered_count} of {total_rules})")
    else:
        st.markdown(f"##### 📁 Rules ({total_rules})")
    
    # Rule list with colored pills
    rule_container = st.container(height=180)
    with rule_container:
        for rule in results:
            rule_id = rule.get('id', 'unknown')
            title = rule.get('title', 'Untitled')
            level = rule.get('level', 'unknown')
            rule_techniques = rule.get('_techniques', [])
            category = rule.get('_category', '')
            
            # Techniques display
            tech_str = ', '.join(rule_techniques[:2])
            if len(rule_techniques) > 2:
                tech_str += f" +{len(rule_techniques) - 2}"
            
            # Button with level in help text
            btn_label = f"{title[:50]}{'...' if len(title) > 50 else ''}"
            
            if st.button(
                btn_label,
                key=f"rule_{rule_id}",
                use_container_width=True,
                help=f"⬤ {level.upper()} | {tech_str} | {category}"
            ):
                st.session_state.selected_rule_yaml = rule.get('_raw_yaml', '')
                st.session_state.converted_query = ""
                st.session_state.raw_query = ""
                st.rerun()

# --- DIVIDER ---
st.markdown("---")

# --- BOTTOM ROW: 2 Columns (rule.yml | Query Output) ---
col_yaml, col_output = st.columns([1, 1])

# --- Column 1: YAML Editor ---
with col_yaml:
    st.markdown("##### 📝 rule.yml")
    
    yaml_content = st.text_area(
        "Sigma Rule YAML",
        value=st.session_state.selected_rule_yaml,
        height=350,
        placeholder="""title: Example Rule
id: 12345678-1234-1234-1234-123456789abc
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains: 'suspicious'
    condition: selection
level: medium
tags:
    - attack.execution
    - attack.t1059""",
        label_visibility="collapsed",
        key="yaml_editor"
    )
    st.session_state.selected_rule_yaml = yaml_content
    
    # Action buttons
    col_btn1, col_btn2, col_btn3 = st.columns([2, 1, 1])
    with col_btn1:
        convert_clicked = st.button("🔄 Convert", type="primary", use_container_width=True)
    with col_btn2:
        validate_clicked = st.button("✅ Validate", use_container_width=True)
    with col_btn3:
        clear_clicked = st.button("🗑️ Clear", use_container_width=True)
    
    # Handle button clicks
    if convert_clicked:
        if yaml_content.strip():
            success, result = sigma.convert_sigma_rule(
                yaml_content,
                backend=backend,
                pipeline=pipeline,
                output_format=output_format
            )
            st.session_state.converted_query = result
            st.session_state.conversion_success = success
            
            # Get raw query for SIEM
            if success:
                raw_success, raw_result = sigma.convert_sigma_rule(
                    yaml_content,
                    backend=backend,
                    pipeline=pipeline,
                    output_format='default'
                )
                st.session_state.raw_query = raw_result if raw_success else result
            else:
                st.session_state.raw_query = ""
            st.rerun()
        else:
            st.warning("Please enter a Sigma rule YAML")
    
    if validate_clicked:
        if yaml_content.strip():
            success, result = sigma.validate_sigma_rule(yaml_content)
            if success:
                st.success(result)
            else:
                st.error(result)
        else:
            st.warning("Please enter a Sigma rule YAML")
    
    if clear_clicked:
        st.session_state.selected_rule_yaml = ""
        st.session_state.converted_query = ""
        st.session_state.raw_query = ""
        st.rerun()

# --- Column 2: Query Output ---
with col_output:
    st.markdown("##### ⚡ Query Output")
    
    if st.session_state.converted_query and st.session_state.conversion_success:
        # Determine language for syntax highlighting
        if backend == 'eql':
            code_lang = "javascript"
        elif backend == 'esql':
            code_lang = "sql"
        elif backend in ['elasticsearch']:
            code_lang = "json" if output_format in ['kibana_ndjson', 'dsl_lucene'] else "text"
        elif backend == 'splunk':
            code_lang = "text"
        elif backend == 'microsoft365defender':
            code_lang = "text"
        else:
            code_lang = "text"
        
        # Show query with syntax highlighting
        st.code(st.session_state.converted_query, language=code_lang, line_numbers=True)
        
        # Download button
        st.download_button(
            "💾 Download Query",
            data=st.session_state.converted_query,
            file_name=f"sigma_query.{backend}.txt",
            mime="text/plain",
            use_container_width=True
        )
        
        # Deploy to SIEM section
        st.markdown("---")
        st.markdown("##### 🚀 Deploy to SIEM")
        
        spaces = sigma.get_kibana_spaces()
        col_space, col_enabled = st.columns([2, 1])
        with col_space:
            selected_space = st.selectbox(
                "Kibana Space",
                options=spaces,
                key="deploy_space"
            )
        with col_enabled:
            enable_rule = st.checkbox("Enable", value=False, key="enable_rule")
        
        if st.button("🚀 Deploy to SIEM", type="primary", use_container_width=True, key="deploy_btn"):
            if yaml_content.strip() and st.session_state.raw_query:
                with st.spinner("Deploying rule..."):
                    success, message = sigma.send_rule_to_siem(
                        yaml_content=yaml_content,
                        query=st.session_state.raw_query,
                        space=selected_space,
                        enabled=enable_rule
                    )
                if success:
                    st.success(message)
                else:
                    st.error(message)
            else:
                st.warning("Convert a rule first before deploying.")
    
    elif st.session_state.converted_query and not st.session_state.conversion_success:
        st.error(st.session_state.converted_query)
    
    else:
        # Empty state
        st.info("Select a rule or paste YAML, then click Convert to see the query output.")

# --- FOOTER ---
st.markdown("---")
with st.expander("ℹ️ About Sigma Converter"):
    col_info1, col_info2 = st.columns(2)
    with col_info1:
        st.markdown("""
        **Supported Backends:**
        - Elasticsearch (Lucene/EQL/ES|QL)
        - Splunk SPL
        - Microsoft 365 Defender (KQL)
        """)
    with col_info2:
        st.markdown("""
        **Available Pipelines:**
        - Sysmon - For Sysmon logs
        - Windows - General Windows events
        - Windows Audit - Security/Audit logs
        - ECS Windows - Elastic Common Schema
        """)
