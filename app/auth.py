"""
Authentication module for TIDE with Keycloak OIDC support.
Supports local development bypass mode when AUTH_DISABLED=true.
"""

import streamlit as st
import os
import requests
import jwt
import inspect
from datetime import datetime, timedelta
from urllib.parse import urlencode, quote, unquote
from dotenv import load_dotenv

# Load .env file if ENV_FILE_LOCATION is set, otherwise use default
env_file_location = os.getenv('ENV_FILE_LOCATION', '.env')
if os.path.exists(env_file_location):
    load_dotenv(env_file_location)
else:
    # Try to load from default location or just use environment variables
    load_dotenv(override=False)  # Don't override existing env vars

# --- CONFIGURATION ---
# Get AUTH_DISABLED from environment (env_file in docker-compose makes it available)
auth_disabled_raw = os.getenv('AUTH_DISABLED', 'false')
AUTH_DISABLED = str(auth_disabled_raw).lower().strip() == 'true'

# KEYCLOAK_URL is what the browser uses (external URL)
KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://localhost:8080')
# KEYCLOAK_INTERNAL_URL is what the backend uses (Docker network or same as KEYCLOAK_URL)
KEYCLOAK_INTERNAL_URL = os.getenv('KEYCLOAK_INTERNAL_URL', KEYCLOAK_URL)

KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'tide')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'tide-app')
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', '')
APP_URL = os.getenv('APP_URL', 'http://localhost:8501')

# OIDC Endpoints - External (for browser redirects)
KEYCLOAK_BASE = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
AUTHORIZATION_URL = f"{KEYCLOAK_BASE}/protocol/openid-connect/auth"
LOGOUT_URL = f"{KEYCLOAK_BASE}/protocol/openid-connect/logout"

# OIDC Endpoints - Internal (for backend API calls)
KEYCLOAK_INTERNAL_BASE = f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}"
TOKEN_URL = f"{KEYCLOAK_INTERNAL_BASE}/protocol/openid-connect/token"
USERINFO_URL = f"{KEYCLOAK_INTERNAL_BASE}/protocol/openid-connect/userinfo"
JWKS_URL = f"{KEYCLOAK_INTERNAL_BASE}/protocol/openid-connect/certs"

# Callback URL for OAuth redirect
REDIRECT_URI = f"{APP_URL}/"


def get_dev_user():
    """Returns a mock user for local development."""
    return {
        'sub': 'dev-user-001',
        'preferred_username': 'developer',
        'name': 'Local Developer',
        'email': 'dev@localhost',
        'email_verified': True,
        'roles': ['admin', 'user'],
        'groups': ['/admins', '/developers']
    }


def init_session_state():
    """Initialize authentication-related session state."""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'user' not in st.session_state:
        st.session_state.user = None
    if 'access_token' not in st.session_state:
        st.session_state.access_token = None
    if 'refresh_token' not in st.session_state:
        st.session_state.refresh_token = None
    if 'token_expiry' not in st.session_state:
        st.session_state.token_expiry = None


def get_login_url(state: str = "", prompt: str = None):
    """Generate the Keycloak authorization URL.
    
    Args:
        state: State parameter to preserve across redirect
        prompt: Set to 'none' for silent auth (no login UI)
    """
    params = {
        'client_id': KEYCLOAK_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state
    }
    if prompt:
        params['prompt'] = prompt
    return f"{AUTHORIZATION_URL}?{urlencode(params)}"


def get_logout_url():
    """Generate the Keycloak logout URL."""
    params = {
        'client_id': KEYCLOAK_CLIENT_ID,
        'post_logout_redirect_uri': REDIRECT_URI
    }
    return f"{LOGOUT_URL}?{urlencode(params)}"


def exchange_code_for_tokens(code: str) -> dict:
    """Exchange authorization code for access/refresh tokens."""
    data = {
        'grant_type': 'authorization_code',
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': KEYCLOAK_CLIENT_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI
    }
    
    try:
        response = requests.post(TOKEN_URL, data=data, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        # Show detailed error for debugging
        error_detail = ""
        if hasattr(e, 'response') and e.response is not None:
            error_detail = f" Response: {e.response.text}"
        st.error(f"Failed to exchange authorization code: {e}{error_detail}")
        st.error(f"Token URL: {TOKEN_URL}")
        return None


def refresh_access_token() -> bool:
    """Refresh the access token using the refresh token."""
    if not st.session_state.refresh_token:
        return False
    
    data = {
        'grant_type': 'refresh_token',
        'client_id': KEYCLOAK_CLIENT_ID,
        'client_secret': KEYCLOAK_CLIENT_SECRET,
        'refresh_token': st.session_state.refresh_token
    }
    
    try:
        response = requests.post(TOKEN_URL, data=data, timeout=10)
        response.raise_for_status()
        tokens = response.json()
        
        st.session_state.access_token = tokens['access_token']
        st.session_state.refresh_token = tokens.get('refresh_token', st.session_state.refresh_token)
        st.session_state.token_expiry = datetime.now() + timedelta(seconds=tokens.get('expires_in', 300))
        
        return True
    except requests.RequestException:
        return False


def get_user_info(access_token: str) -> dict:
    """Fetch user info from Keycloak userinfo endpoint."""
    headers = {'Authorization': f'Bearer {access_token}'}
    
    try:
        response = requests.get(USERINFO_URL, headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        st.error(f"Failed to fetch user info: {e}")
        return None


def decode_token(token: str) -> dict:
    """Decode JWT token without verification (for extracting claims)."""
    try:
        # Decode without verification - we trust Keycloak's token endpoint
        claims = jwt.decode(token, options={"verify_signature": False})
        return claims
    except jwt.DecodeError:
        return None


def handle_oauth_callback():
    """Handle the OAuth callback with authorization code."""
    query_params = st.query_params
    
    # Skip if already authenticated
    if st.session_state.authenticated:
        return
    
    # Handle silent auth error (user not logged in to Keycloak)
    if 'error' in query_params:
        error = query_params.get('error', '')
        if error == 'login_required':
            # Silent auth failed - user needs to log in
            st.session_state['_silent_auth_checked'] = True
            st.query_params.clear()
            st.rerun()
            return
        # Clear other errors
        st.query_params.clear()
        return
    
    if 'code' in query_params:
        code = query_params.get('code', '')
        # Get the original page from state parameter
        state = query_params.get('state', '')
        
        # Handle if state is a list
        if isinstance(state, list):
            state = state[0] if state else ''
        
        original_page = unquote(state) if state else ''
        
        # Clear the code from URL immediately to prevent reprocessing
        st.query_params.clear()
        
        # Exchange code for tokens
        tokens = exchange_code_for_tokens(code)
        
        if tokens:
            st.session_state.access_token = tokens['access_token']
            st.session_state.refresh_token = tokens.get('refresh_token')
            st.session_state.token_expiry = datetime.now() + timedelta(seconds=tokens.get('expires_in', 300))
            
            # Get user info
            user_info = get_user_info(tokens['access_token'])
            if user_info:
                # Also extract roles from the access token if available
                token_claims = decode_token(tokens['access_token'])
                if token_claims:
                    # Keycloak typically stores roles in realm_access or resource_access
                    realm_roles = token_claims.get('realm_access', {}).get('roles', [])
                    client_roles = token_claims.get('resource_access', {}).get(KEYCLOAK_CLIENT_ID, {}).get('roles', [])
                    user_info['roles'] = list(set(realm_roles + client_roles))
                    user_info['groups'] = token_claims.get('groups', [])
                
                st.session_state.user = user_info
                st.session_state.authenticated = True
                st.session_state['_silent_auth_checked'] = True
                
                # Redirect to original page if available (and not the home page)
                if original_page and original_page.startswith('pages/'):
                    try:
                        st.switch_page(original_page)
                    except Exception as e:
                        # If switch_page fails, just rerun on current page
                        st.rerun()
                else:
                    st.rerun()


def check_token_expiry():
    """Check if token is expired and refresh if needed."""
    if st.session_state.token_expiry:
        # Refresh if token expires in less than 60 seconds
        if datetime.now() > st.session_state.token_expiry - timedelta(seconds=60):
            if not refresh_access_token():
                # Refresh failed, user needs to re-authenticate
                logout()
                return False
    return True


def logout():
    """Clear session and logout from Keycloak."""
    st.session_state.authenticated = False
    st.session_state.user = None
    st.session_state.access_token = None
    st.session_state.refresh_token = None
    st.session_state.token_expiry = None


def render_login_page(current_page_path: str = ''):
    """Render the login page with Keycloak redirect."""
    # Hide sidebar on login page
    st.markdown("""
    <style>
        [data-testid="stSidebar"] { display: none; }
        [data-testid="stSidebarCollapsedControl"] { display: none; }
    </style>
    """, unsafe_allow_html=True)
    
    from styles import get_icon_base64
    tide_icon_b64 = get_icon_base64("tide.png")
    st.markdown(f"""
    <div class="login-container">
        <img src="data:image/png;base64,{tide_icon_b64}" class="login-title" style="width: 48px; height: 48px;" alt="TIDE">
        <div class="login-subtitle">TIDE</div>
        <div class="login-card">
            <p class="login-message">Sign in to access the Threat Informed Detection Engine</p>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    # Center the login button
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        login_url = get_login_url(state=quote(current_page_path) if current_page_path else '')
        st.link_button("🔐 Sign in with Keycloak", login_url, use_container_width=True)


def render_user_avatar():
    """Render user avatar button in top-right corner with logout popup."""
    if st.session_state.authenticated and st.session_state.user:
        user = st.session_state.user
        display_name = user.get('name', user.get('preferred_username', 'User'))
        email = user.get('email', '')
        initial = display_name[0].upper() if display_name else 'U'
        
        # Place the button in a container at the top right
        header_cols = st.columns([20, 1])
        with header_cols[1]:
            with st.popover(initial, use_container_width=False):
                st.markdown(f"**{display_name}**")      
                if AUTH_DISABLED:
                    st.caption("🔓 Dev Mode")
                
                st.divider()
                
                if st.button("Sign Out", use_container_width=True):
                    if AUTH_DISABLED:
                        logout()
                        st.rerun()
                    else:
                        logout()
                        # Redirect to Keycloak logout
                        st.markdown(f'<meta http-equiv="refresh" content="0;url={get_logout_url()}">', unsafe_allow_html=True)


def get_current_page_path():
    """Get the current page path for redirect preservation."""
    # Use inspect to find the calling script's path
    try:
        # Walk up the call stack to find the page script
        for frame_info in inspect.stack():
            filename = frame_info.filename
            # Look for files in the pages directory
            if '/pages/' in filename or '\\pages\\' in filename:
                # Get the relative path from app directory
                # e.g., /app/app/pages/4_Rule_health.py -> pages/4_Rule_health.py
                if '/app/app/' in filename:
                    rel_path = filename.split('/app/app/')[-1]
                elif '\\app\\app\\' in filename:
                    rel_path = filename.split('\\app\\app\\')[-1]
                else:
                    # Just get pages/filename.py
                    parts = filename.replace('\\', '/').split('/')
                    pages_idx = parts.index('pages') if 'pages' in parts else -1
                    if pages_idx >= 0:
                        rel_path = '/'.join(parts[pages_idx:])
                    else:
                        continue
                
                rel_path = rel_path.replace('\\', '/')
                return rel_path
    except Exception as e:
        pass
    
    return ''


def require_auth():
    """
    Main authentication gate. Call this at the top of every page.
    Returns True if authenticated, stops execution if not.
    
    Usage:
        from auth import require_auth
        require_auth()  # Will stop here if not authenticated
        
        # Rest of your page code...
    """
    init_session_state()
    
    # Get current page path immediately (before any redirects)
    current_page_path = get_current_page_path()
    
    # Development mode - auto-authenticate with dev user
    if AUTH_DISABLED:
        if not st.session_state.authenticated:
            st.session_state.user = get_dev_user()
            st.session_state.authenticated = True
        render_user_avatar()
        return True
    
    # Handle OAuth callback
    handle_oauth_callback()
    
    # Check if already authenticated
    if st.session_state.authenticated:
        # Verify token is still valid
        if check_token_expiry():
            render_user_avatar()
            return True
    
    # Try silent authentication first (check if user has active Keycloak session)
    if not st.session_state.get('_silent_auth_checked', False):
        # Redirect to Keycloak with prompt=none to check session silently
        silent_auth_url = get_login_url(state=quote(current_page_path) if current_page_path else '', prompt='none')
        st.markdown(f'<meta http-equiv="refresh" content="0;url={silent_auth_url}">', unsafe_allow_html=True)
        st.stop()
    
    # Not authenticated - show login page
    render_login_page(current_page_path)
    st.stop()


def get_current_user() -> dict:
    """Get the current authenticated user info."""
    return st.session_state.get('user')


def has_role(role: str) -> bool:
    """Check if current user has a specific role."""
    user = get_current_user()
    if user:
        return role in user.get('roles', [])
    return False


def has_any_role(roles: list) -> bool:
    """Check if current user has any of the specified roles."""
    user = get_current_user()
    if user:
        user_roles = set(user.get('roles', []))
        return bool(user_roles.intersection(set(roles)))
    return False


def require_role(role: str):
    """
    Require a specific role to access a page.
    Call after require_auth().
    
    Usage:
        require_auth()
        require_role('admin')
    """
    if not has_role(role):
        st.error(f"⛔ Access Denied: This page requires the '{role}' role.")
        st.stop()


def require_any_role(roles: list):
    """
    Require any of the specified roles to access a page.
    Call after require_auth().
    """
    if not has_any_role(roles):
        st.error(f"⛔ Access Denied: This page requires one of the following roles: {', '.join(roles)}")
        st.stop()
