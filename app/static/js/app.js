/**
 * TIDE Application JavaScript
 * 
 * Handles:
 * - HTMX configuration and events
 * - Page initialization after HTMX navigation
 * - Theme and sidebar state management
 * - Toast notifications
 * - Global utilities
 */

(function() {
    'use strict';

    // ========================================
    // CONFIGURATION
    // ========================================
    
    const TIDE = {
        initialized: false,
        currentPage: null
    };

    // ========================================
    // HTMX CONFIGURATION
    // ========================================
    
    // Configure HTMX before any requests
    document.body.addEventListener('htmx:configRequest', function(event) {
        // Add CSRF token if available
        const csrfToken = document.querySelector('meta[name="csrf-token"]');
        if (csrfToken) {
            event.detail.headers['X-CSRF-Token'] = csrfToken.content;
        }
    });

    // Handle HTMX errors
    document.body.addEventListener('htmx:responseError', function(event) {
        console.error('HTMX Response Error:', event.detail);
        showToast('An error occurred. Please try again.', 'error');
    });

    // Handle HTMX request timeout
    document.body.addEventListener('htmx:timeout', function(event) {
        showToast('Request timed out. Please try again.', 'error');
    });

    // ========================================
    // PAGE INITIALIZATION
    // ========================================

    /**
     * Initialize page-specific components after navigation
     */
    function initializePage() {
        // Restore sidebar state
        restoreSidebarState();
        
        // Restore theme
        restoreTheme();
        
        // Initialize any page-specific scripts
        initializePageScripts();
        
        // Mark current nav item as active
        updateActiveNavItem();
    }

    /**
     * Restore sidebar expanded/collapsed state from localStorage
     */
    function restoreSidebarState() {
        const sidebar = document.getElementById('sidebar');
        const toggle = document.getElementById('sidebar-toggle');
        
        if (!sidebar || !toggle) return;
        
        const sidebarExpanded = localStorage.getItem('sidebar-expanded') === 'true';
        const toggleIcon = toggle.querySelector('.toggle-icon');
        const toggleLabel = toggle.querySelector('.nav-label');
        
        if (sidebarExpanded) {
            sidebar.classList.add('expanded');
            if (toggleIcon) toggleIcon.innerHTML = '<path d="m15 18-6-6 6-6"/>';
            if (toggleLabel) toggleLabel.textContent = 'Collapse';
            toggle.setAttribute('data-tooltip', 'Collapse');
        } else {
            sidebar.classList.remove('expanded');
            if (toggleIcon) toggleIcon.innerHTML = '<path d="m9 18 6-6-6-6"/>';
            if (toggleLabel) toggleLabel.textContent = 'Expand';
            toggle.setAttribute('data-tooltip', 'Expand');
        }
    }

    /**
     * Restore theme from localStorage
     */
    function restoreTheme() {
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'light') {
            document.body.classList.add('light');
            updateThemeUI(true);
        } else {
            document.body.classList.remove('light');
            updateThemeUI(false);
        }
    }

    /**
     * Update theme toggle UI
     */
    function updateThemeUI(isLight) {
        const icon = document.getElementById('theme-icon');
        const label = document.getElementById('theme-label');
        
        if (icon) {
            if (isLight) {
                icon.innerHTML = '<circle cx="12" cy="12" r="4"/><path d="M12 2v2"/><path d="M12 20v2"/><path d="m4.93 4.93 1.41 1.41"/><path d="m17.66 17.66 1.41 1.41"/><path d="M2 12h2"/><path d="M20 12h2"/><path d="m6.34 17.66-1.41 1.41"/><path d="m19.07 4.93-1.41 1.41"/>';
            } else {
                icon.innerHTML = '<path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/>';
            }
        }
        if (label) {
            label.textContent = isLight ? 'Light Mode' : 'Dark Mode';
        }
    }

    /**
     * Update active nav item based on current path
     */
    function updateActiveNavItem() {
        const path = window.location.pathname;
        const navItems = document.querySelectorAll('.sidebar .nav-item[href]');
        
        navItems.forEach(item => {
            const href = item.getAttribute('href');
            if (href === path || (href !== '/' && path.startsWith(href))) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });
    }

    /**
     * Initialize page-specific scripts (e.g., CodeMirror for Sigma page)
     */
    function initializePageScripts() {
        // The page-specific scripts will be executed by htmx:afterSettle
        // This function can be used for additional initialization if needed
        
        // Dispatch a custom event that page scripts can listen for
        document.dispatchEvent(new CustomEvent('tide:pageInit'));
    }

    // ========================================
    // HTMX NAVIGATION EVENTS
    // ========================================

    // After HTMX swaps content (page navigation or partial updates)
    document.body.addEventListener('htmx:afterSettle', function(event) {
        // Only reinitialize for full page navigations (boosted links)
        // Check if this is a full page swap by looking at the target
        const target = event.detail.target;
        
        // For full page loads (body or main content area)
        if (target === document.body || 
            target.classList.contains('main-content') ||
            target.tagName === 'MAIN') {
            initializePage();
            
            // Execute any page-specific initializers
            executePageInitializers();
        }
        
        // Re-highlight any code blocks (Prism.js)
        if (typeof Prism !== 'undefined') {
            setTimeout(() => Prism.highlightAll(), 50);
        }
    });
    
    /**
     * Execute page-specific initializers registered via TIDE.registerPageInit
     * This is called after HTMX settles to reinitialize page components
     */
    function executePageInitializers() {
        // Check for Sigma page initializer - force reinit after HTMX navigation
        const yamlTextarea = document.getElementById('yaml-editor');
        if (yamlTextarea) {
            // Wait a moment for scripts to load, then initialize
            // The initSigmaPage function handles CodeMirror loading checks
            setTimeout(() => {
                if (typeof window.initSigmaPage === 'function') {
                    console.debug('Triggering Sigma page initialization after HTMX swap');
                    window.initSigmaPage(0);
                }
            }, 50);
        }
        
        // Re-highlight any code blocks (Prism.js)
        if (typeof Prism !== 'undefined') {
            setTimeout(() => Prism.highlightAll(), 100);
        }
        
        // Dispatch custom event for other pages to listen to
        document.dispatchEvent(new CustomEvent('tide:pageReady'));
    }
    
    // ========================================
    // HTMX NAVIGATION EVENTS
    // ========================================

    // After HTMX swaps content (page navigation or partial updates)
    document.body.addEventListener('htmx:afterSettle', function(event) {
        // Only reinitialize for full page navigations (boosted links)
        // Check if this is a full page swap by looking at the target
        const target = event.detail.target;
        
        // For full page loads (body or main content area)
        if (target === document.body || 
            target.classList.contains('main-content') ||
            target.tagName === 'MAIN') {
            initializePage();
            
            // Execute any page-specific initializers
            executePageInitializers();
        }
        
        // Also check for partial swaps that need Prism highlighting
        if (typeof Prism !== 'undefined') {
            setTimeout(() => Prism.highlightAll(), 50);
        }
    });
    
    // Also listen for htmx:load which fires for each new element loaded via HTMX
    document.body.addEventListener('htmx:load', function(event) {
        // Re-highlight code blocks in newly loaded content
        if (typeof Prism !== 'undefined') {
            setTimeout(() => {
                if (event.detail.elt) {
                    Prism.highlightAllUnder(event.detail.elt);
                }
            }, 50);
        }
    });
    
    // Handle browser back/forward navigation with bfcache
    window.addEventListener('pageshow', function(event) {
        if (event.persisted) {
            // Page was restored from bfcache - reinitialize
            initializePage();
            executePageInitializers();
        }
    });

    // Handle popstate for browser navigation
    window.addEventListener('popstate', function(event) {
        // Let HTMX handle the navigation, we'll initialize after settle
    });

    // ========================================
    // GLOBAL FUNCTIONS (exposed for inline use)
    // ========================================

    /**
     * Toggle sidebar expanded/collapsed state
     */
    window.toggleSidebar = function() {
        const sidebar = document.getElementById('sidebar');
        const toggle = document.getElementById('sidebar-toggle');
        
        if (!sidebar || !toggle) return;
        
        const toggleIcon = toggle.querySelector('.toggle-icon');
        const toggleLabel = toggle.querySelector('.nav-label');
        const isExpanded = sidebar.classList.toggle('expanded');
        
        // Update toggle icon and tooltip
        if (isExpanded) {
            if (toggleIcon) toggleIcon.innerHTML = '<path d="m15 18-6-6 6-6"/>';
            if (toggleLabel) toggleLabel.textContent = 'Collapse';
            toggle.setAttribute('data-tooltip', 'Collapse');
        } else {
            if (toggleIcon) toggleIcon.innerHTML = '<path d="m9 18 6-6-6-6"/>';
            if (toggleLabel) toggleLabel.textContent = 'Expand';
            toggle.setAttribute('data-tooltip', 'Expand');
        }
        
        // Save preference
        localStorage.setItem('sidebar-expanded', isExpanded);
    };

    /**
     * Toggle user menu dropdown
     */
    window.toggleUserMenu = function(event) {
        event.stopPropagation();
        const menu = document.getElementById('user-menu');
        if (!menu) return;
        
        menu.classList.toggle('show');
        
        // Close menu when clicking outside
        if (menu.classList.contains('show')) {
            document.addEventListener('click', closeUserMenu);
        }
    };

    function closeUserMenu(event) {
        const menu = document.getElementById('user-menu');
        const container = document.querySelector('.user-menu-container');
        
        if (menu && container && !container.contains(event.target)) {
            menu.classList.remove('show');
            document.removeEventListener('click', closeUserMenu);
        }
    }

    /**
     * Toggle theme between light and dark
     */
    window.toggleTheme = function() {
        const body = document.body;
        const isLight = body.classList.toggle('light');
        localStorage.setItem('theme', isLight ? 'light' : 'dark');
        updateThemeUI(isLight);
    };

    /**
     * Show a toast notification
     */
    window.showToast = function(message, type = 'success') {
        const container = document.getElementById('toast-container');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        
        // Trigger reflow for animation
        toast.offsetHeight;
        toast.classList.add('show');
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    };

    // Listen for custom toast events from HTMX responses
    document.body.addEventListener('showToast', function(event) {
        showToast(event.detail.message, event.detail.type);
    });

    // ========================================
    // LOADING INDICATOR
    // ========================================

    // Show loading indicator during HTMX requests
    document.body.addEventListener('htmx:beforeRequest', function(event) {
        // Only show loading for page navigations, not small updates
        if (event.detail.boosted) {
            document.body.classList.add('htmx-request');
        }
    });

    document.body.addEventListener('htmx:afterRequest', function(event) {
        document.body.classList.remove('htmx-request');
    });

    // ========================================
    // INITIAL LOAD
    // ========================================

    // Initialize on first page load
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializePage);
    } else {
        initializePage();
    }

    // Mark as initialized
    TIDE.initialized = true;

    // Expose TIDE namespace for debugging
    window.TIDE = TIDE;

})();
