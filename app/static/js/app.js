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

// Log immediately to confirm script is loading
console.debug('TIDE app.js loading...');

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
    // HELPER FUNCTIONS (internal)
    // ========================================

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

    function closeUserMenu(event) {
        const menu = document.getElementById('user-menu');
        const container = document.querySelector('.user-menu-container');
        
        if (menu && container && !container.contains(event.target)) {
            menu.classList.remove('show');
            document.removeEventListener('click', closeUserMenu);
        }
    }

    // ========================================
    // GLOBAL FUNCTIONS (exposed for inline onclick handlers)
    // These must be defined immediately, NOT inside DOMContentLoaded
    // ========================================

    /**
     * Toggle sidebar expanded/collapsed state
     */
    window.toggleSidebar = function() {
        const sidebar = document.getElementById('sidebar');
        const toggle = document.getElementById('sidebar-toggle');
        
        if (!sidebar || !toggle) {
            console.error('toggleSidebar: sidebar or toggle element not found');
            return;
        }
        
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
        if (event) {
            event.stopPropagation();
            event.preventDefault();
        }
        
        const menu = document.getElementById('user-menu');
        if (!menu) {
            console.error('toggleUserMenu: user-menu element not found');
            return;
        }
        
        const isCurrentlyShown = menu.classList.contains('show');
        
        if (isCurrentlyShown) {
            menu.classList.remove('show');
            document.removeEventListener('click', closeUserMenu);
        } else {
            menu.classList.add('show');
            // Use setTimeout to avoid the current click triggering close immediately
            setTimeout(function() {
                document.addEventListener('click', closeUserMenu);
            }, 10);
        }
    };

    /**
     * Toggle theme between light and dark
     */
    window.toggleTheme = function() {
        const body = document.body;
        if (!body) return;
        const isLight = body.classList.toggle('light');
        localStorage.setItem('theme', isLight ? 'light' : 'dark');
        updateThemeUI(isLight);
    };

    /**
     * Show a toast notification
     */
    window.showToast = function(message, type) {
        type = type || 'success';
        const container = document.getElementById('toast-container');
        if (!container) return;
        
        const toast = document.createElement('div');
        toast.className = 'toast toast-' + type;
        toast.textContent = message;
        container.appendChild(toast);
        
        // Trigger reflow for animation
        toast.offsetHeight;
        toast.classList.add('show');
        
        setTimeout(function() {
            toast.classList.remove('show');
            setTimeout(function() { toast.remove(); }, 300);
        }, 3000);
    };

    // Expose TIDE namespace for debugging
    window.TIDE = TIDE;

    // ========================================
    // PAGE INITIALIZATION FUNCTIONS
    // ========================================

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
     * Update active nav item based on current path
     */
    function updateActiveNavItem() {
        const path = window.location.pathname;
        const navItems = document.querySelectorAll('.sidebar .nav-item[href]');
        
        navItems.forEach(function(item) {
            const href = item.getAttribute('href');
            if (href === path || (href !== '/' && path.startsWith(href))) {
                item.classList.add('active');
            } else {
                item.classList.remove('active');
            }
        });
    }

    /**
     * Initialize page-specific components after navigation
     */
    function initializePage() {
        restoreSidebarState();
        restoreTheme();
        updateActiveNavItem();
        document.dispatchEvent(new CustomEvent('tide:pageInit'));
    }

    /**
     * Execute page-specific initializers
     */
    function executePageInitializers() {
        // Check for Sigma page initializer
        const yamlTextarea = document.getElementById('yaml-editor');
        if (yamlTextarea && typeof window.initSigmaPage === 'function') {
            setTimeout(function() {
                window.initSigmaPage(0);
            }, 50);
        }
        
        // Re-highlight any code blocks (Prism.js)
        if (typeof Prism !== 'undefined') {
            setTimeout(function() { Prism.highlightAll(); }, 100);
        }
        
        document.dispatchEvent(new CustomEvent('tide:pageReady'));
    }

    // ========================================
    // DOM-DEPENDENT INITIALIZATION
    // This runs after the DOM is ready
    // ========================================

    function initializeApp() {
        if (!document.body) {
            console.error('initializeApp called but document.body is null');
            return;
        }

        // Configure HTMX before any requests
        // Use document instead of document.body so listeners persist across HTMX swaps
        document.addEventListener('htmx:configRequest', function(event) {
            const csrfToken = document.querySelector('meta[name="csrf-token"]');
            if (csrfToken) {
                event.detail.headers['X-CSRF-Token'] = csrfToken.content;
            }
        });

        // Handle HTMX errors
        document.addEventListener('htmx:responseError', function(event) {
            console.error('HTMX Response Error:', event.detail);
            showToast('An error occurred. Please try again.', 'error');
        });

        // Handle HTMX request timeout
        document.addEventListener('htmx:timeout', function(event) {
            showToast('Request timed out. Please try again.', 'error');
        });

        // After HTMX swaps content (page navigation or partial updates)
        document.addEventListener('htmx:afterSettle', function(event) {
            const target = event.detail.target;
            
            // For full page loads (body or main content area)
            if (target === document.body || 
                target.classList.contains('main-content') ||
                target.tagName === 'MAIN') {
                initializePage();
                executePageInitializers();
            }
            
            // Re-highlight any code blocks (Prism.js)
            if (typeof Prism !== 'undefined') {
                setTimeout(function() { Prism.highlightAll(); }, 50);
            }
        });

        // Also listen for htmx:load
        document.addEventListener('htmx:load', function(event) {
            if (typeof Prism !== 'undefined' && event.detail.elt) {
                setTimeout(function() {
                    Prism.highlightAllUnder(event.detail.elt);
                }, 50);
            }
        });

        // Listen for custom toast events
        document.addEventListener('showToast', function(event) {
            showToast(event.detail.message, event.detail.type);
        });

        // Show loading indicator during HTMX requests
        document.addEventListener('htmx:beforeRequest', function(event) {
            if (event.detail.boosted) {
                document.body.classList.add('htmx-request');
            }
        });

        document.addEventListener('htmx:afterRequest', function(event) {
            document.body.classList.remove('htmx-request');
        });

        // Handle browser back/forward navigation with bfcache
        window.addEventListener('pageshow', function(event) {
            if (event.persisted) {
                initializePage();
                executePageInitializers();
            }
        });

        // Initialize the page
        initializePage();
        
        // Mark as initialized
        TIDE.initialized = true;
        console.debug('TIDE app initialized successfully');
    }

    // ========================================
    // START INITIALIZATION
    // ========================================

    // Wait for DOM to be ready before initializing app
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initializeApp);
    } else {
        // DOM is already ready
        initializeApp();
    }

})();
