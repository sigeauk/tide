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

    const NAV_GROUP_IDS = [
        'nav-group-risk',
        'nav-group-rules',
        'nav-group-threats',
        'nav-group-mitre',
        'nav-group-cti'
    ];

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
     * Toggle a sidebar nav group and persist its collapsed state.
     */
    window.toggleNavGroup = function(id) {
        const el = document.getElementById(id);
        if (!el) return;

        const willOpen = el.classList.contains('collapsed');

        // Accordion behavior: opening one section collapses the rest.
        if (willOpen) {
            NAV_GROUP_IDS.forEach(function(groupId) {
                const groupEl = document.getElementById(groupId);
                if (!groupEl || groupId === id) return;
                groupEl.classList.add('collapsed');
                try {
                    localStorage.setItem('nav_' + groupId, '1');
                } catch (e) {
                    console.warn('Unable to persist nav group state for', groupId, e);
                }
            });
        }

        const isNowCollapsed = el.classList.toggle('collapsed');
        try {
            localStorage.setItem('nav_' + id, isNowCollapsed ? '1' : '0');
        } catch (e) {
            console.warn('Unable to persist nav group state for', id, e);
        }
    };

    /**
     * Expand/collapse all remembered collapsible sections.
     * If scopeSelector is provided, only sections inside that container are updated.
     */
    window.setAllRememberedCollapsibles = function(scopeSelector, expand) {
        const root = scopeSelector ? document.querySelector(scopeSelector) : document;
        if (!root) return;

        const scopeToken = scopeSelector
            ? scopeSelector.replace(/^[#\.]/, '')
            : (root.getAttribute('data-collapse-scope') || 'global');

        const blocks = root.querySelectorAll('details[data-collapse-key]');
        blocks.forEach(function(block) {
            const key = block.getAttribute('data-collapse-key');
            if (!key) return;

            if (expand) {
                block.setAttribute('open', '');
            } else {
                block.removeAttribute('open');
            }

            try {
                localStorage.setItem('collapse_' + key, expand ? '1' : '0');
            } catch (e) {
                console.warn('Unable to persist collapsible state for', key, e);
            }
        });

        try {
            localStorage.setItem('collapse_scope_' + scopeToken, expand ? '1' : '0');
        } catch (e) {
            console.warn('Unable to persist collapsible scope state for', scopeToken, e);
        }
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
     * Toggle client switcher dropdown
     */
    window.toggleClientMenu = function(event) {
        if (event) {
            event.stopPropagation();
            event.preventDefault();
        }
        var switcher = document.getElementById('client-switcher');
        if (!switcher) return;
        var isOpen = switcher.classList.contains('open');
        if (isOpen) {
            switcher.classList.remove('open');
            document.removeEventListener('click', closeClientMenu);
        } else {
            switcher.classList.add('open');
            setTimeout(function() {
                document.addEventListener('click', closeClientMenu);
            }, 10);
        }
    };

    function closeClientMenu(e) {
        var switcher = document.getElementById('client-switcher');
        if (switcher && !switcher.contains(e.target)) {
            switcher.classList.remove('open');
            document.removeEventListener('click', closeClientMenu);
        }
    }

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

    function slidePanelWidthKey() {
        var userId = (document.body && document.body.dataset.userId) || 'anonymous';
        return 'tide.slidePanel.width.' + userId;
    }

    function clampSlidePanelWidth(width) {
        var min = Math.min(360, window.innerWidth);
        var max = Math.max(min, Math.floor(window.innerWidth * 0.9));
        return Math.max(min, Math.min(max, Math.round(width)));
    }

    window.initTechniqueSlidePanel = function(root) {
        root = root || document;
        var panel = root.querySelector ? root.querySelector('.slide-panel') : null;
        if (!panel || panel.dataset.resizableReady === 'true') return;
        panel.dataset.resizableReady = 'true';

        if (window.innerWidth > 980) {
            var stored = parseInt(localStorage.getItem(slidePanelWidthKey()) || '', 10);
            if (stored) panel.style.setProperty('--slide-panel-width', clampSlidePanelWidth(stored) + 'px');
        }

        var handle = panel.querySelector('[data-slide-panel-resize]');
        if (!handle) return;
        handle.addEventListener('pointerdown', function(event) {
            if (window.innerWidth <= 980) return;
            event.preventDefault();
            event.stopPropagation();
            handle.setPointerCapture(event.pointerId);
            panel.classList.add('is-resizing');
            document.body.classList.add('is-resizing-slide-panel');

            function onMove(moveEvent) {
                var width = clampSlidePanelWidth(window.innerWidth - moveEvent.clientX);
                panel.style.setProperty('--slide-panel-width', width + 'px');
            }

            function onUp(upEvent) {
                handle.releasePointerCapture(upEvent.pointerId);
                panel.classList.remove('is-resizing');
                document.body.classList.remove('is-resizing-slide-panel');
                localStorage.setItem(slidePanelWidthKey(), Math.round(panel.getBoundingClientRect().width));
                handle.removeEventListener('pointermove', onMove);
                handle.removeEventListener('pointerup', onUp);
                handle.removeEventListener('pointercancel', onUp);
            }

            handle.addEventListener('pointermove', onMove);
            handle.addEventListener('pointerup', onUp);
            handle.addEventListener('pointercancel', onUp);
        });
    };

    // Expose TIDE namespace for debugging
    window.TIDE = TIDE;

    /**
     * Toggle a "[name]-filter-dropdown" style panel (Rule Health / Promotion
     * filter bar). Flips it to right-anchored when it would otherwise
     * overflow the right edge of the viewport, since these panels sit in a
     * flex-wrapped bar and can land anywhere left-to-right on the page.
     */
    window.tideToggleFilterDropdown = function(id) {
        var dd = document.getElementById(id);
        if (!dd) return;
        var opening = dd.style.display === 'none' || !dd.style.display;
        dd.style.display = opening ? 'block' : 'none';
        dd.style.left = '';
        dd.style.right = '';
        if (opening) {
            var rect = dd.getBoundingClientRect();
            if (rect.right > window.innerWidth) {
                dd.style.left = 'auto';
                dd.style.right = '0';
            }
        }
    };

    window.tideInitInfiniteScroll = function(root) {
        var scope = root && root.querySelectorAll ? root : document;
        var sentinels = Array.prototype.slice.call(
            scope.querySelectorAll('.infinite-scroll-sentinel:not([data-observed])')
        );
        if (scope.matches && scope.matches('.infinite-scroll-sentinel:not([data-observed])')) {
            sentinels.unshift(scope);
        }
        sentinels.forEach(function(sentinel) {
            sentinel.dataset.observed = 'true';
            var scrollRegion = sentinel.closest('.rule-scroll-region');
            var usesInnerScroll = scrollRegion && getComputedStyle(scrollRegion).overflowY !== 'visible';
            var observer = new IntersectionObserver(function(entries) {
                if (!entries.some(function(entry) { return entry.isIntersecting; })) return;
                observer.disconnect();
                htmx.trigger(sentinel, 'tideLoadMore');
            }, {
                root: usesInnerScroll ? scrollRegion : null,
                rootMargin: '0px 0px 600px 0px',
                threshold: 0
            });
            observer.observe(sentinel);
        });
    };

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
     * Restore each nav group's collapse state.
     * Default behavior is collapsed when no preference exists.
     */
    function restoreNavGroupStates() {
        NAV_GROUP_IDS.forEach(function(id) {
            const el = document.getElementById(id);
            if (!el) return;

            let shouldCollapse = true;
            try {
                const saved = localStorage.getItem('nav_' + id);
                if (saved === '0') shouldCollapse = false;
                if (saved === '1') shouldCollapse = true;
            } catch (e) {
                // Keep collapsed default if storage is unavailable.
            }

            el.classList.toggle('collapsed', shouldCollapse);
        });
    }

    /**
     * Restore and persist state for any details[data-collapse-key] block.
     */
    function restoreCollapsibleDetailsState() {
        const scopes = document.querySelectorAll('[data-collapse-scope]');
        scopes.forEach(function(scopeEl) {
            const scopeToken = scopeEl.getAttribute('data-collapse-scope');
            if (!scopeToken) return;
            try {
                const scopeSaved = localStorage.getItem('collapse_scope_' + scopeToken);
                if (scopeSaved === '1' || scopeSaved === '0') {
                    const expand = scopeSaved === '1';
                    const scopedBlocks = scopeEl.querySelectorAll('details[data-collapse-key]');
                    scopedBlocks.forEach(function(block) {
                        if (expand) block.setAttribute('open', '');
                        else block.removeAttribute('open');
                    });
                }
            } catch (e) {
                // Keep per-block or template defaults if storage is unavailable.
            }
        });

        const blocks = document.querySelectorAll('details[data-collapse-key]');
        blocks.forEach(function(block) {
            const key = block.getAttribute('data-collapse-key');
            if (!key) return;

            try {
                const saved = localStorage.getItem('collapse_' + key);
                if (saved === '1') block.setAttribute('open', '');
                if (saved === '0') block.removeAttribute('open');
            } catch (e) {
                // Keep template default if storage is unavailable.
            }

            if (block.dataset.collapseBound === '1') return;
            block.addEventListener('toggle', function() {
                try {
                    localStorage.setItem('collapse_' + key, block.open ? '1' : '0');
                    const scopeEl = block.closest('[data-collapse-scope]');
                    if (scopeEl) {
                        const scopeToken = scopeEl.getAttribute('data-collapse-scope');
                        if (scopeToken) localStorage.removeItem('collapse_scope_' + scopeToken);
                    }
                } catch (e) {
                    console.warn('Unable to persist collapsible state for', key, e);
                }
            });
            block.dataset.collapseBound = '1';
        });
    }

    // Expose for pages that lazily inject nested details blocks.
    window.restoreCollapsibleDetailsState = restoreCollapsibleDetailsState;

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
        restoreNavGroupStates();
        restoreCollapsibleDetailsState();
        restoreTheme();
        updateActiveNavItem();
        document.dispatchEvent(new CustomEvent('tide:pageInit'));
    }

    // Action menu: toggle on trigger click, close on outside click (one-time listener)
    document.addEventListener('click', function(e) {
        var trigger = e.target.closest('.action-menu__trigger');
        if (trigger) {
            e.stopPropagation();
            var menu = trigger.closest('.action-menu');
            document.querySelectorAll('.action-menu.open').forEach(function(m) {
                if (m !== menu) m.classList.remove('open');
            });
            menu.classList.toggle('open');
            return;
        }
        if (e.target.closest('.action-menu__item')) {
            var openMenu = e.target.closest('.action-menu');
            if (openMenu) openMenu.classList.remove('open');
            return;
        }

        document.querySelectorAll('.action-menu.open').forEach(function(m) {
            m.classList.remove('open');
        });
    });

    document.addEventListener('change', function(e) {
        var filter = e.target;
        if (!filter || !filter.id) return;
        if (filter.id !== 'history-user-filter' && filter.id !== 'history-action-filter' && filter.id !== 'history-sort-filter') return;

        var historyRoot = filter.closest('.modal-overlay[data-history-modal]');
        if (!historyRoot) return;

        var userFilter = historyRoot.querySelector('#history-user-filter');
        var actionFilter = historyRoot.querySelector('#history-action-filter');
        var sortFilter = historyRoot.querySelector('#history-sort-filter');
        var timelineList = historyRoot.querySelector('#history-timeline-list');

        var userValue = (userFilter && userFilter.value) || '';
        var actionValue = (actionFilter && actionFilter.value) || '';
        var sortValue = (sortFilter && sortFilter.value) || 'desc';
        var containers = [timelineList].filter(Boolean);

        containers.forEach(function(container) {
            var rows = Array.from(container.querySelectorAll('[data-history-row]'));
            rows.forEach(function(row) {
                var matchesUser = !userValue || (row.dataset.user || '') === userValue;
                var matchesAction = !actionValue || (row.dataset.kind || '') === actionValue;
                row.style.display = (matchesUser && matchesAction) ? '' : 'none';
            });

            var sortedRows = rows.slice().sort(function(a, b) {
                var aTime = Date.parse(a.dataset.time || '') || 0;
                var bTime = Date.parse(b.dataset.time || '') || 0;
                return sortValue === 'asc' ? aTime - bTime : bTime - aTime;
            });

            sortedRows.forEach(function(row) {
                container.appendChild(row);
            });
        });
    });

    document.addEventListener('htmx:afterSwap', function(e) {
        var target = e.detail && e.detail.target;
        if (!target || target.id !== 'modal-container') return;

        var historyRoot = target.querySelector('.modal-overlay[data-history-modal]');
        if (!historyRoot) return;

        var sortFilter = historyRoot.querySelector('#history-sort-filter');
        if (sortFilter) {
            sortFilter.dispatchEvent(new Event('change', { bubbles: true }));
        }
    });

    // ══════════════════════════════════════════════════════════════════
    //  Rule modal behaviour (card/table click → modal in #modal-container)
    //   • loading skeleton while the modal/edit request is in flight
    //   • close (X / Esc / backdrop) with focus returned to the opener
    //   • prev / next (buttons + ← →) through the list the modal was opened from
    //   • history toggle, section order and section open/closed remembered per browser
    //   • copy-query button
    // ══════════════════════════════════════════════════════════════════
    var ruleModalOpener = null;      // element that opened the modal (card / row)
    var ruleModalListRoot = null;    // its [data-rule-list] container
    var ruleSkeletonTimer = null;
    var MODAL_PATHS = ['/history-modal', '/edit-form', '/create-form'];

    function ruleModalOverlay() { return document.querySelector('.modal-overlay[data-rule-modal]'); }

    function closeRuleModal() {
        var overlay = ruleModalOverlay();
        if (!overlay) return false;
        var container = overlay.parentElement;
        overlay.remove();
        if (container && container.id === 'modal-container') container.innerHTML = '';
        if (ruleModalOpener && document.contains(ruleModalOpener)) {
            try { ruleModalOpener.focus({ preventScroll: true }); } catch (_) { /* element not focusable */ }
        }
        return true;
    }

    function showRuleSkeleton(container) {
        var tpl = document.getElementById('rule-modal-skeleton');
        if (!tpl || !container) return;
        container.innerHTML = '';
        container.appendChild(tpl.content.cloneNode(true));
    }

    function clearRuleSkeleton() {
        clearTimeout(ruleSkeletonTimer);
        ruleSkeletonTimer = null;
    }

    // Remember what opened the modal, and show the skeleton if the response is slow.
    document.addEventListener('htmx:beforeRequest', function(e) {
        var elt = e.detail && e.detail.elt;
        var path = (e.detail && e.detail.pathInfo && e.detail.pathInfo.requestPath) || '';
        var target = e.detail && e.detail.target;
        if (elt && elt.hasAttribute && elt.hasAttribute('data-rule-open')) {
            ruleModalOpener = elt;
            ruleModalListRoot = elt.closest('[data-rule-list]');
        }
        if (!target || target.id !== 'modal-container') return;
        if (!MODAL_PATHS.some(function(p) { return path.indexOf(p) !== -1; })) return;
        clearRuleSkeleton();
        ruleSkeletonTimer = setTimeout(function() { showRuleSkeleton(target); }, 120);
    });
    ['htmx:afterSwap', 'htmx:responseError', 'htmx:sendError', 'htmx:timeout'].forEach(function(name) {
        document.addEventListener(name, function(e) {
            var target = e.detail && e.detail.target;
            if (!target || target.id !== 'modal-container') return;
            clearRuleSkeleton();
            if (name !== 'htmx:afterSwap') {
                var overlay = target.querySelector('[data-rm-skeleton]');
                if (overlay) { overlay.remove(); target.innerHTML = ''; }
                if (typeof showToast === 'function') showToast('Could not load the rule. Please try again.', 'error');
            }
        });
    });

    // Close handlers (delegated so they work for swapped-in modals).
    document.addEventListener('click', function(e) {
        if (e.target.closest && e.target.closest('[data-rm-close]')) { closeRuleModal(); return; }
        var overlay = e.target;
        if (overlay && overlay.matches && overlay.matches('.modal-overlay[data-rm-overlay]')) closeRuleModal();
    });

    // Copy query
    document.addEventListener('click', function(e) {
        var btn = e.target.closest && e.target.closest('[data-rm-copy]');
        if (!btn) return;
        var src = document.querySelector(btn.getAttribute('data-rm-copy'));
        if (!src || !navigator.clipboard) return;
        navigator.clipboard.writeText(src.innerText).then(function() {
            btn.classList.add('is-done');
            setTimeout(function() { btn.classList.remove('is-done'); }, 1200);
        });
    });

    // ── prev / next through the list the modal was opened from ──
    function ruleNavItems() {
        var root = ruleModalListRoot && document.contains(ruleModalListRoot) ? ruleModalListRoot : null;
        return root ? Array.prototype.slice.call(root.querySelectorAll('[data-rule-open]')) : [];
    }
    function ruleNavIndex(items) {
        var modal = document.querySelector('.rule-modal[data-rule-id]');
        if (!modal) return -1;
        var id = 'rule-' + modal.getAttribute('data-rule-id');
        for (var i = 0; i < items.length; i++) if (items[i].id === id) return i;
        return -1;
    }
    function ruleNavSentinel() {
        return ruleModalListRoot ? ruleModalListRoot.querySelector('.infinite-scroll-sentinel') : null;
    }
    function updateRuleNavButtons() {
        var modal = document.querySelector('.rule-modal[data-rule-id]');
        if (!modal) return;
        var items = ruleNavItems(), idx = ruleNavIndex(items);
        var prev = modal.querySelector('[data-rm-nav="prev"]'), next = modal.querySelector('[data-rm-nav="next"]');
        if (prev) prev.disabled = idx <= 0;
        if (next) next.disabled = idx === -1 || (idx >= items.length - 1 && !ruleNavSentinel());
    }
    function openAdjacentRule(dir) {
        var items = ruleNavItems(), idx = ruleNavIndex(items);
        if (idx === -1) return;
        var nextIdx = idx + (dir === 'next' ? 1 : -1);
        if (nextIdx >= 0 && nextIdx < items.length) {
            items[nextIdx].scrollIntoView({ block: 'nearest' });
            htmx.trigger(items[nextIdx], 'click');
            return;
        }
        // At the end of what is loaded: pull the next page (infinite scroll), then continue.
        var sentinel = dir === 'next' ? ruleNavSentinel() : null;
        if (!sentinel) return;
        var root = ruleModalListRoot;
        var once = function(ev) {
            if (!root || !root.contains(ev.detail.target) && ev.detail.target !== root && !ev.detail.target.contains(root)) return;
            document.removeEventListener('htmx:afterSettle', once);
            var again = ruleNavItems();
            if (idx + 1 < again.length) htmx.trigger(again[idx + 1], 'click');
        };
        document.addEventListener('htmx:afterSettle', once);
        htmx.trigger(sentinel, 'tideLoadMore');
    }
    document.addEventListener('click', function(e) {
        var btn = e.target.closest && e.target.closest('[data-rm-nav]');
        if (btn && !btn.disabled) openAdjacentRule(btn.getAttribute('data-rm-nav'));
    });
    document.addEventListener('keydown', function(e) {
        if (!ruleModalOverlay()) return;
        if (e.key === 'Escape') { closeRuleModal(); return; }
        if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
        if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
        var a = document.activeElement, tag = a && a.tagName;
        if (tag === 'INPUT' || tag === 'SELECT' || tag === 'TEXTAREA' || (a && a.isContentEditable)) return;
        if (!document.querySelector('.rule-modal[data-rule-id]')) return;   // e.g. edit form is open
        e.preventDefault();
        openAdjacentRule(e.key === 'ArrowRight' ? 'next' : 'prev');
    });

    // ── Preferences remembered per browser: history shown/hidden, section order, section open/closed ──
    window.tideCloseRuleModal = closeRuleModal;      // used by MITRE pills inside the modal (so the side panel is visible)

    function readPref(key, fallback) {
        try { var raw = localStorage.getItem(key); return raw === null ? fallback : JSON.parse(raw); } catch (_) { return fallback; }
    }
    function writePref(key, value) {
        try { localStorage.setItem(key, JSON.stringify(value)); } catch (_) { /* storage blocked */ }
    }

    // History column: one toggle (data-view = default | no-history)
    function applyRuleModalHistory(modal, shown) {
        if (!modal) return;
        modal.setAttribute('data-view', shown ? 'default' : 'no-history');
        var btn = modal.querySelector('[data-rm-history-toggle]');
        if (btn) btn.setAttribute('aria-pressed', shown ? 'true' : 'false');
    }
    document.addEventListener('click', function(e) {
        var btn = e.target.closest && e.target.closest('[data-rm-history-toggle]');
        if (!btn) return;
        var modal = btn.closest('.rule-modal');
        var shown = modal.getAttribute('data-view') === 'no-history';     // was hidden -> now shown
        applyRuleModalHistory(modal, shown);
        writePref('tide.ruleModalHistory', shown ? 'shown' : 'hidden');
    });

    // Centre-column section order (about · logic · guide · references · mappings · scores)
    // The centre column keeps its original storage key; the side columns get their own.
    function ruleOrderKey(col) {
        var m = col.className.match(/rm-col--(\w+)/);
        return !m || m[1] === 'logic' ? 'tide.ruleModalOrder' : 'tide.ruleModalOrder.' + m[1];
    }
    function ruleSectionEls(col) { return Array.prototype.slice.call(col.querySelectorAll(':scope > [data-section]')); }
    function updateMoveButtons(col) {
        var items = ruleSectionEls(col);
        items.forEach(function(el, i) {
            var up = el.querySelector('[data-rm-move="up"]'), down = el.querySelector('[data-rm-move="down"]');
            if (up) up.disabled = i === 0;
            if (down) down.disabled = i === items.length - 1;
        });
    }
    function applyRuleSectionOrder(col) {
        var order = readPref(ruleOrderKey(col), []);
        if (Array.isArray(order) && order.length) {
            var items = ruleSectionEls(col), byKey = {};
            items.forEach(function(el) { byKey[el.getAttribute('data-section')] = el; });
            var anchor = col.querySelector(':scope > .rm-note');            // keep non-section notes where they are
            order.forEach(function(k) { if (byKey[k]) { col.insertBefore(byKey[k], anchor); delete byKey[k]; } });
            Object.keys(byKey).forEach(function(k) { col.insertBefore(byKey[k], anchor); });   // sections added later go last
        }
        updateMoveButtons(col);
    }
    document.addEventListener('click', function(e) {
        var btn = e.target.closest && e.target.closest('[data-rm-move]');
        if (!btn || btn.disabled) return;
        e.preventDefault();               // the buttons live inside <summary>: do not toggle the section
        e.stopPropagation();
        var section = btn.closest('[data-section]'), col = section && section.parentElement;
        if (!col) return;
        var items = ruleSectionEls(col), i = items.indexOf(section);
        var j = btn.getAttribute('data-rm-move') === 'up' ? i - 1 : i + 1;
        if (j < 0 || j >= items.length) return;
        if (j < i) col.insertBefore(section, items[j]); else col.insertBefore(items[j], section);
        writePref(ruleOrderKey(col), ruleSectionEls(col).map(function(el) { return el.getAttribute('data-section'); }));
        updateMoveButtons(col);
        var same = section.querySelector('[data-rm-move="' + btn.getAttribute('data-rm-move') + '"]');
        var target = same && !same.disabled ? same : section.querySelector('[data-rm-move]:not(:disabled)');
        if (target) target.focus({ preventScroll: true });
        section.scrollIntoView({ block: 'nearest' });
    }, true);

    // Section open/closed
    function readRuleModalFolds() { return readPref('tide.ruleModalFolds', {}) || {}; }
    document.addEventListener('toggle', function(e) {
        var fold = e.target;
        if (!fold || !fold.matches || !fold.matches('details.rm-fold[data-fold]')) return;
        var folds = readRuleModalFolds();
        folds[fold.getAttribute('data-fold')] = fold.open;
        writePref('tide.ruleModalFolds', folds);
    }, true);

    // Panels (activity, score chart, logic, actions, MITRE) collapse via a head button and share the fold pref.
    function setPanelCollapsed(panel, collapsed) {
        panel.classList.toggle('is-collapsed', collapsed);
        var btn = panel.querySelector('[data-rm-collapse]');
        if (btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    }
    document.addEventListener('click', function(e) {
        var btn = e.target.closest && e.target.closest('[data-rm-collapse]');
        if (!btn) return;
        var panel = btn.closest('.rm-panel[data-fold]');
        if (!panel) return;
        var collapsed = !panel.classList.contains('is-collapsed');
        setPanelCollapsed(panel, collapsed);
        var folds = readRuleModalFolds();
        folds[panel.getAttribute('data-fold')] = !collapsed;
        writePref('tide.ruleModalFolds', folds);
    }, true);

    // Restore everything when a modal is swapped in
    document.addEventListener('htmx:afterSwap', function(e) {
        var target = e.detail && e.detail.target;
        if (!target || target.id !== 'modal-container') return;
        var modal = target.querySelector('.rule-modal[data-rule-id]');
        if (!modal) return;
        applyRuleModalHistory(modal, readPref('tide.ruleModalHistory', 'shown') !== 'hidden');
        var folds = readRuleModalFolds();
        modal.querySelectorAll('details.rm-fold[data-fold]').forEach(function(fold) {
            if (folds[fold.getAttribute('data-fold')] === false) fold.open = false;
        });
        modal.querySelectorAll('.rm-panel[data-fold]').forEach(function(panel) {
            if (folds[panel.getAttribute('data-fold')] === false) setPanelCollapsed(panel, true);
        });
        modal.querySelectorAll('.rm-col').forEach(applyRuleSectionOrder);
        updateRuleNavButtons();
        var closeBtn = modal.querySelector('[data-rm-close]');
        if (closeBtn) closeBtn.focus({ preventScroll: true });
    });

    // Keep summary link navigation and card expansion separate across list/detail accordions.
    document.addEventListener('pointerdown', function(event) {
        var link = event.target.closest('details > summary a[href]');
        if (!link) return;
        event.stopPropagation();
    }, true);

    document.addEventListener('click', function(event) {
        var link = event.target.closest('details > summary a[href]');
        if (!link) return;

        event.preventDefault();
        event.stopPropagation();

        if (event.metaKey || event.ctrlKey || event.shiftKey || link.target === '_blank' || event.button === 1) {
            window.open(link.href, link.target || '_blank', 'noopener');
            return;
        }
        window.location.assign(link.href);
    }, true);

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
        window.initTechniqueSlidePanel(document);
        
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
            } else {
                // Partial swaps can inject new details[data-collapse-key] blocks.
                // Rebind restore/persistence for newly inserted accordions.
                restoreCollapsibleDetailsState();
            }
            
            // Re-highlight any code blocks (Prism.js)
            if (typeof Prism !== 'undefined') {
                setTimeout(function() { Prism.highlightAll(); }, 50);
            }
        });

        // Also listen for htmx:load
        document.addEventListener('htmx:load', function(event) {
            if (event.detail.elt) {
                window.initTechniqueSlidePanel(event.detail.elt);
                window.tideInitInfiniteScroll(event.detail.elt);
            }
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

    // <details data-remember="key"> keeps its open/closed state per browser. A panel rendered open on purpose
    // (data-keep-open, e.g. right after a save) is left alone.
    function applyRemembered(root) {
        if (!root || !root.querySelectorAll) return;
        var panels = Array.prototype.slice.call(root.querySelectorAll('details[data-remember]'));
        if (root.matches && root.matches('details[data-remember]')) panels.push(root);
        panels.forEach(function (d) {
            if (d.hasAttribute('data-keep-open')) return;
            try {
                var saved = localStorage.getItem('tide.open.' + d.getAttribute('data-remember'));
                if (saved !== null) d.open = saved === '1';
            } catch (_) { /* storage unavailable: keep the default */ }
        });
    }
    document.addEventListener('toggle', function (e) {
        var d = e.target;
        if (!d.matches || !d.matches('details[data-remember]')) return;
        try { localStorage.setItem('tide.open.' + d.getAttribute('data-remember'), d.open ? '1' : '0'); } catch (_) { /* ignore */ }
    }, true);
    document.addEventListener('htmx:load', function (e) { applyRemembered(e.target); });

    // Management > client > Rule scoring: live total of the points allocated (delegated, so it survives htmx swaps).
    document.addEventListener('input', function (e) {
        var input = e.target;
        if (!input.matches || !input.matches('[data-scoring-weight]')) return;
        var form = input.closest('[data-scoring-form]');
        var total = 0;
        form.querySelectorAll('[data-scoring-weight]').forEach(function (el) { total += parseInt(el.value, 10) || 0; });
        var out = form.querySelector('[data-scoring-total]');
        if (out) out.textContent = total;
    });

    // Rule modal > Actions > Promote / Demote: confirm dialog, then POST to the promotion API.
    // Promote: "Delete source" starts from the client default and is only sent when the user changes it,
    // so the server applies the same default logic as before. Demote: the production copy is kept unless ticked.
    function showMoveConfirm(cfg) {
        var host = document.getElementById('modal-container');
        if (!host) return;
        var overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.onclick = function (e) { if (e.target === overlay) overlay.remove(); };
        overlay.innerHTML =
            '<div name="' + cfg.verb + ' Rule Modal" class="modal-content modal-sm" onclick="event.stopPropagation()">' +
            '<h2 class="modal-section-title">' + cfg.title + '</h2>' +
            '<p class="text-secondary mb-md">Are you sure you want to ' + cfg.verb.toLowerCase() + ' <strong data-move-name></strong> ' + cfg.destination + '?</p>' +
            '<div class="alert alert-warning mb-md"><p>' + cfg.warning + '</p></div>' +
            '<label style="display:flex;align-items:center;gap:0.5rem;margin-bottom:1rem;">' +
            '<input type="checkbox" name="delete_source"' + (cfg.deleteDefault ? ' checked' : '') + '> ' + cfg.checkboxLabel + '</label>' +
            '<div class="modal-actions">' +
            '<button name="Cancel" type="button" class="btn btn-secondary" data-move-cancel>Cancel</button>' +
            '<button name="' + cfg.verb + '" type="button" class="btn btn-primary" data-move-go>' + cfg.verb + '</button>' +
            '</div></div>';
        overlay.querySelector('[data-move-name]').textContent = cfg.ruleName;
        var box = overlay.querySelector('input[name="delete_source"]');
        box.dataset.changed = 'false';
        box.addEventListener('change', function () { box.dataset.changed = 'true'; });
        overlay.querySelector('[data-move-cancel]').onclick = function () { overlay.remove(); };
        var go = overlay.querySelector('[data-move-go]');
        go.onclick = function () {
            go.disabled = true;
            go.textContent = cfg.busy;
            var body = new URLSearchParams();
            if (cfg.alwaysSend || box.dataset.changed === 'true') body.set('delete_source', box.checked ? 'true' : 'false');
            var url = '/api/promotion/' + encodeURIComponent(cfg.ruleId) + '/' + cfg.verb.toLowerCase() + (cfg.siemId ? '?siem_id=' + encodeURIComponent(cfg.siemId) : '');
            fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() })
                .then(function (r) { return r.text().then(function (html) { return { ok: r.ok, html: html }; }); })
                .then(function (res) {
                    var toasts = document.getElementById('toast-container');
                    if (toasts) toasts.insertAdjacentHTML('beforeend', res.html);
                    if (res.ok) {
                        document.querySelectorAll('#modal-container .modal-overlay').forEach(function (o) { o.remove(); });
                        setTimeout(function () { window.location.reload(); }, 1200);
                    } else {
                        go.disabled = false;
                        go.textContent = cfg.verb;
                    }
                })
                .catch(function (err) {
                    go.disabled = false;
                    go.textContent = cfg.verb;
                    var toasts = document.getElementById('toast-container');
                    if (toasts) {
                        var t = document.createElement('div');
                        t.className = 'toast toast-danger';
                        t.textContent = 'Error: ' + err.message;
                        t.onclick = function () { t.remove(); };
                        toasts.appendChild(t);
                    }
                });
        };
        host.appendChild(overlay);
    }

    window.showPromoteConfirm = function (ruleId, ruleName, siemId, deleteSourceDefault) {
        showMoveConfirm({
            verb: 'Promote', busy: 'Promoting...', title: 'Promote to Production', destination: 'to the production environment',
            warning: 'The production copy becomes the master rule. Delete source is enabled by default from the client settings.',
            checkboxLabel: 'Delete source after promotion', deleteDefault: deleteSourceDefault,
            ruleId: ruleId, ruleName: ruleName, siemId: siemId
        });
    };

    window.showDemoteConfirm = function (ruleId, ruleName, siemId) {
        showMoveConfirm({
            verb: 'Demote', busy: 'Demoting...', title: 'Demote to Staging', destination: 'back to the staging environment',
            warning: 'A copy is created in staging. The production rule stays live unless you tick the box below.',
            checkboxLabel: 'Delete the production copy after demoting', deleteDefault: false, alwaysSend: true,
            ruleId: ruleId, ruleName: ruleName, siemId: siemId
        });
    };

    // Rule compare dialog: inline / side-by-side layout, remembered per browser.
    function applyDiffView(root) {
        var view = 'inline';
        try { view = localStorage.getItem('tide.diffView') || 'inline'; } catch (_) { /* default */ }
        root.setAttribute('data-view', view === 'side' ? 'side' : 'inline');
    }
    document.addEventListener('htmx:load', function (e) {
        var roots = e.target && e.target.querySelectorAll ? Array.prototype.slice.call(e.target.querySelectorAll('.rd-root')) : [];
        if (e.target && e.target.matches && e.target.matches('.rd-root')) roots.push(e.target);
        roots.forEach(applyDiffView);
    });
    document.addEventListener('click', function (e) {
        var btn = e.target.closest && e.target.closest('[data-rd-view]');
        if (!btn) return;
        var root = btn.closest('.rd-root');
        if (!root) return;
        root.setAttribute('data-view', btn.getAttribute('data-rd-view'));
        try { localStorage.setItem('tide.diffView', btn.getAttribute('data-rd-view')); } catch (_) { /* ignore */ }
    }, true); // capture: the dialog stops click propagation, so a bubbling listener never sees it

})();
