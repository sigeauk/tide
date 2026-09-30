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
    window.showToast = function(message, type, duration) {
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
        }, duration || 3000);
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

    // Any window built on the rule window's frame (the rule window, the baseline technique window):
    // the overlay carries data-rm-overlay and the dialog data-rule-dom-id -- the id of the card or
    // row that opens it, which is what prev/next walk.
    function ruleModalOverlay() { return document.querySelector('.modal-overlay[data-rm-overlay]'); }

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
            // Snapshot the browsable order now, once, from a real card click. Prev/Next below
            // navigates this frozen snapshot by direct AJAX call rather than clicking cards, so
            // it never re-enters this branch and never overwrites the snapshot mid-browse.
            ruleModalNavSnapshot = ruleModalListRoot
                ? snapshotFromItems(Array.prototype.slice.call(ruleModalListRoot.querySelectorAll('[data-rule-open]')))
                : [];
        }
        if (!target || target.id !== 'modal-container') return;
        // A window is already open (prev/next, or a rule opened from inside it): swap the content in
        // place -- no entrance animation and no skeleton, so the window does not flash.
        var open = target.querySelector('.modal-overlay[data-rm-overlay]:not([data-rm-skeleton]) > .modal-content');
        target.classList.toggle('rm-swap-quiet', !!open);
        if (open) { open.setAttribute('aria-busy', 'true'); return; }
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
                var busy = target.querySelector('.modal-content[aria-busy]');
                if (busy) busy.removeAttribute('aria-busy');
                var overlay = target.querySelector('[data-rm-skeleton]');
                if (overlay) { overlay.remove(); target.innerHTML = ''; }
                if (typeof showToast === 'function') showToast('Could not load the rule. Please try again.', 'error');
            }
        });
    });

    // Close handlers (delegated so they work for swapped-in modals). A response can also ask for
    // the window to close once it has updated the page behind it (HX-Trigger-After-Swap).
    document.addEventListener('tideCloseModal', function() { closeRuleModal(); });
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
    // Walks a snapshot of {id, url} taken when the modal opened, not the live grid: the grid
    // behind the modal can fully reload or re-sort while it's open (recording a search time, a
    // sync, a validation all change the rule's score and trigger refreshRules), which can drop
    // the current rule off the loaded page entirely. Re-deriving "next" from a live query would
    // then find nothing. The snapshot is what the operator was actually browsing; opening an
    // entry from it is a direct AJAX call by URL, not a click on a card that may no longer exist.
    var ruleModalNavSnapshot = [];
    function ruleNavItems() {
        var root = ruleModalListRoot && document.contains(ruleModalListRoot) ? ruleModalListRoot : null;
        if (!root) root = document.querySelector('[data-rule-list]');
        return root ? Array.prototype.slice.call(root.querySelectorAll('[data-rule-open]')) : [];
    }
    function snapshotFromItems(items) {
        return items.map(function(el) { return { id: el.id, url: el.getAttribute('hx-get') }; });
    }
    function ruleNavIndex() {
        var modal = document.querySelector('.rule-modal[data-rule-dom-id]');
        if (!modal) return -1;
        // Match on the card's scoped id, not the rule id: the same rule id is on a card per
        // destination once it has been copied, and the first one is not necessarily this one.
        var id = modal.getAttribute('data-rule-dom-id') || ('rule-' + modal.getAttribute('data-rule-id'));
        for (var i = 0; i < ruleModalNavSnapshot.length; i++) if (ruleModalNavSnapshot[i].id === id) return i;
        return -1;
    }
    function ruleNavSentinel() {
        var root = ruleModalListRoot && document.contains(ruleModalListRoot) ? ruleModalListRoot : document.querySelector('[data-rule-list]');
        return root ? root.querySelector('.infinite-scroll-sentinel') : null;
    }
    function updateRuleNavButtons() {
        var modal = document.querySelector('.rule-modal[data-rule-dom-id]');
        if (!modal) return;
        var idx = ruleNavIndex();
        var prev = modal.querySelector('[data-rm-nav="prev"]'), next = modal.querySelector('[data-rm-nav="next"]');
        if (prev) prev.disabled = idx <= 0;
        if (next) next.disabled = idx === -1 || (idx >= ruleModalNavSnapshot.length - 1 && !ruleNavSentinel());
    }
    function openSnapshotEntry(entry) {
        if (!entry || !entry.url) return;
        var live = entry.id ? document.getElementById(entry.id) : null;
        if (live) live.scrollIntoView({ block: 'nearest' });
        htmx.ajax('GET', entry.url, { target: '#modal-container', swap: 'innerHTML' });
    }
    function openAdjacentRule(dir) {
        var idx = ruleNavIndex();
        if (idx === -1) return;
        var nextIdx = idx + (dir === 'next' ? 1 : -1);
        if (nextIdx >= 0 && nextIdx < ruleModalNavSnapshot.length) {
            openSnapshotEntry(ruleModalNavSnapshot[nextIdx]);
            return;
        }
        // At the end of what was snapshotted: pull the next page (infinite scroll) from the
        // live grid, append any newly-loaded entries to the snapshot, then continue.
        var sentinel = dir === 'next' ? ruleNavSentinel() : null;
        if (!sentinel) return;
        var root = ruleModalListRoot;
        var once = function(ev) {
            if (!root || (!root.contains(ev.detail.target) && ev.detail.target !== root && !ev.detail.target.contains(root))) return;
            document.removeEventListener('htmx:afterSettle', once);
            var fresh = snapshotFromItems(ruleNavItems());
            for (var i = ruleModalNavSnapshot.length; i < fresh.length; i++) ruleModalNavSnapshot.push(fresh[i]);
            if (idx + 1 < ruleModalNavSnapshot.length) openSnapshotEntry(ruleModalNavSnapshot[idx + 1]);
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
        if (!document.querySelector('.rule-modal[data-rule-dom-id]')) return;   // e.g. edit form is open
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

    // ── Window layout (rule window, technique window) ──
    // Every [data-section] directly in a .rm-col[data-col] can be dragged by its handle (or moved
    // with the arrow keys on the handle) to any place in any column, and hidden or shown from the
    // header's sections menu. The arrangement is remembered per kind of window (data-layout-key)
    // as {cols: {left: [...], centre: [...], right: [...]}, hidden: [...]}. A column left with
    // nothing visible folds away, and comes back as a drop target while a section is dragged.
    var WINDOW_COL_WIDTHS = { left: 'minmax(260px, 1fr)', centre: 'minmax(0, 1.7fr)', right: 'minmax(240px, 0.85fr)' };
    function windowCols(modal) { return Array.prototype.slice.call(modal.querySelectorAll('.rm-body > .rm-col[data-col]')); }
    function windowSections(col) { return Array.prototype.slice.call(col.querySelectorAll(':scope > [data-section]')); }
    function currentWindowLayout(modal) {
        var cols = {}, hidden = [];
        windowCols(modal).forEach(function(col) {
            cols[col.getAttribute('data-col')] = windowSections(col).map(function(s) {
                if (s.hidden) hidden.push(s.getAttribute('data-section'));
                return s.getAttribute('data-section');
            });
        });
        return { cols: cols, hidden: hidden };
    }
    function arrangeWindow(modal, layout) {
        var byKey = {};
        modal.querySelectorAll('.rm-col > [data-section]').forEach(function(s) { byKey[s.getAttribute('data-section')] = s; });
        windowCols(modal).forEach(function(col) {
            ((layout.cols || {})[col.getAttribute('data-col')] || []).forEach(function(k) {
                if (byKey[k]) { col.appendChild(byKey[k]); delete byKey[k]; }
            });
        });
        var hidden = layout.hidden || [];
        modal.querySelectorAll('.rm-col > [data-section]').forEach(function(s) {
            // A required section (a new technique's title form) is never hidden.
            s.hidden = hidden.indexOf(s.getAttribute('data-section')) !== -1 && !s.hasAttribute('data-section-required');
        });
        fitWindowColumns(modal);
    }
    function fitWindowColumns(modal) {
        var body = modal.querySelector('.rm-body');
        if (!body) return;
        var arranging = modal.classList.contains('is-arranging'), widths = [];
        windowCols(modal).forEach(function(col) {
            var shown = Array.prototype.some.call(col.children, function(el) {
                return !el.hidden && !el.classList.contains('rm-drop-marker') && (el.hasAttribute('data-section') || el.classList.contains('rm-note'));
            });
            col.classList.toggle('rm-col--empty', !shown);
            if (shown || arranging) widths.push(WINDOW_COL_WIDTHS[col.getAttribute('data-col')] || 'minmax(0, 1fr)');
        });
        body.style.setProperty('--rm-cols', widths.join(' ') || '1fr');
    }
    // Sections this window does not have (a new technique has no History; not every ATT&CK
    // technique has sub-techniques) keep their saved place and visibility, so arranging one window
    // never forgets how the fuller ones were arranged.
    function saveWindowLayout(modal) {
        var key = modal.getAttribute('data-layout-key');
        if (!key) return;
        var now = currentWindowLayout(modal), saved = readPref(key, null), present = {};
        Object.keys(now.cols).forEach(function(c) { now.cols[c].forEach(function(k) { present[k] = true; }); });
        if (saved && saved.cols) {
            Object.keys(saved.cols).forEach(function(c) {
                var list = now.cols[c] || (now.cols[c] = []);
                (saved.cols[c] || []).forEach(function(k, i) {
                    if (present[k] || list.indexOf(k) !== -1) return;
                    var after = i > 0 ? list.indexOf(saved.cols[c][i - 1]) : -1;
                    list.splice(after !== -1 ? after + 1 : Math.min(i, list.length), 0, k);
                });
            });
            (saved.hidden || []).forEach(function(k) { if (!present[k] && now.hidden.indexOf(k) === -1) now.hidden.push(k); });
        }
        writePref(key, now);
    }
    function applyWindowLayout(modal) {
        modal._tideDefaultLayout = currentWindowLayout(modal);     // as the page drew it, for Reset
        var saved = readPref(modal.getAttribute('data-layout-key'), null);
        if (saved && saved.cols) arrangeWindow(modal, saved); else fitWindowColumns(modal);
    }

    // Sections menu: tick to show, untick to hide. It stays open while ticking (data-keep-open).
    function sectionLabel(s) {
        return s.getAttribute('data-section-label') || s.getAttribute('data-section');
    }
    document.addEventListener('click', function(e) {
        var toggle = e.target.closest && e.target.closest('[data-rm-layout] [data-more-toggle]');
        if (!toggle) return;
        var modal = toggle.closest('.rule-modal'), list = modal.querySelector('[data-rm-layout-list]');
        list.innerHTML = '';
        windowCols(modal).forEach(function(col) {
            windowSections(col).forEach(function(s) {
                var label = document.createElement('label'), box = document.createElement('input');
                label.className = 'rh-more__item rm-layout__item';
                box.type = 'checkbox';
                box.checked = !s.hidden;
                box.disabled = s.hasAttribute('data-section-required');
                box.setAttribute('data-rm-show', s.getAttribute('data-section'));
                label.appendChild(box);
                label.appendChild(document.createTextNode(sectionLabel(s)));
                list.appendChild(label);
            });
        });
    }, true);
    document.addEventListener('change', function(e) {
        var box = e.target.closest && e.target.closest('[data-rm-show]');
        if (!box) return;
        var modal = box.closest('.rule-modal');
        var s = modal.querySelector('.rm-col > [data-section="' + box.getAttribute('data-rm-show') + '"]');
        if (!s) return;
        s.hidden = !box.checked;
        fitWindowColumns(modal);
        saveWindowLayout(modal);
    });
    document.addEventListener('click', function(e) {
        var btn = e.target.closest && e.target.closest('[data-rm-layout-reset]');
        if (!btn) return;
        var modal = btn.closest('.rule-modal');
        if (modal._tideDefaultLayout) arrangeWindow(modal, modal._tideDefaultLayout);
        try { localStorage.removeItem(modal.getAttribute('data-layout-key')); } catch (_) { /* storage blocked */ }
        closeMoreMenus(null);
    });

    // Drag a section by its handle to any column.
    var draggingSection = null, dropMarker = null;
    document.addEventListener('click', function(e) {
        // The handle sits in a <summary> on some sections: it must not open or close them.
        if (e.target.closest && e.target.closest('[data-rm-drag]')) { e.preventDefault(); e.stopPropagation(); }
    }, true);
    document.addEventListener('dragstart', function(e) {
        var handle = e.target.closest && e.target.closest('[data-rm-drag]');
        if (!handle) return;
        draggingSection = handle.closest('[data-section]');
        var modal = draggingSection.closest('.rule-modal');
        modal.classList.add('is-arranging');
        fitWindowColumns(modal);
        draggingSection.classList.add('is-dragging');
        e.dataTransfer.effectAllowed = 'move';
        try {
            e.dataTransfer.setData('text/plain', draggingSection.getAttribute('data-section'));
            e.dataTransfer.setDragImage(draggingSection, 24, 16);
        } catch (_) { /* older browsers: default drag image */ }
    });
    document.addEventListener('dragover', function(e) {
        if (!draggingSection) return;
        var col = e.target.closest && e.target.closest('.rm-col[data-col]');
        if (!col || col.closest('.rule-modal') !== draggingSection.closest('.rule-modal')) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        var before = null;
        windowSections(col).some(function(s) {
            if (s === draggingSection || s.hidden) return false;
            var r = s.getBoundingClientRect();
            if (e.clientY < r.top + r.height / 2) { before = s; return true; }
            return false;
        });
        if (!dropMarker) { dropMarker = document.createElement('div'); dropMarker.className = 'rm-drop-marker'; }
        if (before) col.insertBefore(dropMarker, before); else col.appendChild(dropMarker);
    });
    document.addEventListener('drop', function(e) {
        if (!draggingSection || !dropMarker || !dropMarker.parentElement) return;
        e.preventDefault();
        dropMarker.parentElement.insertBefore(draggingSection, dropMarker);
    });
    document.addEventListener('dragend', function() {
        if (!draggingSection) return;
        var modal = draggingSection.closest('.rule-modal');
        draggingSection.classList.remove('is-dragging');
        if (dropMarker) dropMarker.remove();
        modal.classList.remove('is-arranging');
        fitWindowColumns(modal);
        saveWindowLayout(modal);
        draggingSection = null;
    });
    // Move a section one place up or down (-1 / 1), or to the column to the 'left' or 'right'.
    function moveWindowSection(section, dir) {
        var col = section.parentElement, modal = section.closest('.rule-modal');
        if (typeof dir === 'number') {
            var shown = windowSections(col).filter(function(s) { return !s.hidden; }), j = shown.indexOf(section) + dir;
            if (j < 0 || j >= shown.length) return;
            if (dir < 0) col.insertBefore(section, shown[j]); else col.insertBefore(shown[j], section);
        } else {
            var cols = windowCols(modal), ci = cols.indexOf(col) + (dir === 'left' ? -1 : 1);
            if (ci < 0 || ci >= cols.length) return;
            cols[ci].appendChild(section);
        }
        fitWindowColumns(modal);
        saveWindowLayout(modal);
        section.scrollIntoView({ block: 'nearest' });
    }
    // Or with the keyboard: arrow keys on a focused handle (or in a section's move bar) move its
    // section. (Captured first, so ← → don't also step to another rule.)
    document.addEventListener('keydown', function(e) {
        var handle = e.target.closest && e.target.closest('[data-rm-drag], [data-rm-movebar]');
        var dir = handle && { ArrowUp: -1, ArrowDown: 1, ArrowLeft: 'left', ArrowRight: 'right' }[e.key];
        if (!dir) return;
        e.preventDefault();
        e.stopPropagation();
        moveWindowSection(handle.closest('[data-section]'), dir);
        e.target.focus({ preventScroll: true });
    }, true);

    // A section's "…" › Move (components/window_ui.html section_menu): its head shows the move bar
    // -- drag handle, arrows, Done -- until Done, Esc, or another section is moved.
    function stopMovingSections(except) {
        document.querySelectorAll('[data-section].is-moving').forEach(function(s) {
            if (s === except) return;
            s.classList.remove('is-moving');
            var bar = s.querySelector('[data-rm-movebar]');
            if (bar) bar.hidden = true;
        });
    }
    document.addEventListener('click', function(e) {
        var t = e.target.closest && e.target.closest('[data-rm-move-start], [data-rm-step], [data-rm-move-done]');
        if (!t) return;
        var section = t.closest('[data-section]');
        if (t.hasAttribute('data-rm-move-done')) { stopMovingSections(null); return; }
        if (t.hasAttribute('data-rm-step')) {
            var step = t.getAttribute('data-rm-step');
            moveWindowSection(section, { up: -1, down: 1 }[step] || step);
            t.focus({ preventScroll: true });
            return;
        }
        stopMovingSections(section);
        section.classList.add('is-moving');
        var bar = section.querySelector('[data-rm-movebar]');
        bar.hidden = false;
        section.scrollIntoView({ block: 'nearest' });
        bar.querySelector('[data-rm-drag]').focus({ preventScroll: true });
    });
    document.addEventListener('keydown', function(e) {
        if (e.key !== 'Escape' || !document.querySelector('[data-section].is-moving')) return;
        e.preventDefault();
        e.stopPropagation();          // ends moving; the window stays open
        stopMovingSections(null);
    }, true);

    // Page sections (a container with data-order-key, e.g. a system's Baselines / Devices /
    // Heatmap): order remembered, moved with their up/down buttons.
    function ruleOrderKey(col) { return col.getAttribute('data-order-key'); }
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
    // Page sections built the same way (a system's Baselines / Devices / Heatmap) keep theirs under
    // their container's data-fold-store key instead, so the two never collide.
    function foldStoreKey(panel) {
        var store = panel.closest('[data-fold-store]');
        return store ? store.getAttribute('data-fold-store') : 'tide.ruleModalFolds';
    }
    function setPanelCollapsed(panel, collapsed) {
        panel.classList.toggle('is-collapsed', collapsed);
        var btn = panel.querySelector('[data-rm-collapse]');
        if (btn) btn.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
    }
    // The whole head row folds a window panel, as a <summary> does, except its own controls.
    document.addEventListener('click', function(e) {
        if (!e.target.closest) return;
        var btn = e.target.closest('[data-rm-collapse]');
        var panel;
        if (btn) {
            panel = btn.closest('.rm-panel[data-fold], .sys-section[data-fold]');
        } else {
            var head = e.target.closest('.rm-panel[data-fold] > .rm-panel__head');
            if (!head || e.target.closest('a, button, input, select, textarea, label, [data-more], [data-rm-movebar]')) return;
            if (window.getSelection && String(window.getSelection())) return;
            panel = head.parentElement;
        }
        if (!panel) return;
        var collapsed = !panel.classList.contains('is-collapsed');
        setPanelCollapsed(panel, collapsed);
        var key = foldStoreKey(panel);
        var folds = readPref(key, {}) || {};
        folds[panel.getAttribute('data-fold')] = !collapsed;
        writePref(key, folds);
    }, true);

    // Page-level reorderable sections (a container with data-order-key AND data-fold-store; a
    // window's columns restore themselves on swap, above): restore order and open/closed state on
    // a full load and on every boosted navigation, which swaps the body without a load event.
    function restorePageSections(root) {
        var scope = root && root.querySelectorAll ? root : document;
        var cols = Array.prototype.slice.call(scope.querySelectorAll('[data-order-key][data-fold-store]'));
        if (scope.matches && scope.matches('[data-order-key][data-fold-store]')) cols.push(scope);
        cols.forEach(function(col) {
            var folds = readPref(col.getAttribute('data-fold-store') || '', {}) || {};
            col.querySelectorAll(':scope > [data-fold]').forEach(function(panel) {
                if (folds[panel.getAttribute('data-fold')] === false) setPanelCollapsed(panel, true);
            });
            applyRuleSectionOrder(col);
        });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function() { restorePageSections(); });
    else restorePageSections();
    document.addEventListener('htmx:load', function(e) { restorePageSections(e.target); });

    // ATT&CK picker (components/mitre_picker.html): tactic, then technique, as often as needed.
    // Chosen techniques are listed as pills with their names; `technique_ids` carries them and
    // `tactic` the first one's tactic. A technique can sit under several tactics (T1078 is under
    // four), so each keeps the tactic it was picked under; one already chosen keeps the form's
    // tactic if it is one of its own, else its first.
    function initMitrePicker(root) {
        if (root.dataset.ready) return;
        root.dataset.ready = '1';
        var groups = JSON.parse(root.querySelector('[data-mitre-groups]').textContent || '[]');
        var lookup = {};
        groups.forEach(function(g) {
            g.options.forEach(function(o) {
                if (!lookup[o.id]) lookup[o.id] = { name: o.name, tactics: [] };
                lookup[o.id].tactics.push(g.tactic);
            });
        });
        var value = root.querySelector('[data-mitre-value]'), tacticOut = root.querySelector('[data-mitre-tactic]');
        var list = root.querySelector('[data-mitre-list]'), empty = root.querySelector('[data-mitre-empty]');
        var tacticSel = root.querySelector('[data-mitre-tactic-select]'), techSel = root.querySelector('[data-mitre-technique-select]');
        var ids = (value.value || '').split(',').map(function(v) { return v.trim().toUpperCase(); }).filter(Boolean);
        var chosenUnder = {}, current = tacticOut.value;
        ids.forEach(function(id) {
            var tactics = (lookup[id] || {}).tactics || [];
            chosenUnder[id] = tactics.indexOf(current) !== -1 ? current : (tactics[0] || '');
        });

        function render() {
            list.innerHTML = '';
            ids.forEach(function(id) {
                var info = { name: (lookup[id] || {}).name, tactic: chosenUnder[id] }, li = document.createElement('li');
                var pill = document.createElement('span');
                pill.className = 'mitre-pill mitre-neutral mitre-sm';
                pill.textContent = id;
                var name = document.createElement('span');
                name.className = 'rm-mitre__name';
                name.textContent = info.name || 'Unknown technique';
                if (info.tactic) { var small = document.createElement('small'); small.textContent = info.tactic; name.appendChild(small); }
                var rm = document.createElement('button');
                rm.type = 'button';
                rm.className = 'rm-x';
                rm.title = 'Remove ' + id;
                rm.setAttribute('aria-label', 'Remove ' + id);
                rm.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg>';
                rm.addEventListener('click', function() { ids.splice(ids.indexOf(id), 1); render(); });
                li.appendChild(pill); li.appendChild(name); li.appendChild(rm);
                list.appendChild(li);
            });
            empty.hidden = ids.length > 0;
            value.value = ids.join(', ');
            tacticOut.value = ids.length ? (chosenUnder[ids[0]] || '') : '';
            fillTechniques();
        }
        function fillTechniques() {
            var group = groups.filter(function(g) { return g.tactic === tacticSel.value; })[0];
            techSel.innerHTML = '';
            var first = document.createElement('option');
            first.value = '';
            first.textContent = group ? 'Technique…' : 'Choose a tactic first';
            techSel.appendChild(first);
            techSel.disabled = !group;
            (group ? group.options : []).forEach(function(o) {
                var opt = document.createElement('option');
                opt.value = o.id;
                opt.textContent = o.id + ' - ' + o.name;
                opt.disabled = ids.indexOf(o.id) !== -1;
                techSel.appendChild(opt);
            });
        }
        tacticSel.addEventListener('change', fillTechniques);
        techSel.addEventListener('change', function() {
            if (techSel.value && ids.indexOf(techSel.value) === -1) {
                ids.push(techSel.value);
                chosenUnder[techSel.value] = tacticSel.value;
            }
            render();
        });
        render();
    }
    function initMitrePickers(scope) {
        (scope && scope.querySelectorAll ? scope : document).querySelectorAll('[data-mitre-picker]').forEach(initMitrePicker);
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function() { initMitrePickers(); });
    else initMitrePickers();
    document.addEventListener('htmx:load', function(e) { initMitrePickers(e.target); });

    // "…" menus (data-more > [data-more-toggle] + .rh-more__menu). Rule Health wires its own.
    function closeMoreMenus(except) {
        document.querySelectorAll('[data-more] .rh-more__menu:not([hidden])').forEach(function(m) {
            if (m === except) return;
            m.hidden = true;
            var t = m.parentElement.querySelector('[data-more-toggle]');
            if (t) t.setAttribute('aria-expanded', 'false');
        });
    }
    document.addEventListener('click', function(e) {
        var toggle = e.target.closest && e.target.closest('[data-more-toggle]');
        if (toggle) {
            var menu = toggle.parentElement.querySelector('.rh-more__menu');
            closeMoreMenus(menu);
            menu.hidden = !menu.hidden;
            toggle.setAttribute('aria-expanded', menu.hidden ? 'false' : 'true');
            return;
        }
        // Picking an item, or clicking anywhere else, closes any open menu. Deferred so the item's
        // own htmx/onclick handler still sees it. A menu of checkboxes (data-keep-open) stays open
        // while they are ticked.
        if (e.target.closest && e.target.closest('.rh-more__menu[data-keep-open]')) return;
        setTimeout(function() { closeMoreMenus(null); }, 0);
    });
    // Esc closes an open menu first; only the next Esc closes the window it is in.
    document.addEventListener('keydown', function(e) {
        if (e.key !== 'Escape' || !document.querySelector('[data-more] .rh-more__menu:not([hidden])')) return;
        e.preventDefault();
        e.stopPropagation();
        closeMoreMenus(null);
    }, true);

    // The rule modal can stay open while the grid behind it fully reloads (recording a search
    // time, a sync, a validation all trigger refreshRules) — re-sync the prev/next buttons'
    // disabled state once the new list is in the DOM, or a stale "disabled" from before the
    // reload blocks the click handler even after ruleNavItems() can find the new list.
    document.addEventListener('htmx:afterSwap', function(e) {
        var target = e.detail && e.detail.target;
        if (target && target.id === 'rules-grid' && ruleModalOverlay()) updateRuleNavButtons();
    });

    // An edit swapped into a collapsed section (Update from its "…" menu) opens it, without changing
    // the remembered fold, so the form is never loaded out of sight.
    document.addEventListener('htmx:afterSwap', function(e) {
        var target = e.detail && e.detail.target;
        var panel = target && target.closest && target.closest('.rule-modal .rm-panel.is-collapsed[data-fold]');
        if (panel) setPanelCollapsed(panel, false);
    });

    // Restore everything when a modal is swapped in
    document.addEventListener('htmx:afterSwap', function(e) {
        var target = e.detail && e.detail.target;
        if (!target || target.id !== 'modal-container') return;
        var modal = target.querySelector('.rule-modal[data-rule-dom-id]');
        if (!modal) return;
        var folds = readRuleModalFolds();
        modal.querySelectorAll('details.rm-fold[data-fold]').forEach(function(fold) {
            if (folds[fold.getAttribute('data-fold')] === false) fold.open = false;
        });
        modal.querySelectorAll('.rm-panel[data-fold]').forEach(function(panel) {
            if (folds[panel.getAttribute('data-fold')] === false && !panel.hasAttribute('data-section-required')) setPanelCollapsed(panel, true);
        });
        applyWindowLayout(modal);
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

    // A TIDE-themed stand-in for window.confirm(), for the rule window's actions that change a
    // SIEM. The native dialog is unstyled, unreadable on a long message, and gives no room to
    // mark the destructive choice as destructive. Returns a Promise<boolean>. It appends to
    // #modal-container, so it stacks above whatever modal asked for it (Compare, the edit form).
    window.tideConfirm = function (opts) {
        return new Promise(function (resolve) {
            var host = document.getElementById('modal-container');
            if (!host) { resolve(window.confirm(opts.body || opts.title || 'Are you sure?')); return; }
            var overlay = document.createElement('div');
            overlay.className = 'modal-overlay modal-overlay--confirm';
            overlay.setAttribute('data-tide-confirm', '');
            var danger = opts.danger !== false;
            overlay.innerHTML =
                '<div name="Confirm Modal" class="modal-content modal-sm" role="alertdialog" aria-modal="true" onclick="event.stopPropagation()">' +
                '<h2 class="modal-section-title">' + (opts.title || 'Are you sure?') + '</h2>' +
                '<div class="text-secondary mb-md" data-confirm-body>' + (opts.body || '') + '</div>' +
                '<div class="modal-actions">' +
                '<button name="Cancel" type="button" class="btn btn-secondary" data-confirm-cancel>' + (opts.cancelLabel || 'Cancel') + '</button>' +
                '<button name="Confirm" type="button" class="btn ' + (danger ? 'btn-danger' : 'btn-primary') + '" data-confirm-go>' +
                (opts.confirmLabel || 'Confirm') + '</button>' +
                '</div></div>';
            var done = function (answer) {
                document.removeEventListener('keydown', onKey, true);
                overlay.remove();
                resolve(answer);
            };
            var onKey = function (e) { if (e.key === 'Escape') { e.stopPropagation(); done(false); } };
            document.addEventListener('keydown', onKey, true);
            overlay.onclick = function (e) { if (e.target === overlay) done(false); };
            overlay.querySelector('[data-confirm-cancel]').onclick = function () { done(false); };
            overlay.querySelector('[data-confirm-go]').onclick = function () { done(true); };
            host.appendChild(overlay);
            overlay.querySelector('[data-confirm-cancel]').focus();
        });
    };

    // hx-confirm renders the browser's own dialog; route it through tideConfirm instead so every
    // confirmation in the app looks like the app. htmx issues the request itself once we say yes.
    document.addEventListener('htmx:confirm', function (e) {
        if (!e.detail.question) return;
        e.preventDefault();
        window.tideConfirm({
            title: 'Confirm',
            body: e.detail.question,
            confirmLabel: 'Continue',
            danger: /delete|remove|permanent/i.test(e.detail.question),
        }).then(function (ok) { if (ok) e.detail.issueRequest(true); });
    });

    // Rule modal > Actions > Move: confirm dialog, then POST to the promotion API.
    // Copying (delete_source off) keeps the source live and links the two rows; ticking it
    // is a true move (today's promote/demote), same one action either way.
    window.showMoveDialog = function (ruleId, ruleName, siemId, space, deleteSourceDefault, targets) {
        var host = document.getElementById('modal-container');
        if (!host) return;
        var overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.onclick = function (e) { if (e.target === overlay) overlay.remove(); };
        var options = (targets || []).map(function (t) {
            return '<option value="' + t.siem_id + '|' + t.space + '">' + (t.name || t.label) + '</option>';
        }).join('');
        overlay.innerHTML =
            '<div name="Move Rule Modal" class="modal-content modal-sm" onclick="event.stopPropagation()">' +
            '<h2 class="modal-section-title">Move rule</h2>' +
            '<p class="text-secondary mb-md">Move <strong>' + ruleName + '</strong> to another linked destination.</p>' +
            '<label class="form-label" style="font-size:0.78rem;">Target</label>' +
            '<select name="target_scope" class="form-input mb-md" data-move-target>' + options + '</select>' +
            '<label style="display:flex;align-items:center;gap:0.5rem;margin-bottom:1rem;">' +
            '<input type="checkbox" name="delete_source"' + (deleteSourceDefault ? ' checked' : '') + ' data-move-delete> Delete source after move</label>' +
            '<p class="text-muted mb-md" style="font-size:0.78rem;">Unticked, this is a copy: the source stays live and the two rows are linked (see the Linked panel).</p>' +
            '<div class="inline-error mb-md" data-move-error hidden></div>' +
            '<div class="modal-actions">' +
            '<button name="Cancel" type="button" class="btn btn-secondary" data-move-cancel>Cancel</button>' +
            '<button name="Move" type="button" class="btn btn-primary" data-move-go>Move</button>' +
            '</div></div>';
        overlay.querySelector('[data-move-cancel]').onclick = function () { overlay.remove(); };
        var err = overlay.querySelector('[data-move-error]');
        // A refused move is the common case worth designing for (moving onto a destination that
        // already holds this rule id is refused so it can't silently overwrite), and its message
        // explains what to do instead. It belongs next to the target picker the user has to
        // change, not in a toast behind this dialog — which is where it used to go.
        var showError = function (text) {
            err.textContent = text;
            err.hidden = false;
            err.scrollIntoView({ block: 'nearest' });
        };
        var go = overlay.querySelector('[data-move-go]');
        go.onclick = function () {
            var target = overlay.querySelector('[data-move-target]').value;
            if (!target) return;
            err.hidden = true;
            go.disabled = true;
            go.textContent = 'Moving...';
            var body = new URLSearchParams();
            body.set('target_scope', target);
            body.set('delete_source', overlay.querySelector('[data-move-delete]').checked ? 'true' : 'false');
            var url = '/api/promotion/' + encodeURIComponent(ruleId) + '/move?siem_id=' + encodeURIComponent(siemId) + '&space=' + encodeURIComponent(space);
            fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() })
                .then(function (r) { return r.text().then(function (html) { return { ok: r.ok, html: html }; }); })
                .then(function (res) {
                    if (res.ok) {
                        var toasts = document.getElementById('toast-container');
                        if (toasts) toasts.insertAdjacentHTML('beforeend', res.html);
                        document.querySelectorAll('#modal-container .modal-overlay').forEach(function (o) { o.remove(); });
                        setTimeout(function () { window.location.reload(); }, 1200);
                    } else {
                        // The body is the server's toast markup; read its text so the reason
                        // shows in the dialog rather than behind it.
                        var tmp = document.createElement('div');
                        tmp.innerHTML = res.html;
                        showError((tmp.textContent || '').trim() || 'The move could not be completed.');
                        go.disabled = false;
                        go.textContent = 'Move';
                    }
                })
                .catch(function (e) {
                    go.disabled = false;
                    go.textContent = 'Move';
                    showError('Error: ' + e.message);
                });
        };
        host.appendChild(overlay);
    };

    // Delete (rule window). Deleting from TIDE alone needs no second confirm: if the rule still
    // exists in Elastic the next sync brings it straight back, so nothing is lost. Ticking "also
    // delete from Elastic" is the irreversible part, and only that asks again. A deprecated rule
    // is already gone from Elastic, so it gets no Elastic option at all.
    window.showDeleteRuleDialog = function (ruleId, ruleName, siemId, space, destName, deprecated) {
        var host = document.getElementById('modal-container');
        if (!host) return;
        var esc = function (s) { var d = document.createElement('div'); d.textContent = s == null ? '' : String(s); return d.innerHTML; };
        var dest = destName || space;
        var overlay = document.createElement('div');
        overlay.className = 'modal-overlay';
        overlay.onclick = function (e) { if (e.target === overlay) overlay.remove(); };
        overlay.innerHTML =
            '<div name="Delete Rule Modal" class="modal-content modal-sm" onclick="event.stopPropagation()">' +
            '<h2 class="modal-section-title">Delete rule</h2>' +
            '<p class="text-secondary mb-md">Remove <strong>' + esc(ruleName) + '</strong> from TIDE.' +
            (deprecated ? '' : ' If it is still in Elastic, the next sync brings it back unless you delete it there too.') + '</p>' +
            (deprecated ? '' :
                '<label style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;">' +
                '<input type="checkbox" data-delete-elastic> Also delete it from Elastic (' + esc(dest) + ')</label>') +
            '<label style="display:flex;align-items:center;gap:0.5rem;margin-bottom:1rem;">' +
            '<input type="checkbox" checked data-delete-links> Also remove any links to this rule</label>' +
            '<p class="inline-error" data-delete-error hidden></p>' +
            '<div class="modal-actions">' +
            '<button name="Cancel" type="button" class="btn btn-secondary" data-delete-cancel>Cancel</button>' +
            '<button name="Delete" type="button" class="btn btn-danger" data-delete-go>Delete</button>' +
            '</div></div>';
        overlay.querySelector('[data-delete-cancel]').onclick = function () { overlay.remove(); };
        var err = overlay.querySelector('[data-delete-error]');
        var go = overlay.querySelector('[data-delete-go]');
        var reset = function () { go.disabled = false; go.textContent = 'Delete'; };
        var run = function (fromElastic, removeLinks) {
            go.disabled = true;
            go.textContent = 'Deleting...';
            err.hidden = true;
            var url = '/api/rules/' + encodeURIComponent(ruleId) + '?siem_id=' + encodeURIComponent(siemId) +
                      '&space=' + encodeURIComponent(space) + '&remove_links=' + (removeLinks ? 'true' : 'false') +
                      '&from_elastic=' + (fromElastic ? 'true' : 'false');
            fetch(url, { method: 'DELETE' })
                .then(function (r) { return r.text().then(function (t) { return { ok: r.ok, text: t }; }); })
                .then(function (res) {
                    if (res.ok) {
                        document.querySelectorAll('#modal-container .modal-overlay').forEach(function (o) { o.remove(); });
                        if (typeof showToast === 'function') {
                            showToast(fromElastic ? 'Rule deleted from Elastic and TIDE.' : 'Rule deleted from TIDE.', 'success');
                        }
                        if (window.htmx) htmx.trigger(document.body, 'refreshRules');
                        return;
                    }
                    // Say why next to the button, not in a toast behind this dialog.
                    var tmp = document.createElement('div');
                    tmp.innerHTML = res.text;
                    err.textContent = (tmp.textContent || '').trim() || 'The rule could not be deleted.';
                    err.hidden = false;
                    reset();
                })
                .catch(function (e) {
                    err.textContent = 'Error: ' + e.message;
                    err.hidden = false;
                    reset();
                });
        };
        go.onclick = function () {
            var elasticBox = overlay.querySelector('[data-delete-elastic]');
            var fromElastic = !!(elasticBox && elasticBox.checked);
            var removeLinks = overlay.querySelector('[data-delete-links]').checked;
            if (!fromElastic) { run(false, removeLinks); return; }
            window.tideConfirm({
                title: 'Delete from Elastic',
                body: '<p class="mb-md"><strong>' + esc(ruleName) + '</strong> is permanently deleted from ' +
                      '<strong>' + esc(dest) + '</strong> in Elastic, and from TIDE.</p>' +
                      '<p class="inline-error">This cannot be undone. The rule stops alerting immediately.</p>',
                confirmLabel: 'Delete from Elastic',
                danger: true,
            }).then(function (ok) { if (ok) run(true, removeLinks); });
        };
        host.appendChild(overlay);
    };

    // Add-link search results (rule_modal.html): clicking a match fills the name box with the
    // exact name (so the exact-match lookup on submit succeeds) and closes the dropdown.
    window.tidePickLinkTarget = function (btn) {
        var results = btn.closest('.rm-add-link__results');
        var input = results && results.parentElement && results.parentElement.querySelector('input[name="target_name"]');
        if (input) input.value = btn.dataset.name;
        if (results) results.innerHTML = '';
    };
    document.addEventListener('click', function (e) {
        document.querySelectorAll('.rm-add-link__results').forEach(function (r) {
            if (!r.contains(e.target) && e.target.name !== 'target_name') r.innerHTML = '';
        });
    });

    // Merge button (rule_migration_diff.html), wired as a plain onclick attribute rather than a
    // per-render <script> block with addEventListener -- a <script> tag only runs when the
    // fragment containing it is inserted via htmx's own swap (which specifically re-executes
    // script tags) or a real page load; a plain `el.innerHTML = html` assignment, like
    // tideSwitchCompareTarget below uses to switch which linked rule you're comparing against,
    // never executes embedded scripts at all. That silently left the Merge button dead after
    // switching targets. An onclick attribute has no such dependency -- it's wired by the
    // browser's own HTML parser the moment the element exists, however it got there.
    window.tideMergeLinked = function (root) {
        var direction = (document.querySelector('input[name="rm-merge-direction"]:checked') || {}).value || 'source_over_target';
        var deleteWhich = (document.querySelector('input[name="rm-merge-delete"]:checked') || {}).value || 'none';
        var sourceName = root.dataset.sourceName, targetName = root.dataset.targetName;
        var winner = direction === 'source_over_target' ? sourceName : targetName;
        var loser = direction === 'source_over_target' ? targetName : sourceName;
        var esc = function (s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; };
        var body = '<p class="mb-md"><strong>' + esc(loser) + '</strong> will be overwritten with the content of <strong>' +
                   esc(winner) + '</strong>. Its own enabled/disabled state is kept.</p>';
        var doomed = deleteWhich === 'source' ? sourceName : (deleteWhich === 'target' ? targetName : null);
        if (doomed) {
            body += '<p class="inline-error"><strong>' + esc(doomed) +
                    '</strong> is then permanently deleted — from its SIEM as well as TIDE. This cannot be undone.</p>';
        }
        window.tideConfirm({
            title: doomed ? 'Merge and delete' : 'Merge rules',
            body: body,
            confirmLabel: doomed ? 'Merge and delete' : 'Merge',
            danger: !!doomed,
        }).then(function (ok) { if (ok) tideRunMerge(root, direction, deleteWhich); });
    };

    function tideRunMerge(root, direction, deleteWhich) {
        root.disabled = true;
        root.textContent = 'Merging...';
        var qs = 'siem_id=' + encodeURIComponent(root.dataset.siemId) + '&space=' + encodeURIComponent(root.dataset.space) +
                 '&target_rule_id=' + encodeURIComponent(root.dataset.targetRuleId) +
                 '&target_siem_id=' + encodeURIComponent(root.dataset.targetSiemId) +
                 '&target_space=' + encodeURIComponent(root.dataset.targetSpace);
        var body = new URLSearchParams({ direction: direction, delete_which: deleteWhich });
        fetch('/api/promotion/' + encodeURIComponent(root.dataset.ruleId) + '/merge?' + qs, {
            method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(),
        })
            .then(function (r) { return r.text().then(function (html) { return { ok: r.ok, html: html }; }); })
            .then(function (res) {
                var host = document.getElementById('modal-container');
                if (host) host.innerHTML = res.html;
                if (window.htmx && host) htmx.process(host);
                if (res.ok && window.htmx) htmx.trigger(document.body, 'refreshRules');
            })
            .catch(function (err) {
                root.disabled = false;
                root.textContent = 'Merge';
                if (typeof showToast === 'function') showToast('Error: ' + err.message, 'error');
            });
    }

    // Compare view's "Comparing against" dropdown (rule_migration_diff.html): re-fetches the
    // whole diff view against a different linked rule, without closing and reopening Compare.
    window.tideSwitchCompareTarget = function (ruleId, siemId, space, targetValue) {
        var parts = (targetValue || '').split('|');
        if (parts.length !== 3) return;
        var host = document.getElementById('modal-container');
        var url = '/api/promotion/' + encodeURIComponent(ruleId) + '/diff?siem_id=' + encodeURIComponent(siemId) +
                  '&space=' + encodeURIComponent(space) +
                  '&target_rule_id=' + encodeURIComponent(parts[0]) +
                  '&target_siem_id=' + encodeURIComponent(parts[1]) +
                  '&target_space=' + encodeURIComponent(parts[2]);
        fetch(url, { method: 'GET' })
            .then(function (r) { return r.text(); })
            .then(function (html) { if (host) { host.innerHTML = html; if (window.htmx) htmx.process(host); } })
            .catch(function (err) {
                if (typeof showToast === 'function') showToast('Error: ' + err.message, 'error');
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
