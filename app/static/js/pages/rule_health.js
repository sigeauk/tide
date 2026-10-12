/*
 * Rule Health (pages/rules/rule_health.html): the filter bar (dropdown labels, "last selected wins"
 * sorts, cards / table view), the address bar kept in step with the grid, the table view's columns
 * (resize, choose, arrange), the "…" menu, gutter alignment and bulk edit.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }
    function onPage() { return !!$('rules-grid'); }

    // ── Filter bar ──
    // Close sync/filter dropdowns on outside click
    document.addEventListener('click', function (e) {
        if (!onPage()) return;
        document.querySelectorAll('.sync-dropdown, .tide-filter-dropdown').forEach(function (d) {
            if (!d.parentElement.contains(e.target)) d.style.display = 'none';
        });
    });

    // "Last selected wins" for the three sort selects: clearing the siblings in the CAPTURE phase
    // runs before htmx's own (bubble-phase) change listener reads them via hx-include, so only the
    // just-changed one is sent as active.
    var SORT_IDS = ['rh-sort-score', 'rh-sort-validated', 'rh-sort-name'];
    document.addEventListener('change', function (e) {
        if (SORT_IDS.indexOf(e.target.id) === -1) return;
        var col = $('rh-sort-col'), dir = $('rh-sort-dir');
        if (col) col.value = '';
        if (dir) dir.value = '';
        SORT_IDS.forEach(function (id) {
            var el = $(id);
            if (el && el !== e.target) el.value = '';
        });
    }, true);

    // Each dropdown button's label follows its filters.
    function updateStateLabel() {
        var label = $('rh-state-label');
        if (!label) return;
        var checked = Array.prototype.slice.call(document.querySelectorAll("#rh-state-dropdown input[name='state']:checked"));
        label.textContent = checked.length
            ? checked.map(function (c) { return c.nextElementSibling ? c.nextElementSibling.textContent : c.value; }).join(', ')
            : 'All states';
    }
    function updateScoreLabel() {
        var label = $('rh-score-label');
        if (!label) return;
        var sort = $('rh-sort-score').value;
        var min = document.querySelector("#rh-score-dropdown [name='min_score']").value;
        var max = document.querySelector("#rh-score-dropdown [name='max_score']").value;
        var parts = [];
        if (sort === 'desc') parts.push('High → Low');
        else if (sort === 'asc') parts.push('Low → High');
        if (min || max) parts.push((min || '0') + '–' + (max || '100'));
        label.textContent = parts.length ? parts.join(' · ') : 'Score';
    }
    function updateValidatedLabel() {
        var label = $('rh-validated-label');
        if (!label) return;
        var sort = $('rh-sort-validated').value;
        var from = document.querySelector("#rh-validated-dropdown [name='validated_from']").value;
        var to = document.querySelector("#rh-validated-dropdown [name='validated_to']").value;
        var parts = [];
        if (sort === 'desc') parts.push('Newest → Oldest');
        else if (sort === 'asc') parts.push('Oldest → Newest');
        if (from || to) parts.push((from || '…') + ' – ' + (to || '…'));
        label.textContent = parts.length ? parts.join(' · ') : 'Validate';
    }
    document.addEventListener('change', function (e) {
        if (!e.target.matches) return;
        if (e.target.matches("#rh-state-dropdown input[name='state']")) updateStateLabel();
        if (e.target.closest('#rh-score-dropdown')) updateScoreLabel();
        if (e.target.closest('#rh-validated-dropdown')) updateValidatedLabel();
    });

    // A rule card's own actions (validate, edit, sync, archive, restore) swap only that card, so
    // they don't get the grid's "rulesFiltered" trigger: refresh the metrics here (they carry their
    // own hx-include, so the active filters still apply). A page appended by infinite scroll is
    // not a change and doesn't count.
    document.addEventListener('htmx:afterSwap', function (event) {
        var path = (event.detail.pathInfo && event.detail.pathInfo.requestPath) || '';
        if (/[?&]append=true/.test(path)) return;
        var t = event.target, metrics = $('metrics-container');
        if (metrics && t.classList && (t.classList.contains('rule-card') || t.classList.contains('rule-row'))) {
            htmx.trigger(metrics, 'rulesFiltered');
        }
    });

    // Cards / table view: the choice rides along as the `view` filter (hidden input), is kept in
    // the URL, and is remembered per browser.
    function setPressed(view) {
        document.querySelectorAll('[data-rh-view]').forEach(function (btn) {
            btn.setAttribute('aria-pressed', btn.getAttribute('data-rh-view') === view ? 'true' : 'false');
        });
    }
    document.addEventListener('click', function (e) {
        var btn = e.target.closest && e.target.closest('[data-rh-view]'), input = $('rh-view');
        if (!btn || !input) return;
        var view = btn.getAttribute('data-rh-view');
        if (input.value === view) return;
        input.value = view;
        try { localStorage.setItem('tide.rulesView', view); } catch (_) { /* storage blocked */ }
        setPressed(view);
        htmx.trigger(document.body, 'refreshRules');
    });

    // Table view: a sortable header. Score / rule / validated drive the filter bar's sort selects;
    // SIEM / state / severity / author / lang use the table-only sort_col + sort_dir. Either way
    // the latest choice wins and the other sorts are cleared.
    document.addEventListener('click', function (e) {
        var th = e.target.closest && e.target.closest('.rt-th--sortable');
        if (!th) return;
        var def = th.getAttribute('data-sort-default'), col = th.getAttribute('data-sort-col');
        var colInput = $('rh-sort-col'), dirInput = $('rh-sort-dir');
        if (col) {
            dirInput.value = colInput.value === col ? (dirInput.value === 'asc' ? 'desc' : 'asc') : def;
            colInput.value = col;
            SORT_IDS.forEach(function (id) { var el = $(id); if (el) el.value = ''; });
            updateScoreLabel();
            updateValidatedLabel();
            htmx.trigger(document.body, 'refreshRules');
            return;
        }
        var select = $(th.getAttribute('data-sort-select'));
        if (!select) return;
        select.value = (select.value === def) ? (def === 'desc' ? 'asc' : 'desc') : def;
        select.dispatchEvent(new Event('change', { bubbles: true }));   // the capture handler clears sort_col + siblings
    });

    // A sync finished (HX-Trigger from /api/sync/status): the metrics too (the grid has refreshRules).
    document.addEventListener('syncComplete', function () {
        if ($('metrics-container')) htmx.ajax('GET', '/api/rules/metrics', { target: '#metrics-container', swap: 'innerHTML' });
    });
    // Import validation file finished (HX-Trigger): close and clear its dialog.
    document.addEventListener('validationImported', function () {
        var modal = $('import-validation-modal'), form = $('import-validation-form');
        if (modal) modal.style.display = 'none';
        if (form) form.reset();
    });

    // Keep the address bar (so a refresh) in step with the grid's last filters and page.
    document.addEventListener('htmx:afterRequest', function (event) {
        if (!event.detail.successful || !event.detail.target || event.detail.target.id !== 'rules-grid') return;
        var reqPath = event.detail.pathInfo && (event.detail.pathInfo.finalRequestPath || event.detail.pathInfo.requestPath);
        if (reqPath && reqPath.indexOf('/api/rules') === 0) {
            window.history.replaceState(null, '', '/rules' + reqPath.slice('/api/rules'.length));
        }
    });

    // Toasts swapped into the toast container fade after 5 s.
    document.addEventListener('htmx:afterSwap', function (event) {
        if (!onPage() || event.detail.target.id !== 'toast-container') return;
        event.detail.target.querySelectorAll('.toast').forEach(function (toast) {
            setTimeout(function () {
                toast.style.opacity = '0';
                setTimeout(function () { toast.remove(); }, 300);
            }, 5000);
        });
    });

    // ── Table view: resize neighbouring columns, choose and arrange columns ──
    // The table is always full width. Dragging the edge between two columns moves width from one
    // to the other and nothing else changes. The "..." at the end of the header opens a list of
    // every column: untick to hide one, use the arrows to move it (top of the list = leftmost).
    // The layout (order, hidden columns, each column's share of the width) is kept per browser.
    var LS_KEY = 'tide.rulesTable.layout.v2';
    var MIN_W = 48;
    var COLUMNS = [
        ['score', 'Score'], ['name', 'Rule'], ['siem', 'SIEM'], ['state', 'State'], ['severity', 'Severity'],
        ['validated', 'Validated'], ['author', 'Author'], ['mitre', 'MITRE'], ['lang', 'Lang'],
    ];
    var TITLES = {};
    COLUMNS.forEach(function (c) { TITLES[c[0]] = c[1]; });
    var DEFAULT_ORDER = COLUMNS.map(function (c) { return c[0]; });
    var FIXED = { check: true, cols: true };     // the checkbox column and the "..." column are not user-arranged

    function table() { return document.querySelector('.rules-table'); }
    function load() {
        try {
            var v = JSON.parse(localStorage.getItem(LS_KEY) || 'null');
            return v && typeof v === 'object' ? v : {};
        } catch (_) { return {}; }
    }
    function save(l) {
        try { localStorage.setItem(LS_KEY, JSON.stringify(l)); } catch (_) { /* storage blocked */ }
    }
    function domOrder(t) {
        return Array.prototype.map.call(t.querySelectorAll('thead th[data-col]'), function (th) { return th.dataset.col; })
            .filter(function (c) { return !FIXED[c]; });
    }
    // The saved order, reconciled with the columns that actually exist.
    function fullOrder(t, l) {
        var have = domOrder(t);
        var order = (Array.isArray(l.order) ? l.order : DEFAULT_ORDER).filter(function (c) { return have.indexOf(c) !== -1; });
        have.forEach(function (c) { if (order.indexOf(c) === -1) order.push(c); });
        return order;
    }
    function hiddenSet(l) { return Array.isArray(l.hidden) ? l.hidden : []; }
    function visibleOrder(t, l) {
        var hid = hiddenSet(l);
        return fullOrder(t, l).filter(function (c) { return hid.indexOf(c) === -1; });
    }
    function headOf(t, col) { return t.querySelector('thead th[data-col="' + col + '"]'); }

    // Put every row's cells in order, hide the hidden columns. Rows with no column cells
    // (loading / end-of-list rows) are left alone. The checkbox column is first, "..." last.
    function applyOrderAndVisibility(t, l) {
        var order = fullOrder(t, l), hid = hiddenSet(l);
        var want = ['check'].concat(order, ['cols']);
        Array.prototype.forEach.call(t.querySelectorAll('tr'), function (tr) {
            var cells = {};
            Array.prototype.forEach.call(tr.children, function (c) { if (c.dataset && c.dataset.col) cells[c.dataset.col] = c; });
            if (!cells.score && !cells.name) return;
            var seq = want.filter(function (c) { return cells[c]; });
            var have = Array.prototype.map.call(tr.children, function (c) { return c.dataset && c.dataset.col; });
            if (!(have.length === seq.length && have.every(function (c, i) { return c === seq[i]; }))) {
                seq.forEach(function (c) { tr.appendChild(cells[c]); });
            }
            order.forEach(function (c) {
                if (cells[c]) cells[c].style.display = hid.indexOf(c) === -1 ? '' : 'none';
            });
        });
    }

    function refreshHandles(t, l) {
        Array.prototype.forEach.call(t.querySelectorAll('.rt-resize'), function (h) { h.remove(); });
        var vis = visibleOrder(t, l);
        vis.forEach(function (col, i) {
            if (i === vis.length - 1) return;   // the last visible column has no right neighbour to trade with
            var th = headOf(t, col);
            if (!th) return;
            var h = document.createElement('span');
            h.className = 'rt-resize';
            h.setAttribute('role', 'separator');
            h.setAttribute('aria-orientation', 'vertical');
            h.title = 'Drag to resize this column and the next one. Double-click to reset the table layout.';
            th.appendChild(h);
        });
    }

    function fixedWidth(t) {
        var w = 0;
        ['check', 'cols'].forEach(function (c) {
            var th = headOf(t, c);
            if (th) w += th.getBoundingClientRect().width;
        });
        return w;
    }
    function applyWidths(t, l) {
        var vis = visibleOrder(t, l), frac = l.frac;
        Array.prototype.forEach.call(t.querySelectorAll('thead th[data-col]'), function (th) {
            if (!FIXED[th.dataset.col]) th.style.width = '';
        });
        if (!frac || !vis.every(function (c) { return frac[c] > 0; })) return;
        var avail = t.getBoundingClientRect().width - fixedWidth(t);
        if (avail <= 0) return;
        var total = 0;
        vis.forEach(function (c) { total += frac[c]; });
        var used = 0;
        vis.forEach(function (c, i) {
            var px = i === vis.length - 1 ? avail - used : Math.round(frac[c] / total * avail);
            headOf(t, c).style.width = Math.max(MIN_W, px) + 'px';
            used += px;
        });
    }

    // The "Loading more..." and "All rules loaded" rows span the whole table. If they span more
    // columns than are shown (a hidden column, or the checkbox column while bulk edit is off) the
    // browser invents empty columns and hands them part of the width. Span exactly the shown ones.
    function syncSpans(t) {
        var shown = Array.prototype.filter.call(t.querySelectorAll('thead th[data-col]'), function (th) {
            return getComputedStyle(th).display !== 'none';
        }).length;
        if (!shown) return;
        Array.prototype.forEach.call(t.querySelectorAll('tr.infinite-scroll-sentinel > td, tr.infinite-scroll-end > td'), function (td) {
            if (td.colSpan !== shown) td.colSpan = shown;
        });
    }

    function applyTable() {
        var t = table();
        if (!t) return;
        var l = load();
        applyOrderAndVisibility(t, l);
        syncSpans(t);
        refreshHandles(t, l);
        applyWidths(t, l);
    }
    function resetTable() {
        try { localStorage.removeItem(LS_KEY); } catch (_) { /* storage blocked */ }
        closeColMenu();
        applyTable();
    }

    // Resize: the edge belongs to a column and its right-hand visible neighbour.
    document.addEventListener('pointerdown', function (e) {
        var h = e.target.closest && e.target.closest('.rt-resize');
        if (!h) return;
        e.preventDefault();
        e.stopPropagation();
        var t = table(), l = load(), vis = visibleOrder(t, l), th = h.parentElement;
        var i = vis.indexOf(th.dataset.col), next = i === -1 ? null : headOf(t, vis[i + 1]);
        if (!next) return;
        var w = {};
        vis.forEach(function (c) { w[c] = headOf(t, c).getBoundingClientRect().width; });
        var a = th.dataset.col, b = next.dataset.col, startA = w[a], startB = w[b], startX = e.clientX;
        h.setPointerCapture(e.pointerId);
        h.classList.add('is-active');
        document.body.classList.add('rt-resizing');
        function move(ev) {
            var dx = Math.max(MIN_W - startA, Math.min(startB - MIN_W, ev.clientX - startX));
            w[a] = startA + dx;
            w[b] = startB - dx;
            th.style.width = Math.round(w[a]) + 'px';
            next.style.width = Math.round(w[b]) + 'px';
        }
        function up() {
            h.removeEventListener('pointermove', move);
            h.removeEventListener('pointerup', up);
            h.classList.remove('is-active');
            document.body.classList.remove('rt-resizing');
            var total = 0, frac = {};
            vis.forEach(function (c) { total += w[c]; });
            vis.forEach(function (c) { frac[c] = w[c] / total; });
            var cur = load();
            cur.frac = frac;
            save(cur);
            applyWidths(t, cur);   // absorb rounding so the table stays exactly full width
        }
        h.addEventListener('pointermove', move);
        h.addEventListener('pointerup', up);
    });
    // Letting go of a resize drag must not count as a click on the header (that would re-sort).
    window.addEventListener('click', function (e) {
        if (e.target.closest && e.target.closest('.rt-resize')) { e.stopPropagation(); e.preventDefault(); }
    }, true);
    document.addEventListener('dblclick', function (e) {
        if (e.target.closest && e.target.closest('.rt-resize')) resetTable();
    });

    // Column chooser ("..." at the end of the header)
    var colMenu = null;
    function closeColMenu() {
        if (colMenu) { colMenu.remove(); colMenu = null; }
        var btn = $('rt-cols-btn');
        if (btn) btn.setAttribute('aria-expanded', 'false');
    }
    function persist(t, l, widthsChanged) {
        if (widthsChanged) delete l.frac;     // a different set of visible columns starts from default widths
        save(l);
        applyTable();
        buildColList();
    }
    function buildColList() {
        if (!colMenu) return;
        var t = table();
        if (!t) { closeColMenu(); return; }
        var l = load(), order = fullOrder(t, l), hid = hiddenSet(l);
        var ul = colMenu.querySelector('ul');
        ul.innerHTML = '';
        order.forEach(function (col, i) {
            var li = document.createElement('li');
            var label = document.createElement('label');
            var box = document.createElement('input');
            box.type = 'checkbox';
            box.checked = hid.indexOf(col) === -1;
            // At least one column stays visible.
            box.disabled = box.checked && order.length - hid.length <= 1;
            box.addEventListener('change', function () {
                var cur = load();
                var hidden = hiddenSet(cur).filter(function (c) { return c !== col; });
                if (!box.checked) hidden.push(col);
                cur.hidden = hidden;
                cur.order = fullOrder(t, cur);
                persist(t, cur, true);
            });
            label.appendChild(box);
            label.appendChild(document.createTextNode(TITLES[col] || col));
            li.appendChild(label);

            var move = document.createElement('span');
            move.className = 'rt-colmenu__move';
            [['up', '▲', -1, 'Move ' + (TITLES[col] || col) + ' left'], ['down', '▼', 1, 'Move ' + (TITLES[col] || col) + ' right']]
                .forEach(function (d) {
                    var b = document.createElement('button');
                    b.type = 'button';
                    b.textContent = d[1];
                    b.title = d[3];
                    b.setAttribute('aria-label', d[3]);
                    b.disabled = (d[2] < 0 && i === 0) || (d[2] > 0 && i === order.length - 1);
                    b.addEventListener('click', function () {
                        var cur = load(), o = fullOrder(t, cur), at = o.indexOf(col), to = at + d[2];
                        if (to < 0 || to >= o.length) return;
                        o.splice(to, 0, o.splice(at, 1)[0]);
                        cur.order = o;
                        persist(t, cur, false);
                    });
                    move.appendChild(b);
                });
            li.appendChild(move);
            ul.appendChild(li);
        });
    }
    function openColMenu(btn) {
        closeColMenu();
        colMenu = document.createElement('div');
        colMenu.className = 'rt-colmenu';
        colMenu.setAttribute('role', 'dialog');
        colMenu.setAttribute('aria-label', 'Choose table columns');
        colMenu.innerHTML = '<div class="rt-colmenu__title">Columns (top = left)</div><ul></ul>' +
            '<button type="button" class="btn btn-secondary btn-sm rt-colmenu__reset">Reset columns</button>';
        colMenu.querySelector('.rt-colmenu__reset').addEventListener('click', resetTable);
        document.body.appendChild(colMenu);
        // Fixed position under the button, kept inside the viewport.
        var r = btn.getBoundingClientRect(), w = colMenu.offsetWidth;
        colMenu.style.top = Math.round(r.bottom + 4) + 'px';
        colMenu.style.left = Math.round(Math.max(8, Math.min(r.right - w, window.innerWidth - w - 8))) + 'px';
        btn.setAttribute('aria-expanded', 'true');
        buildColList();
    }
    document.addEventListener('click', function (e) {
        var btn = e.target.closest && e.target.closest('#rt-cols-btn');
        if (btn) {
            e.stopPropagation();
            if (colMenu) closeColMenu(); else openColMenu(btn);
            return;
        }
        if (colMenu && !colMenu.contains(e.target)) closeColMenu();
    });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeColMenu(); });

    // Keep the table full width when the window or the scroll region changes size.
    var raf = 0;
    function relayout() {
        cancelAnimationFrame(raf);
        raf = requestAnimationFrame(function () { var t = table(); if (t) applyWidths(t, load()); });
    }
    window.addEventListener('resize', relayout);
    // A grid reload replaces the table, and infinite scroll adds rows: re-apply to both.
    document.addEventListener('htmx:afterSettle', function () { closeColMenu(); applyTable(); });

    TIDE.page('.rule-browser-page', function (page) {
        // Filter bar labels, view toggle, and the offline notice (data-offline-notice)
        updateScoreLabel();
        updateValidatedLabel();
        var viewInput = $('rh-view');
        if (viewInput) {
            if (!viewInput.value) {
                var stored = 'cards';
                try { stored = localStorage.getItem('tide.rulesView') || 'cards'; } catch (_) { /* storage blocked */ }
                viewInput.value = stored === 'table' ? 'table' : 'cards';
            }
            setPressed(viewInput.value);
        }
        if (page.dataset.offlineNotice && window.showToast) window.showToast(page.dataset.offlineNotice, 'warning', 10000);

        // Table columns
        var resetBtn = $('rh-reset-layout');
        if (resetBtn) resetBtn.addEventListener('click', resetTable);
        var region = page.querySelector('.rule-scroll-region');
        // The scroll area moves under a fixed popover; close it rather than let it float.
        if (region) region.addEventListener('scroll', closeColMenu, { passive: true });
        if (window.ResizeObserver && region) new ResizeObserver(relayout).observe(region);
        applyTable();

        initPageMenuAndBulk(page, region);
    });

    // ── "..." actions menu, gutter alignment, bulk edit ──
    // Listeners on document belong to this page; once it is gone (another page was opened) they stop.
    function initPageMenuAndBulk(page, region) {
        function live(fn) { return function (e) { if (page.isConnected) fn(e); }; }

        var moreBtn = $('rh-more-btn'), moreMenu = $('rh-more-menu');
        function closeMenu() {
            if (!moreMenu || moreMenu.hidden) return;
            moreMenu.hidden = true;
            moreBtn.setAttribute('aria-expanded', 'false');
        }
        if (moreBtn && moreMenu) {
            moreBtn.addEventListener('click', function (e) {
                e.stopPropagation();
                var open = moreMenu.hidden;
                moreMenu.hidden = !open;
                moreBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
            });
            document.addEventListener('click', live(function (e) { if (!moreMenu.contains(e.target)) closeMenu(); }));
            document.addEventListener('keydown', live(function (e) { if (e.key === 'Escape') closeMenu(); }));
            moreMenu.addEventListener('click', function (e) {
                // Picking any item closes the menu (the sync spinner shows in the page header).
                if (e.target.closest('.rh-more__item')) setTimeout(closeMenu, 0);
            });
        }

        // Cards are exactly as wide as the metrics and filters above them: the scroll region
        // reserves a scrollbar gutter, and the controls take the same inset.
        function measureGutter() {
            if (!region) return;
            page.style.setProperty('--rh-gutter', Math.max(0, region.offsetWidth - region.clientWidth) + 'px');
        }
        measureGutter();
        window.addEventListener('resize', live(measureGutter));

        var bar = $('bulk-bar'), toggle = $('bulk-edit-toggle');
        var selected = new Map();      // "rule_id|siem_id|space" -> {rule_id, siem_id, space, state}
        var matching = null;           // keys matching the filters, from the last "select all"
        var busy = false;

        function isOn() { return page.classList.contains('bulk-on'); }
        function itemOf(cb) {
            return { rule_id: cb.dataset.ruleId, siem_id: cb.dataset.siemId, space: cb.dataset.space, state: cb.dataset.state };
        }
        function toast(msg, kind) { if (typeof showToast === 'function') showToast(msg, kind || 'error'); }

        function refresh() {
            if (!bar) return;
            document.querySelectorAll('input[data-bulk-check]').forEach(function (cb) {
                var on = selected.has(cb.dataset.key);
                cb.checked = on;
                var host = cb.closest('.rule-card, .rule-row');
                if (host) {
                    host.classList.toggle('rule-card--selected', on && host.classList.contains('rule-card'));
                    host.classList.toggle('rule-row--selected', on && host.classList.contains('rule-row'));
                }
            });
            var n = selected.size;
            $('bulk-count').textContent = n + ' selected';
            // Any selected rule can take any action.
            bar.querySelectorAll('[data-bulk-action]').forEach(function (b) { b.disabled = n === 0; });
            $('bulk-hint').textContent = '';
            // The header box (table) and the bar box (cards and table) always agree.
            var full = !!matching && matching.size > 0 && Array.from(matching).every(function (k) { return selected.has(k); });
            ['bulk-select-all', 'bulk-bar-all'].forEach(function (id) {
                var box = $(id);
                if (!box) return;
                box.checked = full;
                box.indeterminate = !full && n > 0;
            });
        }

        function setBulk(on) {
            page.classList.toggle('bulk-on', on);
            if (bar) bar.hidden = !on;
            if (toggle) {
                toggle.setAttribute('aria-pressed', on ? 'true' : 'false');
                var label = toggle.querySelector('[data-bulk-toggle-label]');
                if (label) label.textContent = on ? 'Exit bulk edit' : 'Bulk edit';
            }
            if (!on) { selected.clear(); matching = null; }
            refresh();
            applyTable();   // the checkbox column comes and goes
            measureGutter();
        }
        if (toggle && bar) {
            toggle.addEventListener('click', function () { setBulk(!isOn()); });
            $('bulk-exit').addEventListener('click', function () { setBulk(false); });
        }

        // Select all = every rule matching the current filters (all pages), decided by the server.
        function filterQuery() {
            var vals = htmx.values($('bulk-filter-src')), qs = new URLSearchParams();
            Object.keys(vals).forEach(function (k) {
                [].concat(vals[k]).forEach(function (v) { if (v !== '' && v != null) qs.append(k, v); });
            });
            return qs;
        }
        function selectMatching(select) {
            if (busy) return;
            busy = true;
            fetch('/api/rules/bulk-edit/ids?' + filterQuery().toString(), { credentials: 'same-origin' })
                .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
                .then(function (list) {
                    var keys = list.map(function (it) { return it.rule_id + '|' + it.siem_id + '|' + it.space; });
                    matching = new Set(keys);
                    list.forEach(function (it, i) { if (select) selected.set(keys[i], it); else selected.delete(keys[i]); });
                    refresh();
                })
                .catch(function (err) { toast('Could not select all rules: ' + err.message); refresh(); })
                .finally(function () { busy = false; });
        }
        if (bar) $('bulk-clear').addEventListener('click', function () { selected.clear(); refresh(); });

        document.addEventListener('change', live(function (e) {
            var t = e.target;
            if (t.matches && t.matches('input[data-bulk-check]')) {
                if (t.checked) selected.set(t.dataset.key, itemOf(t)); else selected.delete(t.dataset.key);
                refresh();
            } else if (t.id === 'bulk-select-all' || t.id === 'bulk-bar-all') {
                selectMatching(t.checked);
            }
        }));

        // Actions: the server re-checks the selection and returns a confirm dialog.
        if (bar) bar.addEventListener('click', function (e) {
            var btn = e.target.closest && e.target.closest('[data-bulk-action]');
            if (!btn || btn.disabled) return;
            var items = Array.from(selected.values()).map(function (it) {
                return { rule_id: it.rule_id, siem_id: it.siem_id, space: it.space };
            });
            var body = new URLSearchParams({ action: btn.dataset.bulkAction, items: JSON.stringify(items) });
            fetch('/api/rules/bulk-edit/dialog', {
                method: 'POST', credentials: 'same-origin',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString(),
            })
                .then(function (r) { return r.text(); })
                .then(function (html) {
                    var box = $('modal-container');
                    box.innerHTML = html;
                    if (window.htmx) htmx.process(box);
                })
                .catch(function (err) { toast('Could not open the bulk dialog: ' + err.message); });
        });

        // A full grid reload (filters, sort, view) starts a fresh selection; pages appended by
        // infinite scroll do not, so their rows pick up the current selection.
        document.addEventListener('htmx:beforeSwap', live(function (e) {
            if (e.detail.target && e.detail.target.id === 'rules-grid') { selected.clear(); matching = null; }
        }));
        document.addEventListener('htmx:afterSettle', live(function () { refresh(); measureGutter(); }));
    }
})();
