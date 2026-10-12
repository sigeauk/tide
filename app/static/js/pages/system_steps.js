/*
 * A technique grid (a system's page, or the templates on the Baselines page;
 * partials/system_steps_filters.html + system_steps_grid.html): remembered choices, one refresh
 * event, the URL, a deep link. The filter bar (#sys-filters) says which grid: its data-pref-key,
 * data-base-path (the page), data-window-url (a technique's window, "{id}" for the technique),
 * data-url-keys (filters the URL set) and data-default-group.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }
    function bar() { return $('sys-filters'); }
    function windowUrl(id) { var b = bar(); return b ? b.getAttribute('data-window-url').replace('{id}', encodeURIComponent(id)) : ''; }

    // Remembered choices, applied before the grid first loads (its hx-trigger="load" reads them).
    function applyPrefs(b) {
        var fromUrl = (b.getAttribute('data-url-keys') || '').split(',');
        var p = {};
        try { p = JSON.parse(localStorage.getItem(b.getAttribute('data-pref-key')) || '{}') || {}; } catch (_) { /* storage blocked */ }
        if (fromUrl.indexOf('tactic_sort') === -1 && p.tactic_sort) $('sys-tactic-sort').value = p.tactic_sort;
        if (fromUrl.indexOf('sort_name') === -1 && typeof p.sort_name === 'string') $('sys-sort-name').value = p.sort_name;
        // Grouping: the URL's, else this browser's last, else the page's default (the Baselines
        // page groups by template, so an empty one still shows).
        var group = Array.isArray(p.group) ? p.group : (b.getAttribute('data-default-group') || '').split(',').filter(Boolean);
        if (fromUrl.indexOf('group') === -1 && (Array.isArray(p.group) || group.length)) {
            b.querySelectorAll('input[name="group"][type="checkbox"]').forEach(function (c) { c.checked = group.indexOf(c.value) !== -1; });
        }
        var view = $('sys-view');
        if (fromUrl.indexOf('view') === -1) view.value = p.view === 'table' ? 'table' : 'cards';
        if (!view.value) view.value = 'cards';
    }

    function savePrefs() {
        var b = bar();
        var p = {
            tactic_sort: $('sys-tactic-sort').value,
            sort_name: $('sys-sort-name').value,
            group: Array.prototype.map.call(b.querySelectorAll('input[name="group"][type="checkbox"]:checked'), function (c) { return c.value; }),
            view: $('sys-view').value || 'cards',
        };
        try { localStorage.setItem(b.getAttribute('data-pref-key'), JSON.stringify(p)); } catch (_) { /* storage blocked */ }
    }

    // Button labels follow their dropdowns.
    function updateLabels() {
        var b = bar();
        if (!b) return;
        var tSort = $('sys-tactic-sort'), shown = b.querySelectorAll('input[name="tactic"]:checked');
        var tLabel = shown.length === 1 ? shown[0].value : (shown.length ? shown.length + ' tactics' : 'All');
        $('sys-tactic-label').textContent = tLabel + (tSort.value === 'off' ? '' : ' · ' + tSort.options[tSort.selectedIndex].text);
        var status = $('sys-status'), mapping = $('sys-mapping');
        if (status && mapping) {   // a system's grid only: templates have no coverage
            var cParts = [];
            if (status.value) cParts.push(status.options[status.selectedIndex].text);
            if (mapping.value) cParts.push(mapping.options[mapping.selectedIndex].text);
            $('sys-coverage-label').textContent = cParts.length ? cParts.join(' · ') : 'Any';
        }
        var groups = Array.prototype.map.call(b.querySelectorAll('input[name="group"][type="checkbox"]:checked'), function (c) {
            return c.nextElementSibling ? c.nextElementSibling.textContent : c.value;
        });
        $('sys-group-label').textContent = groups.length ? groups.join(' › ') : 'None';
        var view = $('sys-view').value;
        b.querySelectorAll('[data-sys-view]').forEach(function (btn) {
            btn.setAttribute('aria-pressed', btn.getAttribute('data-sys-view') === view ? 'true' : 'false');
        });
    }

    function refresh() {
        updateLabels();
        savePrefs();
        if (window.htmx) htmx.trigger(document.body, 'sysFilter');
    }

    // Table headers sort the same way as the bar: technique = Name, tactic = Tactic sort.
    document.addEventListener('click', function (e) {
        var th = e.target.closest && e.target.closest('[data-sys-sort]');
        if (!th || !bar()) return;
        if (th.getAttribute('data-sys-sort') === 'name') {
            var n = $('sys-sort-name');
            n.value = n.value === 'asc' ? 'desc' : 'asc';
        } else {
            var t = $('sys-tactic-sort');
            t.value = t.value === 'attack' ? 'alpha' : 'attack';
        }
        refresh();
    });
    document.addEventListener('click', function (e) {
        document.querySelectorAll('#sys-filters .tide-filter-dropdown').forEach(function (d) {
            if (!d.parentElement.contains(e.target)) d.style.display = 'none';
        });
    });

    // The address bar mirrors the grid's filters (so a refresh or a shared link shows the same
    // thing), plus the open technique window if there is one.
    var gridQuery = '';
    document.addEventListener('htmx:afterRequest', function (e) {
        if (!e.detail.successful || !e.detail.target || e.detail.target.id !== 'system-steps-grid') return;
        var path = e.detail.pathInfo && (e.detail.pathInfo.finalRequestPath || e.detail.pathInfo.requestPath) || '';
        var i = path.indexOf('?');
        gridQuery = i === -1 ? '' : path.slice(i + 1);
        writeUrl();
    });
    function writeUrl() {
        var base = bar() ? bar().getAttribute('data-base-path') : '';   // the system, or the Baselines page
        if (!base || window.location.pathname !== base) return;
        var params = new URLSearchParams(gridQuery);
        params.delete('technique');
        // Only a technique of this grid: a rule's Covers can open another system's technique here.
        var m = document.querySelector('#modal-container .rule-modal[data-step-id]');
        if (m && $('step-' + m.getAttribute('data-step-id'))) params.set('technique', m.getAttribute('data-step-id'));
        var qs = params.toString();
        window.history.replaceState(window.history.state, '', base + (qs ? '?' + qs : ''));
    }

    TIDE.page('#sys-filters', function (b) {
        applyPrefs(b);
        updateLabels();
        var searchTimer = null;
        b.addEventListener('input', function (e) {
            if (e.target.name !== 'search') return;
            clearTimeout(searchTimer);
            searchTimer = setTimeout(refresh, 300);
        });
        b.addEventListener('change', function (e) { if (e.target.name !== 'search') refresh(); });
        b.addEventListener('click', function (e) {
            var btn = e.target.closest('[data-sys-view]');
            if (!btn) return;
            var input = $('sys-view');
            if (input.value === btn.getAttribute('data-sys-view')) return;
            input.value = btn.getAttribute('data-sys-view');
            refresh();
        });
        gridQuery = window.location.search.slice(1);   // until the grid answers
        TIDE.ready(function () {
            var host = $('modal-container');
            if (host) new MutationObserver(writeUrl).observe(host, { childList: true });
            // Deep link: ?technique=<step id> opens that technique's window.
            var t = new URLSearchParams(window.location.search).get('technique');
            if (t) htmx.ajax('GET', windowUrl(t), { target: '#modal-container', swap: 'innerHTML' });
        });
    });

    // A baseline group's Manage / Edit opens in the shared dialog without toggling the group.
    TIDE.action('steps.openDialog', function (e, el) {
        e.preventDefault();
        e.stopPropagation();
        htmx.ajax('GET', el.dataset.url, { target: '#modal-container', swap: 'innerHTML' });
    });
})();
