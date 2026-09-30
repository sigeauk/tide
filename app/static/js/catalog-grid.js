/* ══════════════════════════════════════════════════════════════════
 * MITRE catalogue pages (pages/mitre/catalog.html)
 *
 * One filter bar ([data-catalog-bar]) drives one grid (#catalog-grid): any change there refetches
 * the grid with the bar's inputs. Sort, direction, grouping and view are remembered per page in
 * this browser, unless the URL carries them. The address bar mirrors the grid's query, plus the
 * open window (?open=<id>), so a refresh or a shared link shows the same thing.
 *
 * Navigation is hx-boost: arriving swaps the body, so the bar is wired from htmx:load (and on a
 * full load) each visit; document-level listeners are installed once per tab.
 * ══════════════════════════════════════════════════════════════════ */
(function () {
    function bar() { return document.querySelector('[data-catalog-bar]'); }
    function grid() { return document.getElementById('catalog-grid'); }

    function readPrefs(b) {
        try { return JSON.parse(localStorage.getItem(b.getAttribute('data-pref-key')) || '{}') || {}; }
        catch (_) { return {}; }
    }
    function savePrefs(b) {
        var p = {};
        b.querySelectorAll('[data-cat-pref]').forEach(function (el) { p[el.name] = el.value; });
        try { localStorage.setItem(b.getAttribute('data-pref-key'), JSON.stringify(p)); } catch (_) { /* storage blocked */ }
    }
    function syncView(b) {
        var v = b.querySelector('[name="view"]').value || 'cards';
        b.querySelectorAll('[data-cat-view]').forEach(function (btn) {
            btn.setAttribute('aria-pressed', btn.getAttribute('data-cat-view') === v ? 'true' : 'false');
        });
    }
    function refresh(b) {
        syncView(b);
        savePrefs(b);
        var g = grid();
        if (g && window.htmx) htmx.trigger(g, 'catalogFilter');
    }

    function domId(kind, id) { return 'mitre-' + kind + '-' + String(id).replace(/[^A-Za-z0-9_-]/g, '_'); }
    function windowUrl(b, id) {
        var src = b.querySelector('[name="src"]');
        return b.getAttribute('data-window-url').replace('{id}', encodeURIComponent(id)) +
            '?src=' + encodeURIComponent(src ? src.value : 'enterprise');
    }

    // ?open=<id> (read before the grid's first answer rewrites the address): once the grid has
    // loaded, open the object from its card (so prev/next walks the grid), or straight from its
    // window's address if it is not on the first page.
    function openFromUrl(b, id) {
        if (!id) return;
        var card = document.getElementById(domId(b.getAttribute('data-kind'), id));
        if (card) htmx.trigger(card, 'click');
        else htmx.ajax('GET', windowUrl(b, id), { target: '#modal-container', swap: 'innerHTML' });
    }

    function wire(b) {
        if (b.hasAttribute('data-cat-ready')) return;
        b.setAttribute('data-cat-ready', '');
        // Remembered presentation choices, except where the URL set them.
        var fromUrl = (b.getAttribute('data-url-keys') || '').split(',');
        var p = readPrefs(b);
        b.querySelectorAll('[data-cat-pref]').forEach(function (el) {
            var v = p[el.name];
            if (fromUrl.indexOf(el.name) !== -1 || typeof v !== 'string' || v === '') return;
            if (el.tagName === 'SELECT' && !Array.prototype.some.call(el.options, function (o) { return o.value === v; })) return;
            el.value = v;
        });
        syncView(b);

        var searchTimer = null;
        b.addEventListener('input', function (e) {
            if (e.target.name !== 'q') return;
            clearTimeout(searchTimer);
            searchTimer = setTimeout(function () { refresh(b); }, 300);
        });
        b.addEventListener('change', function (e) {
            if (e.target.name === 'q') return;
            // Another source has other options (its own tactics): reload with that source's, dropping
            // a choice that belonged to the old one.
            if (e.target.name === 'src' && b.querySelector('[data-cat-by-source]')) {
                savePrefs(b);
                var params = new URLSearchParams();
                b.querySelectorAll('input[name], select[name]').forEach(function (el) {
                    if (el.value && !el.hasAttribute('data-cat-by-source')) params.set(el.name, el.value);
                });
                window.location.assign(b.getAttribute('data-base-path') + '?' + params.toString());
                return;
            }
            if (e.target.name === 'sort') {
                var opt = e.target.options[e.target.selectedIndex];
                b.querySelector('[name="dir"]').value = opt.getAttribute('data-default-dir') || 'asc';
            }
            refresh(b);
        });
        b.addEventListener('click', function (e) {
            var btn = e.target.closest('[data-cat-view]');
            if (!btn) return;
            var input = b.querySelector('[name="view"]');
            if (input.value === btn.getAttribute('data-cat-view')) return;
            input.value = btn.getAttribute('data-cat-view');
            refresh(b);
        });

        // #modal-container is part of the swapped body, so it is a new element every visit.
        var host = document.getElementById('modal-container');
        if (host) new MutationObserver(writeUrl).observe(host, { childList: true });

        var g = grid();
        var pendingOpen = new URLSearchParams(window.location.search).get('open');
        var first = function (ev) {
            if (ev.detail.target !== g) return;
            g.removeEventListener('htmx:afterSettle', first);
            openFromUrl(b, pendingOpen);
        };
        g.addEventListener('htmx:afterSettle', first);
        htmx.process(g);   // idempotent; makes sure the grid listens before it is asked to load
        htmx.trigger(g, 'catalogFilter');
    }

    function writeUrl() {
        var b = bar();
        if (!b || window.location.pathname !== b.getAttribute('data-base-path')) return;
        var params = new URLSearchParams(window.__tideCatalogQuery || '');
        ['page', 'in_group', 'open'].forEach(function (k) { params.delete(k); });
        Array.from(params.keys()).forEach(function (k) { if (params.get(k) === '') params.delete(k); });
        var win = document.querySelector('#modal-container [data-mitre-open]');
        if (win && win.getAttribute('data-mitre-kind') === b.getAttribute('data-kind')) params.set('open', win.getAttribute('data-mitre-open'));
        var qs = params.toString();
        window.history.replaceState(window.history.state, '', b.getAttribute('data-base-path') + (qs ? '?' + qs : ''));
    }

    if (!window.__tideCatalogWired) {
        window.__tideCatalogWired = true;

        document.addEventListener('htmx:load', function (e) {
            var b = e.target && e.target.querySelector ? (e.target.matches && e.target.matches('[data-catalog-bar]') ? e.target : e.target.querySelector('[data-catalog-bar]')) : null;
            if (b) wire(b);
        });

        // Table headers: the same column again flips the direction; another starts at its default.
        document.addEventListener('click', function (e) {
            var th = e.target.closest && e.target.closest('[data-cat-sort]');
            var b = bar();
            if (!th || !b) return;
            var sort = b.querySelector('[name="sort"]'), dir = b.querySelector('[name="dir"]');
            var key = th.getAttribute('data-cat-sort');
            if (sort.value === key) {
                var current = dir.value || (sort.options[sort.selectedIndex].getAttribute('data-default-dir') || 'asc');
                dir.value = current === 'asc' ? 'desc' : 'asc';
            } else {
                sort.value = key;
                dir.value = sort.options[sort.selectedIndex].getAttribute('data-default-dir') || 'asc';
            }
            refresh(b);
        });

        document.body.addEventListener('htmx:afterRequest', function (e) {
            if (!e.detail.successful || !e.detail.target || e.detail.target.id !== 'catalog-grid') return;
            var path = e.detail.pathInfo && (e.detail.pathInfo.finalRequestPath || e.detail.pathInfo.requestPath) || '';
            var i = path.indexOf('?');
            window.__tideCatalogQuery = i === -1 ? '' : path.slice(i + 1);
            writeUrl();
        });
    }

    function start() { var b = bar(); if (b && window.htmx) wire(b); }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else setTimeout(start, 0);
})();
