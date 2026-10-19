/*
 * Documentation (pages/admin/docs.html): the sidebar's search over every section of the guide.
 * The index (/settings/docs/search.json: page, section, its words) is fetched the first time the
 * box is used. Every word typed must appear in a section's page, heading or text; a heading match
 * ranks first. The results take the groups' place in the sidebar until the box is cleared. Arrow
 * keys move through them, Enter opens one, Escape clears.
 */
(function () {
    'use strict';

    var index = null, loading = null;
    function load() {
        if (index) return Promise.resolve(index);
        if (!loading) {
            loading = fetch('/settings/docs/search.json', { credentials: 'same-origin' })
                .then(function (r) { return r.ok ? r.json() : []; })
                .then(function (rows) {
                    index = rows.map(function (r) {
                        r.hay = (r.page + ' ' + r.section + ' ' + r.text).toLowerCase();
                        r.head = (r.page + ' ' + r.section).toLowerCase();
                        return r;
                    });
                    return index;
                })
                .catch(function () { index = []; return index; });
        }
        return loading;
    }

    function escapeHtml(s) {
        return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; });
    }

    // A few words of the section around the first word searched for.
    function snippet(text, term) {
        var at = text.toLowerCase().indexOf(term);
        if (at < 0) return text.slice(0, 110) + (text.length > 110 ? '…' : '');
        var start = Math.max(0, at - 40);
        return (start ? '…' : '') + text.slice(start, start + 120) + (start + 120 < text.length ? '…' : '');
    }

    function search(q) {
        var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
        if (!terms.length) return [];
        return index
            .filter(function (r) { return terms.every(function (t) { return r.hay.indexOf(t) !== -1; }); })
            .map(function (r) {
                var score = terms.reduce(function (n, t) { return n + (r.head.indexOf(t) !== -1 ? 3 : 1); }, 0);
                return { r: r, score: score };
            })
            .sort(function (a, b) { return b.score - a.score; })
            .slice(0, 8)
            .map(function (x) { return x.r; });
    }

    function searching(box, on) {
        var nav = box.closest('[data-docs-nav]');
        if (nav) nav.classList.toggle('is-searching', on);
    }

    function show(box, input) {
        var list = box.querySelector('[data-docs-search-results]'), q = input.value.trim();
        if (!q) { list.hidden = true; list.innerHTML = ''; searching(box, false); return; }
        load().then(function () {
            if (input.value.trim() !== q) return;          // typed on since
            var hits = search(q), first = q.toLowerCase().split(/\s+/)[0];
            list.innerHTML = hits.length ? hits.map(function (r, i) {
                var href = '/settings/docs/' + r.slug + (r.id ? '#' + r.id : '');
                return '<a class="docs-search__hit" role="option" href="' + href + '"' + (i === 0 ? ' aria-selected="true"' : '') + '>' +
                    '<span class="docs-search__where">' + escapeHtml(r.page) + '</span>' +
                    '<span class="docs-search__section">' + escapeHtml(r.section) + '</span>' +
                    '<span class="docs-search__snippet">' + escapeHtml(snippet(r.text, first)) + '</span></a>';
            }).join('') : '<p class="docs-search__none">Nothing in the guide matches “' + escapeHtml(q) + '”.</p>';
            list.hidden = false;
            searching(box, true);
        });
    }

    function move(list, step) {
        var hits = Array.prototype.slice.call(list.querySelectorAll('.docs-search__hit'));
        if (!hits.length) return;
        var at = hits.findIndex(function (h) { return h.getAttribute('aria-selected') === 'true'; });
        hits.forEach(function (h) { h.removeAttribute('aria-selected'); });
        var next = hits[(at + step + hits.length) % hits.length];
        next.setAttribute('aria-selected', 'true');
        next.scrollIntoView({ block: 'nearest' });
    }

    TIDE.page('[data-docs-search]', function (box) {
        var input = box.querySelector('[data-docs-search-input]'), list = box.querySelector('[data-docs-search-results]');
        var timer = null;
        input.addEventListener('focus', load);
        input.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(function () { show(box, input); }, 120); });
        input.addEventListener('keydown', function (e) {
            if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); move(list, e.key === 'ArrowDown' ? 1 : -1); }
            else if (e.key === 'Enter') {
                var hit = list.querySelector('.docs-search__hit[aria-selected="true"]') || list.querySelector('.docs-search__hit');
                if (hit) { e.preventDefault(); window.location.href = hit.href; }
            } else if (e.key === 'Escape') { input.value = ''; show(box, input); }
        });
        input.addEventListener('search', function () { show(box, input); });   // the box's own clear (x)
    });
})();
