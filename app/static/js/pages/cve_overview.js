/*
 * CVE Overview (pages/inventory/cve_overview.html, partials/cve_overview_table.html): the feed
 * uploads, and asking the server for the CVE cards the filter bar shows (search, matched only,
 * systems, coverage, sort), 50 at a time.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    // The ticked boxes of a filter: nothing when all are ticked (no filter), "none" when none are.
    function ticked(cls, query, name) {
        var boxes = Array.from(document.querySelectorAll('.' + cls));
        var on = boxes.filter(function (c) { return c.checked; }).map(function (c) { return c.value; });
        if (on.length === boxes.length) return 'all';
        (on.length ? on : ['none']).forEach(function (v) { query.append(name, v); });
        return on.length;
    }

    // The cards are filtered, sorted and paged by the server (50 at a time, the next as the end
    // scrolls into view): ask it for those the filter bar shows.
    var timer = null;
    function filterCards(e) {
        clearTimeout(timer);
        timer = setTimeout(load, e && e.type === 'input' ? 250 : 0);
    }
    function load() {
        var list = $('cve-card-list');
        if (!list) return;
        var query = new URLSearchParams();
        var q = (($('kev-search') || {}).value || '').trim();
        if (q) query.set('search', q);
        if (($('filter-matched') || {}).value === 'matched') query.set('matched', 'matched');
        var sys = ticked('sys-filter-cb', query, 'system');
        var cov = ticked('cov-filter-cb', query, 'coverage');
        var sort = (($('sort-field') || {}).value || 'cve_id:desc').split(':');
        query.set('sort', sort[0]);
        query.set('dir', sort[1] || 'desc');
        var sysLabel = $('sys-filter-label');
        if (sysLabel) sysLabel.textContent = sys === 'all' ? 'Any' : sys + ' system' + (sys !== 1 ? 's' : '');
        var covLabel = $('cov-filter-label');
        if (covLabel) covLabel.textContent = cov === 'all' ? 'Any' : cov + ' selected';
        htmx.ajax('GET', '/api/inventory/cve-overview-cards?' + query.toString(), { target: list, swap: 'innerHTML' });
    }

    // Feed uploads: the response replaces the CVE table (or reports into the status line).
    async function upload(e, inp) {
        if (!inp.files.length) return;
        var status = $('upload-status'), targetId = inp.dataset.target;
        if (status) status.innerHTML = TIDE.loadingHtml('Uploading…');
        var fd = new FormData();
        fd.append('file', inp.files[0]);
        inp.value = '';   // so the same file can be chosen again
        try {
            var resp = await fetch(inp.dataset.endpoint, { method: 'POST', body: fd });
            if (resp.redirected || resp.status === 401) {
                if (status) status.innerHTML = '<span class="req">' + TIDE.iconHtml('x', 14) + '</span> Session expired — please reload the page.';
                return;
            }
            var html = await resp.text();
            if (!resp.ok) {
                if (status) status.innerHTML = '<span class="req">' + TIDE.iconHtml('x', 14) + '</span> Error: ' + resp.status;
                return;
            }
            var target = $(targetId);
            if (target) { target.innerHTML = html; htmx.process(target); }
            if (status) status.innerHTML = '<span class="text-success">' + TIDE.iconHtml('check', 14) + '</span> ' + (inp.dataset.done || 'Done');
            setTimeout(function () { if (status) status.innerHTML = ''; }, 4000);
        } catch (err) {
            if (status) status.innerHTML = '<span class="req">' + TIDE.iconHtml('x', 14) + '</span> ' + err.message;
        }
    }

    TIDE.actions('cves', {
        filter: filterCards,
        sort: filterCards,
        // "All" / "None" in a filter dropdown: data-boxes is the class of its checkboxes.
        checkAll: function (e, a) {
            document.querySelectorAll('.' + a.dataset.boxes).forEach(function (c) { c.checked = a.dataset.value === 'true'; });
            filterCards();
            return false;
        },
        upload: upload,
    });
})();
