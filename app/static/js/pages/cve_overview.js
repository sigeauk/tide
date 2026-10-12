/*
 * CVE Overview (pages/inventory/cve_overview.html, partials/cve_overview_table.html): the feed
 * uploads, filtering the CVE cards (search, matched only, systems, coverage) and sorting them.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }
    var sortAsc = false;

    function cards() { return Array.from(document.querySelectorAll('#cve-card-list .cve-card-item')); }

    // Close the filter dropdowns on a click outside them
    document.addEventListener('click', function (e) {
        document.querySelectorAll('.filter-multi__dropdown').forEach(function (dd) {
            if (!dd.classList.contains('hidden') && !dd.parentElement.contains(e.target)) dd.classList.add('hidden');
        });
    });

    function filterCards() {
        var q = (($('kev-search') || {}).value || '').toLowerCase();
        var matchedOnly = ($('filter-matched') || {}).checked;
        var sysCbs = document.querySelectorAll('.sys-filter-cb');
        var selectedSys = Array.from(sysCbs).filter(function (c) { return c.checked; }).map(function (c) { return c.value; });
        var allSys = selectedSys.length === sysCbs.length;
        var covCbs = document.querySelectorAll('.cov-filter-cb');
        var selectedCov = Array.from(covCbs).filter(function (c) { return c.checked; }).map(function (c) { return c.value; });
        var allCov = selectedCov.length === covCbs.length;

        var sysLabel = $('sys-filter-label');
        if (sysLabel) sysLabel.textContent = allSys ? 'All Systems' : selectedSys.length + ' System' + (selectedSys.length !== 1 ? 's' : '');
        var covLabel = $('cov-filter-label');
        if (covLabel) covLabel.textContent = allCov ? 'All Coverage' : selectedCov.length + ' Selected';

        var visible = 0;
        cards().forEach(function (card) {
            // A card shows when any of its systems is ticked, and its coverage is ticked.
            var cardSystems = card.dataset.systems ? card.dataset.systems.split(',') : [];
            var showSys = allSys || cardSystems.some(function (s) { return selectedSys.includes(s); });
            var showCov = allCov || selectedCov.includes(card.dataset.coverage || '');
            var show = card.textContent.toLowerCase().includes(q) && (!matchedOnly || card.dataset.matched === '1') && showSys && showCov;
            card.style.display = show ? '' : 'none';
            if (show) visible++;
        });
        var countEl = $('cve-visible-count');
        if (countEl) countEl.textContent = visible;
    }

    function sortCards() {
        var sortField = ($('sort-field') || {}).value || 'cve_id';
        var list = $('cve-card-list');
        if (!list) return;
        var all = cards();
        all.sort(function (a, b) {
            if (sortField === 'matched') {
                var m = b.dataset.matched.localeCompare(a.dataset.matched);   // matched first
                return sortAsc ? m : -m;
            }
            var field = { cve_id: 'cveId', name: 'name', vendor: 'vendor', date_added: 'dateAdded', due_date: 'dueDate' }[sortField] || 'cveId';
            var va = a.dataset[field] || a.dataset[sortField] || '', vb = b.dataset[field] || b.dataset[sortField] || '';
            var cmp = va.localeCompare(vb, undefined, { numeric: true, sensitivity: 'base' });
            return sortAsc ? cmp : -cmp;
        });
        all.forEach(function (c) { list.appendChild(c); });
    }

    // A freshly loaded table: sorted by CVE ID, newest first.
    TIDE.page('#cve-card-list', function () {
        sortAsc = false;
        var sortSel = $('sort-field');
        if (sortSel) sortSel.value = 'cve_id';
        var dirIcon = $('sort-dir-icon');
        if (dirIcon) dirIcon.textContent = '▲';
        sortCards();
    });

    // Feed uploads: the response replaces the CVE table (or reports into the status line).
    async function upload(e, inp) {
        if (!inp.files.length) return;
        var status = $('upload-status'), targetId = inp.dataset.target;
        if (status) status.innerHTML = '<span class="loading-state flex-row p-0 gap-sm"><span class="loading-spinner loading-spinner--sm"></span><span>Uploading…</span></span>';
        var fd = new FormData();
        fd.append('file', inp.files[0]);
        inp.value = '';   // so the same file can be chosen again
        try {
            var resp = await fetch(inp.dataset.endpoint, { method: 'POST', body: fd });
            if (resp.redirected || resp.status === 401) {
                if (status) status.innerHTML = '<span class="req">&#10007;</span> Session expired — please reload the page.';
                return;
            }
            var html = await resp.text();
            if (!resp.ok) {
                if (status) status.innerHTML = '<span class="req">&#10007;</span> Error: ' + resp.status;
                return;
            }
            var target = $(targetId);
            if (target) { target.innerHTML = html; htmx.process(target); }
            if (status) status.innerHTML = '<span class="text-success">&#10003;</span> ' + (inp.dataset.done || 'Done');
            setTimeout(function () { if (status) status.innerHTML = ''; }, 4000);
        } catch (err) {
            if (status) status.innerHTML = '<span class="req">&#10007;</span> ' + err.message;
        }
    }

    TIDE.actions('cves', {
        filter: filterCards,
        sort: sortCards,
        sortDir: function () {
            sortAsc = !sortAsc;
            var icon = $('sort-dir-icon');
            if (icon) icon.textContent = sortAsc ? '▼' : '▲';
            sortCards();
        },
        // "All" / "None" in a filter dropdown: data-boxes is the class of its checkboxes.
        checkAll: function (e, a) {
            document.querySelectorAll('.' + a.dataset.boxes).forEach(function (c) { c.checked = a.dataset.value === 'true'; });
            filterCards();
            return false;
        },
        upload: upload,
    });
})();
