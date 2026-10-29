/*
 * A system's hosts (partials/host_list.html: search, CVE filter, sort) and a host's page
 * (pages/inventory/host_detail.html, partials/host_software.html: package search, picking a
 * package to see its CVEs, editing a package).
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    // ── Host list ──
    function filterHosts() {
        var q = $('host-search').value.toLowerCase(), cveFilter = $('host-cve-filter').value;
        var cards = document.querySelectorAll('#host-card-grid .host-cve-card'), visible = 0;
        cards.forEach(function (card) {
            var text = (card.dataset.name || '') + ' ' + (card.dataset.ip || '') + ' ' + (card.dataset.os || '') + ' ' + (card.dataset.software || '');
            var show = (!q || text.indexOf(q) !== -1) && (cveFilter === 'all' || card.dataset.cve === cveFilter);
            card.style.display = show ? '' : 'none';
            if (show) visible++;
        });
        $('host-search-count').textContent = (q || cveFilter !== 'all') ? visible + ' of ' + cards.length + ' shown' : '';
    }
    function sortHosts() {
        var field = ($('host-sort') || {}).value || 'name', grid = $('host-card-grid');
        if (!grid) return;
        Array.from(grid.querySelectorAll('.host-cve-card')).sort(function (a, b) {
            if (field === 'name') return (a.dataset.name || '').localeCompare(b.dataset.name || '');
            if (field === 'vuln') return parseInt(a.dataset.vulnCount || 0) - parseInt(b.dataset.vulnCount || 0);
            if (field === 'status') return parseInt(a.dataset.rag || 0) - parseInt(b.dataset.rag || 0);
            return 0;
        }).forEach(function (c) { grid.appendChild(c); });
    }

    // ── A host's packages and CVEs ──
    function filterPackages() {
        var q = ($('pkg-search').value || '').toLowerCase();
        document.querySelectorAll('#software-section .sw-card').forEach(function (card) {
            var text = ['.sw-card__name', '.sw-card__meta', '.sw-card__cpe'].map(function (s) {
                return (card.querySelector(s) || {}).textContent || '';
            }).join(' ').toLowerCase();
            card.style.display = (!q || text.indexOf(q) !== -1) ? '' : 'none';
        });
        filterCves();
    }

    function packageName(card) { return ((card.querySelector('.sw-card__name') || {}).textContent || '').trim().toLowerCase(); }

    // The CVEs shown follow the picked package, else the packages the search leaves visible.
    function filterCves() {
        var selected = document.querySelector('#software-section .sw-card--selected');
        var cveCards = document.querySelectorAll('#cve-matches-card .cve-mini-card'), status = $('cve-filter-status');
        var q = (($('pkg-search') || {}).value || '').toLowerCase();
        if (!selected && !q) {
            cveCards.forEach(function (c) { c.style.display = ''; });
            if (status) status.style.display = 'none';
            return;
        }
        var names = selected ? [packageName(selected)] : Array.from(document.querySelectorAll('#software-section .sw-card'))
            .filter(function (card) { return card.style.display !== 'none'; }).map(packageName).filter(Boolean);
        var shown = 0;
        cveCards.forEach(function (c) {
            var match = Array.from(c.querySelectorAll('.badge.badge-neutral')).some(function (b) {
                return names.indexOf(b.textContent.trim().toLowerCase()) !== -1;
            });
            c.style.display = match ? '' : 'none';
            if (match) shown++;
        });
        if (status) {
            status.textContent = selected ? 'Showing ' + shown + ' CVE(s) for "' + names[0] + '"' : 'Filtered: ' + shown + ' CVE(s) matching visible packages';
            status.style.display = '';
        }
    }

    // Clicking a package card picks it (again: drops it) and shows its CVEs. Its ⋮ and its edit
    // form are for the package, not for picking it.
    TIDE.page('#software-section .sw-card', function (card) {
        card.classList.add('cursor-pointer');
        card.addEventListener('click', function (e) {
            if (e.target.closest('[data-more], form')) return;
            var wasSelected = card.classList.contains('sw-card--selected');
            document.querySelectorAll('#software-section .sw-card').forEach(function (c) { c.classList.remove('sw-card--selected'); });
            if (!wasSelected) card.classList.add('sw-card--selected');
            filterCves();
        });
    });

    // Edit a package in place: data-display / data-edit are the two rows' ids.
    function swEdit(e, btn) {
        $(btn.dataset.display).style.display = 'none';
        $(btn.dataset.edit).style.display = 'flex';
    }
    function swCancel(e, btn) {
        $(btn.dataset.edit).style.display = 'none';
        $(btn.dataset.display).style.display = '';
    }

    TIDE.actions('hosts', {
        filter: function () { filterHosts(); return false; },
        sort: sortHosts,
        filterPackages: filterPackages,
        swEdit: swEdit, swCancel: swCancel,
    });
})();
