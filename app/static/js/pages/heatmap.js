/*
 * ATT&CK heatmap (pages/threats/heatmap.html): the actor and source pickers, the technique search,
 * redrawing the matrix, and the Export report and Create baseline dialogs.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }
    function checkedActors() { return document.querySelectorAll('input[name="actors"]:checked'); }

    function toggleDropdown(containerId, dropdownId) {
        var isOpen = $(containerId).classList.toggle('open');
        $(dropdownId).style.display = isOpen ? 'flex' : 'none';
    }

    // Close the pickers on a click outside them, and a dialog on a click on its backdrop.
    document.addEventListener('click', function (e) {
        [['actor-select-container', 'actor-dropdown'], ['source-select-container', 'source-dropdown']].forEach(function (p) {
            var container = $(p[0]), dropdown = $(p[1]);
            if (container && !container.contains(e.target)) {
                container.classList.remove('open');
                if (dropdown) dropdown.style.display = 'none';
            }
        });
        var overlay = $('export-modal-overlay');
        if (overlay && e.target === overlay) closeExport();
        var baselineOverlay = $('baseline-gen-overlay');
        if (baselineOverlay && e.target === baselineOverlay) closeBaseline();
    });

    function filterActors(e, input) {
        var q = input.value.toLowerCase();
        document.querySelectorAll('.actor-checkbox-item').forEach(function (item) {
            var matches = (item.dataset.name || '').includes(q) || (item.dataset.aliases || '').includes(q);
            item.style.display = matches ? 'flex' : 'none';
        });
    }

    function selectionLabel(textId, checked, none, many) {
        var textEl = $(textId);
        if (checked.length === 0) {
            textEl.textContent = none;
            textEl.classList.remove('has-selection');
        } else {
            textEl.textContent = checked.length === 1 ? checked[0].value : checked.length + many;
            textEl.classList.add('has-selection');
        }
    }

    function redraw() {
        var params = new URLSearchParams();
        Array.from(checkedActors()).forEach(function (cb) { params.append('actors', cb.value); });
        if ($('show-defense-checkbox').checked) params.append('show_defense', 'on');
        document.querySelectorAll('input[name="source_filter"]:checked').forEach(function (cb) { params.append('source_filter', cb.value); });
        htmx.ajax('GET', '/api/heatmap/matrix?' + params.toString(), { target: '#heatmap-container', swap: 'innerHTML' });
    }

    // Highlight the techniques matching the search in the matrix.
    function filterTechniques(e, input) {
        var q = input.value.toLowerCase().trim();
        document.querySelectorAll('.ttp-card').forEach(function (cell) {
            var matches = !q || (cell.dataset.techId || '').toLowerCase().includes(q)
                || (cell.dataset.techName || '').toLowerCase().includes(q)
                || (cell.getAttribute('title') || '').toLowerCase().includes(q);
            var hit = !!q && matches;
            cell.style.opacity = matches ? '1' : '0.2';
            cell.style.transform = hit ? 'scale(1.08)' : '';
            cell.style.zIndex = hit ? '10' : '';
            cell.style.boxShadow = hit ? '0 0 8px var(--color-primary)' : '';
        });
    }

    // ── Export report ──
    function openExport() {
        if (checkedActors().length === 0) { alert('Select at least one threat actor before exporting a report.'); return; }
        $('export-modal-overlay').style.display = 'flex';
    }
    function closeExport() { $('export-modal-overlay').style.display = 'none'; }
    function confirmExport() {
        var params = new URLSearchParams();
        params.set('format', $('modal-format').value);
        params.set('classification', $('modal-classification').value);
        params.set('audience_level', $('modal-audience').value);
        Array.from(checkedActors()).forEach(function (cb) { params.append('actors', cb.value); });
        if ($('show-defense-checkbox').checked) params.set('show_defense', 'true');
        closeExport();
        window.location.href = '/api/heatmap/export?' + params.toString();
    }

    // ── Create baseline from the selected actors ──
    function openBaseline() {
        var names = Array.from(checkedActors()).map(function (cb) { return cb.value; });
        if (!names.length) { alert('Select at least one threat actor to generate a baseline.'); return; }
        $('baseline-gen-actors').value = names.join(', ');
        $('baseline-gen-name').value = names.length === 1 ? names[0] + ' Baseline' : names.length + ' Actors Baseline';
        $('baseline-gen-desc').value = '';
        $('baseline-gen-overlay').style.display = 'flex';
    }
    function closeBaseline() { $('baseline-gen-overlay').style.display = 'none'; }

    TIDE.actions('heatmap', {
        actorMenu: function () { toggleDropdown('actor-select-container', 'actor-dropdown'); },
        sourceMenu: function () { toggleDropdown('source-select-container', 'source-dropdown'); },
        filterActors: filterActors,
        actorPicked: function () {
            selectionLabel('actor-select-text', checkedActors(), 'Choose threat actors...', ' actors selected');
            redraw();
        },
        sourcePicked: function () {
            selectionLabel('source-select-text', document.querySelectorAll('input[name="source_filter"]:checked'), 'All sources', ' sources');
            redraw();
        },
        redraw: redraw,
        filterTechniques: filterTechniques,
        exportOpen: openExport, exportClose: closeExport, exportConfirm: confirmExport,
        baselineOpen: openBaseline, baselineClose: closeBaseline,
    });
})();
