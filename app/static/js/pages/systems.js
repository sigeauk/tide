/*
 * Systems (pages/inventory/systems.html): filtering the system cards, the Nessus upload's new
 * environment, and exporting / importing systems as JSON.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }
    function checked(id) { return $(id).checked ? 'true' : 'false'; }

    function filterCards() {
        var query = (($('system-filter-q') || {}).value || '').toLowerCase();
        var classification = ($('system-filter-classification') || {}).value || '';
        var risk = ($('system-filter-risk') || {}).value || '';
        var cards = document.querySelectorAll('#systems-grid .system-cve-card'), visible = 0;
        cards.forEach(function (card) {
            var haystack = [card.dataset.name || '', card.dataset.description || '', card.dataset.classification || '', card.dataset.metrics || ''].join(' ');
            var show = (!query || haystack.indexOf(query) !== -1)
                && (!classification || (card.dataset.classification || '') === classification)
                && (!risk || (card.dataset.risk || '') === risk);
            card.style.display = show ? 'block' : 'none';
            if (show) visible++;
        });
        var countEl = $('systems-filter-count');
        if (countEl) countEl.textContent = (query || classification || risk) ? visible + ' of ' + cards.length + ' systems shown' : '';
    }
    document.addEventListener('htmx:afterSettle', function (evt) {
        if (evt.detail.target && evt.detail.target.id === 'systems-grid') filterCards();
    });

    function openTransfer(e, el) {
        var mode = el.dataset.mode;
        $('system-transfer-modal').style.display = 'flex';
        $('system-export-options').style.display = mode === 'export' ? 'flex' : 'none';
        $('system-import-options').style.display = mode === 'import' ? 'flex' : 'none';
        $('system-transfer-title').textContent = mode === 'export' ? 'Export systems' : 'Import systems';
    }

    function exportSystems() {
        var selected = Array.from(document.querySelectorAll('input[name="export-system-id"]:checked'));
        if (!selected.length) { alert('Select at least one system.'); return; }
        var params = new URLSearchParams();
        selected.forEach(function (input) { params.append('system_ids', input.value); });
        params.set('include_baselines', checked('transfer-include-baselines'));
        params.set('include_rules', checked('transfer-include-rules'));
        params.set('include_devices', checked('transfer-include-devices'));
        fetch('/api/systems/export.json?' + params.toString(), { credentials: 'same-origin' })
            .then(function (response) { if (!response.ok) throw new Error('System export failed (' + response.status + ')'); return response.blob(); })
            .then(function (blob) {
                var link = document.createElement('a');
                link.href = URL.createObjectURL(blob);
                link.download = 'tide-systems-export.json';
                link.click();
                URL.revokeObjectURL(link.href);
                $('system-transfer-modal').style.display = 'none';
            }).catch(function (error) { alert(error.message); });
    }

    function importSystems() {
        var input = $('system-import-file');
        if (!input.files || !input.files.length) { alert('Choose a JSON export first.'); return; }
        var form = new FormData();
        form.append('file', input.files[0]);
        form.append('include_baselines', checked('system-import-baselines'));
        form.append('include_rules', checked('system-import-rules'));
        form.append('include_devices', checked('system-import-devices'));
        form.append('conflict', $('system-import-conflict').value);
        fetch('/api/systems/import.json', { method: 'POST', body: form, credentials: 'same-origin' })
            .then(function (response) {
                if (!response.ok) throw new Error('System import failed (' + response.status + ')');
                window.location.reload();
            }).catch(function (error) { alert(error.message); });
    }

    TIDE.actions('systems', {
        filter: function () { filterCards(); return false; },
        clearFilters: function () {
            $('system-filter-q').value = '';
            $('system-filter-classification').value = '';
            $('system-filter-risk').value = '';
            filterCards();
        },
        // Nessus upload: "+ New environment…" asks for its name.
        envPicked: function (e, sel) { $('new-env-form').style.display = sel.value === '__new__' ? 'block' : 'none'; },
        envName: function () { $('new-env-name-hidden').value = $('new-env-name').value; },
        transferOpen: openTransfer, exportSystems: exportSystems, importSystems: importSystems,
    });
})();
