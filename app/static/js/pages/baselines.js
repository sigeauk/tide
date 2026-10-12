/*
 * Baselines (pages/inventory/baselines.html): importing a TIDE baseline JSON, asking what to do
 * when a baseline of that name exists.
 */
(function () {
    'use strict';

    async function submitImport(event, form) {
        event.preventDefault();
        var data = new FormData(form);
        data.set('conflict', 'prompt');
        var response = await fetch(form.action, { method: 'POST', body: data, credentials: 'same-origin' });
        if (response.status === 409) {
            var conflict = await response.json();
            var choice = window.prompt('Baseline "' + conflict.existing_name + '" already exists. Enter CREATE for a new copy or OVERRIDE to replace it.', 'CREATE');
            if (!choice) return;
            var override = choice.toLowerCase() === 'override';
            data.set('conflict', override ? 'override' : 'create');
            if (override) data.set('target_baseline_id', conflict.existing_id);
            response = await fetch(form.action, { method: 'POST', body: data, credentials: 'same-origin' });
        }
        if (!response.ok) { alert('Baseline import failed (' + response.status + ').'); return; }
        window.location.reload();
    }

    TIDE.actions('baselines', {
        importSubmit: submitImport,
        // Importing into an existing baseline needs no new name.
        importTarget: function (e, sel) {
            var ns = document.getElementById('import-new-name');
            ns.hidden = !!sel.value;
            ns.querySelector('input').required = !sel.value;
        },
    });
})();
