/*
 * A system's page (pages/inventory/system_detail.html): the Export report dialog, the heatmap's
 * baseline filter, and reloading once Manage baselines closes after a change.
 * Its anchor: <div hidden data-system-page data-system-id="…" data-baselines="id,id,…">.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }
    function anchor() { return document.querySelector('[data-system-page]'); }

    function closeExport() { $('export-modal-overlay').style.display = 'none'; }

    function confirmExport() {
        var params = new URLSearchParams(), mode = $('modal-audience').value;
        params.set('mode', mode);
        params.set('format', $('modal-format').value);
        params.set('classification', $('modal-classification').value);
        params.set('include_devices', $('modal-include-devices').checked ? '1' : '0');
        var chosen = Array.prototype.filter.call(document.querySelectorAll('.modal-baseline'), function (cb) { return cb.checked; });
        params.set('include_baselines', chosen.length ? '1' : '0');
        chosen.forEach(function (cb) { params.append('baseline_id', cb.value); });
        if (mode === 'technical') params.set('techniques', $('modal-techniques').value);
        closeExport();
        window.location.href = '/api/inventory/systems/' + anchor().dataset.systemId + '/report?' + params.toString();
    }

    function loadHeatmap() {
        var ids = [];
        document.querySelectorAll('.sys-heatmap-bl-filter:not([value=""])').forEach(function (cb) { if (cb.checked) ids.push(cb.value); });
        var params = ids.map(function (id) { return 'baseline_ids=' + encodeURIComponent(id); }).join('&');
        htmx.ajax('GET', '/api/heatmap/system/' + anchor().dataset.systemId + '/matrix' + (params ? '?' + params : ''),
                  { target: '#system-heatmap-matrix', swap: 'innerHTML' });
    }

    // Applying or removing baselines changes more than the grid (the count, the metric strip, the
    // heatmap's filters), so once the Manage baselines window closes after a change, reload.
    TIDE.page('[data-system-page]', function (page) {
        var host = $('modal-container');
        if (!host) return;
        var initial = page.dataset.baselines, latest = initial;
        var observer = new MutationObserver(function () {
            if (!page.isConnected) { observer.disconnect(); return; }
            var d = host.querySelector('[data-baselines-dialog]');
            if (d) { latest = d.getAttribute('data-applied'); return; }
            if (latest !== initial) window.location.reload();
        });
        observer.observe(host, { childList: true, subtree: true });
    });

    TIDE.actions('systemPage', {
        exportOpen: function () { $('export-modal-overlay').style.display = 'flex'; },
        exportClose: closeExport,
        exportConfirm: confirmExport,
        // Technique detail only applies to the technical report.
        exportAudience: function () { $('modal-techniques-field').hidden = $('modal-audience').value !== 'technical'; },
        heatmapBaselines: loadHeatmap,
        heatmapAll: function (e, all) {
            document.querySelectorAll('.sys-heatmap-bl-filter:not([value=""])').forEach(function (cb) { cb.checked = all.checked; });
            loadHeatmap();
        },
    });
})();
