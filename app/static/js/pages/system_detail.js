/*
 * A system's page (pages/inventory/system_detail.html): the Export report dialog and the heatmap's
 * baseline filter. (Adding, renaming or removing a baseline reloads the page from the server:
 * inventory._system_page_reload.)
 * Its anchor: <div hidden data-system-page data-system-id="…">.
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
