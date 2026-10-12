/*
 * A CVE's page (pages/inventory/cve_detail.html): the Export report dialog. Its overlay carries
 * the CVE (data-cve-id).
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }
    function closeExport() { $('export-modal-overlay').style.display = 'none'; }

    document.addEventListener('click', function (e) {
        var overlay = $('export-modal-overlay');
        if (overlay && overlay.hasAttribute('data-cve-id') && e.target === overlay) closeExport();
    });

    TIDE.actions('cvePage', {
        exportOpen: function () { $('export-modal-overlay').style.display = 'flex'; },
        exportClose: closeExport,
        exportConfirm: function () {
            var overlay = $('export-modal-overlay'), params = new URLSearchParams();
            params.set('format', $('modal-format').value);
            params.set('classification', $('modal-classification').value);
            // Include the affected-devices search, if any
            var q = (($('affected-search') || {}).value || '').trim();
            if (q) params.set('search', q);
            closeExport();
            window.location.href = '/api/inventory/cve/' + overlay.dataset.cveId + '/report?' + params.toString();
        },
    });
})();
