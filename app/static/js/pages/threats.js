/*
 * Threat Landscape (pages/threats/threat_landscape.html, partials/threats_grid.html): the metrics
 * refreshed with the grid. An actor's Create baseline is in its window's "…".
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    document.addEventListener('htmx:afterSwap', function (event) {
        var target = event.detail.target;
        if (target.id === 'threats-grid') {
            htmx.ajax('GET', '/api/threats/metrics', { target: '#metrics-container', swap: 'innerHTML' });
        } else if (target.id === 'toast-container' && $('threats-grid')) {
            // Toasts swapped into the toast container fade after 5 s.
            target.querySelectorAll('.toast').forEach(function (toast) {
                setTimeout(function () {
                    toast.style.opacity = '0';
                    setTimeout(function () { toast.remove(); }, 300);
                }, 5000);
            });
        }
    });

})();
