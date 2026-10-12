/*
 * Threat Landscape (pages/threats/threat_landscape.html, partials/threats_grid.html): an actor's
 * Create baseline dialog, and the metrics refreshed with the grid.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    function closeBaseline() { $('actor-baseline-overlay').style.display = 'none'; }
    document.addEventListener('click', function (e) {
        var overlay = $('actor-baseline-overlay');
        if (overlay && e.target === overlay) closeBaseline();
    });

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

    TIDE.actions('threats', {
        baselineOpen: function (e, el) {
            $('actor-bl-actors').value = el.dataset.actor;
            $('actor-bl-group-ids').value = el.dataset.groupId || '';
            $('actor-bl-name').value = el.dataset.actor + ' Baseline';
            $('actor-bl-desc').value = '';
            $('actor-baseline-overlay').style.display = 'flex';
        },
        baselineClose: closeBaseline,
    });
})();
