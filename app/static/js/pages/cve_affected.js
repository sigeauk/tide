/*
 * A CVE's affected devices (partials/cve_affected_hosts.html): search, applying a detection to a
 * device, and the Log blind spot dialog.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    // An Apply form posts to a path with __DET_ID__ standing for the detection picked in its select.
    document.addEventListener('htmx:configRequest', function (e) {
        var path = e.detail.path, form = e.detail.elt.closest('form');
        if (!form || !path || path.indexOf('__DET_ID__') === -1) return;
        var sel = form.querySelector('select');
        if (sel && sel.value) e.detail.path = path.replace('__DET_ID__', sel.value);
        else e.preventDefault();
    });

    TIDE.actions('affected', {
        search: function () {
            var q = ($('affected-search').value || '').toLowerCase();
            var cards = document.querySelectorAll('#cve-affected-section .host-card[data-aff-name]'), visible = 0;
            cards.forEach(function (card) {
                var show = !q || ((card.dataset.affName || '') + ' ' + (card.dataset.affIp || '')).indexOf(q) !== -1;
                card.style.display = show ? '' : 'none';
                if (show) visible++;
            });
            $('affected-search-count').textContent = q ? visible + ' of ' + cards.length + ' shown' : '';
        },
        // Nothing picked: nothing to apply.
        applySubmit: function (e, form) { if (!form.querySelector('select').value) return false; },
        blindSpot: function (e, btn) {
            var m = $('blind-spot-modal'), d = btn.dataset;
            m.querySelector('[name=entity_type]').value = d.entityType;
            m.querySelector('[name=entity_id]').value = d.entityId;
            m.querySelector('[name=system_id]').value = d.systemId || '';
            m.querySelector('[name=host_id]').value = d.hostId || '';
            m.querySelector('#bs-modal-target').textContent = d.hostName || d.entityId;
            m.querySelector('[name=reason]').value = '';
            m.style.display = 'flex';
        },
    });
})();
