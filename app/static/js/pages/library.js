/*
 * Rule and hunt libraries (pages/rules/sigma.html, elastic.html, hunting.html): a list row loads its
 * item into the detail pane (htmx). This marks the row as open, keeps the choice across filtering
 * (the filter form's hidden "selected"), and puts it in the address under the workbench's
 * data-library name, so a reload or a link reopens it. A page's settings row (data-library-settings)
 * rides along with each row's request; a change to a setting marked data-refresh-view shows the
 * open item again with it.
 */
(function () {
    'use strict';

    var refreshTimer = null;
    function refreshOpen(e) {
        if (!(e.target.closest && e.target.closest('[data-library-settings] [data-refresh-view]'))) return;
        clearTimeout(refreshTimer);
        refreshTimer = setTimeout(function () {
            var open = document.querySelector('[data-library] .sigma-rule-selected[hx-get]');
            if (open && window.htmx) htmx.trigger(open, 'click');
        }, e.type === 'input' ? 500 : 0);
    }
    document.addEventListener('change', refreshOpen);
    document.addEventListener('input', refreshOpen);

    TIDE.actions('library', {
        open: function (e, btn) {
            var workbench = btn.closest('[data-library]');
            if (!workbench) return;
            var id = btn.getAttribute('data-item-id');
            workbench.querySelectorAll('.sigma-rule-selected').forEach(function (el) {
                el.classList.remove('sigma-rule-selected');
            });
            btn.classList.add('sigma-rule-selected');
            var selected = workbench.querySelector('input[name="selected"]');
            if (selected) selected.value = id;
            var url = new URL(window.location.href);
            url.searchParams.set(workbench.getAttribute('data-library'), id);
            history.replaceState(history.state, '', url);
        },
    });
})();
