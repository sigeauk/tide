/*
 * Small partials: snapshots history search (partials/audit_history.html), a template's Manage
 * dialog (partials/template_manage_dialog.html: apply to a system, export), a new technique's
 * title focus (partials/technique_new_form.html), and a CVE's Add detection form
 * (partials/cve_detection_badge.html).
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    // The title first, after the window's own focus handling (app.js focuses Close on open).
    TIDE.page('#tf-name', function (t) { setTimeout(function () { t.focus(); }, 50); });

    TIDE.actions('audit', {
        // A baseline group shows when its name, or one of its techniques, matches.
        filter: function (e, input) {
            var q = input.value.toLowerCase();
            document.querySelectorAll('.audit-group').forEach(function (grp) {
                var match = grp.dataset.baseline.indexOf(q) >= 0 || Array.prototype.some.call(grp.querySelectorAll('.tech-card'), function (card) {
                    return card.dataset.search && card.dataset.search.toLowerCase().indexOf(q) >= 0;
                });
                grp.style.display = match ? '' : 'none';
            });
        },
    });

    TIDE.actions('tpl', {
        apply: function (e, btn) {
            htmx.ajax('POST', '/api/baselines/' + btn.dataset.baselineId + '/apply/' + encodeURIComponent($('tpl-apply').value), { swap: 'none' });
        },
        // Export: a report (PDF or Markdown, for an audience and classification) or the template as TIDE JSON.
        export: function (e, btn) {
            var id = btn.closest('[data-tpl-export]').getAttribute('data-baseline-id'), format = $('tpl-export-format').value;
            if (format === 'json') {
                window.location.href = '/api/baselines/' + encodeURIComponent(id) + '/export.json?include_rules=false';
                return;
            }
            var params = new URLSearchParams({
                mode: $('tpl-export-audience').value, format: format,
                classification: $('tpl-export-classification').value,
            });
            window.location.href = '/api/baselines/' + encodeURIComponent(id) + '/report?' + params.toString();
        },
    });

    TIDE.actions('detection', {
        addOpen: function (e, btn) {
            btn.style.display = 'none';
            $('add-det-form').style.display = 'flex';
        },
        addCancel: function (e, btn) {
            btn.closest('form').style.display = 'none';
            $('add-det-btn').style.display = 'inline-flex';
        },
        // A SIEM rule picked fills the reference and marks the source; nothing picked is manual.
        rulePicked: function (e, sel) {
            var f = sel.closest('form');
            if (sel.value) {
                f.querySelector('[name=rule_ref]').value = sel.value;
                f.querySelector('[name=source]').value = 'siem';
            } else {
                f.querySelector('[name=source]').value = 'manual';
            }
        },
    });
})();
