/*
 * Controls used across the app, over the helpers in app.js: the sidebar (nav groups, the account
 * group's theme switch, collapse) and client switcher, MITRE technique pills (open the side panel), the rule
 * window's Move / Delete / Add link, the rule compare window, clickable list rows, Expand / Collapse
 * all, and a few form helpers (diagnostics, generate baselines, a system's Manage baselines).
 */
(function () {
    'use strict';

    function hold(e) { e.preventDefault(); e.stopPropagation(); }

    TIDE.actions('nav', {
        group: function (e, el) { window.toggleNavGroup(el.dataset.group); },
        clientMenu: function (e) { window.toggleClientMenu(e); },
        theme: function () { window.toggleTheme(); },
        sidebar: function () { window.toggleSidebar(); },
    });

    // A technique pill opens its side panel; pressing it must not start a drag or reach the
    // card or summary it sits in. data-close-modal: close the rule window first so the panel shows.
    TIDE.actions('pill', {
        hold: hold,
        open: function (e, el) {
            hold(e);
            if (el.hasAttribute('data-close-modal') && window.tideCloseRuleModal) window.tideCloseRuleModal();
            var url = '/api/heatmap/technique/' + el.dataset.technique + (el.dataset.search ? '?search=' + encodeURIComponent(el.dataset.search) : '');
            if (window.htmx) htmx.ajax('GET', url, { target: '#slide-panel-container', swap: 'innerHTML' });
            return false;
        },
    });

    TIDE.actions('rule', {
        move: function (e, el) {
            var d = el.dataset;
            window.showMoveDialog(d.ruleId, d.ruleName, d.siemId, d.space, d.deleteDefault === 'true', JSON.parse(d.targets));
        },
        delete: function (e, el) {
            var d = el.dataset;
            window.showDeleteRuleDialog(d.ruleId, d.ruleName, d.siemId, d.space, d.destName, d.deprecated === 'true');
        },
        // Add link: another destination, or typing a name again, forgets the picked rule.
        linkScope: function (e, sel) { window.tideClearLinkTarget(sel.form); },
        linkName: function (e, input) { input.form.target_rule_id.value = ''; },
        linkPick: function (e, btn) { window.tidePickLinkTarget(btn); },
        // Compare: another linked rule; Merge.
        compareTarget: function (e, sel) { window.tideSwitchCompareTarget(sel.dataset.ruleId, sel.dataset.siemId, sel.dataset.space, sel.value); },
        merge: function (e, btn) { window.tideMergeLinked(btn); },
        // Move onto a destination that already has this rule id: link, or a new rule id.
        moveResolve: function (e, btn) { window.tideMoveResolve(btn); },
    });

    TIDE.actions('ui', {
        // A list row that opens its page (data-href).
        go: function (e, el) { window.location = el.dataset.href; },
        // Expand / Collapse all the remembered sections under data-scope.
        expandAll: function (e, el) { window.setAllRememberedCollapsibles(el.dataset.scope, el.dataset.expand === 'true'); },
        closePanel: function (e, el) { el.closest('.slide-panel-overlay').remove(); },
        // Diagnostics: the look-up's placeholder follows its kind; Support needs a client.
        lookupKind: function (e, sel) { sel.form.q.placeholder = sel.selectedOptions[0].dataset.hint; },
        accessAction: function (e, sel) { sel.form.client.hidden = !sel.value.endsWith('_support'); },
        // Generate baselines: the button counts the ticked ones.
        genCount: function () {
            var a = document.getElementById('gen-preview-area'), b = a.querySelector('.gen-btn-count');
            if (b) b.textContent = a.querySelectorAll('input[name=selected_baselines]:checked').length;
        },
        // A system's Manage baselines: apply the picked template.
        sysBaselineApply: function (e, btn) {
            htmx.ajax('POST', '/api/baselines/' + encodeURIComponent(document.getElementById('sys-bl-apply').value) +
                      '/apply/' + btn.dataset.systemId + '?return=system-dialog', { target: '#modal-container', swap: 'innerHTML' });
        },
    });
})();
