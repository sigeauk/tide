/*
 * Controls used across the app, over the helpers in app.js: the sidebar (nav groups, the account
 * group's theme switch, collapse) and client switcher, MITRE technique pills (open the side panel), the rule
 * window's Move / Delete / Add link and Record outcome…, the rule compare window, clickable list rows, Expand / Collapse
 * all, inline tabs, a select that loads what it picks, a few form helpers (diagnostics, generate baselines, a
 * system's Add baseline), and the scrollbar inset of a page in Rule Health's layout.
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

    // Record outcome…: the outcome's meaning beneath it, who fixes what it calls for, and Needs tuning
    // ticked for an outcome that calls for tuning.
    TIDE.actions('tuning', {
        outcome: function (e, sel) {
            var opt = sel.selectedOptions[0], form = sel.form;
            if (!opt || !opt.value) return;
            form.querySelector('[data-tuning-meaning]').textContent = opt.dataset.meaning;
            form.querySelector('[data-tuning-needs]').checked = opt.dataset.tune === 'true';
            form.querySelector('[data-tuning-fixer]').textContent = opt.dataset.fixer ? 'Who fixes: ' + opt.dataset.fixer : '';
        },
    });

    TIDE.actions('ui', {
        // A list row that opens its page (data-href).
        go: function (e, el) { window.location = el.dataset.href; },
        // Expand / Collapse all the folds under data-scope, remembered.
        expandAll: function (e, el) { window.tideSetFolds(el.dataset.scope, el.dataset.expand === 'true'); },
        closePanel: function (e, el) { el.closest('.slide-panel-overlay').remove(); },
        // Diagnostics: the look-up's placeholder follows its kind; Support needs a client.
        lookupKind: function (e, sel) { sel.form.q.placeholder = sel.selectedOptions[0].dataset.hint; },
        // (form.client would also find the enhanced select's button, which carries the same name.)
        accessAction: function (e, sel) { sel.form.querySelector('select[name="client"]').hidden = !sel.value.endsWith('_support'); },
        // A system's Add baseline: apply the picked template (the page then reloads).
        sysBaselineApply: function (e, btn) {
            htmx.ajax('POST', '/api/baselines/' + encodeURIComponent(document.getElementById('sys-bl-apply').value) +
                      '/apply/' + btn.dataset.systemId + '?return=system-dialog', { target: '#modal-container', swap: 'innerHTML' });
        },
        // Inline tabs (.settings-tabs--inline, role="tablist"): the tab shows the panel its aria-controls
        // names and hides its siblings', and puts ?tab=<data-tab> in the address so a reload or a link
        // keeps it (a client's page, Simulations).
        tab: function (e, btn) {
            btn.closest('[role="tablist"]').querySelectorAll('[role="tab"]').forEach(function (t) {
                var on = t === btn, panel = document.getElementById(t.getAttribute('aria-controls'));
                t.classList.toggle('active', on);
                t.setAttribute('aria-selected', on ? 'true' : 'false');
                if (panel) panel.hidden = !on;
            });
            var url = new URL(window.location.href);
            url.searchParams.set('tab', btn.dataset.tab);
            history.replaceState(history.state, '', url);
        },
        // A select that shows what its choice picks: data-url with {id} as the chosen value, into data-target.
        load: function (e, sel) {
            htmx.ajax('GET', sel.dataset.url.replace('{id}', encodeURIComponent(sel.value)),
                      { target: sel.dataset.target, swap: 'innerHTML' });
        },
    });

    // A page in Rule Health's layout (.rule-browser-page: Threat Landscape, the MITRE pages, ...)
    // keeps its figures and filters as wide as the cards scrolling below them: the scroll region
    // reserves a scrollbar gutter, and the controls take the same inset (--rh-gutter, style.css).
    TIDE.page('.rule-browser-page', function (page) {
        var region = page.querySelector(':scope > .rule-scroll-region');
        if (!region) return;
        var measure = function () { page.style.setProperty('--rh-gutter', Math.max(0, region.offsetWidth - region.clientWidth) + 'px'); };
        measure();
        if (window.ResizeObserver) new ResizeObserver(measure).observe(region);
    });
})();
