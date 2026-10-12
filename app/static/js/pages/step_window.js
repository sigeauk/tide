/*
 * The baseline technique windows (components/step_modal.html; template_step_modal.html shares
 * Risks): Risks view / form, Add coverage (a rule, a gap or N/A, a dashboard / report / log),
 * relinking a mapping to another rule, a watch item's Update, and the rule picker's results
 * (partials/siem_rule_options.html).
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    function toggleRisks(editing) {
        $('sm-risks-view').hidden = editing;
        $('sm-risks-form').hidden = !editing;
        if (editing) $('sm-risk-priority').focus();
    }

    // Relink: the rule picker, searched by the mapping's rule name; picking a rule points that
    // mapping at it (replace_id) instead of adding another.
    function setRelink(btn) {
        $('siem-det-replace').value = btn ? btn.dataset.relinkId : '';
        $('sm-relink-name').textContent = btn ? btn.dataset.relinkName : '';
        $('sm-relink-note').hidden = !btn;
    }

    // Add coverage: the type picks the form under it.
    function coverageKind(kind) {
        var shown = { rule: 'sm-cov-rule', gap: 'sm-cov-mark', na: 'sm-cov-mark' }[kind] || 'sm-cov-watch';
        document.querySelectorAll('#sm-add-coverage [data-cov-form]').forEach(function (el) { el.hidden = el.id !== shown; });
        if (kind === 'rule') {
            var input = $('sm-rule-search'), picker = $('sm-cov-rule');
            input.focus();
            if (!picker.dataset.loaded) { picker.dataset.loaded = '1'; htmx.trigger(input, 'tideOpenPicker'); }
        } else if (kind === 'gap' || kind === 'na') {
            $('sm-gap-type').value = kind;
            $('sm-gap-reason').focus();
        } else {
            $('sm-cov-watch-kind').value = kind;
            $('sm-cov-title').focus();
        }
    }

    function openCoverage() {
        var panel = $('sm-add-coverage');
        panel.hidden = false;
        panel.scrollIntoView({ block: 'nearest' });
    }

    // A dashboard, report or log's Update: its card shows its form in place of its body.
    function editWatch(el, editing) {
        var item = el.closest('[data-watch-item]');
        item.querySelector('[data-watch-view]').hidden = editing;
        item.querySelector('[data-watch-form]').hidden = !editing;
        if (editing) item.querySelector('[data-watch-form] input[name="title"]').focus();
    }

    // A refused dashboard / report / log comes back with its form open.
    TIDE.page('#sm-add-coverage', function (panel) {
        if (!panel.hidden) coverageKind($('sm-cov-kind').value);
    });

    TIDE.actions('step', {
        risksEdit: function () { toggleRisks(true); },
        risksCancel: function () { toggleRisks(false); },
        coverageAdd: function () {
            setRelink(null);
            openCoverage();
            coverageKind($('sm-cov-kind').value);
        },
        coverageClose: function () { $('sm-add-coverage').hidden = true; },
        coverageKind: function (e, sel) { coverageKind(sel.value); },
        relink: function (e, btn) {
            var input = $('sm-rule-search');
            setRelink(btn);
            $('sm-cov-kind').value = 'rule';
            input.value = btn.dataset.relinkQuery || '';
            $('sm-cov-rule').dataset.loaded = '1';   // one search, by name
            openCoverage();
            coverageKind('rule');
            htmx.trigger(input, 'tideOpenPicker');
        },
        watchEdit: function (e, el) { editWatch(el, true); },
        watchCancel: function (e, el) { editWatch(el, false); },
        // A rule picked in the picker: posted with its destination -- the same rule at two
        // destinations is two different mappings.
        pickRule: function (e, btn) {
            $('siem-det-rule-ref').value = btn.dataset.ruleId;
            $('siem-det-rule-scope').value = btn.dataset.scope || '';
            document.querySelector('#add-siem-det-form input[name="note"]').value = btn.dataset.ruleName || '';
            htmx.trigger($('add-siem-det-form'), 'submit');
        },
    });
})();
