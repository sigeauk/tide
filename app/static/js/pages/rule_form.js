/*
 * The create / edit rule form (components/rule_create_form.html): the MITRE technique rows
 * (tactic, then technique; the techniques come from the form's JSON [data-technique-groups]),
 * a destination's default index, and the edit form's required Reason for Change.
 */
(function () {
    'use strict';

    function createOption(value, text, selected) {
        var option = document.createElement('option');
        option.value = value;
        option.textContent = text;
        if (selected) option.selected = true;
        return option;
    }

    function initMitreBuilder(form) {
        var builder = form.querySelector('#mitre-builder'), addBtn = form.querySelector('#mitre-add-btn');
        var hidden = form.querySelector('#rule-mitre-values'), data = form.querySelector('[data-technique-groups]');
        if (!builder || !addBtn || !hidden || !data) return;
        var groups = JSON.parse(data.textContent);
        var selectedIds = (hidden.value || '').split(',').map(function (v) { return v.trim().toUpperCase(); }).filter(Boolean);

        function updateTechniqueSelect(tacticSelect, techniqueSelect, selectedTechnique) {
            techniqueSelect.replaceChildren(createOption('', 'Select a technique...', false));
            var group = tacticSelect.value && groups.find(function (item) { return item.tactic === tacticSelect.value; });
            if (!group) return;
            group.options.forEach(function (opt) {
                techniqueSelect.appendChild(createOption(opt.id, opt.id + ' - ' + opt.name, opt.id === selectedTechnique));
            });
        }

        function syncHidden() {
            hidden.value = Array.from(builder.querySelectorAll('select[data-role="technique"]'))
                .map(function (select) { return (select.value || '').trim().toUpperCase(); })
                .filter(Boolean)
                .join(', ');
        }

        function addRow(initialTechnique) {
            var row = document.createElement('div');
            row.className = 'mitre-builder-row';
            var tacticSelect = document.createElement('select');
            tacticSelect.className = 'rule-form-select';
            tacticSelect.setAttribute('data-role', 'tactic');
            tacticSelect.appendChild(createOption('', 'Select a tactic...', true));
            groups.forEach(function (group) { tacticSelect.appendChild(createOption(group.tactic, group.tactic, false)); });
            var techniqueSelect = document.createElement('select');
            techniqueSelect.className = 'rule-form-select';
            techniqueSelect.setAttribute('data-role', 'technique');
            techniqueSelect.appendChild(createOption('', 'Select a technique...', true));
            var removeBtn = document.createElement('button');
            removeBtn.type = 'button';
            removeBtn.className = 'btn btn-secondary btn-sm';
            removeBtn.textContent = 'Remove';
            row.append(tacticSelect, techniqueSelect, removeBtn);
            builder.appendChild(row);

            if (initialTechnique) {
                var matched = groups.find(function (group) {
                    return group.options.some(function (opt) { return opt.id === initialTechnique; });
                });
                if (matched) {
                    tacticSelect.value = matched.tactic;
                    updateTechniqueSelect(tacticSelect, techniqueSelect, initialTechnique);
                }
            }
            tacticSelect.addEventListener('change', function () {
                updateTechniqueSelect(tacticSelect, techniqueSelect, '');
                syncHidden();
            });
            techniqueSelect.addEventListener('change', syncHidden);
            removeBtn.addEventListener('click', function () {
                row.remove();
                syncHidden();
                if (!builder.children.length) addRow('');
            });
            syncHidden();
        }

        if (selectedIds.length) selectedIds.forEach(function (id) { addRow(id); });
        else addRow('');
        addBtn.addEventListener('click', function () { addRow(''); });
    }

    function initForm(form) {
        var mode = form.dataset.mode;
        var scopeSelect = form.querySelector('#rule-scope-pair'), indexInput = form.querySelector('#rule-index');
        var reasonInput = form.querySelector('#rule-reason'), popup = document.getElementById('rule-form-popup');

        // A destination's default index fills an empty index field (an operator's own value wins).
        function updateDefaultIndex() {
            if (!scopeSelect || !indexInput) return;
            var selected = scopeSelect.options[scopeSelect.selectedIndex];
            var defaultIndex = selected && (selected.getAttribute('data-default-index') || '').trim();
            if (defaultIndex && !indexInput.value.trim()) indexInput.value = defaultIndex;
        }
        if (scopeSelect) {
            scopeSelect.addEventListener('change', updateDefaultIndex);
            if (mode === 'create') updateDefaultIndex();
        }

        function showPopup(message) {
            if (!popup) return;
            popup.textContent = message;
            popup.style.display = 'inline-flex';
        }
        function hidePopup() {
            if (!popup) return;
            popup.style.display = 'none';
            popup.textContent = '';
        }
        if (reasonInput) reasonInput.addEventListener('input', hidePopup);

        // Saving an edit needs a Reason for Change.
        function enforceEditReason() {
            if (mode !== 'edit') return true;
            if (reasonInput) reasonInput.value = (reasonInput.value || '').trim();
            if (reasonInput && reasonInput.value) return true;
            var about = Array.from(document.querySelectorAll('.rule-accordion > summary')).find(function (summary) {
                return (summary.textContent || '').trim().toLowerCase() === 'about rule';
            });
            if (about && about.parentElement && !about.parentElement.open) about.parentElement.open = true;
            if (reasonInput) reasonInput.focus();
            showPopup('Reason for Change is required before saving.');
            return false;
        }
        form.addEventListener('submit', function (evt) {
            hidePopup();
            if (!enforceEditReason()) { evt.preventDefault(); evt.stopPropagation(); }
        });
        form.addEventListener('htmx:beforeRequest', function (evt) {
            hidePopup();
            if (!enforceEditReason()) evt.preventDefault();
        });
    }

    // A rule saved (create or edit): sync so it shows up. Rule Health shows the sync's progress
    // in its tracker; from anywhere else (a technique window's Sigma Convert) the sync just runs.
    TIDE.page('[data-start-sync]', function (el) {
        el.remove();
        var s = document.getElementById('sync-status');
        htmx.ajax('POST', '/api/rules/sync', s ? { target: s, swap: 'outerHTML' } : { target: 'body', swap: 'none' });
    });

    TIDE.page('.rule-create-form', function (form) {
        initMitreBuilder(form);
        initForm(form);
    });
})();
