/*
 * The create / edit rule form (components/rule_create_form.html): the MITRE technique rows
 * (tactic, then technique; the techniques come from the form's JSON [data-technique-groups]),
 * Rule type and the settings it shows (a threshold, new terms or indicator match rule's, with
 * field names suggested), a destination's default index, and the edit form's required Reason for
 * Change.
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
            techniqueSelect.replaceChildren(createOption('', 'Select a technique…', false));
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
            tacticSelect.appendChild(createOption('', 'Select a tactic…', true));
            groups.forEach(function (group) { tacticSelect.appendChild(createOption(group.tactic, group.tactic, false)); });
            var techniqueSelect = document.createElement('select');
            techniqueSelect.className = 'rule-form-select';
            techniqueSelect.setAttribute('data-role', 'technique');
            techniqueSelect.appendChild(createOption('', 'Select a technique…', true));
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

    // The types with settings of their own (rules._FORM_TYPES).
    var TYPED = ['threshold', 'new_terms', 'threat_match'];

    // Rule type: Query language takes what the type takes (its option's data-languages), and each
    // [data-rule-types] block shows for its types only. A hidden block's fields (those that post) are
    // disabled, so they are neither checked nor posted. A typed rule starts its query on *:*.
    function initRuleType(form, onType) {
        var typeSelect = form.querySelector('#rule-type'), language = form.querySelector('#rule-language');
        if (!typeSelect || !language) return;
        var posted = form.querySelector('input[type="hidden"][name="type"]');
        function apply(changed) {
            var type = posted ? posted.value : typeSelect.value;
            var option = typeSelect.options[typeSelect.selectedIndex];
            var allowed = ((option && option.getAttribute('data-languages')) || 'kuery kql lucene').split(' ');
            Array.prototype.forEach.call(language.options, function (o) { o.disabled = allowed.indexOf(o.value) === -1; });
            if (allowed.indexOf(language.value) === -1) language.value = allowed[0];
            form.querySelectorAll('[data-rule-types]').forEach(function (block) {
                var on = block.getAttribute('data-rule-types').split(' ').indexOf(type) !== -1;
                block.hidden = !on;
                block.querySelectorAll('input[name], select[name], textarea[name]').forEach(function (field) { field.disabled = !on; });
            });
            var query = form.querySelector('#rule-query');
            if (changed && TYPED.indexOf(type) !== -1 && query && !query.value.trim()) query.value = '*:*';
            onType(type);
        }
        typeSelect.addEventListener('change', function () { apply(true); });
        apply(false);
    }

    // Field names to suggest as you type a field (the <datalist>s), from TIDE's field catalogue for
    // the index patterns given (rules.field_suggestions, which never asks the SIEM). Loaded when a
    // typed rule's fields are shown, and again when its patterns or destination change.
    function initFieldSuggestions(form) {
        var scope = form.querySelector('#rule-scope-pair'), fixed = form.querySelector('input[type="hidden"][name="scope_pair"]');
        var lists = [['#rule-index', '#rule-source-fields'], ['#rule-threat-index', '#rule-indicator-fields']];
        var wanted = false;
        function load(inputSel, listSel) {
            var input = form.querySelector(inputSel), list = form.querySelector(listSel);
            var pair = (fixed && fixed.value) || (scope && scope.value) || '';
            if (!wanted || !input || !list) return;
            if (!pair || !input.value.trim()) { list.replaceChildren(); return; }
            fetch('/api/rules/field-suggestions?scope_pair=' + encodeURIComponent(pair) + '&patterns=' + encodeURIComponent(input.value.trim()),
                  { headers: { 'HX-Request': 'true' } })
                .then(function (r) { return r.ok ? r.text() : ''; })
                .then(function (html) { list.innerHTML = html; })
                .catch(function () { /* no suggestions: any field can still be typed */ });
        }
        function loadAll() { lists.forEach(function (l) { load(l[0], l[1]); }); }
        lists.forEach(function (l) {
            var input = form.querySelector(l[0]);
            if (input) input.addEventListener('change', function () { load(l[0], l[1]); });
        });
        if (scope) scope.addEventListener('change', loadAll);
        return function (type) {
            var was = wanted;
            wanted = TYPED.indexOf(type) !== -1;
            if (wanted && !was) loadAll();
        };
    }

    // A list of field names (a threshold's Group by, a new terms rule's Fields): a row each, its name
    // suggested from the rule's index fields, kept as comma-separated text in the hidden input named
    // by data-field-list. At most three, as Kibana takes; Remove on the last row empties it.
    function initFieldLists(form) {
        form.querySelectorAll('[data-field-list]').forEach(function (box) {
            var hidden = form.querySelector('input[type="hidden"][name="' + box.getAttribute('data-field-list') + '"]');
            if (!hidden) return;
            var label = box.getAttribute('data-label') || 'Field', MAX = 3;
            var values = hidden.value.split(',').map(function (v) { return v.trim(); }).filter(Boolean);
            if (!values.length) values = [''];
            function sync() { hidden.value = values.map(function (v) { return v.trim(); }).filter(Boolean).join(', '); }
            function render(focus) {
                box.replaceChildren();
                values.forEach(function (value, i) {
                    var row = document.createElement('div');
                    row.className = 'tm-row tm-row--one';
                    var input = document.createElement('input');
                    input.type = 'text';
                    input.className = 'rule-form-control mono';
                    input.value = value;
                    input.placeholder = label;
                    input.autocomplete = 'off';
                    input.setAttribute('list', 'rule-source-fields');
                    input.setAttribute('aria-label', label);
                    input.addEventListener('input', function () { values[i] = input.value; sync(); });
                    var remove = document.createElement('button');
                    remove.type = 'button';
                    remove.className = 'btn btn-secondary btn-sm';
                    remove.textContent = 'Remove';
                    remove.addEventListener('click', function () {
                        values.splice(i, 1);
                        if (!values.length) values = [''];
                        render();
                    });
                    row.append(input, remove);
                    box.appendChild(row);
                });
                if (values.length < MAX) {
                    var actions = document.createElement('div');
                    actions.className = 'tm-actions';
                    var add = document.createElement('button');
                    add.type = 'button';
                    add.className = 'btn btn-secondary btn-sm';
                    add.textContent = 'Add field';
                    add.addEventListener('click', function () { values.push(''); render(values.length - 1); });
                    actions.appendChild(add);
                    box.appendChild(actions);
                }
                sync();
                if (focus !== undefined) box.querySelectorAll('input')[focus].focus();
            }
            render();
        });
    }

    // Indicator mapping (rule_type_settings): groups joined by OR, each of entries joined by AND, kept
    // in the hidden JSON input. An entry Kibana holds as "does not match" (Kibana 9.x) is shown as it
    // is and kept: the form never makes or changes one (047741/TIDE#91).
    function initThreatMapping(form) {
        var builder = form.querySelector('#threat-mapping-builder'), hidden = form.querySelector('#rule-threat-mapping');
        if (!builder || !hidden) return;
        var groups;
        try { groups = JSON.parse(hidden.value || '[]'); } catch (_) { groups = []; }
        function blank() { return { entries: [{ field: '', value: '' }] }; }
        if (!groups.length) groups = [blank()];

        function sync() {
            hidden.value = JSON.stringify(groups.map(function (group) {
                return { entries: group.entries.map(function (e) {
                    var entry = { field: e.field || '', type: 'mapping', value: e.value || '' };
                    if (e.negate) entry.negate = true;
                    return entry;
                }) };
            }));
        }
        function field(list, value, label, locked, onInput) {
            var input = document.createElement('input');
            input.type = 'text';
            input.className = 'rule-form-control mono';
            input.value = value || '';
            input.placeholder = label;
            input.autocomplete = 'off';
            input.setAttribute('list', list);
            input.setAttribute('aria-label', label);
            if (locked) input.disabled = true;
            else input.addEventListener('input', function () { onInput(input.value.trim()); sync(); });
            return input;
        }
        function button(text, onClick) {
            var b = document.createElement('button');
            b.type = 'button';
            b.className = 'btn btn-secondary btn-sm';
            b.textContent = text;
            b.addEventListener('click', onClick);
            return b;
        }
        function join(text) {
            var el = document.createElement('div');
            el.className = 'tm-join';
            el.textContent = text;
            return el;
        }
        function render(focus) {
            builder.replaceChildren();
            groups.forEach(function (group, gi) {
                if (gi) builder.appendChild(join('OR'));
                var box = document.createElement('div');
                box.className = 'tm-group';
                group.entries.forEach(function (entry, ei) {
                    if (ei) box.appendChild(join('AND'));
                    var row = document.createElement('div');
                    row.className = 'tm-row';
                    var op = document.createElement('span');
                    op.className = 'tm-op';
                    op.textContent = entry.negate ? 'does not match' : 'matches';
                    var end = entry.negate ? document.createElement('span') : button('Remove', function () {
                        group.entries.splice(ei, 1);
                        if (!group.entries.length) groups.splice(gi, 1);
                        if (!groups.length) groups = [blank()];
                        render();
                    });
                    if (entry.negate) row.title = 'Kibana holds this as "does not match": TIDE keeps it as it is.';
                    row.append(field('rule-source-fields', entry.field, 'Field', entry.negate, function (v) { entry.field = v; }), op,
                               field('rule-indicator-fields', entry.value, 'Indicator index field', entry.negate, function (v) { entry.value = v; }), end);
                    box.appendChild(row);
                });
                var actions = document.createElement('div');
                actions.className = 'tm-actions';
                actions.appendChild(button('AND', function () { group.entries.push({ field: '', value: '' }); render(gi); }));
                box.appendChild(actions);
                builder.appendChild(box);
            });
            var more = document.createElement('div');
            more.className = 'tm-actions';
            more.appendChild(button('OR', function () { groups.push(blank()); render(groups.length - 1); }));
            builder.appendChild(more);
            sync();
            if (focus !== undefined) {
                var inputs = builder.querySelectorAll('.tm-group')[focus].querySelectorAll('input:not([disabled])');
                if (inputs.length) inputs[inputs.length - 2 >= 0 ? inputs.length - 2 : 0].focus();
            }
        }
        render();
    }

    function initForm(form) {
        var mode = form.dataset.mode;
        var scopeSelect = form.querySelector('#rule-scope-pair'), indexInput = form.querySelector('#rule-index');
        var reasonInput = form.querySelector('#rule-reason'), errorBox = form.querySelector('#rule-form-error');

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

        // A rule that searches a data view: Use index patterns instead shows the patterns to save
        // in its place (filled with the data view's own); unticked, none are sent.
        var useIndex = form.querySelector('#rule-use-index'), indexSection = form.querySelector('#rule-index-section');
        if (useIndex && indexSection && indexInput) {
            useIndex.addEventListener('change', function () {
                indexSection.hidden = !useIndex.checked;
                indexInput.disabled = !useIndex.checked;
                indexInput.required = useIndex.checked;
            });
        }

        function showError(message) { showFormError(form, message); }
        function clearError() { if (errorBox) errorBox.replaceChildren(); }

        // A field the user can't see (its section is folded) must say what's wrong: otherwise the
        // browser refuses to submit and shows nothing, and Save looks like it does nothing.
        // (app.js opens the sections of every invalid field; this names the first.)
        function reveal(field) {
            var section = field.closest('details');
            if (section && !section.open) section.open = true;
            var btn = field.classList.contains('tide-select__native') && field.parentElement.querySelector(':scope > .tide-filter-btn');
            (btn || field).focus();
        }
        form.addEventListener('invalid', function (evt) {
            var field = evt.target, label = field.id && form.querySelector('label[for="' + field.id + '"]');
            if (form.querySelector(':invalid') !== field) return;     // report the first one only
            reveal(field);
            showError(((label && label.textContent) || field.name).replace('*', '').trim() + ': ' + field.validationMessage);
        }, true);

        // Saving an edit needs a Reason for Change.
        function enforceEditReason() {
            if (mode !== 'edit') return true;
            if (reasonInput) reasonInput.value = (reasonInput.value || '').trim();
            if (reasonInput && reasonInput.value) return true;
            if (reasonInput) reveal(reasonInput);
            showError('Reason for Change is required before saving.');
            return false;
        }
        if (reasonInput) reasonInput.addEventListener('input', clearError);
        form.addEventListener('submit', function (evt) {
            clearError();
            if (!enforceEditReason()) { evt.preventDefault(); evt.stopPropagation(); }
        });
        // Only the form's own save: not a request from something inside it.
        form.addEventListener('htmx:beforeRequest', function (evt) {
            if (evt.detail.elt !== form) return;
            clearError();
            if (!enforceEditReason()) evt.preventDefault();
        });

        form.addEventListener('htmx:sendError', function (evt) {
            if (evt.detail.elt !== form) return;
            showError('TIDE could not be reached, so nothing was saved. Check your connection and try again.');
        });
    }

    function showFormError(form, message) {
        var box = form.querySelector('#rule-form-error');
        if (!box) return;
        var note = document.createElement('p');
        note.className = 'rm-note rm-note--danger';
        note.setAttribute('role', 'alert');
        note.textContent = message;
        box.replaceChildren(note);
    }

    // The server refused a save (rules._form_error): show why in the form, keeping what was typed,
    // instead of the page's generic "request failed" toasts. A lapsed sign-in still goes to the
    // login page. htmx fires this on the swap target (#modal-container), so it is caught here.
    document.addEventListener('htmx:beforeSwap', function (evt) {
        var form = evt.detail.requestConfig && evt.detail.requestConfig.elt, status = evt.detail.xhr.status;
        if (!form || !form.matches || !form.matches('.rule-create-form') || status < 400 || status === 401) return;
        evt.detail.shouldSwap = false;
        evt.detail.isError = false;
        var text = new DOMParser().parseFromString(evt.detail.xhr.responseText || '', 'text/html').body.textContent;
        showFormError(form, (text || '').trim() || 'Could not save (HTTP ' + status + '). Nothing was changed.');
    });

    // A rule saved (create or edit): sync so it shows up. Rule Health shows the sync's progress
    // in its tracker; from anywhere else (a technique window's Sigma Convert) the sync just runs.
    TIDE.page('[data-start-sync]', function (el) {
        el.remove();
        var s = document.getElementById('sync-status');
        htmx.ajax('POST', '/api/rules/sync', s ? { target: s, swap: 'outerHTML' } : { target: 'body', swap: 'none' });
    });

    TIDE.page('.rule-create-form', function (form) {
        initMitreBuilder(form);
        initThreatMapping(form);
        initFieldLists(form);
        initRuleType(form, initFieldSuggestions(form));
        initForm(form);
    });
})();
