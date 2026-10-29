/*
 * Sigma Rules (pages/rules/sigma.html, partials/sigma_rules_list.html, sigma_rule_detail.html,
 * sigma_convert_result.html). Laid out like the Elastic Rules and Hunting pages: a row opens its rule
 * in the detail pane through library.js. This keeps the conversion settings across the top (target,
 * format, pipeline, the ordered Custom Pipelines and Templates pickers) in the hidden fields of
 * #sigma-settings, which the open rule's view and Convert send, and shows the open rule again when
 * they change. Add your own Sigma rule (⋮) opens a YAML editor (CodeMirror, window.sigmaYamlEditor)
 * and shows that rule the same way. A conversion's create-rule payload opens the rule window.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    var selection = { pipeline: [], template: [] };   // ordered selections in the two pickers
    var ownYaml = '';                                  // the rule of your own on show, if any

    function savedIndices() {
        try { return JSON.parse(localStorage.getItem('sigma-indices') || '[]'); } catch (_e) { return []; }
    }

    // ── Custom Pipelines / Templates pickers ──
    function syncPicker(kind) {
        var combined = selection[kind].join(',');
        var hidden = $('form-' + kind + '-file');
        if (hidden) hidden.value = combined;
        if (kind === 'template') {
            // A template's vars.index_names wins over the saved index patterns.
            var indexField = $('form-index-pattern');
            if (indexField) indexField.value = selection.template.length ? '' : savedIndices().join(', ');
        }
        var label = $(kind + '-dropdown-label'), count = selection[kind].length;
        if (label) label.textContent = count === 0 ? 'None selected' : count + ' ' + kind + (count !== 1 ? 's' : '') + ' selected';
        return combined;
    }

    function toggleOption(kind, el) {
        var val = el.getAttribute('data-value'), idx = selection[kind].indexOf(val);
        if (idx === -1) { selection[kind].push(val); el.classList.add('selected'); }
        else { selection[kind].splice(idx, 1); el.classList.remove('selected'); }
        // Order badges on the selected items, cleared on the rest
        var menu = '#' + kind + '-multiselect';
        selection[kind].forEach(function (v, i) {
            var opt = document.querySelector(menu + ' .pipeline-option[data-value="' + v + '"]');
            var badge = opt && opt.querySelector('.pipeline-option-badge');
            if (badge) badge.textContent = i + 1;
        });
        document.querySelectorAll(menu + ' .pipeline-option:not(.selected) .pipeline-option-badge').forEach(function (b) { b.textContent = ''; });
        syncPicker(kind);
        refreshDetail();
    }

    // Rebuild a picker from the saved-pipelines/-templates API, so edits on Management show without a reload.
    function refreshPicker(kind) {
        var widget = $(kind + '-multiselect');
        if (!widget) return;
        var prev = selection[kind].slice();
        var bust = (typeof crypto !== 'undefined' && crypto.randomUUID) ? crypto.randomUUID() : Date.now();
        var api = '/api/sigma/saved-' + kind + 's';
        fetch(api + '?_v=' + bust, { credentials: 'same-origin' })
            .then(function (r) {
                var ct = (r.headers.get('content-type') || '').toLowerCase();
                if (r.status === 401 || r.redirected || ct.includes('text/html')) {
                    window.location.href = '/login?next=/sigma';
                    throw new Error('Authentication required');
                }
                if (!ct.includes('application/json')) throw new Error('Unexpected response type from ' + api);
                return r.json();
            })
            .then(function (items) {
                widget.innerHTML = '';
                items.forEach(function (it) {
                    var row = document.createElement('button');
                    row.className = 'pipeline-option';
                    row.setAttribute('type', 'button');
                    row.setAttribute('data-value', it.filename);
                    var ord = prev.indexOf(it.filename);
                    if (ord !== -1) row.classList.add('selected');
                    row.innerHTML =
                        '<span class="pipeline-option-check">' + TIDE.iconHtml('check', 10) + '</span>' +
                        '<span class="pipeline-option-name">' + it.display + '</span>' +
                        '<span class="pipeline-option-badge">' + (ord !== -1 ? (ord + 1) : '') + '</span>';
                    widget.appendChild(row);
                });
                // Keep only the selections still present
                selection[kind] = prev.filter(function (v) { return items.some(function (p) { return p.filename === v; }); });
                syncPicker(kind);
            })
            .catch(function (e) { console.error('[Sigma] Failed to refresh ' + kind + ' list:', e); });
    }

    // ── The settings the view and Convert send ──
    function settings() {
        var pairs = { 'form-backend': 'backend-select', 'form-pipeline': 'pipeline-select', 'form-format': 'format-select' };
        Object.keys(pairs).forEach(function (hidden) {
            if ($(hidden) && $(pairs[hidden])) $(hidden).value = $(pairs[hidden]).value;
        });
        syncPicker('pipeline');
        syncPicker('template');
        var values = {};
        document.querySelectorAll('#sigma-settings input[type="hidden"]').forEach(function (i) { values[i.name] = i.value; });
        return values;
    }

    // The open rule again (a SigmaHQ one, or yours), converted with the settings as they are now.
    function refreshDetail() {
        if (!window.htmx || !$('sigma-detail')) return;
        var values = settings();
        if (ownYaml) {
            values.yaml_content = ownYaml;
            htmx.ajax('POST', '/api/sigma/render', { target: '#sigma-detail', swap: 'innerHTML', values: values });
            return;
        }
        var selected = ($('selected-rule-id') || {}).value || '';
        if (selected) {
            htmx.ajax('GET', '/api/sigma/rules/' + encodeURIComponent(selected) + '/view',
                { target: '#sigma-detail', swap: 'innerHTML', values: values });
        }
    }

    // A row opened: that is the rule on show now, not one of your own.
    document.addEventListener('click', function (e) {
        if (e.target.closest && e.target.closest('#rules-list [data-item-id]')) ownYaml = '';
    }, true);

    // ── Add your own Sigma rule ──
    function editor() {
        if (window.sigmaYamlEditor) return Promise.resolve(window.sigmaYamlEditor);
        return TIDE.codeMirrorYaml().then(function () {
            var ta = $('yaml-editor');
            var cm = CodeMirror.fromTextArea(ta, {
                mode: 'yaml', theme: 'material-darker', lineNumbers: true, lineWrapping: true,
                tabSize: 2, indentWithTabs: false, autofocus: true,
            });
            cm.on('change', function () { ta.value = cm.getValue(); });   // Validate sends the textarea
            window.sigmaYamlEditor = cm;
            return cm;
        });
    }

    function openOwn() {
        var modal = $('sigma-own-modal');
        if (!modal) return;
        modal.style.display = 'flex';
        editor().then(function (cm) {
            if (ownYaml && !cm.getValue()) cm.setValue(ownYaml);
            setTimeout(function () { cm.refresh(); cm.focus(); }, 10);
        }).catch(function (e) { console.error('[Sigma] YAML editor failed to load:', e); });
    }

    function showOwn() {
        var cm = window.sigmaYamlEditor, yaml = cm ? cm.getValue() : (($('yaml-editor') || {}).value || '');
        if (!yaml.trim()) {
            $('validation-result').innerHTML = '<div class="alert alert-warning">Paste or write a Sigma rule first.</div>';
            return;
        }
        ownYaml = yaml;
        // Nothing in the browser is open now.
        var hidden = $('selected-rule-id');
        if (hidden) hidden.value = '';
        document.querySelectorAll('#rules-list .sigma-rule-selected').forEach(function (el) { el.classList.remove('sigma-rule-selected'); });
        var url = new URL(window.location.href);
        url.searchParams.delete('rule');
        history.replaceState(history.state, '', url);
        $('sigma-own-modal').style.display = 'none';
        refreshDetail();
        var scroller = $('sigma-detail');
        if (scroller) scroller.scrollTop = 0;
    }

    function clearEditor() {
        if (window.sigmaYamlEditor) window.sigmaYamlEditor.setValue('');
        var ta = $('yaml-editor');
        if (ta) ta.value = '';
        $('validation-result').innerHTML = '';
    }

    // ── The page ──
    TIDE.page('#sigma-settings', function () {
        window.sigmaYamlEditor = null;   // the previous visit's editor is gone with its page
        ownYaml = '';
        selection = { pipeline: [], template: [] };

        // Saved index patterns (Preferences) apply only when no template is selected:
        // a template's vars.index_names wins.
        var idxField = $('form-index-pattern'), saved = savedIndices();
        if (idxField && saved.length) idxField.value = saved.join(', ');

        refreshPicker('pipeline');
        refreshPicker('template');
        ['pipeline', 'template'].forEach(function (kind) {
            var menu = $(kind + '-multiselect');
            if (menu) menu.addEventListener('click', function (e) {
                var opt = e.target.closest('.pipeline-option');
                if (!opt) return;
                e.preventDefault();
                toggleOption(kind, opt);
            });
        });

        var backendSelect = $('backend-select');
        if (backendSelect) backendSelect.addEventListener('change', function () {
            var backend = this.value;
            // This backend's output formats
            fetch('/api/sigma/formats/' + backend, { credentials: 'same-origin' })
                .then(function (response) {
                    if (response.status === 401) {
                        window.location.href = '/login?next=/sigma';
                        throw new Error('Authentication required');
                    }
                    return response.text();
                })
                .then(function (html) { $('format-select').innerHTML = html; window.tideFilterSync($('sigma-settings')); settings(); })
                .catch(function (err) { console.error('Failed to load formats:', err); });
            refreshDetail();
        });
        var pipelineSelect = $('pipeline-select');
        if (pipelineSelect) pipelineSelect.addEventListener('change', refreshDetail);
        var formatSelect = $('format-select');
        if (formatSelect) formatSelect.addEventListener('change', settings);

        // Opened with a rule (?rule=…): show it with these settings.
        var detail = $('sigma-detail');
        if (detail && detail.getAttribute('data-rule-id')) refreshDetail();
    });

    // A converted rule with a create-rule payload opens it in the shared rule window.
    TIDE.page('[data-sigma-prefill]', function (el) {
        var prefill = el.getAttribute('data-sigma-prefill');
        if (prefill && window.htmx) {
            setTimeout(function () {
                htmx.ajax('GET', '/api/rules/create-form?prefill=' + prefill, { target: '#modal-container', swap: 'innerHTML' });
            }, 0);
        }
    });

    TIDE.actions('sigma', {
        ownRule: openOwn,
        showOwn: showOwn,
        clear: clearEditor,
    });
})();
