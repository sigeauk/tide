/*
 * Sigma Converter (pages/rules/sigma.html, partials/sigma_rules_list.html, sigma_convert_result.html):
 * the YAML editor (CodeMirror, kept on window.sigmaYamlEditor), the rule browser, the backend /
 * format / pipeline selects and the ordered Custom Pipelines and Templates pickers, Convert and
 * Deploy, and opening a converted rule in the create-rule window.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    // On hx-boost navigation, head-support does not run <script defer> tags added to <head>, so
    // the vendor scripts are loaded here when missing.
    function loadScript(src) {
        return new Promise(function (resolve, reject) {
            if (document.querySelector('script[data-tide-loaded="' + src + '"]')) { resolve(); return; }
            var s = document.createElement('script');
            s.src = src;
            s.setAttribute('data-tide-loaded', src);
            s.onload = resolve;
            s.onerror = function () { reject(new Error('Failed to load ' + src)); };
            document.head.appendChild(s);
        });
    }

    var selection = { pipeline: [], template: [] };   // ordered selections in the two pickers
    var selectedRuleId = '';

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
                        '<span class="pipeline-option-check">&#10003;</span>' +
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

    function toggleMenu(kind) {
        var dd = $(kind + '-multiselect');
        if (dd) dd.style.display = dd.style.display === 'none' ? '' : 'none';
    }

    // Close a picker on a click outside it
    document.addEventListener('click', function (e) {
        ['pipeline', 'template'].forEach(function (kind) {
            var dd = $(kind + '-multiselect'), btn = $(kind + '-dropdown-btn');
            if (dd && btn && dd.style.display !== 'none' && !dd.contains(e.target) && !btn.contains(e.target)) dd.style.display = 'none';
        });
    });

    function syncDeploySiemId() {
        var sel = $('deploy-space-select'), siem = $('deploy-siem-id');
        if (!sel || !siem) return;
        var opt = sel.options[sel.selectedIndex];
        siem.value = (opt && opt.dataset) ? (opt.dataset.siemId || '') : '';
    }

    // ── Rule browser ──
    function setSelectedRule(ruleId, syncHiddenField) {
        selectedRuleId = ruleId || '';
        document.querySelectorAll('#rules-list [data-rule-id]').forEach(function (row) {
            var isSelected = !!ruleId && row.getAttribute('data-rule-id') === ruleId;
            row.classList.toggle('sigma-rule-selected', isSelected);
            var summaryOrBtn = row.querySelector('.rule-item-btn');
            if (summaryOrBtn) summaryOrBtn.classList.toggle('sigma-rule-selected', isSelected);
        });
        if (syncHiddenField !== false) {
            var hidden = $('selected-rule-id');
            if (hidden) hidden.value = ruleId || '';
        }
    }

    // One expanded rule card at a time.
    function bindAccordion() {
        var ruleList = $('rules-list');
        if (!ruleList) return;
        ruleList.querySelectorAll('details.sigma-rule-card--expandable').forEach(function (card) {
            if (card._sigmaAccordionBound) return;
            card._sigmaAccordionBound = true;
            card.addEventListener('toggle', function () {
                if (!card.open) return;
                ruleList.querySelectorAll('details.sigma-rule-card--expandable[open]').forEach(function (other) {
                    if (other !== card) other.open = false;
                });
            });
        });
    }
    document.addEventListener('htmx:afterSwap', function (event) {
        var target = event.detail && event.detail.target;
        if (!target || target.id !== 'rules-list') return;
        bindAccordion();
        if (selectedRuleId) setSelectedRule(selectedRuleId, false);
    });

    function loadRule(ruleId, opts) {
        opts = opts || {};
        var editor = window.sigmaYamlEditor;
        if (!editor) { console.error('YAML editor not initialized'); return; }
        fetch('/api/sigma/rule/' + ruleId)
            .then(function (response) { return response.text(); })
            .then(function (yaml) {
                setSelectedRule(ruleId, true);
                editor.setValue(yaml);
                var ta = $('yaml-editor');
                if (ta) ta.value = yaml;
                // Force refresh to ensure syntax highlighting is applied
                setTimeout(function () { editor.refresh(); }, 10);
                var convertTarget = $('sigma-convert-response');
                if (convertTarget) convertTarget.innerHTML = '';
                $('validation-result').innerHTML = '';
                if (opts.convertAfterLoad) {
                    var convertForm = $('convert-form');
                    if (convertForm) setTimeout(function () { convertForm.requestSubmit(); }, 0);
                }
            })
            .catch(function (err) { console.error('Failed to load rule:', err); });
    }

    // ── The editor and the page's selects ──
    function initPage(retryCount) {
        retryCount = retryCount || 0;
        if (typeof CodeMirror === 'undefined' || !CodeMirror.modes || !CodeMirror.modes.yaml) {
            if (retryCount === 0) {
                if (typeof CodeMirror === 'undefined') {
                    loadScript('/static/js/vendor/codemirror.min.js')
                        .then(function () { return loadScript('/static/js/vendor/codemirror-yaml.min.js'); })
                        .catch(function (e) { console.error('[Sigma] CodeMirror load error:', e); });
                } else {
                    loadScript('/static/js/vendor/codemirror-yaml.min.js')
                        .catch(function (e) { console.error('[Sigma] YAML mode load error:', e); });
                }
                if (typeof Prism === 'undefined') {
                    loadScript('/static/js/vendor/prism.min.js')
                        .then(function () { return loadScript('/static/js/vendor/prism-json.min.js'); })
                        .catch(function (e) { console.error('[Sigma] Prism load error:', e); });
                }
            }
            if (retryCount < 50) setTimeout(function () { initPage(retryCount + 1); }, 100);   // up to 5 s
            else console.error('[Sigma] CodeMirror failed to load after multiple retries');
            return;
        }

        var ta = $('yaml-editor');
        if (!ta) return;
        var editor = CodeMirror.fromTextArea(ta, {
            mode: 'yaml', theme: 'material-darker', lineNumbers: true, lineWrapping: true,
            tabSize: 2, indentWithTabs: false, autofocus: false,
        });
        window.sigmaYamlEditor = editor;
        // Refresh a few times so syntax highlighting survives late CSS
        [50, 200, 500].forEach(function (ms) { setTimeout(function () { editor.refresh(); }, ms); });
        // Keep the textarea in step for form submission
        editor.on('change', function () { ta.value = editor.getValue(); });

        // Saved index patterns (Preferences) apply only when no template is selected:
        // a template's vars.index_names wins.
        var idxField = $('form-index-pattern'), saved = savedIndices();
        if (idxField && saved.length) idxField.value = saved.join(', ');
        try {
            // Restore the saved space only if it is one of the rendered options; a stale value
            // would otherwise blank the SIEM dropdown and the operator couldn't deploy.
            var savedSpace = localStorage.getItem('pref-sigma-default-space'), spaceSelect = $('deploy-space-select');
            if (spaceSelect && savedSpace && Array.prototype.some.call(spaceSelect.options, function (o) { return o.value === savedSpace; })) {
                spaceSelect.value = savedSpace;
            }
        } catch (_e) { /* storage blocked */ }
        var deploySelect = $('deploy-space-select');
        if (deploySelect) deploySelect.addEventListener('change', syncDeploySiemId);
        syncDeploySiemId();

        var ruleBrowser = $('rule-browser');
        if (ruleBrowser) ruleBrowser.classList.add('open');
        bindAccordion();

        selection = { pipeline: [], template: [] };
        refreshPicker('pipeline');
        refreshPicker('template');

        var backendSelect = $('backend-select');
        if (backendSelect) backendSelect.addEventListener('change', function () {
            var backend = this.value;
            $('form-backend').value = backend;
            // This backend's output formats
            fetch('/api/sigma/formats/' + backend, { credentials: 'same-origin' })
                .then(function (response) {
                    if (response.status === 401) {
                        window.location.href = '/login?next=/sigma';
                        throw new Error('Authentication required');
                    }
                    return response.text();
                })
                .then(function (html) {
                    var formatSelect = $('format-select');
                    formatSelect.innerHTML = html;
                    if (formatSelect.options[0]) $('form-format').value = formatSelect.options[0].value;
                })
                .catch(function (err) { console.error('Failed to load formats:', err); });
        });
        var formatSelect = $('format-select');
        if (formatSelect) formatSelect.addEventListener('change', function () { $('form-format').value = this.value; });
        var pipelineSelect = $('pipeline-select');
        if (pipelineSelect) pipelineSelect.addEventListener('change', function () { $('form-pipeline').value = this.value; });

        ['pipeline', 'template'].forEach(function (kind) {
            $(kind + '-multiselect').addEventListener('click', function (e) {
                var opt = e.target.closest('.pipeline-option');
                if (!opt) return;
                e.preventDefault();
                toggleOption(kind, opt);
            });
            syncPicker(kind);
        });

        // Re-sync the hidden fields just before each submit, so navigating away and back
        // doesn't leave stale values.
        var convertForm = $('convert-form');
        if (convertForm) convertForm.addEventListener('htmx:configRequest', function () {
            ta.value = editor.getValue();
            syncPicker('pipeline');
            syncPicker('template');
            $('form-pipeline').value = $('pipeline-select').value;
            $('form-backend').value = $('backend-select').value;
            $('form-format').value = $('format-select').value;
        });
        var deployForm = $('deploy-form');
        if (deployForm) deployForm.addEventListener('htmx:configRequest', fillDeployForm);

        // Opened from another page with a rule (?selected=…): load it.
        var prefill = $('sigma-prefill-config'), ruleId = prefill ? prefill.dataset.ruleId || '' : '';
        selectedRuleId = ruleId;
        if (ruleId) loadRule(ruleId, { convertAfterLoad: false });
    }

    // Everything the deploy request needs, from the page's state.
    function fillDeployForm() {
        if (window.sigmaYamlEditor) $('deploy-yaml').value = window.sigmaYamlEditor.getValue();
        var rawQuery = $('raw-query-store');
        if (rawQuery) $('deploy-query').value = rawQuery.value;
        syncDeploySiemId();
        $('deploy-pipeline-file').value = syncPicker('pipeline');
        $('deploy-template-file').value = syncPicker('template');
        // Index patterns from Preferences only when no template is selected.
        var idx = selection.template.length ? '' : savedIndices().join(', ');
        $('deploy-index-pattern').value = idx;
        var formIdx = $('form-index-pattern');
        if (formIdx) formIdx.value = idx;
    }

    function clearEditor() {
        var editor = window.sigmaYamlEditor;
        if (!editor) return;
        editor.setValue('');
        var convertTarget = $('sigma-convert-response');
        if (convertTarget) convertTarget.innerHTML = '';
        $('validation-result').innerHTML = '';
    }

    function downloadQuery() {
        var original = ($('raw-query-store') || {}).value || '';
        var url = URL.createObjectURL(new Blob([original], { type: 'text/plain' }));
        var a = document.createElement('a');
        a.href = url;
        a.download = 'sigma_query.ndjson';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }

    TIDE.page('.sigma-workbench', function () {
        window.sigmaYamlEditor = null;   // the previous visit's editor is gone with its page
        initPage(0);
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
        pipelineMenu: function () { toggleMenu('pipeline'); },
        templateMenu: function () { toggleMenu('template'); },
        clear: clearEditor,
        download: downloadQuery,
        deploy: fillDeployForm,
        openRule: function (e, el) { loadRule(el.closest('[data-rule-id]').dataset.ruleId); },
    });
})();
