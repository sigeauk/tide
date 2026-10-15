/*
 * Management (pages/admin/management.html and the tabs app/api/management.py renders into it):
 * the Clients/Users tab bar, the SIEM, OpenCTI, GitLab, Keycloak and Connector dialogs, the Sigma
 * pipeline and template editors with their tenant assignment, and the Query tab's presets.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }
    function onBackdrop(close) { return function (e, el) { if (e.target === el) close(); }; }
    function jsonBlock(id) {
        var el = $(id);
        try { return el ? JSON.parse(el.textContent) : null; } catch (_) { return null; }
    }

    // A dialog's form posts, and the tab it belongs to is replaced by the response.
    async function submitTo(url, method, formData, close, panelId) {
        try {
            var resp = await fetch(url, { method: method, body: formData });
            if (!resp.ok) { showToast('Request failed', 'error'); return; }
            close();
            var html = await resp.text();
            var panel = $(panelId) || $('management-content');
            panel.innerHTML = html;
            htmx.process(panel);
        } catch (ex) {
            showToast('Network error', 'error');
        }
    }

    async function testConnection(btnId, resultId, url, formData) {
        var btn = $(btnId), result = $(resultId);
        btn.disabled = true;
        result.innerHTML = '<span class="text-secondary fs-md">Testing...</span>';
        try {
            var resp = await fetch(url, { method: 'POST', body: formData });
            result.innerHTML = await resp.text();
        } catch (ex) {
            result.innerHTML = '<span class="badge badge-danger">Network error</span>';
        }
        btn.disabled = false;
    }

    function checked(id) { return $(id).checked ? 'true' : 'false'; }

    // ── Tenants & Users tab bar ──
    function activateTab(e, btn) {
        btn.parentElement.querySelectorAll('.settings-tab').forEach(function (t) { t.classList.remove('active'); });
        btn.classList.add('active');
        history.replaceState(null, '', '/settings/management?tab=' + btn.dataset.tab);
    }

    // ── SIEM dialog: fields per type ──
    function updateSiemFields() {
        var type = $('siem-form-type').value;
        $('siem-fields-elastic').style.display = type === 'elastic' ? '' : 'none';
        $('siem-fields-splunk').style.display = type === 'splunk' ? '' : 'none';
        $('siem-fields-sentinel').style.display = type === 'sentinel' ? '' : 'none';
        // Only show Test Connection for elastic
        $('siem-test-btn').style.display = type === 'elastic' ? '' : 'none';
        $('siem-test-result').innerHTML = '';
    }
    function clearSiemFields() {
        ['siem-form-es-url', 'siem-form-kb-url', 'siem-form-token',
         'siem-form-splunk-url', 'siem-form-splunk-token',
         'siem-form-sentinel-url', 'siem-form-sentinel-token'].forEach(function (id) {
            var el = $(id);
            if (el) el.value = '';
        });
    }
    function openSiem(s) {
        var editing = !!s.id;
        $('siem-modal-title').textContent = editing ? 'Edit SIEM' : 'New SIEM';
        $('siem-form-submit').textContent = editing ? 'Save' : 'Create';
        $('siem-form-id').value = s.id || '';
        $('siem-form-label').value = s.label || '';
        $('siem-form-type').value = s.type || 'elastic';
        $('siem-form-type').disabled = editing;
        $('siem-form-tls-verify').checked = s.tlsVerify === 'true';
        clearSiemFields();
        // Populate the right fields based on type
        if (s.type === 'elastic') {
            $('siem-form-es-url').value = s.esUrl || '';
            $('siem-form-kb-url').value = s.kbUrl || '';
        } else if (s.type === 'splunk') {
            $('siem-form-splunk-url').value = s.kbUrl || '';
        } else if (s.type === 'sentinel') {
            $('siem-form-sentinel-url').value = s.kbUrl || '';
        }
        $('siem-test-result').innerHTML = '';
        updateSiemFields();
        $('siem-modal').style.display = 'flex';
    }
    function closeSiem() { $('siem-modal').style.display = 'none'; }
    function submitSiem(e) {
        e.preventDefault();
        var id = $('siem-form-id').value, type = $('siem-form-type').value;
        var fd = new FormData();
        fd.append('label', $('siem-form-label').value);
        fd.append('siem_type', type);
        fd.append('tls_verify', checked('siem-form-tls-verify'));
        if (type === 'elastic') {
            fd.append('elasticsearch_url', $('siem-form-es-url').value);
            fd.append('kibana_url', $('siem-form-kb-url').value);
            fd.append('api_token', $('siem-form-token').value);
        } else if (type === 'splunk') {
            fd.append('kibana_url', $('siem-form-splunk-url').value);
            fd.append('api_token', $('siem-form-splunk-token').value);
        } else if (type === 'sentinel') {
            fd.append('kibana_url', $('siem-form-sentinel-url').value);
            fd.append('api_token', $('siem-form-sentinel-token').value);
        }
        submitTo(id ? '/api/management/siems/' + id : '/api/management/siems', id ? 'PUT' : 'POST', fd, closeSiem, 'mgmt-sub-siems');
    }
    function testSiem() {
        var fd = new FormData();
        fd.append('siem_id', $('siem-form-id').value);
        fd.append('kibana_url', $('siem-form-kb-url').value);
        fd.append('api_token', $('siem-form-token').value);
        fd.append('siem_type', $('siem-form-type').value);
        fd.append('tls_verify', checked('siem-form-tls-verify'));
        testConnection('siem-test-btn', 'siem-test-result', '/api/management/siems/test-connection', fd);
    }

    // ── OpenCTI dialog ──
    function openOpenCTI(d) {
        var editing = !!d.id;
        $('opencti-modal-title').textContent = editing ? 'Edit OpenCTI Instance' : 'New OpenCTI Instance';
        $('opencti-form-submit').textContent = editing ? 'Save' : 'Create';
        $('opencti-form-id').value = d.id || '';
        $('opencti-form-label').value = d.label || '';
        $('opencti-form-url').value = d.url || '';
        $('opencti-form-token').value = '';
        var k = (d.kind || 'actors').toLowerCase();
        if (k !== 'actors' && k !== 'cti' && k !== 'both') k = 'actors';
        $('opencti-form-kind').value = k;
        $('opencti-modal').style.display = 'flex';
    }
    function closeOpenCTI() { $('opencti-modal').style.display = 'none'; }
    function submitOpenCTI(e) {
        e.preventDefault();
        var id = $('opencti-form-id').value, fd = new FormData();
        fd.append('label', $('opencti-form-label').value);
        fd.append('url', $('opencti-form-url').value);
        fd.append('token', $('opencti-form-token').value);
        fd.append('kind', $('opencti-form-kind').value);
        submitTo(id ? '/api/management/opencti/' + id : '/api/management/opencti', id ? 'PUT' : 'POST', fd, closeOpenCTI, 'mgmt-sub-opencti');
    }
    function testOpenCTI() {
        var fd = new FormData();
        fd.append('opencti_id', $('opencti-form-id').value);
        fd.append('url', $('opencti-form-url').value);
        fd.append('token', $('opencti-form-token').value);
        testConnection('opencti-test-btn', 'opencti-test-result', '/api/management/opencti/test-connection', fd);
    }

    // ── GitLab dialog ──
    function openGitLab(d) {
        var editing = !!d.id;
        $('gitlab-modal-title').textContent = editing ? 'Edit GitLab Instance' : 'New GitLab Instance';
        $('gitlab-form-submit').textContent = editing ? 'Save' : 'Create';
        $('gitlab-form-id').value = d.id || '';
        $('gitlab-form-label').value = d.label || '';
        $('gitlab-form-url').value = d.url || '';
        $('gitlab-form-token').value = '';
        $('gitlab-form-group').value = !d.group || d.group === '—' ? '' : d.group;
        $('gitlab-form-tls-verify').checked = d.tlsVerify === 'true';
        $('gitlab-modal').style.display = 'flex';
    }
    function closeGitLab() { $('gitlab-modal').style.display = 'none'; }
    function submitGitLab(e) {
        e.preventDefault();
        var id = $('gitlab-form-id').value, fd = new FormData();
        fd.append('label', $('gitlab-form-label').value);
        fd.append('url', $('gitlab-form-url').value);
        fd.append('token', $('gitlab-form-token').value);
        fd.append('default_group', $('gitlab-form-group').value);
        fd.append('tls_verify', checked('gitlab-form-tls-verify'));
        submitTo(id ? '/api/management/gitlab/' + id : '/api/management/gitlab', id ? 'PUT' : 'POST', fd, closeGitLab, 'mgmt-sub-gitlab');
    }

    // ── Keycloak dialog ──
    function openKeycloak(d) {
        var editing = !!d.id;
        $('keycloak-modal-title').textContent = editing ? 'Edit Keycloak Instance' : 'New Keycloak Instance';
        $('keycloak-form-submit').textContent = editing ? 'Save' : 'Create';
        $('keycloak-form-id').value = d.id || '';
        $('keycloak-form-label').value = d.label || '';
        $('keycloak-form-url').value = d.url || '';
        $('keycloak-form-realm').value = d.realm || 'master';
        $('keycloak-form-client-id').value = '';
        $('keycloak-form-client-secret').value = '';
        $('keycloak-form-tls-verify').checked = d.tlsVerify === 'true';
        $('keycloak-modal').style.display = 'flex';
    }
    function closeKeycloak() { $('keycloak-modal').style.display = 'none'; }
    function submitKeycloak(e) {
        e.preventDefault();
        var id = $('keycloak-form-id').value, fd = new FormData();
        fd.append('label', $('keycloak-form-label').value);
        fd.append('url', $('keycloak-form-url').value);
        fd.append('realm', $('keycloak-form-realm').value || 'master');
        fd.append('client_id', $('keycloak-form-client-id').value);
        fd.append('client_secret', $('keycloak-form-client-secret').value);
        fd.append('tls_verify', checked('keycloak-form-tls-verify'));
        submitTo(id ? '/api/management/keycloak/' + id : '/api/management/keycloak', id ? 'PUT' : 'POST', fd, closeKeycloak, 'mgmt-sub-keycloak');
    }
    function testKeycloak() {
        var fd = new FormData();
        fd.append('keycloak_id', $('keycloak-form-id').value);
        fd.append('url', $('keycloak-form-url').value);
        fd.append('realm', $('keycloak-form-realm').value || 'master');
        fd.append('tls_verify', checked('keycloak-form-tls-verify'));
        testConnection('keycloak-test-btn', 'keycloak-test-result', '/api/management/keycloak/test-connection', fd);
    }

    // ── Connectors (multi-vendor CTI framework) ──
    // The Connectors tab carries its vendors and rows as JSON (#connector-data), read when needed,
    // so a tab replaced after a save is current.
    var editingConnector = null;
    function connectorData() { return jsonBlock('connector-data') || { vendors: [], rows: [] }; }
    function vendorOptions(selected) {
        return connectorData().vendors.map(function (v) {
            var o = document.createElement('option');
            o.value = v.name;
            o.textContent = v.label;
            if (v.name === selected) o.selected = true;
            return o;
        });
    }
    function openConnector(c) {
        editingConnector = c || null;
        $('connector-modal-title').textContent = c ? 'Edit Connector' : 'New Connector';
        $('connector-form-submit').textContent = c ? 'Save' : 'Create';
        $('connector-form-id').value = c ? c.id : '';
        $('connector-form-label').value = c ? (c.label || '') : '';
        // Auto-sync interval: match against one of the preset options, fall back to '' (Off) if
        // the stored value isn't one of the presets so the operator sees a defined state.
        var iv = c && c.sync_interval_minutes != null ? String(c.sync_interval_minutes) : '';
        $('connector-form-interval').value = ['', '15', '60', '360', '1440'].indexOf(iv) >= 0 ? iv : '';
        var vsel = $('connector-form-vendor');
        vsel.replaceChildren.apply(vsel, vendorOptions(c && c.vendor));
        vsel.disabled = !!c;
        $('connector-test-result').innerHTML = '';
        onVendorChange();
        $('connector-modal').style.display = 'flex';
    }
    function closeConnector() { $('connector-modal').style.display = 'none'; editingConnector = null; }
    async function onVendorChange() {
        var vendor = $('connector-form-vendor').value, container = $('connector-vendor-fields');
        if (!vendor) { container.innerHTML = ''; return; }
        container.innerHTML = '<div class="text-secondary fs-md">Loading fields…</div>';
        try {
            var resp = await fetch('/api/management/connectors/vendor-fields/' + encodeURIComponent(vendor));
            container.innerHTML = await resp.text();
            // Pre-fill non-secret values when editing
            if (editingConnector && editingConnector.vendor === vendor) {
                var cfg = editingConnector.config || {};
                Object.keys(cfg).forEach(function (key) {
                    var inp = container.querySelector('[name="cfg_' + key + '"]');
                    if (inp && inp.type !== 'password') inp.value = cfg[key];
                });
            }
        } catch (ex) {
            container.innerHTML = '<span class="badge badge-danger">Failed to load vendor fields</span>';
        }
    }
    function submitConnector(e, form) {
        e.preventDefault();
        var id = $('connector-form-id').value, fd = new FormData();
        fd.append('vendor', $('connector-form-vendor').value);
        fd.append('label', $('connector-form-label').value);
        fd.append('kind', 'cti');
        fd.append('sync_interval_minutes', $('connector-form-interval').value || '');
        // Append all cfg_* fields from the vendor-specific block
        form.querySelectorAll('[name^="cfg_"]').forEach(function (inp) {
            fd.append(inp.name, inp.type === 'checkbox' ? (inp.checked ? 'true' : 'false') : inp.value);
        });
        submitTo(id ? '/api/management/connectors/' + id : '/api/management/connectors', id ? 'PUT' : 'POST', fd, closeConnector, 'mgmt-sub-connectors');
    }
    function openImport() {
        $('connector-import-payload').value = '';
        $('connector-import-result').innerHTML = '';
        $('connector-import-modal').style.display = 'flex';
    }
    function closeImport() { $('connector-import-modal').style.display = 'none'; }
    async function submitImport(e) {
        e.preventDefault();
        var result = $('connector-import-result');
        result.innerHTML = '<span class="text-secondary">Importing…</span>';
        var fd = new FormData();
        fd.append('payload', $('connector-import-payload').value);
        try {
            var resp = await fetch('/api/management/connectors/import', { method: 'POST', body: fd });
            var html = await resp.text();
            if (!resp.ok) { result.innerHTML = html; return; }
            var panel = $('mgmt-sub-connectors');
            panel.innerHTML = html;
            htmx.process(panel);
            closeImport();
        } catch (ex) {
            result.innerHTML = '<div class="alert alert-error">Import failed: ' + (ex && ex.message ? ex.message : ex) + '</div>';
        }
    }

    // ── Sigma assets: pipeline & template editors ──
    var assets = {
        pipeline: { current: null, cm: null, pending: null, label: 'pipeline', plural: 'pipelines', api: '/api/sigma/saved-pipelines',
                    stub: 'name: my-custom-pipeline\npriority: 20\n\ntransformations:\n  - id: map_fields\n    type: field_name_mapping\n    mapping:\n      Image: process.executable\n' },
        template: { current: null, cm: null, pending: null, label: 'template', plural: 'templates', api: '/api/sigma/saved-templates',
                    stub: 'vars:\n  index_names:\n    - logs-*\npostprocessing:\n  - type: template\n    template: |+\n      {{ query }}\n' },
    };
    var assignments = { pipeline: {}, template: {} };
    var assignTarget = { type: null, filename: null };
    var clientsCache = null;

    function apiJson(url, options) {
        var opts = Object.assign({ credentials: 'same-origin' }, options || {});
        return fetch(url, opts).then(function (r) {
            var ct = (r.headers.get('content-type') || '').toLowerCase();
            if (r.status === 401) {
                window.location.href = '/login?next=/management';
                throw new Error('Authentication required');
            }
            if (!ct.includes('application/json')) {
                if (r.redirected || ct.includes('text/html')) {
                    window.location.href = '/login?next=/management';
                    throw new Error('Session expired');
                }
                throw new Error('Unexpected response type from API');
            }
            return r.json().then(function (body) {
                if (!r.ok) throw new Error((body && (body.detail || body.message)) || ('Request failed (' + r.status + ')'));
                return body;
            });
        });
    }

    function status(type, msg, isError) {
        var el = $(type + '-status');
        if (!el) return;
        el.textContent = msg;
        el.style.color = isError ? 'var(--color-danger)' : 'var(--color-success)';
    }

    function renderChips(type, filename) {
        var el = $(type + '-tenants-chips');
        if (!el) return;
        var clients = (assignments[type] || {})[filename] || [];
        if (!filename) { el.innerHTML = '<span class="form-hint">— save first —</span>'; return; }
        if (!clients.length) { el.innerHTML = '<span class="badge badge-warning badge--xs">unassigned</span>'; return; }
        el.innerHTML = clients.map(function (c) {
            return '<span class="badge badge-info badge--xs">' + (c.name || c.id) + '</span>';
        }).join('');
    }

    function refreshAssignments(type) {
        return apiJson('/api/sigma/assignments/' + type + '?_v=' + Date.now())
            .then(function (map) {
                assignments[type] = map || {};
                renderChips(type, assets[type].current);
            })
            .catch(function () { /* non-fatal */ });
    }

    function loadList(type) {
        var a = assets[type];
        return apiJson(a.api + '?_v=' + Date.now())
            .then(function (items) {
                var list = $(type + '-list');
                if (!list) return;
                if (!items.length) {
                    list.innerHTML = '<span class="text-muted fs-sm">No ' + a.plural + ' saved.</span>';
                    return refreshAssignments(type);
                }
                list.innerHTML = items.map(function (it) {
                    return '<button name="' + it.display + '" type="button" class="' + type + '-list-item asset-editor__item'
                        + (a.current === it.filename ? ' is-active' : '') + '" data-file="' + encodeURIComponent(it.filename) + '">'
                        + it.display + '</button>';
                }).join('');
                return refreshAssignments(type);
            })
            .catch(function (err) { status(type, err.message || 'Failed to load ' + a.plural + '.', true); });
    }

    function initEditor(type) {
        if (typeof CodeMirror === 'undefined') { setTimeout(function () { initEditor(type); }, 300); return; }
        var a = assets[type], el = $(type + '-yaml-editor');
        if (!el || el._cmInited) return;
        el._cmInited = true;
        a.cm = CodeMirror.fromTextArea(el, { mode: 'yaml', theme: 'material-darker', lineNumbers: true, tabSize: 2 });
        a.cm.setSize(null, 300);
        if (a.pending) { a.cm.setValue(a.pending); a.pending = null; }
    }

    function loadAsset(type, filename) {
        var a = assets[type];
        apiJson(a.api + '/' + encodeURIComponent(filename))
            .then(function (data) {
                a.current = data.filename;
                $(type + '-name-input').value = data.filename.replace(/\.ya?ml$/, '');
                if (a.cm) {
                    a.cm.setValue(data.content);
                    setTimeout(function () { a.cm.refresh(); }, 80);
                } else {
                    a.pending = data.content;
                    initEditor(type);
                }
                $(type + '-delete-btn').style.display = '';
                renderChips(type, data.filename);
                loadList(type);
                status(type, '');
            })
            .catch(function (err) { status(type, err.message || 'Failed to load ' + a.label + '.', true); });
    }

    function newAsset(type) {
        var a = assets[type];
        a.current = null;
        $(type + '-name-input').value = '';
        if (a.cm) a.cm.setValue(a.stub);
        $(type + '-delete-btn').style.display = 'none';
        renderChips(type, null);
        status(type, '');
    }

    function saveAsset(type) {
        var a = assets[type], name = $(type + '-name-input').value.trim();
        if (!name) { status(type, 'Enter a name.', true); return; }
        var fd = new FormData();
        fd.append('name', name);
        fd.append('content', a.cm ? a.cm.getValue() : '');
        apiJson(a.api, { method: 'POST', body: fd })
            .then(function (data) {
                a.current = data.filename;
                $(type + '-delete-btn').style.display = '';
                status(type, 'Saved: ' + data.filename);
                return loadList(type);
            })
            .catch(function (err) { status(type, err.message || 'Failed to save ' + a.label + '.', true); });
    }

    function deleteAsset(type) {
        var a = assets[type];
        if (!a.current || !confirm('Delete this ' + a.label + '?')) return;
        apiJson(a.api + '/' + encodeURIComponent(a.current), { method: 'DELETE' })
            .then(function () { newAsset(type); loadList(type); })
            .catch(function (err) { status(type, err.message || 'Failed to delete ' + a.label + '.', true); });
    }

    function openAssign(type) {
        var current = assets[type].current;
        if (!current) { alert('Save the ' + type + ' first, then assign tenants.'); return; }
        assignTarget = { type: type, filename: current };
        $('sigma-assign-title').textContent = 'Assign tenants — ' + current;
        $('sigma-assign-error').textContent = '';
        $('sigma-assign-modal').style.display = 'flex';
        var box = $('sigma-assign-checkboxes');
        box.innerHTML = '<span class="text-secondary fs-sm">Loading clients…</span>';
        var assignedIds = new Set(((assignments[type] || {})[current] || []).map(function (c) { return c.id; }));
        var load = clientsCache ? Promise.resolve(clientsCache)
            : apiJson('/api/clients').then(function (clients) { clientsCache = clients || []; return clientsCache; });
        load.then(function (clients) {
            if (!clients.length) { box.innerHTML = '<span class="text-secondary fs-sm">No clients defined.</span>'; return; }
            box.innerHTML = clients.map(function (c) {
                return '<label class="check-label fs-md">'
                     + '<input name="' + c.id + '" type="checkbox" value="' + c.id + '" ' + (assignedIds.has(c.id) ? 'checked' : '') + '> '
                     + (c.name || c.id) + '</label>';
            }).join('');
        }).catch(function (err) {
            box.innerHTML = '<span class="text-danger fs-sm">' + (err.message || 'Failed to load clients.') + '</span>';
        });
    }
    function closeAssign() {
        $('sigma-assign-modal').style.display = 'none';
        assignTarget = { type: null, filename: null };
    }
    function saveAssign() {
        var t = assignTarget;
        if (!t.type || !t.filename) return;
        var ids = Array.prototype.map.call(
            document.querySelectorAll('#sigma-assign-checkboxes input[type=checkbox]:checked'), function (c) { return c.value; });
        var errEl = $('sigma-assign-error');
        errEl.textContent = '';
        if (!ids.length) { errEl.textContent = 'Pick at least one tenant.'; return; }
        apiJson('/api/sigma/assignments/' + t.type + '/' + encodeURIComponent(t.filename), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ client_ids: ids }),
        }).then(function () {
            closeAssign();
            refreshAssignments(t.type);
        }).catch(function (err) {
            errEl.textContent = err.message || 'Failed to save assignment.';
        });
    }

    // The Sigma section's editors are built the first time it is opened.
    TIDE.page('#mgmt-sigma-section', function (section) {
        var inited = false;
        function maybeInit() {
            if (inited) return;
            inited = true;
            ['pipeline', 'template'].forEach(function (type) {
                $(type + '-list').addEventListener('click', function (e) {
                    var btn = e.target.closest('.' + type + '-list-item');
                    var raw = btn && btn.getAttribute('data-file');
                    if (raw) loadAsset(type, decodeURIComponent(raw));
                });
                initEditor(type);
                loadList(type);
            });
        }
        if (section.open) maybeInit();
        section.addEventListener('toggle', function () {
            if (!section.open) return;
            maybeInit();
            setTimeout(function () {
                if (assets.pipeline.cm) assets.pipeline.cm.refresh();
                if (assets.template.cm) assets.template.cm.refresh();
            }, 80);
        });
    });

    // ── Query tab: predefined queries (JSON in #mgmt-query-presets) ──
    function updateQueryActions() {
        var sel = $('mgmt-query-preset'), del = $('mgmt-query-delete');
        if (sel && del) del.disabled = !(sel.value && sel.value.indexOf('custom:') === 0);
    }
    function applyPreset(e, sel) {
        var p = sel.value && (jsonBlock('mgmt-query-presets') || {})[sel.value];
        if (p) {
            var sqlEl = $('mgmt-query-sql'), targetEl = $('mgmt-query-target'), nameEl = $('mgmt-query-name');
            if (sqlEl) sqlEl.value = p.sql || '';
            if (targetEl && p.target) targetEl.value = p.target;
            if (nameEl && (p.kind || '') === 'custom') nameEl.value = p.name || p.label || '';
        }
        updateQueryActions();
    }
    function newQuery() {
        $('mgmt-query-sql').value = '';
        $('mgmt-query-name').value = '';
        $('mgmt-query-results').innerHTML = '';
        $('mgmt-query-preset').value = '';
        updateQueryActions();
    }
    TIDE.page('#mgmt-query-root', updateQueryActions);

    TIDE.actions('mgmt', {
        tab: activateTab,
        siemNew: function () { openSiem({}); },
        siemEdit: function (e, el) { openSiem(el.dataset); },
        siemClose: closeSiem, siemBackdrop: onBackdrop(closeSiem),
        siemSubmit: submitSiem, siemTest: testSiem, siemType: updateSiemFields,
        openctiNew: function () { openOpenCTI({}); },
        openctiEdit: function (e, el) { openOpenCTI(el.dataset); },
        openctiClose: closeOpenCTI, openctiBackdrop: onBackdrop(closeOpenCTI),
        openctiSubmit: submitOpenCTI, openctiTest: testOpenCTI,
        gitlabNew: function () { openGitLab({}); },
        gitlabEdit: function (e, el) { openGitLab(el.dataset); },
        gitlabClose: closeGitLab, gitlabBackdrop: onBackdrop(closeGitLab), gitlabSubmit: submitGitLab,
        keycloakNew: function () { openKeycloak({}); },
        keycloakEdit: function (e, el) { openKeycloak(el.dataset); },
        keycloakClose: closeKeycloak, keycloakBackdrop: onBackdrop(closeKeycloak),
        keycloakSubmit: submitKeycloak, keycloakTest: testKeycloak,
        connectorNew: function () { openConnector(null); },
        connectorEdit: function (e, el) {
            var c = connectorData().rows.find(function (r) { return r.id === el.dataset.id; });
            if (c) openConnector(c);
        },
        connectorClose: closeConnector, connectorBackdrop: onBackdrop(closeConnector),
        connectorVendor: onVendorChange, connectorSubmit: submitConnector,
        importOpen: openImport, importClose: closeImport, importBackdrop: onBackdrop(closeImport), importSubmit: submitImport,
        assetNew: function (e, el) { newAsset(el.dataset.asset); },
        assetList: function (e, el) { loadList(el.dataset.asset); },
        assetSave: function (e, el) { saveAsset(el.dataset.asset); },
        assetDelete: function (e, el) { deleteAsset(el.dataset.asset); },
        assignOpen: function (e, el) { openAssign(el.dataset.asset); },
        assignClose: closeAssign, assignBackdrop: onBackdrop(closeAssign), assignSave: saveAssign,
        queryPreset: applyPreset, queryNew: newQuery,
        // Data import: "+ Create a new client…" shows the new client's name field.
        importTenant: function (e, sel) { $('data-new-client').style.display = sel.value === '__new__' ? '' : 'none'; },
    });
})();
