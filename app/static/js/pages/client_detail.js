/*
 * A client's page (pages/admin/client_detail.html) and its sections: Edit client, Move a system to
 * another client, Linked SIEMs (partials/client_siems.html: a destination's edit popover, colour
 * swatches, the Add SIEM form's spaces, validation mode), GitLab Projects (partials/client_gitlab.html:
 * the edit popover is the destinations' one; Link a project's fields follow what it is for).
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    // ── Edit client ──
    async function submitEdit(e, form) {
        e.preventDefault();
        var payload = {
            name: $('edit-client-name').value,
            description: $('edit-client-desc').value || null,
        };
        try {
            var resp = await fetch('/api/clients/' + form.dataset.clientId, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            if (!resp.ok) {
                var err = await resp.json();
                showToast(err.detail || 'Could not update the client.', 'error');
                return;
            }
            showToast('Client updated.', 'success');
            window.location.reload();
        } catch (ex) {
            showToast(TIDE.UNREACHABLE, 'error');
        }
    }

    // ── Move a system (from the Manage Systems dialog) ──
    function moveSystem(e, el) {
        $('edit-systems-modal').style.display = 'none';
        $('move-system-id').value = el.dataset.id;
        $('move-system-name').textContent = el.dataset.name;
        $('move-target-client').value = '';
        $('move-check-result').innerHTML = '<p class="text-muted p-sm fs-base">Select a target client above.</p>';
        $('move-system-modal').style.display = 'flex';
    }

    // ── Linked SIEMs ──
    // A destination's edit popover ("…"): one open at a time, closed by a click anywhere else.
    // From a row's ⋮ (Edit) or the box's Cancel. The click goes on, so the ⋮ menu closes; the
    // listener below leaves the box open for it.
    function toggleEdit(e, btn) {
        var el = $(btn.dataset.target);
        if (!el) return;
        var opening = el.style.display === 'none';
        document.querySelectorAll('.client-siem-edit-popover').forEach(function (p) { p.style.display = 'none'; });
        el.style.display = opening ? 'block' : 'none';
    }
    document.addEventListener('click', function (e) {
        if (e.target.closest('.client-siem-edit-popover') || e.target.closest('[data-click="clientSiems.toggleEdit"]')) return;
        document.querySelectorAll('.client-siem-edit-popover').forEach(function (p) { p.style.display = 'none'; });
    });

    // Colour swatches (edit popover + Add SIEM form) write into the row's <input type="color">
    // and show the pick in the swatch row itself.
    function pickColor(e, btn) {
        var row = btn.closest('.client-siem-color-row');
        if (!row) return;
        var input = row.querySelector('input[type="color"]');
        if (input) input.value = btn.dataset.color;
        row.querySelectorAll('.client-siem-swatch').forEach(function (s) { s.classList.remove('client-siem-swatch--selected'); });
        btn.classList.add('client-siem-swatch--selected');
    }
    document.addEventListener('input', function (e) {
        if (e.target.matches && e.target.matches('.client-siem-color-input')) {
            var row = e.target.closest('.client-siem-color-row');
            if (row) row.querySelectorAll('.client-siem-swatch').forEach(function (s) { s.classList.remove('client-siem-swatch--selected'); });
        }
    });

    function validationMode(e, sel) {
        var grid = $('criticality-validation-grid');
        if (grid) grid.hidden = sel.value !== 'criticality';
    }

    // Add SIEM: an Elastic SIEM asks for a Kibana space, offering that SIEM's own spaces
    // (fetched from it) with each one's rule count (#siem-space-counts: siem_id -> space -> counts).
    function addSiemChange(e, sel) {
        var opt = sel.options[sel.selectedIndex];
        var siemType = opt ? opt.getAttribute('data-siem-type') : '';
        var siemId = opt ? opt.value : '';
        var field = $('siem-space-field'), input = $('add-siem-space-input'), hint = $('add-siem-space-hint');
        field.style.display = siemType === 'elastic' ? '' : 'none';
        if (siemType !== 'elastic' || !siemId) {
            if (input) { input.setAttribute('list', ''); input.value = ''; }
            if (hint) hint.textContent = '';
            return;
        }
        // Point the input's autocomplete at THIS SIEM's datalist only.
        if (input) { input.setAttribute('list', 'known-spaces-' + siemId); input.value = ''; }
        var countsEl = $('siem-space-counts');
        var counts = ((countsEl && JSON.parse(countsEl.textContent)) || {})[siemId] || {};
        // Spaces are fetched from the SIEM on demand so the list is always fresh, and present
        // even when this page was rendered before the SIEM existed.
        if (hint) hint.textContent = 'Loading spaces from the SIEM…';
        var requested = siemId;
        fetch('/api/management/siems/' + encodeURIComponent(siemId) + '/spaces', { credentials: 'same-origin' })
            .then(function (r) { return r.json().catch(function () { return {}; }); })
            .then(function (data) {
                if ($('add-siem-select').value !== requested) return;  // selection moved on
                var spaces = (data && data.spaces) || [];
                var listId = 'known-spaces-' + requested, list = $(listId);
                if (!list) {
                    list = document.createElement('datalist');
                    list.id = listId;
                    field.appendChild(list);
                }
                list.innerHTML = '';
                spaces.forEach(function (sp) {
                    var o = document.createElement('option');
                    o.value = sp;
                    if (counts[sp]) o.label = counts[sp].total + ' rules';
                    list.appendChild(o);
                });
                input.setAttribute('list', listId);
                hint.textContent = '';
                if (!spaces.length) {
                    hint.textContent = ((data && data.message) || 'No spaces found.') + ' Type the Kibana space ID.';
                    return;
                }
                hint.appendChild(document.createTextNode('Spaces on this SIEM — click to use: '));
                spaces.forEach(function (sp) {
                    var b = document.createElement('button');
                    b.type = 'button';
                    b.className = 'btn btn-secondary btn-sm space-pick-btn';
                    b.textContent = sp + (counts[sp] ? ' (' + counts[sp].total + ')' : '');
                    b.addEventListener('click', function () { input.value = sp; });
                    hint.appendChild(b);
                });
            })
            .catch(function () {
                if (hint) hint.textContent = 'Could not load spaces from the server. Type the Kibana space ID.';
            });
    }

    // ── GitLab Projects ──
    // Link a project, or its pencil: only rule backup has a branch, a folder and destinations.
    function gitlabUses(e, box) {
        var form = box.closest('form');
        var backup = form && form.querySelector('input[name="use"][value="backup"]');
        var fields = form && form.querySelector('[data-gitlab-backup-only]');
        if (fields && backup) fields.hidden = !backup.checked;
    }

    TIDE.actions('clientDetail', { submitEdit: submitEdit, moveSystem: moveSystem });
    TIDE.actions('clientSiems', { toggleEdit: toggleEdit, pickColor: pickColor, validationMode: validationMode, addSiem: addSiemChange });
    TIDE.actions('clientGitlab', { uses: gitlabUses });
})();
