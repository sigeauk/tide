/*
 * The New / Edit Client dialog (#client-modal) on Management and the Clients page, and Delete
 * client (those pages and a client's own page). What follows a save or a delete is the control's
 * data-after: "tab" refreshes Management's Clients tab, a path opens that page, anything else
 * reloads the page.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    function after(where) {
        if (where === 'tab') htmx.ajax('GET', '/api/management/tab/clients', '#management-content');
        else if (where && where.charAt(0) === '/') window.location.href = where;
        else window.location.reload();
    }

    function openModal(id, name, desc) {
        var editing = !!id;
        $('client-modal-title').textContent = editing ? 'Edit Client' : 'New Client';
        $('client-form-submit').textContent = editing ? 'Save' : 'Create';
        $('client-form-id').value = id || '';
        $('client-form-name').value = name || '';
        $('client-form-slug').value = '';
        $('client-form-slug').disabled = editing;
        $('client-form-desc').value = desc || '';
        $('client-modal').style.display = 'flex';
    }

    function closeModal() { $('client-modal').style.display = 'none'; }

    TIDE.actions('clients', {
        create: function () { openModal(); },
        edit: function (e, el) { openModal(el.dataset.id, el.dataset.name, el.dataset.desc); },
        close: closeModal,
        backdrop: function (e, el) { if (e.target === el) closeModal(); },
        submit: async function (e, form) {
            e.preventDefault();
            var id = $('client-form-id').value;
            var payload = {
                name: $('client-form-name').value,
                description: $('client-form-desc').value || null,
            };
            if (!id) payload.slug = $('client-form-slug').value || null;
            try {
                var resp = await fetch(id ? '/api/clients/' + id : '/api/clients', {
                    method: id ? 'PUT' : 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                if (!resp.ok) {
                    var err = await resp.json();
                    showToast(err.detail || 'Could not save the client.', 'error');
                    return;
                }
                closeModal();
                after(form.dataset.after);
            } catch (ex) {
                showToast(TIDE.UNREACHABLE, 'error');
            }
        },
        delete: async function (e, el) {
            if (!confirm('Delete client "' + el.dataset.name + '"? This cannot be undone.')) return;
            try {
                var resp = await fetch('/api/clients/' + el.dataset.id, { method: 'DELETE' });
                if (!resp.ok) {
                    var err = await resp.json();
                    showToast(err.detail || 'Could not delete the client.', 'error');
                    return;
                }
                after(el.dataset.after);
            } catch (ex) {
                showToast(TIDE.UNREACHABLE, 'error');
            }
        },
    });
})();
