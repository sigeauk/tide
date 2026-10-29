/*
 * TIDE — element actions and page modules (#60). Templates carry no inline scripts or on*="" handlers:
 *
 *   <button data-click="mgmt.editSiem" data-id="…">        an element's handler, by name
 *   <form data-submit="clients.save">                       (click, change, input, submit, keyup, keydown,
 *                                                            keypress, blur, focus, mouseover, mouseout, toggle)
 *   TIDE.action('mgmt.editSiem', function (event, el) { … })   registers it (in app/static/js/pages/*.js);
 *                                                              `this` is the element, returning false
 *                                                              prevents the default, as an inline handler did.
 *   TIDE.page('[data-page="management"]', function (el) { … }) runs once for each such element, when the
 *                                                              page loads and whenever htmx or a script adds one.
 *
 * Handlers are bound on the element itself (not delegated), so they run when and where an inline
 * handler did, and event.stopPropagation() inside one still works. New content is picked up by a
 * MutationObserver, whether htmx swapped it in, a script set innerHTML, or a <template> was cloned.
 * Template values a script needs travel in data-* attributes, or a <script type="application/json">.
 */
(function () {
    'use strict';
    var TIDE = window.TIDE = window.TIDE || {};
    var EVENTS = ['click', 'change', 'input', 'submit', 'keyup', 'keydown', 'keypress', 'blur', 'focus',
                  'mouseover', 'mouseout', 'toggle', 'dblclick', 'pointerdown', 'mousedown'];
    var actions = {}, pages = [];

    TIDE.action = function (name, fn) { actions[name] = fn; };
    TIDE.actions = function (prefix, map) { Object.keys(map).forEach(function (k) { actions[prefix + '.' + k] = map[k]; }); };

    function run(event) {
        var el = event.currentTarget, name = el.getAttribute('data-' + event.type);
        var fn = actions[name];
        if (!fn) { console.error('TIDE: no action "' + name + '" for ' + event.type); return; }
        if (fn.call(el, event, el) === false) event.preventDefault();
    }

    function each(root, selector, fn) {
        if (!root || root.nodeType !== 1 && root.nodeType !== 9) return;
        if (root.nodeType === 1 && root.matches(selector)) fn(root);
        root.querySelectorAll(selector).forEach(fn);
    }

    function bind(root) {
        EVENTS.forEach(function (type) {
            each(root, '[data-' + type + ']', function (el) {
                var bound = el.__tideBound || (el.__tideBound = {});
                if (bound[type]) return;
                bound[type] = true;
                // toggle, focus and blur don't bubble; listening on the element covers them anyway.
                el.addEventListener(type, run);
            });
        });
        // An element that keeps its clicks to itself (e.g. a link inside a clickable row).
        each(root, '[data-stop-click]', function (el) {
            if (el.__tideStop) return;
            el.__tideStop = true;
            el.addEventListener('click', function (e) { e.stopPropagation(); });
        });
        pages.forEach(function (p) {
            each(root, p.selector, function (el) {
                var done = el.__tidePages || (el.__tidePages = []);
                if (done.indexOf(p) !== -1) return;
                done.push(p);
                try { p.init(el); } catch (err) { console.error('TIDE: init for ' + p.selector + ' failed', err); }
            });
        });
    }
    TIDE.bind = bind;

    TIDE.page = function (selector, init) {
        var p = { selector: selector, init: init };
        pages.push(p);
        if (started) bind(document);
    };

    // Run fn once the document has finished loading (and htmx has processed it): after
    // DOMContentLoaded on a full load, on the next turn after a boosted navigation.
    var domReady = document.readyState === 'complete';
    document.addEventListener('DOMContentLoaded', function () { domReady = true; });
    TIDE.ready = function (fn) {
        if (domReady) setTimeout(fn, 0);
        else document.addEventListener('DOMContentLoaded', fn);
    };

    var started = false;
    function start() {
        if (started) return;
        started = true;
        bind(document);
        // Content htmx swaps in is bound before htmx starts its triggers: a page init can then set
        // values a hx-trigger="load" request reads (as an inline script in the swap used to).
        document.addEventListener('htmx:beforeProcessNode', function (e) { bind(e.target); });
        new MutationObserver(function (records) {
            records.forEach(function (r) {
                r.addedNodes.forEach(function (n) { if (n.nodeType === 1) bind(n); });
            });
        }).observe(document.documentElement, { childList: true, subtree: true });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();

    // ── Shared actions ──────────────────────────────────────────────────────────────────────
    // A dialog's backdrop: a click on the backdrop itself (not the dialog in it) closes it.
    TIDE.action('backdrop.hide', function (e, el) { if (e.target === el) el.style.display = 'none'; });
    TIDE.action('backdrop.remove', function (e, el) { if (e.target === el) el.remove(); });
    // Close the dialog this control is in.
    TIDE.action('modal.remove', function (e, el) { var m = el.closest('.modal-overlay'); if (m) m.remove(); });
    // Hide or show an element by id: data-target="some-id" (data-display for the shown display value).
    TIDE.action('el.hide', function (e, el) {
        var t = document.getElementById(el.getAttribute('data-target'));
        if (t) t.style.display = 'none';
    });
    TIDE.action('el.show', function (e, el) {
        var t = document.getElementById(el.getAttribute('data-target'));
        if (t) t.style.display = el.getAttribute('data-display') || 'flex';
    });
    TIDE.action('el.remove', function (e, el) { el.remove(); });
    // Load data-url into the shared dialog container (e.g. back to the rule from its edit form;
    // a hx-get button inside a hx-post form would be dropped by htmx).
    TIDE.action('modal.load', function (e, el) {
        htmx.ajax('GET', el.getAttribute('data-url'), { target: '#modal-container', swap: 'innerHTML' });
    });
    // A section head that shows or hides its body (data-body; data-display is its shown display),
    // turning its chevron (data-chev). Its ⋮ menu (data-more) opens without folding it.
    TIDE.action('section.toggle', function (e, el) {
        if (e.target.closest && e.target.closest('[data-more]')) return;
        var b = document.getElementById(el.getAttribute('data-body')), c = document.getElementById(el.getAttribute('data-chev'));
        var opening = b.style.display === 'none';
        b.style.display = opening ? (el.getAttribute('data-display') || '') : 'none';
        if (c) c.style.transform = opening ? 'rotate(90deg)' : 'rotate(0deg)';
    });
    TIDE.action('el.toggleNextHidden', function (e, el) { el.nextElementSibling.classList.toggle('hidden'); });
    TIDE.action('page.reload', function () { window.location.reload(); });
    // A filter bar's dropdown panel (Rule Health, a system's techniques): data-target is its id.
    TIDE.action('filterDropdown.toggle', function (e, el) {
        window.tideToggleFilterDropdown(el.getAttribute('data-target'));
    });
    // Every <select> is a choice dropdown (app.js tideEnhanceSelect), wherever it appears.
    TIDE.page('select', function (el) { window.tideEnhanceSelect(el); });
    // A filter in a plain GET form (no htmx): a new choice submits it, as filters elsewhere apply at once.
    TIDE.action('filterDropdown.submit', function (e, el) {
        var form = el.form || el.closest('form');
        if (form) form.requestSubmit();
    });
    TIDE.action('event.prevent', function () { return false; });

    // A status that goes away by itself: replaced by an empty element with its id after data-clear-after ms.
    TIDE.page('[data-clear-after]', function (el) {
        setTimeout(function () {
            if (!el.isConnected) return;
            var empty = document.createElement('div');
            if (el.id) empty.id = el.id;
            el.replaceWith(empty);
        }, parseInt(el.getAttribute('data-clear-after'), 10) || 0);
    });
    // A result that applies on a reload: the page reloads after data-reload-after ms.
    TIDE.page('[data-reload-after]', function (el) {
        setTimeout(function () { window.location.reload(); }, parseInt(el.getAttribute('data-reload-after'), 10) || 0);
    });

    // A partial that reports its result as a toast: <div hidden data-toast="…">.
    TIDE.page('[data-toast]', function (el) {
        var msg = el.getAttribute('data-toast');
        if (msg && window.showToast) window.showToast(msg, 'success');
    });
})();
