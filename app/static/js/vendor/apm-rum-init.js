(function () {
    var config = window.TIDE_APM_RUM_CONFIG;
    if (!config || !window.elasticApm || typeof window.elasticApm.init !== 'function') {
        return;
    }

    function sanitizeLabel(value) {
        if (!value) {
            return '';
        }
        return String(value).replace(/\s+/g, ' ').trim().slice(0, 80);
    }

    function applyInteractionHints(rootNode) {
        var root = rootNode && rootNode.querySelectorAll ? rootNode : document;
        var controls = root.querySelectorAll('a[name], button[name], [name][hx-get], [name][hx-post], [name][hx-put], [name][hx-delete], [name][hx-patch], [name][onclick]');

        controls.forEach(function(control) {
            var label = sanitizeLabel(control.getAttribute('name'));
            if (!label) {
                return;
            }

            control.querySelectorAll('span, svg, path, use').forEach(function(child) {
                if (!child.getAttribute('name')) {
                    child.setAttribute('name', label);
                }

                var tag = (child.tagName || '').toLowerCase();
                if ((tag === 'svg' || tag === 'path' || tag === 'use') && !child.style.pointerEvents) {
                    child.style.pointerEvents = 'none';
                }
            });
        });
    }

    try {
        window.TIDE_APM = window.elasticApm.init(config);

        if (!document.body) {
            return;
        }

        applyInteractionHints(document);

        document.body.addEventListener('htmx:beforeRequest', function(evt) {
            if (evt.detail.boosted || (evt.detail.elt && evt.detail.elt.hasAttribute('hx-push-url'))) {
                window.tide_active_txn = window.elasticApm.startTransaction(
                    evt.detail.pathInfo.requestPath,
                    'route-change',
                    { managed: true, canReuse: true }
                );
            }
        });

        document.body.addEventListener('htmx:afterSettle', function() {
            if (window.tide_active_txn) {
                window.tide_active_txn.end();
                window.tide_active_txn = null;
            }

            applyInteractionHints(document);
        });
    } catch (error) {
        if (window.console && typeof window.console.warn === 'function') {
            window.console.warn('TIDE Elastic APM RUM initialization failed', error);
        }
    }
})();
