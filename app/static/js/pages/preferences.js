/*
 * Preferences (pages/admin/preferences.html): theme, brand hue and the per-browser preferences,
 * all kept in localStorage.
 */
(function () {
    'use strict';

    function $(id) { return document.getElementById(id); }

    function themeButtons(theme) {
        var dark = $('theme-dark'), light = $('theme-light');
        if (dark) dark.classList.toggle('active', theme === 'dark');
        if (light) light.classList.toggle('active', theme === 'light');
    }

    TIDE.page('#hue-slider', function (hueSlider) {
        themeButtons(localStorage.getItem('theme') || 'dark');
        var hue = localStorage.getItem('brand-hue') || '240';
        hueSlider.value = hue;
        var hueValue = $('hue-value');
        if (hueValue) hueValue.textContent = hue;
        ['notify-sync', 'notify-validation'].forEach(function (key) {
            var val = localStorage.getItem('pref-' + key), el = $(key);
            if (val !== null && el) el.checked = val === 'true';
        });
        ['cards-per-row', 'page-size'].forEach(function (key) {
            var val = localStorage.getItem('pref-' + key), el = $(key);
            if (val && el) el.value = val;
        });
    });

    TIDE.actions('prefs', {
        theme: function (e, btn) {
            var theme = btn.dataset.theme;
            document.body.classList.toggle('light', theme === 'light');
            localStorage.setItem('theme', theme);
            themeButtons(theme);
        },
        hue: function (e, input) {
            $('hue-value').textContent = input.value;
            document.documentElement.style.setProperty('--brand-hue', input.value);
            localStorage.setItem('brand-hue', input.value);
        },
        // data-pref is the key; a checkbox saves whether it's ticked, anything else its value.
        save: function (e, el) {
            localStorage.setItem('pref-' + el.dataset.pref, el.type === 'checkbox' ? el.checked : el.value);
            showToast('Preference saved', 'success');
        },
    });
})();
