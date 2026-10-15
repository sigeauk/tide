/*
 * Settings & Administration -> Profile & Preferences (pages/admin/settings.html): the theme and
 * brand colour, kept in localStorage (window.setTheme / window.setBrandHue in app.js).
 */
(function () {
    'use strict';

    var DEFAULT_HUE = '212';   // the theme's own accent (body.brand-custom in style.css)

    function $(id) { return document.getElementById(id); }

    function themeButtons(theme) {
        var dark = $('theme-dark'), light = $('theme-light');
        if (dark) dark.classList.toggle('active', theme === 'dark');
        if (light) light.classList.toggle('active', theme === 'light');
    }

    // The slider shows the hue in use; "Default" and no Reset while it is the theme's own.
    function showHue(hue) {
        $('hue-slider').value = hue === null ? DEFAULT_HUE : hue;
        $('hue-value').textContent = hue === null ? 'Default' : hue;
        $('hue-reset').hidden = hue === null;
    }

    // The pencil beside your name (and Cancel, or Esc) swaps it for the name form and back.
    function nameEdit() {
        var card = $('profile-identity'), input = $('profile-display-name');
        if (card.classList.toggle('is-editing')) { input.focus(); input.select(); }
        else input.value = input.defaultValue;
    }

    TIDE.page('#hue-slider', function () {
        themeButtons(localStorage.getItem('theme') || 'dark');
        showHue(localStorage.getItem('brand-hue'));
    });

    TIDE.actions('prefs', {
        theme: function (e, btn) { window.setTheme(btn.dataset.theme === 'light'); },
        hue: function (e, input) {
            window.setBrandHue(input.value);
            showHue(input.value);
        },
        hueReset: function () {
            window.setBrandHue(null);
            showHue(null);
        },
        nameEdit: function () { nameEdit(); },
        nameKey: function (e) {
            if (e.key === 'Escape' && $('profile-identity').classList.contains('is-editing')) nameEdit();
        },
    });
})();
