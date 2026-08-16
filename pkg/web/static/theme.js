/* theme.js — minimal theme bootstrap.
 * Loaded synchronously in <head> (no defer) so the saved theme is applied
 * before first paint, preventing a flash of the wrong theme.
 * Strict separation: this file owns ONLY theme state; all other behavior
 * lives in app.js. */
(function () {
    'use strict';

    // Apply persisted theme before paint.
    try {
        var saved = localStorage.getItem('p2ptap_theme');
        if (saved === 'light') {
            document.documentElement.setAttribute('data-theme', 'light');
        }
    } catch (e) { /* ignore */ }

    // Toggle between dark and light; expose globally so the
    // data-onclick delegation in app.js can invoke it.
    window.toggleTheme = function () {
        var d = document.documentElement;
        var cur = d.getAttribute('data-theme');
        var next = (cur === 'light') ? 'dark' : 'light';
        if (next === 'dark') {
            d.removeAttribute('data-theme');
        } else {
            d.setAttribute('data-theme', next);
        }
        try { localStorage.setItem('p2ptap_theme', next); } catch (e) { /* ignore */ }
    };
})();
