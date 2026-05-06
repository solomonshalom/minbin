/*
 * theme.js
 *
 * Light/dark/auto theme switcher. Same logic as the inline blocks in
 * index.html / paste.html / 404.html, extracted so pages with strict CSP
 * (paste-encrypted.html) can load it as `<script src>`.
 */
(function () {
    'use strict';

    var getStoredTheme = function () { return localStorage.getItem('theme'); };
    var setStoredTheme = function (theme) { localStorage.setItem('theme', theme); };
    var forcedTheme = document.documentElement.getAttribute('data-bss-forced-theme');

    var getPreferredTheme = function () {
        if (forcedTheme) return forcedTheme;
        var stored = getStoredTheme();
        if (stored) return stored;
        var pageTheme = document.documentElement.getAttribute('data-bs-theme');
        if (pageTheme) return pageTheme;
        return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    };

    var setTheme = function (theme) {
        if (theme === 'auto' && window.matchMedia('(prefers-color-scheme: dark)').matches) {
            document.documentElement.setAttribute('data-bs-theme', 'dark');
        } else {
            document.documentElement.setAttribute('data-bs-theme', theme);
        }
    };

    setTheme(getPreferredTheme());

    var showActiveTheme = function (theme) {
        var switchers = document.querySelectorAll('.theme-switcher');
        if (!switchers.length) return;
        document.querySelectorAll('[data-bs-theme-value]').forEach(function (el) {
            el.classList.remove('active');
            el.setAttribute('aria-pressed', 'false');
        });
        for (var i = 0; i < switchers.length; i++) {
            var btn = switchers[i].querySelector('[data-bs-theme-value="' + theme + '"]');
            if (btn) {
                btn.classList.add('active');
                btn.setAttribute('aria-pressed', 'true');
            }
        }
    };

    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function () {
        var stored = getStoredTheme();
        if (stored !== 'light' && stored !== 'dark') setTheme(getPreferredTheme());
    });

    window.addEventListener('DOMContentLoaded', function () {
        showActiveTheme(getPreferredTheme());
        document.querySelectorAll('[data-bs-theme-value]').forEach(function (toggle) {
            toggle.addEventListener('click', function (e) {
                e.preventDefault();
                var theme = toggle.getAttribute('data-bs-theme-value');
                setStoredTheme(theme);
                setTheme(theme);
                showActiveTheme(theme);
            });
        });
    });
})();
