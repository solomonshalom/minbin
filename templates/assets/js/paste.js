/*
 * paste.js
 *
 * Inline-script-free behaviors for the plaintext paste page (paste.html):
 *   - expiry timer (counts down from data-seconds to 00:00)
 *   - share-modal QR code + clipboard copy
 *   - confetti on ?party=1 landing and on share-modal open
 *   - report-abuse modal wiring (POST /report)
 *
 * Loaded as `<script src>` so paste.html does not require
 * `script-src 'unsafe-inline'`.
 *
 * Server-rendered values are read from data- attributes:
 *   <span id="expiry-timer" data-seconds="{{ paste_expiry }}">
 *   <div id="paste-meta" data-app-domain="..." data-paste-id="...">
 */
(function () {
    'use strict';

    var $ = function (id) { return document.getElementById(id); };

    function wireExpiryTimer() {
        var el = $('expiry-timer');
        if (!el || el.dataset.wired === '1') return;
        el.dataset.wired = '1';
        var seconds = parseInt(el.getAttribute('data-seconds') || '0', 10);
        if (isNaN(seconds) || seconds <= 0) {
            el.textContent = 'expired';
            return;
        }
        var update = function () {
            if (seconds <= 0) {
                clearInterval(handle);
                el.textContent = '00:00';
                return;
            }
            var m = Math.floor(seconds / 60);
            var s = seconds % 60;
            el.textContent = String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
            seconds--;
        };
        update();
        var handle = setInterval(update, 1000);
    }

    function fireConfetti() {
        if (typeof confetti !== 'function') return;
        confetti({
            particleCount: 150,
            spread: 70,
            origin: { y: 0.6 },
        });
    }

    function wirePartyOnLoad() {
        var params = new URLSearchParams(window.location.search);
        if (params.get('party') === '1') {
            fireConfetti();
            var newUrl = window.location.pathname;
            window.history.replaceState({}, document.title, newUrl);
        }
    }

    function wireShareConfetti() {
        var btns = document.querySelectorAll('[data-bs-target="#share-modal"]');
        for (var i = 0; i < btns.length; i++) {
            btns[i].addEventListener('click', fireConfetti);
        }
    }

    function wireQrCode() {
        var meta = $('paste-meta');
        var qrEl = $('qrcode');
        if (!meta || !qrEl || typeof QRCode === 'undefined') return;
        var domain = meta.getAttribute('data-app-domain') || '';
        var id = meta.getAttribute('data-paste-id') || '';
        if (!domain || !id) return;
        try {
            new QRCode(qrEl, {
                text: 'https://' + domain + '/' + id,
                width: 94,
                height: 94,
                colorDark: '#000000',
                colorLight: '#ffffff',
                correctLevel: QRCode.CorrectLevel.L,
            });
        } catch (_) { /* ignore */ }
    }

    function wireCopyButtons() {
        var copyButtons = document.querySelectorAll('.copy-btn');
        for (var i = 0; i < copyButtons.length; i++) {
            (function (button) {
                button.addEventListener('click', async function () {
                    var textToCopy = button.getAttribute('data-copy-value') || '';
                    var targetId = button.getAttribute('data-target-id');
                    var targetEl = targetId ? document.getElementById(targetId) : null;
                    var origBtnColor = button.style.color;
                    var origTargetColor = targetEl ? targetEl.style.color : '';
                    try {
                        await navigator.clipboard.writeText(textToCopy);
                    } catch (_) {
                        var ta = document.createElement('textarea');
                        ta.value = textToCopy;
                        ta.style.position = 'fixed';
                        ta.style.opacity = '0';
                        document.body.appendChild(ta);
                        ta.select();
                        try { document.execCommand('copy'); } catch (_) {}
                        document.body.removeChild(ta);
                    }
                    var success = '#2fd588';
                    button.style.color = success;
                    if (targetEl) targetEl.style.color = success;
                    setTimeout(function () {
                        button.style.color = origBtnColor;
                        if (targetEl) targetEl.style.color = origTargetColor;
                    }, 1000);
                });
            })(copyButtons[i]);
        }
    }

    function wireReportAbuseModal() {
        var openBtns = document.querySelectorAll('[data-bs-target="#report-modal"]');
        if (openBtns.length === 0) return;
        var meta = $('paste-meta');
        var pasteId = meta ? (meta.getAttribute('data-paste-id') || '') : '';
        var idField = $('report-paste-id');
        var linkField = $('report-link');
        if (idField) idField.value = pasteId;
        if (linkField) linkField.value = window.location.href;
        var form = $('report-form');
        var status = $('report-status');
        if (!form) return;
        form.addEventListener('submit', async function (ev) {
            ev.preventDefault();
            if (status) { status.textContent = 'sending…'; status.style.color = ''; }
            var btn = $('report-submit');
            if (btn) btn.disabled = true;
            var reasonEl = $('report-reason');
            var contactEl = $('report-contact');
            var payload = {
                paste_id: pasteId,
                reason: reasonEl ? reasonEl.value : '',
                contact: contactEl ? contactEl.value : '',
                link: linkField ? linkField.value : '',
            };
            try {
                var r = await fetch('/report', {
                    method: 'POST',
                    headers: { 'content-type': 'application/json' },
                    body: JSON.stringify(payload),
                    credentials: 'omit',
                });
                if (!r.ok) {
                    var detail = await r.text();
                    try {
                        var p = JSON.parse(detail);
                        if (p && p.detail) detail = p.detail;
                    } catch (_) {}
                    throw new Error(detail);
                }
                if (status) {
                    status.textContent = 'thanks — report received.';
                    status.style.color = '#2fd588';
                }
                form.reset();
                if (idField) idField.value = pasteId;
                if (linkField) linkField.value = window.location.href;
            } catch (e) {
                if (status) {
                    status.textContent = e.message || 'Could not send the report.';
                    status.style.color = '#d4264a';
                }
            } finally {
                if (btn) btn.disabled = false;
            }
        });
    }

    document.addEventListener('DOMContentLoaded', function () {
        wireExpiryTimer();
        wirePartyOnLoad();
        wireShareConfetti();
        wireQrCode();
        wireCopyButtons();
        wireReportAbuseModal();
    });
})();
