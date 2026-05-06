/*
 * paste-encrypted.js
 *
 * Client-side decrypt-and-render for encrypted pastes (Skiff-aligned).
 *
 * Random-key + password modes (SRP-gated):
 *   1. GET /raw/:id  -> JSON header (mode, kdfSalt, argon2 params, srpSalt)
 *   2. derive auth_key + enc_key (HKDF from link_key OR from Argon2id master)
 *   3. POST /:id/srp/init  with A
 *   4. POST /:id/srp/verify with M1   -> M2, full record (chunks)
 *   5. verify M2, decrypt chunks with enc_key, render
 *   6. if record.maxAccesses set, POST /:id/access (server bumps counter,
 *      auto-deletes when the cap is reached)
 *
 * Pubkey mode:
 *   1. GET /raw/:id  -> the full record (no SRP gate; the X25519 ECDH is the
 *      gate -- only the holder of the recipient private key can decrypt)
 *   2. ECDH(my_priv, record.recipient.epk) -> shared       (legacy single)
 *      or  unwrap_recipient_key(record.recipients, my)     (new multi)
 *   3. HKDF(shared) -> enc_key
 *   4. decrypt chunks
 *   5. if record.maxAccesses set, POST /:id/access
 */
(function () {
    'use strict';

    var C = globalThis.MinbinCrypto;
    if (!C) {
        showFatal('Decryption module failed to load. Refresh the page.');
        return;
    }

    var $ = function (id) { return document.getElementById(id); };

    function setHidden(el, hidden) {
        if (!el) return;
        if (hidden) el.classList.add('d-none');
        else el.classList.remove('d-none');
        if (el.style.display) el.style.display = '';
    }

    function showState(name) {
        var shell = $('state-shell');
        var output = $('paste-output');
        var status = $('decrypt-status');
        var err = $('decrypt-error');
        var prompt = $('password-prompt');

        switch (name) {
            case 'loading':
                setHidden(shell, false);
                setHidden(output, true);
                setHidden(status, false);
                setHidden(err, true);
                setHidden(prompt, true);
                break;
            case 'locked':
                setHidden(shell, false);
                setHidden(output, true);
                setHidden(status, true);
                setHidden(err, true);
                setHidden(prompt, false);
                break;
            case 'error':
                setHidden(shell, false);
                setHidden(output, true);
                setHidden(status, true);
                setHidden(err, false);
                setHidden(prompt, true);
                break;
            case 'decrypted':
                setHidden(shell, true);
                setHidden(output, false);
                break;
        }
    }

    function setStatus(msg) {
        var s = $('decrypt-status');
        if (s) s.textContent = msg;
    }

    function showFatal(message) {
        showState('error');
        var t = $('decrypt-error-text');
        if (t) t.textContent = message;
        else if ($('decrypt-error')) $('decrypt-error').textContent = message;
    }

    function showRowError(msg) {
        var b = $('password-row-error');
        if (b) {
            b.textContent = msg || '';
            b.style.display = msg ? '' : 'none';
        }
    }

    var meta = $('paste-meta');
    if (!meta) { showFatal('Page is missing required metadata. Refresh.'); return; }
    var pasteId = meta.getAttribute('data-paste-id') || '';
    var needsPassword = meta.getAttribute('data-needs-password') === '1';
    var isOnce = meta.getAttribute('data-once') === '1';
    var isPubkey = meta.getAttribute('data-pubkey') === '1';
    var fragment = C.parseFragment(window.location.hash);

    async function fetchHeader() {
        var resp = await fetch('/raw/' + encodeURIComponent(pasteId), {
            method: 'GET',
            headers: { Accept: 'application/json' },
            credentials: 'omit',
        });
        if (resp.status === 404) {
            throw new Error('This paste has expired or was already burned.');
        }
        if (!resp.ok) {
            throw new Error('Failed to fetch paste (' + resp.status + ').');
        }
        var record = await resp.json();
        if (!record || record.v !== 3) {
            throw new Error('Server returned an unexpected record shape.');
        }
        return record;
    }

    async function srpExchange(authKey, srpSalt) {
        // Step 1: send A
        var state = await C.srpClientStart();
        var initResp = await fetch('/' + encodeURIComponent(pasteId) + '/srp/init', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ A: C.b64uEncode(state.A_bytes) }),
            credentials: 'omit',
        });
        if (!initResp.ok) {
            var msg = 'SRP init failed (' + initResp.status + ').';
            try {
                var j = await initResp.json();
                if (j && j.detail) msg = j.detail;
            } catch (_) {}
            throw new Error(msg);
        }
        var initBody = await initResp.json();
        var serverSalt = C.b64uDecode(initBody.salt);
        if (srpSalt && !C.bytesEqual(serverSalt, C.b64uDecode(srpSalt))) {
            // Header advertises a different salt than init returned. Bail.
            throw new Error('SRP salt mismatch — refusing to continue.');
        }
        var B_bytes = C.b64uDecode(initBody.B);
        var step2 = await C.srpClientStep2(state, B_bytes, serverSalt, authKey);

        // Step 2: send M1, expect M2 + record
        var verifyResp = await fetch('/' + encodeURIComponent(pasteId) + '/srp/verify', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({
                challengeId: initBody.challengeId,
                M1: C.b64uEncode(step2.M1),
            }),
            credentials: 'omit',
        });
        if (!verifyResp.ok) {
            if (verifyResp.status === 401) {
                throw new Error('Wrong key/passphrase, or paste was tampered with.');
            }
            throw new Error('SRP verify failed (' + verifyResp.status + ').');
        }
        var verifyBody = await verifyResp.json();
        var M2 = C.b64uDecode(verifyBody.M2);
        var ok = await C.srpClientVerifyM2(M2, step2.padA, step2.M1, step2.K);
        if (!ok) {
            // Active MITM -- server's M2 is wrong. Refuse to use the
            // returned record even if it parsed.
            throw new Error('Server proof rejected — possible MITM.');
        }
        return verifyBody.record;
    }

    async function burn() {
        try {
            await fetch('/' + encodeURIComponent(pasteId) + '/burn', {
                method: 'POST',
                credentials: 'omit',
            });
        } catch (_) { /* best effort */ }
    }

    // Bump the server-side access counter for `maxAccesses`-capped pastes.
    // No-op (still safe) when the record had no cap. The server idempotently
    // returns 200 + { remaining, expired } and deletes the paste on the call
    // that reaches the cap.
    async function bumpAccessIfCapped(record) {
        if (!record || typeof record.maxAccesses !== 'number') return;
        try {
            await fetch('/' + encodeURIComponent(pasteId) + '/access', {
                method: 'POST',
                credentials: 'omit',
            });
        } catch (_) { /* best effort */ }
    }

    // Reveal the decrypted textarea without ever showing the body
    // background. The shell and the output textarea share the .textarea
    // class, so the grey box surface is identical across them — we swap
    // the box instantly (no element-level opacity fade) and only animate
    // the *contents*. First the shell's inner centered div fades to 0,
    // then we hide the shell and reveal the textarea; the textarea's
    // text fades in via a color transition from transparent. The grey
    // surface stays opaque the whole time, so there's no "lights off"
    // flash through to the body.
    function fadeSwapShellToOutput() {
        var shell = $('state-shell');
        var output = $('paste-output');
        if (!shell || !output) {
            showState('decrypted');
            return;
        }
        var inner = shell.firstElementChild;
        if (inner) {
            inner.style.transition = 'opacity 320ms ease-in-out';
            inner.style.opacity = '0';
        }
        setTimeout(function () {
            shell.classList.add('d-none');
            output.classList.remove('d-none');
            output.style.display = '';
            output.style.transition = 'none';
            output.style.color = 'transparent';
            void output.offsetHeight;
            output.style.transition = 'color 320ms ease-in-out';
            output.style.color = '';
        }, 320);
    }

    function showPlaintext(bytes) {
        var text;
        try {
            text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
        } catch (_) {
            text = '[binary content, ' + bytes.length + ' bytes]';
        }
        var ta = $('paste-output');
        if (ta) ta.value = text;
        fadeSwapShellToOutput();
    }

    async function decryptRandomKey(header) {
        var keyB64 = fragment.k;
        if (!keyB64) {
            throw new Error('No decryption key in the URL. Make sure you copied the full link including the part after #.');
        }
        var linkKey;
        try { linkKey = C.b64uDecode(keyB64); }
        catch (e) { throw new Error('Decryption key in URL is malformed.'); }
        if (linkKey.length !== 32) throw new Error('Decryption key has wrong length.');
        var keys = await C.deriveRandomKeys(linkKey);
        var record = await srpExchange(keys.authKey, header.srpSalt);
        var pt = await C.decrypt(record, keys.encKey);
        return { plaintext: pt, record: record };
    }

    async function decryptPassword(header, passphrase) {
        var keys = await C.derivePasswordKeys(passphrase, header);
        var record = await srpExchange(keys.authKey, header.srpSalt);
        var pt = await C.decrypt(record, keys.encKey);
        return { plaintext: pt, record: record };
    }

    async function decryptPubkey(record) {
        // record IS the full record in pubkey mode (no SRP gate).
        var identity = await C.loadIdentity();
        if (!identity) {
            throw new Error('No identity in this browser. Generate one in the home-page options modal so the sender can encrypt to your pubkey.');
        }
        if (Array.isArray(record.recipients)) {
            var myPubB64 = C.b64uEncode(identity.pub);
            var found = false;
            for (var i = 0; i < record.recipients.length; i++) {
                if (record.recipients[i].pubkey === myPubB64) { found = true; break; }
            }
            if (!found) {
                var fps = [];
                for (var j = 0; j < record.recipients.length; j++) {
                    fps.push(await C.fingerprintPubkey(C.b64uDecode(record.recipients[j].pubkey)));
                }
                throw new Error(
                    'This paste was encrypted to ' + record.recipients.length + ' recipient(s) (' + fps.join('; ') + '). ' +
                    'Your identity is not on the list — only the matching private key can decrypt.',
                );
            }
        } else if (record.recipient && record.recipient.pubkey) {
            // Legacy single-recipient shape.
            var myPubB64Legacy = C.b64uEncode(identity.pub);
            if (record.recipient.pubkey !== myPubB64Legacy) {
                var fp = await C.fingerprintPubkey(C.b64uDecode(record.recipient.pubkey));
                throw new Error(
                    'This paste was encrypted to a different recipient (' + fp + '). ' +
                    'Your identity does not match — only the matching private key can decrypt.',
                );
            }
        } else {
            throw new Error('Pubkey-mode record is missing recipient information.');
        }
        var encKey = await C.derivePubkeyEnc(record, identity);
        var pt = await C.decrypt(record, encKey);
        return { plaintext: pt, record: record };
    }

    // ---------- shared UI helpers ----------
    function getOtpInputs() {
        return Array.prototype.slice.call(document.querySelectorAll('.otp-cell'));
    }

    function readPassphraseFromUI() {
        var customWrap = $('custom-phrase-wrap');
        var customVisible = customWrap
            && !customWrap.classList.contains('d-none')
            && customWrap.style.display !== 'none';
        if (customVisible) return $('custom-phrase-input').value;
        var cells = getOtpInputs();
        return cells.map(function (c) { return c.value; }).join('');
    }

    function setOtpFromString(s) {
        var clean = String(s || '').replace(/-/g, '').toUpperCase();
        var cells = getOtpInputs();
        for (var i = 0; i < cells.length; i++) {
            var chunk = clean.slice(i * 4, i * 4 + 4);
            cells[i].value = chunk;
            if (chunk.length === 4) cells[i].classList.add('filled');
            else cells[i].classList.remove('filled');
        }
    }

    function wireOtpInputs() {
        var cells = getOtpInputs();
        cells.forEach(function (cell, idx) {
            cell.addEventListener('input', function () {
                var v = cell.value.toUpperCase();
                cell.value = v;
                if (v.length === 4) {
                    cell.classList.add('filled');
                    if (idx < cells.length - 1) cells[idx + 1].focus();
                } else {
                    cell.classList.remove('filled');
                }
                showRowError('');
            });
            cell.addEventListener('keydown', function (ev) {
                if (ev.key === 'Backspace' && cell.value.length === 0 && idx > 0) {
                    ev.preventDefault();
                    cells[idx - 1].focus();
                    cells[idx - 1].value = cells[idx - 1].value.slice(0, -1);
                    cells[idx - 1].classList.remove('filled');
                } else if (ev.key === 'ArrowLeft' && idx > 0) {
                    ev.preventDefault(); cells[idx - 1].focus();
                } else if (ev.key === 'ArrowRight' && idx < cells.length - 1) {
                    ev.preventDefault(); cells[idx + 1].focus();
                }
            });
            cell.addEventListener('paste', function (ev) {
                var text = (ev.clipboardData || window.clipboardData).getData('text');
                if (!text) return;
                ev.preventDefault();
                setOtpFromString(text);
                for (var i = 0; i < cells.length; i++) {
                    if (cells[i].value.length < 4) { cells[i].focus(); return; }
                }
                cells[cells.length - 1].focus();
            });
            cell.addEventListener('focus', function () { cell.select(); });
        });

        var customLink = $('toggle-custom-phrase');
        var customWrap = $('custom-phrase-wrap');
        var otpWrap = $('otp-input');
        if (customLink && customWrap && otpWrap) {
            customLink.addEventListener('click', function (ev) {
                ev.preventDefault();
                var showingCustom = !customWrap.classList.contains('d-none')
                    && customWrap.style.display !== 'none';
                if (showingCustom) {
                    setHidden(customWrap, true);
                    setHidden(otpWrap, false);
                    customLink.textContent = 'use a custom phrase instead';
                    var firstEmpty = cells.find(function (c) { return c.value.length < 4; }) || cells[0];
                    firstEmpty.focus();
                } else {
                    setHidden(customWrap, false);
                    setHidden(otpWrap, true);
                    customLink.textContent = 'use the chunked code instead';
                    $('custom-phrase-input').focus();
                }
            });
        }
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
        // ?party=1 in the URL means the user just landed here from a successful
        // publish. Fire confetti once and strip the param so a refresh doesn't
        // re-trigger it.
        var params = new URLSearchParams(window.location.search);
        if (params.get('party') === '1') {
            fireConfetti();
            params.delete('party');
            var newUrl = window.location.pathname +
                (params.toString() ? '?' + params.toString() : '') +
                window.location.hash;
            window.history.replaceState({}, document.title, newUrl);
        }
    }

    function wireShareConfetti() {
        // Confetti also fires every time the user opens the share modal,
        // regardless of which encryption mode they picked.
        var shareBtns = document.querySelectorAll('[data-bs-target="#share-modal"]');
        for (var i = 0; i < shareBtns.length; i++) {
            shareBtns[i].addEventListener('click', fireConfetti);
        }
    }

    function wireShareModal() {
        var fullUrl = window.location.origin + window.location.pathname + window.location.hash;
        var copyBtns = document.querySelectorAll('.copy-btn');
        for (var i = 0; i < copyBtns.length; i++) {
            (function (b) {
                b.addEventListener('click', async function () {
                    var val = b.getAttribute('data-copy-value') || fullUrl;
                    var targetId = b.getAttribute('data-target-id');
                    var target = targetId ? document.getElementById(targetId) : null;
                    try { await navigator.clipboard.writeText(val); }
                    catch (_) {
                        var ta = document.createElement('textarea');
                        ta.value = val; ta.style.position = 'fixed'; ta.style.opacity = '0';
                        document.body.appendChild(ta); ta.select();
                        try { document.execCommand('copy'); } catch (_) {}
                        document.body.removeChild(ta);
                    }
                    var orig = b.style.color;
                    var origT = target ? target.style.color : '';
                    b.style.color = '#2fd588';
                    if (target) target.style.color = '#2fd588';
                    setTimeout(function () {
                        b.style.color = orig;
                        if (target) target.style.color = origT;
                    }, 900);
                });
            })(copyBtns[i]);
        }
        var qrEl = $('qrcode');
        if (qrEl && typeof QRCode !== 'undefined') {
            try {
                new QRCode(qrEl, {
                    text: fullUrl, width: 94, height: 94,
                    colorDark: '#000000', colorLight: '#ffffff',
                    correctLevel: QRCode.CorrectLevel.L,
                });
            } catch (_) {}
        }
        var shareTextEl = $('share-text');
        if (shareTextEl) {
            var node = shareTextEl.firstChild;
            while (node && node.nodeType !== 3) node = node.nextSibling;
            if (node) node.nodeValue = ' ' + fullUrl + ' ';
            var btn0 = shareTextEl.querySelector('.copy-btn');
            if (btn0) btn0.setAttribute('data-copy-value', fullUrl);
        }
    }

    function wireExpiryTimer() {
        var el = $('expiry-timer');
        if (!el || el.dataset.wired === '1') return;
        el.dataset.wired = '1';
        var seconds = parseInt(el.getAttribute('data-seconds') || '0', 10);
        if (isNaN(seconds) || seconds <= 0) { el.textContent = 'expired'; return; }
        var update = function () {
            if (seconds <= 0) { el.textContent = '00:00'; clearInterval(handle); return; }
            var m = Math.floor(seconds / 60), s = seconds % 60;
            el.textContent = String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
            seconds--;
        };
        update();
        var handle = setInterval(update, 1000);
    }

    function wireReportAbuseModal() {
        var openBtns = document.querySelectorAll('[data-bs-target="#report-modal"]');
        if (openBtns.length === 0) return;
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

    async function startup() {
        showState('loading');
        setStatus('Fetching paste…');

        var record;
        try { record = await fetchHeader(); }
        catch (e) { showFatal(e.message); return; }

        // Trust the record's mode over server-rendered hints; the meta tags
        // are just initial-render hints and the JSON record carries the
        // authoritative metadata.
        var mode = record.mode;

        if (mode === 'pubkey') {
            setStatus('Decrypting with your private key…');
            try {
                var resPk = await decryptPubkey(record);
                showPlaintext(resPk.plaintext);
                if (isOnce) await burn();
                else await bumpAccessIfCapped(resPk.record);
            } catch (e) {
                showFatal(e.message || 'Decryption failed.');
            }
            return;
        }

        if (mode === 'password') {
            wireOtpInputs();
            showState('locked');
            var firstCell = document.querySelector('.otp-cell');
            if (firstCell) firstCell.focus();

            $('password-form').addEventListener('submit', async function (ev) {
                ev.preventDefault();
                var pp = readPassphraseFromUI();
                if (!pp) { showRowError('Enter your passphrase.'); return; }
                showRowError('');
                setStatus('Deriving key with Argon2id…');
                showState('loading');

                var btn = $('password-submit');
                if (btn) btn.disabled = true;
                try {
                    var resPw = await decryptPassword(record, pp);
                    showPlaintext(resPw.plaintext);
                    if (isOnce) await burn();
                    else await bumpAccessIfCapped(resPw.record);
                } catch (e) {
                    showState('locked');
                    showRowError(e.message || 'Wrong passphrase, or the paste was tampered with.');
                } finally {
                    if (btn) btn.disabled = false;
                }
            });
            return;
        }

        // mode === 'random'
        setStatus('Authenticating with the link key…');
        // Hold the auth screen for at least 2s before revealing the paste.
        // On a fast network SRP completes in tens of ms and the screen
        // would flicker; the dwell makes the transition feel deliberate.
        // If SRP is already slow, we don't pile on more delay.
        var authStartMs = Date.now();
        try {
            var resR = await decryptRandomKey(record);
            var elapsed = Date.now() - authStartMs;
            if (elapsed < 2000) {
                await new Promise(function (r) { setTimeout(r, 2000 - elapsed); });
            }
            showPlaintext(resR.plaintext);
            if (isOnce) await burn();
            else await bumpAccessIfCapped(resR.record);
        } catch (e) {
            showFatal(e.message || 'Decryption failed.');
        }
    }

    document.addEventListener('DOMContentLoaded', function () {
        wireShareModal();
        wireShareConfetti();
        wirePartyOnLoad();
        wireExpiryTimer();
        wireReportAbuseModal();
        startup();
    });

    // Suppress unused-warning for `needsPassword` / `isPubkey` -- they're
    // server-rendered hints kept for the meta-tag contract; the live path
    // uses the JSON record's mode field.
    void needsPassword;
    void isPubkey;
})();
