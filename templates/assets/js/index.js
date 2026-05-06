/*
 * index.js
 *
 * Submission handler for the home page. Three encryption modes:
 *   - plaintext (legacy curl-equivalent path; opt-in via the "encrypt" toggle)
 *   - random-key encrypted (default in the web UI; v3 + SRP)
 *   - password-encrypted via Argon2id (v3 + SRP)
 *   - send-to-pubkey with multi-recipient support (Skiff §6.5)
 *
 * After a successful POST we navigate to /<id>{#k=...|#p=1|#x=1}.
 *
 * Plaintext POSTs solve a hashcash-style PoW captcha when the deployment
 * has CAPTCHA_BITS > 0. Encrypted POSTs are exempt because the SRP+Argon2
 * cost already raises the per-paste work for an attacker.
 */
(function () {
    'use strict';

    var $ = function (id) { return document.getElementById(id); };

    function setStatus(msg) {
        var s = $('submit-status');
        if (s) s.textContent = msg;
    }

    function setError(msg) {
        var e = $('submit-error');
        if (!e) return;
        e.textContent = msg;
        e.style.display = msg ? 'block' : 'none';
    }

    function readClipboardInto(textarea) {
        if (!navigator.clipboard || !navigator.clipboard.readText) return;
        navigator.clipboard.readText().then(function (text) {
            textarea.value = text;
        }).catch(function () { /* ignore */ });
    }

    // The options button shows a small green dot whenever the user has any
    // non-default option set. Defaults: encrypt=ON, password=OFF, once=OFF,
    // pubkey=OFF, max-views=OFF.
    function refreshOptionsActiveDot() {
        var dot = $('options-active-dot');
        if (!dot) return;
        var encToggle = $('toggle-encrypt');
        var pwToggle = $('toggle-password');
        var onceToggle = $('toggle-once');
        var pkToggle = $('toggle-pubkey');
        var mvToggle = $('toggle-max-views');
        var nonDefault =
            (encToggle && !encToggle.checked) ||
            (pwToggle && pwToggle.checked) ||
            (onceToggle && onceToggle.checked) ||
            (pkToggle && pkToggle.checked) ||
            (mvToggle && mvToggle.checked);
        dot.style.display = nonDefault ? 'inline-block' : 'none';
    }

    // ---------- pubkey-recipients UI ----------
    // Each row = one pubkey input + a "remove" button + a fingerprint preview.
    // The first row is created on init so the UI never feels empty when the
    // toggle opens. Add/remove buttons stay enabled within [1, 16].
    function makeRecipientRow(C) {
        var wrap = document.createElement('div');
        wrap.className = 'pubkey-recipient-row';
        wrap.style.display = 'flex';
        wrap.style.flexDirection = 'column';
        wrap.style.gap = '4px';

        var inputRow = document.createElement('div');
        inputRow.className = 'd-flex align-items-stretch';
        inputRow.style.gap = '6px';

        var input = document.createElement('input');
        input.type = 'text';
        input.autocomplete = 'off';
        input.spellcheck = false;
        input.className = 'form-control shadow-none recipient-pubkey-input';
        input.placeholder = 'recipient pubkey (base64url, 32 bytes)';
        input.style.fontFamily = "'Geist Mono', monospace";
        input.style.fontSize = '13px';
        input.style.letterSpacing = '0.05em';
        input.style.borderRadius = '0';
        input.style.border = '1px solid var(--bs-border-color)';
        input.style.backgroundColor = 'var(--bs-body-bg)';
        input.style.color = 'var(--bs-body-color)';

        var removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'btn shadow-none recipient-remove';
        removeBtn.title = 'remove recipient';
        removeBtn.setAttribute('aria-label', 'remove recipient');
        removeBtn.style.border = '1px solid var(--bs-border-color)';
        removeBtn.style.borderRadius = '0';
        removeBtn.style.minWidth = '38px';
        removeBtn.style.padding = '0 8px';
        removeBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="1em" height="1em" viewBox="0 0 24 24" fill="none" style="font-size: 16px;"><path d="M6 6L18 18M18 6L6 18" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"></path></svg>';

        inputRow.appendChild(input);
        inputRow.appendChild(removeBtn);
        wrap.appendChild(inputRow);

        var fpDiv = document.createElement('div');
        fpDiv.className = 'recipient-fingerprint';
        fpDiv.style.fontSize = '11px';
        fpDiv.style.color = 'var(--bs-tertiary-color)';
        fpDiv.style.lineHeight = '1.4';
        fpDiv.style.fontFamily = "'Geist Mono', monospace";
        fpDiv.style.minHeight = '14px';
        wrap.appendChild(fpDiv);

        async function refreshFp() {
            var raw = input.value.trim();
            if (!raw) { fpDiv.textContent = ''; return; }
            try {
                var bytes = C.b64uDecode(raw);
                if (bytes.length !== 32) {
                    fpDiv.textContent = 'invalid: expected 32 bytes (base64url)';
                    return;
                }
                var fp = await C.fingerprintPubkey(bytes);
                fpDiv.textContent = 'fingerprint: ' + fp;
            } catch (_) {
                fpDiv.textContent = 'invalid base64url';
            }
        }
        input.addEventListener('input', refreshFp);
        input.addEventListener('blur', refreshFp);

        removeBtn.addEventListener('click', function () {
            var rowsParent = $('pubkey-recipients');
            if (!rowsParent) return;
            var rows = rowsParent.querySelectorAll('.pubkey-recipient-row');
            // Always keep at least one row visible; clear instead of removing
            // when there's only one. This avoids a confusing empty UI.
            if (rows.length <= 1) {
                input.value = '';
                fpDiv.textContent = '';
                input.focus();
            } else {
                wrap.parentNode.removeChild(wrap);
                refreshAddBtnState();
            }
        });
        return wrap;
    }

    function refreshAddBtnState() {
        var btn = $('pubkey-add-recipient');
        if (!btn) return;
        var rowsParent = $('pubkey-recipients');
        if (!rowsParent) return;
        var count = rowsParent.querySelectorAll('.pubkey-recipient-row').length;
        btn.disabled = count >= 16;
        btn.style.opacity = btn.disabled ? '0.4' : '1';
    }

    function addRecipientRow(C, focus) {
        var rowsParent = $('pubkey-recipients');
        if (!rowsParent) return null;
        var row = makeRecipientRow(C);
        rowsParent.appendChild(row);
        refreshAddBtnState();
        if (focus) {
            var input = row.querySelector('input');
            if (input) input.focus();
        }
        return row;
    }

    function readRecipientPubkeys(C) {
        var inputs = document.querySelectorAll('.recipient-pubkey-input');
        var out = [];
        for (var i = 0; i < inputs.length; i++) {
            var raw = inputs[i].value.trim();
            if (!raw) continue;
            var bytes;
            try { bytes = C.b64uDecode(raw); }
            catch (e) {
                throw new Error('Recipient #' + (i + 1) + ' is not valid base64url.');
            }
            if (bytes.length !== 32) {
                throw new Error('Recipient #' + (i + 1) + ' must decode to 32 bytes.');
            }
            out.push(bytes);
        }
        return out;
    }

    document.addEventListener('DOMContentLoaded', function () {
        var pasteBtn = $('paste-button');
        var textarea = $('paste-content');
        if (pasteBtn && textarea) {
            pasteBtn.addEventListener('click', function () { readClipboardInto(textarea); });
        }

        var encToggle = $('toggle-encrypt');
        var pwToggle = $('toggle-password');
        var onceToggle = $('toggle-once');
        var pkToggle = $('toggle-pubkey');
        var mvToggle = $('toggle-max-views');
        var pwInputWrap = $('password-input-wrap');
        var pkInputWrap = $('pubkey-input-wrap');
        var mvWrap = $('max-views-wrap');
        var mvInput = $('max-views-input');
        var addRecBtn = $('pubkey-add-recipient');

        var passwordInput = $('password-input');
        var regenBtn = $('password-regenerate');
        var copyBtn = $('password-copy');

        function fillNewPassphrase() {
            if (passwordInput && globalThis.MinbinCrypto) {
                passwordInput.value = globalThis.MinbinCrypto.generatePassphrase();
            }
        }

        if (pwToggle && pwInputWrap) {
            pwToggle.addEventListener('change', function () {
                pwInputWrap.style.display = pwToggle.checked ? '' : 'none';
                if (pwToggle.checked) {
                    if (encToggle && !encToggle.checked) encToggle.checked = true;
                    if (pkToggle && pkToggle.checked) {
                        // password and pubkey are mutually exclusive
                        pkToggle.checked = false;
                        if (pkInputWrap) pkInputWrap.style.display = 'none';
                    }
                    if (passwordInput && passwordInput.value.length === 0) {
                        fillNewPassphrase();
                    }
                }
                refreshOptionsActiveDot();
            });
        }

        if (regenBtn) {
            regenBtn.addEventListener('click', function () {
                fillNewPassphrase();
                if (passwordInput) passwordInput.focus();
            });
        }

        if (copyBtn && passwordInput) {
            copyBtn.addEventListener('click', async function () {
                var v = passwordInput.value;
                if (!v) return;
                try {
                    await navigator.clipboard.writeText(v);
                } catch (_) {
                    passwordInput.select();
                    try { document.execCommand('copy'); } catch (_) {}
                }
                var orig = copyBtn.style.color;
                copyBtn.style.color = '#2fd588';
                setTimeout(function () { copyBtn.style.color = orig; }, 900);
            });
        }

        if (encToggle) {
            encToggle.addEventListener('change', function () {
                if (!encToggle.checked) {
                    if (pwToggle) {
                        pwToggle.checked = false;
                        if (pwInputWrap) pwInputWrap.style.display = 'none';
                    }
                    if (pkToggle) {
                        pkToggle.checked = false;
                        if (pkInputWrap) pkInputWrap.style.display = 'none';
                    }
                }
                refreshOptionsActiveDot();
            });
        }

        // one-time and max-views are mutually exclusive: one-time is just
        // shorthand for "max views = 1". Toggling either off the other.
        if (onceToggle) {
            onceToggle.addEventListener('change', function () {
                if (onceToggle.checked && mvToggle && mvToggle.checked) {
                    mvToggle.checked = false;
                    if (mvWrap) mvWrap.style.display = 'none';
                }
                refreshOptionsActiveDot();
            });
        }
        if (mvToggle && mvWrap) {
            mvToggle.addEventListener('change', function () {
                mvWrap.style.display = mvToggle.checked ? '' : 'none';
                if (mvToggle.checked) {
                    if (onceToggle && onceToggle.checked) {
                        onceToggle.checked = false;
                    }
                    if (mvInput && (!mvInput.value || mvInput.value === '0')) {
                        mvInput.value = '5';
                    }
                }
                refreshOptionsActiveDot();
            });
        }

        // ---------- pubkey-mode UI ----------
        if (pkToggle && pkInputWrap) {
            pkToggle.addEventListener('change', function () {
                pkInputWrap.style.display = pkToggle.checked ? '' : 'none';
                if (pkToggle.checked) {
                    if (encToggle && !encToggle.checked) encToggle.checked = true;
                    if (pwToggle && pwToggle.checked) {
                        pwToggle.checked = false;
                        if (pwInputWrap) pwInputWrap.style.display = 'none';
                    }
                    // Ensure at least one recipient row exists when the
                    // toggle is first opened.
                    var rowsParent = $('pubkey-recipients');
                    if (rowsParent && rowsParent.children.length === 0 && globalThis.MinbinCrypto) {
                        addRecipientRow(globalThis.MinbinCrypto, true);
                    }
                }
                refreshOptionsActiveDot();
            });
        }
        if (addRecBtn) {
            addRecBtn.addEventListener('click', function () {
                if (!globalThis.MinbinCrypto) return;
                addRecipientRow(globalThis.MinbinCrypto, true);
            });
        }
        // Pre-render the first row (hidden until toggled on).
        if (globalThis.MinbinCrypto) {
            addRecipientRow(globalThis.MinbinCrypto, false);
        }

        // ---------- identity (one's own pubkey for sharing) ----------
        var identitySection = $('identity-section');
        var identityPub = $('identity-pubkey');
        var identityFp = $('identity-fingerprint');
        var identityCopyBtn = $('identity-copy');
        var identityGenBtn = $('identity-generate');
        var identityResetBtn = $('identity-reset');

        async function refreshIdentitySection() {
            if (!identitySection || !globalThis.MinbinCrypto) return;
            var id = await globalThis.MinbinCrypto.loadIdentity();
            if (!id) {
                if (identityPub) identityPub.value = '';
                if (identityFp) identityFp.textContent = 'no identity yet — generate one to receive pubkey-mode pastes.';
                if (identityCopyBtn) identityCopyBtn.disabled = true;
                if (identityResetBtn) identityResetBtn.disabled = true;
                return;
            }
            var pubB64 = globalThis.MinbinCrypto.b64uEncode(id.pub);
            if (identityPub) identityPub.value = pubB64;
            var fp = await globalThis.MinbinCrypto.fingerprintPubkey(id.pub);
            if (identityFp) identityFp.textContent = 'fingerprint: ' + fp;
            if (identityCopyBtn) identityCopyBtn.disabled = false;
            if (identityResetBtn) identityResetBtn.disabled = false;
        }

        if (identityGenBtn) {
            identityGenBtn.addEventListener('click', async function () {
                if (!globalThis.MinbinCrypto) return;
                var existing = await globalThis.MinbinCrypto.loadIdentity();
                if (existing) {
                    var ok = window.confirm(
                        'replace existing identity? any pastes encrypted to your old pubkey will become undecryptable.',
                    );
                    if (!ok) return;
                }
                var id = await globalThis.MinbinCrypto.generateIdentity();
                globalThis.MinbinCrypto.saveIdentity(id);
                refreshIdentitySection();
            });
        }

        if (identityResetBtn) {
            identityResetBtn.addEventListener('click', function () {
                var ok = window.confirm(
                    'forget identity? pastes encrypted to your pubkey will become undecryptable.',
                );
                if (!ok) return;
                globalThis.MinbinCrypto.clearIdentity();
                refreshIdentitySection();
            });
        }

        if (identityCopyBtn && identityPub) {
            identityCopyBtn.addEventListener('click', async function () {
                var v = identityPub.value;
                if (!v) return;
                try { await navigator.clipboard.writeText(v); }
                catch (_) {
                    identityPub.select();
                    try { document.execCommand('copy'); } catch (_) {}
                }
                var orig = identityCopyBtn.style.color;
                identityCopyBtn.style.color = '#2fd588';
                setTimeout(function () { identityCopyBtn.style.color = orig; }, 900);
            });
        }

        refreshOptionsActiveDot();
        refreshIdentitySection();

        var form = $('main-form');
        if (!form) return;

        form.addEventListener('submit', async function (ev) {
            ev.preventDefault();
            setError('');

            var text = textarea.value;
            if (!text) { setError('Paste is empty.'); return; }

            var encrypted = encToggle ? encToggle.checked : true;
            var usePassword = pwToggle ? pwToggle.checked : false;
            var usePubkey = pkToggle ? pkToggle.checked : false;
            var rawPassword = usePassword ? ($('password-input').value || '') : '';
            var password = usePassword
                ? globalThis.MinbinCrypto.normalizePassphrase(rawPassword)
                : '';
            var once = $('toggle-once') ? $('toggle-once').checked : false;

            // max-views: numeric, defaults to 5 if toggle is on but field was
            // cleared. Capped server-side; we surface a friendly error if
            // it's clearly out of range.
            var useMaxViews = mvToggle ? mvToggle.checked : false;
            var maxAccessesValue = null;
            if (useMaxViews) {
                var v = parseInt(mvInput && mvInput.value, 10);
                if (!Number.isInteger(v) || v < 1 || v > 1000) {
                    setError('Max views must be a whole number between 1 and 1000.');
                    return;
                }
                maxAccessesValue = v;
            }

            if (usePassword && password.length < 6) {
                setError('Use a password with at least 6 characters (longer is better — passwords are the only thing protecting password-mode pastes).');
                return;
            }

            var recipientPubkeys = null;
            if (usePubkey) {
                try { recipientPubkeys = readRecipientPubkeys(globalThis.MinbinCrypto); }
                catch (e) { setError(e.message); return; }
                if (recipientPubkeys.length === 0) {
                    setError('Add at least one recipient pubkey (32 bytes base64url).');
                    return;
                }
                if (recipientPubkeys.length > 16) {
                    setError('At most 16 recipients are supported.');
                    return;
                }
            }

            // Open a blank tab synchronously while we're still inside the
            // click gesture. Browsers attribute the popup to that gesture,
            // so the new tab is allowed; pointing it at the final URL
            // happens once the upload returns. The editor tab itself
            // never navigates — if a strict popup blocker stops the new
            // tab from opening we surface an inline link instead so the
            // user can click through to their paste manually.
            var pasteWindow = null;
            try { pasteWindow = window.open('about:blank', '_blank'); }
            catch (_) { /* popup blocked or sandboxed; handled below */ }

            function showOpenLinkFallback(url) {
                var e = $('submit-error');
                if (!e) return;
                e.textContent = '';
                var prefix = document.createTextNode('paste created — popup was blocked. ');
                var a = document.createElement('a');
                a.href = url;
                a.target = '_blank';
                a.rel = 'noopener';
                a.textContent = 'open paste';
                a.style.color = 'inherit';
                e.appendChild(prefix);
                e.appendChild(a);
                e.style.display = 'block';
            }

            function navigateToPaste(url) {
                if (pasteWindow && !pasteWindow.closed) {
                    try {
                        pasteWindow.location.href = url;
                        // The editor tab is done — reload it to "/" so
                        // the textarea, status line, and option toggles
                        // reset to a clean home page instead of being
                        // left mid-upload.
                        window.location.replace('/');
                        return;
                    } catch (_) { /* fall through to inline-link fallback */ }
                }
                setStatus('');
                showOpenLinkFallback(url);
            }

            try {
                if (!encrypted) {
                    setStatus('Solving captcha (if required)…');
                    var captcha;
                    try {
                        captcha = await globalThis.MinbinCrypto.solveCaptchaForUpload(function (bits) {
                            setStatus('Solving captcha (' + bits + ' bits)…');
                        });
                    } catch (e) {
                        // Captcha endpoint failure shouldn't block uploads on
                        // self-hosted setups where the captcha is disabled --
                        // the server will still accept without a token.
                        captcha = { token: '', nonce: '' };
                    }

                    setStatus('Uploading…');
                    var url = '/?relative=true' + (once ? '&once=true' : '');
                    if (maxAccessesValue !== null) {
                        url += '&maxAccesses=' + maxAccessesValue;
                    }
                    var headers = { 'content-type': 'text/plain; charset=utf-8' };
                    if (captcha.token) headers['x-captcha-token'] = captcha.token;
                    if (captcha.nonce) headers['x-captcha-nonce'] = captcha.nonce;
                    var r = await fetch(url, {
                        method: 'POST',
                        headers: headers,
                        body: text,
                        credentials: 'omit',
                    });
                    if (!r.ok) {
                        var detail = await r.text();
                        try {
                            var parsed = JSON.parse(detail);
                            if (parsed && parsed.detail) detail = parsed.detail;
                        } catch (_) {}
                        throw new Error('Server returned ' + r.status + ': ' + detail);
                    }
                    var id = (await r.text()).trim();
                    navigateToPaste('/' + id + '?party=1');
                    return;
                }

                if (!globalThis.MinbinCrypto) {
                    throw new Error('Encryption module failed to load. Try a non-encrypted paste, or refresh.');
                }
                if (usePassword && (!globalThis.hashwasm || !globalThis.hashwasm.argon2id)) {
                    throw new Error('Password module failed to load. Refresh and try again.');
                }

                setStatus(usePassword
                    ? 'Deriving key with Argon2id (this takes a moment)…'
                    : 'Encrypting…');

                var mode = usePubkey ? 'pubkey' : (usePassword ? 'password' : 'random');
                var encOpts = {
                    mode: mode,
                    password: usePassword ? password : null,
                    once: once,
                };
                if (maxAccessesValue !== null) encOpts.maxAccesses = maxAccessesValue;
                if (usePubkey) encOpts.recipientPubkeys = recipientPubkeys;

                var enc = await globalThis.MinbinCrypto.encrypt(text, encOpts);

                setStatus('Uploading ciphertext…');
                var resp = await fetch('/?relative=true', {
                    method: 'POST',
                    headers: { 'content-type': 'application/vnd.minbin.encrypted+json' },
                    body: JSON.stringify(enc.record),
                    credentials: 'omit',
                });
                if (!resp.ok) {
                    var detailE = await resp.text();
                    try {
                        var parsedE = JSON.parse(detailE);
                        if (parsedE && parsedE.detail) detailE = parsedE.detail;
                    } catch (_) {}
                    throw new Error('Server returned ' + resp.status + ': ' + detailE);
                }
                var pasteId = (await resp.text()).trim();

                var fragment;
                if (usePubkey) {
                    fragment = '#x=1';
                } else if (usePassword) {
                    fragment = '#p=1';
                } else {
                    fragment = '#k=' + globalThis.MinbinCrypto.b64uEncode(enc.link_key);
                }
                navigateToPaste('/' + pasteId + '?party=1' + fragment);
            } catch (e) {
                setStatus('');
                setError(e && e.message ? e.message : 'Submission failed.');
                if (pasteWindow && !pasteWindow.closed) {
                    try { pasteWindow.close(); } catch (_) { /* ignore */ }
                }
            }
        });
    });
})();
