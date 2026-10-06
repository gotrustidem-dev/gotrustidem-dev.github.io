'use strict';

/**
 * WebAuthn debug logger.
 * Wraps navigator.credentials.create() / get() so every request, response
 * and error is printed to the DevTools console with the binary fields
 * decoded (hex / JSON / CBOR).
 *
 * Only active when the page URL contains ?debug=1 (e.g. SignData.html?debug=1).
 *
 * Note: request options contain the full PKI command (user.id /
 * allowCredentials[].id), which for SignWithPIN includes the encrypted PIN.
 * Do not share these logs externally.
 */
(function () {
    if (new URLSearchParams(window.location.search).get('debug') !== '1') {
        return;
    }
    if (!window.navigator || !navigator.credentials || navigator.credentials.__webauthnLoggerInstalled) {
        return;
    }

    var toHex = function (buf) {
        if (buf == null) return buf;
        var bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf)
            : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        return Array.prototype.map.call(bytes, function (x) {
            return x.toString(16).padStart(2, '0');
        }).join('');
    };

    var dumpResponse = function (fn, cred) {
        var r = cred.response;
        var out = {
            id: cred.id,
            rawId: toHex(cred.rawId),
            type: cred.type,
        };
        try {
            out.clientDataJSON = JSON.parse(new TextDecoder().decode(r.clientDataJSON));
        } catch (e) {
            out.clientDataJSON = toHex(r.clientDataJSON);
        }

        if (r.attestationObject) {
            // create(): authenticator public key (e.g. 0xE0 ECDH key) is inside authData
            out.attestationObjectHex = toHex(r.attestationObject);
            try {
                var attObj = CBOR.decode(r.attestationObject);
                out.attestationObject = attObj;
                if (typeof parseAuthData === 'function') {
                    out.authData = parseAuthData(attObj.authData);
                }
            } catch (e) {
                out.attestationObjectDecodeError = e.message;
            }
        }

        if (r.authenticatorData) {
            // get(): PKI command responses are carried in signature
            out.authenticatorData = toHex(r.authenticatorData);
            out.signature = toHex(r.signature);
            out.userHandle = toHex(r.userHandle);
        }

        console.log('[WebAuthn] ' + fn + ' response', out, cred);
    };

    ['create', 'get'].forEach(function (fn) {
        var orig = navigator.credentials[fn].bind(navigator.credentials);
        navigator.credentials[fn] = function (options) {
            console.log('[WebAuthn] ' + fn + ' request', options);
            return orig(options).then(function (cred) {
                try {
                    if (cred && cred.response) dumpResponse(fn, cred);
                } catch (e) {
                    console.warn('[WebAuthn] ' + fn + ' response dump failed', e, cred);
                }
                return cred;
            }, function (err) {
                console.error('[WebAuthn] ' + fn + ' error', err && err.name, err && err.message, err);
                throw err;
            });
        };
    });

    navigator.credentials.__webauthnLoggerInstalled = true;
    console.log('[WebAuthn] logger installed');
})();
