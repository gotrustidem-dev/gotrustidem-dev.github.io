'use strict';





/**
 *  Return  a list of certificate that stored on token
 * 
 * 
 */
function readSimpleCerts() {


}

/** 
 * Return a full certificate by searching the index
 * 
 * 
 */
function readCert() {




}


/**
 * 
 *  Return the value of Signature of input data 
 *  @returns
 *      The value of Signature 
 */


function sign() {


}



async function requirePINVerify() {

    var userpin;
    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var local_privateKey;
    var local_privateKey;
    var externalECPublicKey;
    var exportECPublicKeyArray;
    var pinEncKey;
    var EncryptedPINArray;

    //Prepare PKI commmand
    //Header
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
    var pki_header = new Uint8Array(3);
    pki_header[0] = 0xE1;
    pki_header[1] = 0x00
    pki_header[2] = 0x00;
    //PKI Command


    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);

    console.log(bufToHex(pki_buffer));

    var request_keyagreement = {
        'challenge': challenge,

        'rp': {
            'name': 'GoTrustID Inc.',
        },

        'user': {
            'id': pki_buffer,
            'name': 'alice@example.com',
            'displayName': 'Alice von Wunderland'
        },

        "authenticatorSelection": {
            "userVerification": "discouraged",
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform"

        },
        'attestation': "direct",
        'pubKeyCredParams': [{
                'type': 'public-key',
                'alg': -7
            },
            {
                'type': 'public-key',
                'alg': -257
            }
        ]
    }
    console.log('Get ECDH Key request', request_keyagreement);

    await new Promise(resolve => {
        navigator.credentials.create({
            'publicKey': request_keyagreement
        }).then((newCredentialInfo) => {
            userpin = prompt("Input your PIN", "");
            if (userpin == null) {
                return;
            }
            console.log('PIN', userpin);

            let attestationObject = CBOR.decode(newCredentialInfo.response.attestationObject);
            let authData = parseAuthData(attestationObject.authData);
            var publicKEy = CBOR.decode(authData.COSEPublicKey.buffer);
            console.log('X point: ', bufToHex(Object.values(publicKEy)[3]));
            console.log('Y point: ', bufToHex(Object.values(publicKEy)[4]));

            var externalECPublicKeyX = base64EncodeURL(Object.values(publicKEy)[3]);
            var externalECPublicKeyY = base64EncodeURL(Object.values(publicKEy)[4]);
            return window.crypto.subtle.importKey(
                "jwk", //can be "jwk" (public or private), "raw" (public only), "spki" (public only), or "pkcs8" (private only)
                { //this is an example jwk key, other key types are Uint8Array objects
                    kty: "EC",
                    crv: "P-256",
                    x: externalECPublicKeyX,
                    y: externalECPublicKeyY,
                    ext: true,
                }, { //these are the algorithm options
                    name: "ECDH",
                    namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                [] //"deriveKey" and/or "deriveBits" for private keys only (just put an empty list if importing a public key)
            );

        }).then(function (external_public) {
            //returns a privateKey (or publicKey if you are importing a public key)
            externalECPublicKey = external_public;
            console.log("external_public", externalECPublicKey);
            return window.crypto.subtle.generateKey({
                    name: "ECDH",
                    namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
                },
                true, //whether the key is extractable (i.e. can be used in exportKey)
                ["deriveKey",
                    "deriveBits"
                ] //can be any combination of "deriveKey" and "deriveBits"
            );
        }).then(function (key) { //generate ecdh pair

            var local_publicKey = key.publicKey;
            var local_privateKey = key.privateKey;
            window.crypto.subtle.exportKey("raw", local_publicKey).then(
                function (keydata) {
                    exportECPublicKeyArray = keydata;
                    console.log("exportECPublicKeyArray", bufToHex(exportECPublicKeyArray));
                }
            );
            return window.crypto.subtle.deriveBits({
                    name: "ECDH",
                    namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
                    public: externalECPublicKey, //an ECDH public key from generateKey or importKey

                },
                local_privateKey, //from generateKey or importKey above
                256 //the number of bits you want to derive
            );

        }).then(function (keybits) { //convert share secret to pinEncKey
            return crypto.subtle.digest(
                "SHA-256",
                new Uint8Array(keybits)
            );
        }).then(function (pinEncKeyBytes) {
            console.log("pinEncKeyBytes", bufToHex(pinEncKeyBytes));
            return crypto.subtle.importKey("raw",
                pinEncKeyBytes,
                "aes-cbc", false, ["encrypt"]);

        }).then(function (importKey) {
            pinEncKey = importKey;
            console.log("pinEncKey ", pinEncKey);
            const encoder = new TextEncoder();
            const data = encoder.encode(userpin);
            return crypto.subtle.digest(
                "SHA-256",
                data);
        }).then(function (userpin_digestBytes) {
            console.log("userpin_digestBytes", bufToHex(userpin_digestBytes.slice(0, 16)));
            var iv = new Uint8Array(16);
            console.log("iv .... ", iv);

            return crypto.subtle.encrypt({
                name: "aes-cbc",
                iv
            }, pinEncKey, userpin_digestBytes.slice(0, 16));
        }).then(function (cipherPIN) { // start get assertion

            EncryptedPINArray = cipherPIN.slice(0, 16);
            console.log("EncryptedPINArray", bufToHex(EncryptedPINArray.slice(0, 16)));
            


        });

    });

    return {EncryptedPINArray,exportECPublicKeyArray};

}