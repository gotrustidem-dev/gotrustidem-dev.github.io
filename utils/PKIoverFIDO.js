'use strict';


// Command Header GoTrust-Idem-PKI
const GTheader = 'R29UcnVzdC1JZGVtLVBLSQ==';

const CMD_KeyAgreement = 0xE0;
const CMD_ReadCertificate = 0xE1;
const CMD_TokenInfo = 0xE2;
const CMD_Sign = 0xE3;
const CMD_SignWithPIN = 0xE5;
const CMD_GenRsaKeyPair = 0xE6;
const CMD_ImportCertificate = 0xE7;



var g_encryptedPIN;
var g_platformECpublickey;

// const ALG_RSA2048SHA256;
// const ALG_RSA2048SHA256_PreHash;
// const ALG_RSA2048

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


async function requestSignDataByKEYHANDLE(keyhandle, alg_num, plaintext) {


    var signDataPayload = plaintext;

    var pki_buffer = [];
    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var keyHandle_buf = new Uint8Array(keyhandle.length + 4);
    keyHandle_buf[0] = 0xDF;
    keyHandle_buf[1] = 0x19;
    keyHandle_buf[2] = keyhandle.length >> 8;
    keyHandle_buf[3] = keyhandle.length;
    keyHandle_buf.set(new Uint8Array(keyhandle), 4);

    var alg_buf = new Uint8Array(5);
    alg_buf[0] = 0xDF;
    alg_buf[1] = 0x03;
    alg_buf[2] = 0;
    alg_buf[3] = 1;
    alg_buf[4] = alg_num;

    var signDataBuf = new Uint8Array(4 + signDataPayload.byteLength);
    signDataBuf[0] = 0xDF;
    signDataBuf[1] = 0x06;
    signDataBuf[2] = signDataPayload.byteLength >> 8;
    signDataBuf[3] = signDataPayload.byteLength;
    signDataBuf.set(signDataPayload, 4);



    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + keyHandle_buf.byteLength +
        alg_buf.byteLength + signDataBuf.byteLength);
    var pki_payload_length = keyHandle_buf.byteLength + alg_buf.byteLength + signDataBuf.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = CMD_Sign;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(keyHandle_buf), gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(alg_buf), gtheaderbuffer.byteLength + 3 + keyHandle_buf
        .byteLength);
    pki_buffer.set(new Uint8Array(signDataBuf), gtheaderbuffer.byteLength + 3 + keyHandle_buf
        .byteLength + alg_buf.byteLength);

    console.log("sign-keyhandle: " + bufToHex(pki_buffer));

    var getAssertionChallenge = {
        'challenge': challenge,
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('List getAssertionChallenge', getAssertionChallenge)

    return await new Promise(resolve => {
        navigator.credentials.get({
                'publicKey': getAssertionChallenge
            })
            .then((newCredentialInfo) => {
                console.log('GetAssertion response', newCredentialInfo);
                resolve(newCredentialInfo);
            })
    });

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
    pki_header[0] = CMD_ReadCertificate;
    pki_header[1] = 0x00
    pki_header[2] = 0x00;
    //PKI Command


    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);

    console.log(bufToHex(pki_buffer));

    //because pki command : 0xe0 has bug, use randomly id as user id 
    var userID = 'Kosv9fPtkDoh4Oz7Yq/pVgWHS8HhdlCto5cR0aBoVMw='
    var id = Uint8Array.from(window.atob(userID), c => c.charCodeAt(0))

    var request_keyagreement = {
        'challenge': challenge,

        'rp': {
            'name': 'GoTrustID Inc.',
        },

        'user': {
            //'id': pki_buffer,
            'id': id,
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

    return await new Promise(resolve => {
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
            resolve([EncryptedPINArray, exportECPublicKeyArray]);
            //return EncryptedPINArray;
        });

    });
}

async function requireEncryptedPINandEncryptedNewPIN(oldpin, newpin) {



    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var local_privateKey;
    var local_privateKey;
    var externalECPublicKey;
    var exportECPublicKeyArray;
    var pinEncKey;
    var EncryptedUserPINArray;
    var EncryptedNewUserPINArray;

    //Prepare PKI commmand
    //Header
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
    var pki_header = new Uint8Array(3);
    pki_header[0] = CMD_ReadCertificate;
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
    return await (new Promise(resolve => {
        navigator.credentials.create({
            'publicKey': request_keyagreement
        }).then((newCredentialInfo) => {


            console.log('oldpin', oldpin);
            console.log('newpin', newpin);

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
            const data = encoder.encode(oldpin);
            return crypto.subtle.digest(
                "SHA-256",
                data);
        }).then(function (oldpin_digestBytes) {
            console.log("oldpin_digestBytes", bufToHex(oldpin_digestBytes.slice(0, 16)));
            var iv = new Uint8Array(16);
            console.log("iv .... ", iv);

            return crypto.subtle.encrypt({
                name: "aes-cbc",
                iv
            }, pinEncKey, oldpin_digestBytes.slice(0, 16));
        }).then(function (cipherPIN) {
            EncryptedUserPINArray = cipherPIN.slice(0, 16);
            const encoder = new TextEncoder();
            const data = encoder.encode(newpin);
            return crypto.subtle.digest(
                "SHA-256",
                data);
        }).then(function (newpin_digestBytes) {
            console.log("newpin_digestBytes", bufToHex(newpin_digestBytes.slice(0, 16)));
            var iv = new Uint8Array(16);

            return crypto.subtle.encrypt({
                name: "aes-cbc",
                iv
            }, pinEncKey, newpin_digestBytes.slice(0, 16));
        }).then(function (cipherPIN) { // start get assertion

            EncryptedNewUserPINArray = cipherPIN.slice(0, 16);

            console.log("EncryptedNewUserPINArray", bufToHex(EncryptedNewUserPINArray.slice(0, 16)));

            resolve([EncryptedPINArray, EncryptedNewUserPINArray, exportECPublicKeyArray]);
        });

    }));





}

async function ReadCertByIndex(index) {


    var pki_buffer = [];

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    //Prepare PKI commmand
    //Header
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var command_bufer = new Uint8Array(5);
    command_bufer[0] = 0xDF;
    command_bufer[1] = 0x02;
    command_bufer[2] = 0x00;
    command_bufer[3] = 0x01;
    command_bufer[4] = index;

    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + command_bufer.byteLength);
    var pki_payload_length = command_bufer.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = CMD_ReadCertificate;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(command_bufer), 3 + gtheaderbuffer.byteLength);

    console.log(bufToHex(pki_buffer));

    var publicKey1 = {
        'challenge': challenge,

        'rp': {
            'name': 'GoTrustID Inc.',
        },

        'user': {
            'id': pki_buffer,
            'name': '王大強',
            'displayName': '王大強'
        },

        "authenticatorSelection": {
            "requireResidentKey": false,
            //"userVerification": "discouraged",
            "authenticatorAttachment": "cross-platform"

        },
        'attestation': "none",
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
    console.log('Search_by_Index:', publicKey1)

    return await new Promise(resolve => {
        navigator.credentials.create({
                'publicKey': publicKey1
            })
            .then((newCredentialInfo) => {

                console.log('SUCCESS', newCredentialInfo)
                console.log('ClientDataJSON: ', bufferToString(newCredentialInfo.response.clientDataJSON))
                let attestationObject = CBOR.decode(newCredentialInfo.response.attestationObject);
                console.log('AttestationObject: ', attestationObject)
                let authData = parseAuthData(attestationObject.authData);
                console.log('AuthData: ', authData);
                console.log('CredID: ', bufToHex(authData.credID));
                console.log('AAGUID: ', bufToHex(authData.aaguid));
                console.log('PublicKey', CBOR.decode(authData.COSEPublicKey.buffer));
                resolve(new Uint8Array(authData.credID.slice(1, authData.credID.length)));
            })
            .catch((error) => {
                alert(error)
                console.log('FAIL', error)
            })
    });
}

async function ReadCertByLable(strLable) {
    var pki_buffer = [];

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);


    var pki_header = new Uint8Array(3);
    var command_bufer = new Uint8Array(strLable.length + 4);
    window.crypto.getRandomValues(command_bufer);
    command_bufer[0] = 0xDF
    command_bufer[1] = 0x01;
    command_bufer[2] = strLable.length >> 8;
    command_bufer[3] = strLable.length;
    command_bufer.set(toUTF8Array(strLable), 4);



    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + pki_header.byteLength + command_bufer
        .byteLength);
    var pki_payload_length = command_bufer.byteLength;

    pki_header[0] = CMD_ReadCertificate;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;

    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(command_bufer), gtheaderbuffer.byteLength + pki_header.byteLength);

    console.log(bufToHex(pki_buffer));

    var publicKey1 = {
        'challenge': challenge,

        'rp': {
            'name': 'GoTrustID Inc.',
        },

        'user': {
            'id': pki_buffer,
            'name': 'Get Cert By Label',
            'displayName': 'Get Cert By Label'
        },

        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform"

        },
        'attestation': "none",
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
    console.log('List publicKey1', publicKey1)


    return await new Promise(resolve => {
        navigator.credentials.create({
                'publicKey': publicKey1
            })
            .then((newCredentialInfo) => {

                console.log('SUCCESS', newCredentialInfo)
                console.log('ClientDataJSON: ', bufferToString(newCredentialInfo.response
                    .clientDataJSON))
                let attestationObject = CBOR.decode(newCredentialInfo.response.attestationObject);
                console.log('AttestationObject: ', attestationObject);
                let authData = parseAuthData(attestationObject.authData);
                console.log('AuthData: ', authData);
                console.log('CredID: ', bufToHex(authData.credID));
                console.log('AAGUID: ', bufToHex(authData.aaguid));
                console.log('PublicKey', CBOR.decode(authData.COSEPublicKey.buffer));
                resolve(new Uint8Array(authData.credID.slice(1, authData.credID.length)));
            })
            .catch((error) => {
                alert(error)
                console.log('FAIL', error)
            })
    });
}

async function SignDataByIndex(index, alg_number, plain) {

    var pki_buffer = [];
    let certIndex = document.getElementById('use-index').certIndex.value;

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var command_buf = new Uint8Array(5);
    command_buf[0] = 0xDF;
    command_buf[1] = 0x02;
    command_buf[2] = 0x00;
    command_buf[3] = 0x01;
    command_buf[4] = index;

    var alg_buf = new Uint8Array(5);
    alg_buf[0] = 0xDF;
    alg_buf[1] = 0x03;
    alg_buf[2] = 0x00;
    alg_buf[3] = 0x01;
    alg_buf[4] = alg_number;

    var signDataBuf = new Uint8Array(4 + plain.byteLength);
    signDataBuf[0] = 0xDF;
    signDataBuf[1] = 0x06;
    signDataBuf[2] = plain.length >> 8;
    signDataBuf[3] = plain.length;
    signDataBuf.set(plain, 4);

    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + command_buf.byteLength + alg_buf
        .byteLength + signDataBuf.byteLength);
    var pki_payload_length = command_buf.byteLength + alg_buf.byteLength + signDataBuf.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = CMD_Sign;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(command_buf), gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(alg_buf), gtheaderbuffer.byteLength + 3 + command_buf.byteLength);
    pki_buffer.set(new Uint8Array(signDataBuf), gtheaderbuffer.byteLength + 3 + command_buf
        .byteLength + alg_buf.byteLength);

    console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        'rp': {
            'name': 'GoTrustID Inc.',
        },

    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('SignDataByIndex', getAssertionChallenge)


    return await new Promise(resolve => {
        navigator.credentials.get({
                'publicKey': getAssertionChallenge
            })
            .then((newCredentialInfo) => {

                console.log('SUCCESS', newCredentialInfo);
                console.log("Sign", newCredentialInfo.response.signature);

                const sign = newCredentialInfo.response.signature;
                resolve(sign);
            })
            .catch((error) => {
                alert(error)
                console.log('FAIL', error)
            })

    });


}


async function SignDataByIndex2(index, alg_number, plain, serial_number) {

    var pki_buffer = [];
    let certIndex = document.getElementById('use-index').certIndex.value;

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var command_buf = new Uint8Array(5);
    command_buf[0] = 0xDF;
    command_buf[1] = 0x02;
    command_buf[2] = 0x00;
    command_buf[3] = 0x01;
    command_buf[4] = index;

    var alg_buf = new Uint8Array(5);
    alg_buf[0] = 0xDF;
    alg_buf[1] = 0x03;
    alg_buf[2] = 0x00;
    alg_buf[3] = 0x01;
    alg_buf[4] = alg_number;

    var signDataBuf = new Uint8Array(4 + plain.byteLength);
    signDataBuf[0] = 0xDF;
    signDataBuf[1] = 0x06;
    signDataBuf[2] = plain.length >> 8;
    signDataBuf[3] = plain.length;
    signDataBuf.set(plain, 4);

    var sn_Buf = new Uint8Array(4 + serial_number.byteLength);
    sn_Buf[0] = 0xDF;
    sn_Buf[1] = 0x20;
    sn_Buf[2] = 0x00;
    sn_Buf[3] = 0x09;
    sn_Buf.set(serial_number, 4);



    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + command_buf.byteLength + alg_buf
        .byteLength + signDataBuf.byteLength + sn_Buf.byteLength);
    var pki_payload_length = command_buf.byteLength + alg_buf.byteLength + signDataBuf.byteLength + sn_Buf.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = CMD_Sign;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(command_buf), gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(alg_buf), gtheaderbuffer.byteLength + 3 + command_buf.byteLength);
    pki_buffer.set(new Uint8Array(signDataBuf), gtheaderbuffer.byteLength + 3 + command_buf.byteLength + alg_buf.byteLength);
    pki_buffer.set(new Uint8Array(sn_Buf), gtheaderbuffer.byteLength + 3 + command_buf.byteLength + alg_buf.byteLength + signDataBuf.byteLength);


    console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        'rp': {
            'name': 'GoTrustID Inc.',
        },

    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('SignDataByIndex', getAssertionChallenge)


    return await new Promise(resolve => {
        navigator.credentials.get({
                'publicKey': getAssertionChallenge
            })
            .then((newCredentialInfo) => {

                console.log('SUCCESS', newCredentialInfo);
                console.log("Sign", newCredentialInfo.response.signature);

                const sign = newCredentialInfo.response.signature;
                resolve(sign);
            })
            .catch((error) => {
                alert(error)
                console.log('FAIL', error)
            })

    });


}


async function SignDataByLabel(label, alg_number, plain) {

    var pki_buffer = [];

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var command_bufer = new Uint8Array(label.length + 4);
    window.crypto.getRandomValues(command_bufer);
    command_bufer[0] = 0xDF
    command_bufer[1] = 0x01;
    command_bufer[2] = label.length >> 8;
    command_bufer[3] = label.length;
    command_bufer.set(toUTF8Array(label), 4);


    var alg_buf = new Uint8Array(5);
    alg_buf[0] = 0xDF;
    alg_buf[1] = 0x03;
    alg_buf[2] = 0x00;
    alg_buf[3] = 0x01;
    alg_buf[4] = alg_number;

    var signDataBuf = new Uint8Array(4 + plain.byteLength);
    signDataBuf[0] = 0xDF;
    signDataBuf[1] = 0x06;
    signDataBuf[2] = plain.length >> 8;
    signDataBuf[3] = plain.length;
    signDataBuf.set(plain, 4);


    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + command_bufer.byteLength + alg_buf
        .byteLength + signDataBuf.byteLength);
    var pki_payload_length = command_bufer.byteLength + alg_buf.byteLength + signDataBuf.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = CMD_Sign;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(command_bufer), gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(alg_buf), gtheaderbuffer.byteLength + 3 + command_bufer.byteLength);
    pki_buffer.set(new Uint8Array(signDataBuf), gtheaderbuffer.byteLength + 3 + command_bufer
        .byteLength + alg_buf.byteLength);

    console.log("SignDataByLabel", bufToHex(pki_buffer));


    var getAssertionChallenge = {
        'challenge': challenge,
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('SignDataByLabel', getAssertionChallenge)


    return await new Promise(resolve => {
        navigator.credentials.get({
                'publicKey': getAssertionChallenge
            })
            .then((newCredentialInfo) => {

                console.log('SUCCESS', newCredentialInfo)
                console.log("Sign", newCredentialInfo.response.signature)
                const sign = newCredentialInfo.response.signature;
                resolve(sign);

            })
            .catch((error) => {
                alert(error)
                console.log('FAIL', error)
            })
    });
}

async function GenRSA2048KeyPair() {

    var pki_buffer = [];


    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    //Prepare PKI commmand
    //Header
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var command_bufer = new Uint8Array(5);
    command_bufer[0] = 0xDF;
    command_bufer[1] = 0x16;
    command_bufer[2] = 0x0;
    command_bufer[3] = 0x01;
    command_bufer[4] = 0x02;

    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + command_bufer.byteLength);
    var pki_payload_length = command_bufer.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = 0xE6;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(command_bufer), 3 + gtheaderbuffer.byteLength);

    console.log(bufToHex(pki_buffer));

    var publicKey1 = {
        'challenge': challenge,

        'rp': {
            'name': 'GoTrustID Inc.',
        },

        'user': {
            'id': pki_buffer,
            'name': 'Get Cert By Index',
            'displayName': 'Get Cert By Index'
        },

        "authenticatorSelection": {
            "requireResidentKey": false,
            "authenticatorAttachment": "cross-platform"

        },
        'attestation': "none",
        'pubKeyCredParams': [{
            'type': 'public-key',
            'alg': -7
        }]
    }
    console.log('Gen RSA Key Pair:', publicKey1)


    return await new Promise(resolve => {
        navigator.credentials.create({
                'publicKey': publicKey1
            })
            .then((newCredentialInfo) => {

                console.log('SUCCESS', newCredentialInfo)
                console.log('ClientDataJSON: ', bufferToString(newCredentialInfo.response
                    .clientDataJSON))
                let attestationObject = CBOR.decode(newCredentialInfo.response.attestationObject);
                console.log('AttestationObject: ', attestationObject)
                let authData = parseAuthData(attestationObject.authData);
                console.log('AuthData: ', authData);
                console.log('CredID: ', bufToHex(authData.credID));
                console.log('AAGUID: ', bufToHex(authData.aaguid));
                console.log('PublicKey', CBOR.decode(authData.COSEPublicKey.buffer));

                let returnData = showRSAKeyPair(authData.credID);

                resolve(returnData);




            })
        // .catch((error) => {
        //     alert(error)
        //     console.log('FAIL', error)
        // })
    });
}

async function ImportCertificate(keyHandleBuf, KeyIDBuf, ImportedHexCertBuf) {

    console.log('key_handle', bufToHex(keyHandleBuf));
    console.log('key_id', bufToHex(KeyIDBuf));
    console.log('hexCert', bufToHex(ImportedHexCertBuf));

    var pki_buffer = [];
    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var cert_buf = new Uint8Array(ImportedHexCertBuf.length + 4);
    cert_buf[0] = 0xDF
    cert_buf[1] = 0x17;
    cert_buf[2] = ImportedHexCertBuf.length >> 8;
    cert_buf[3] = ImportedHexCertBuf.length;
    cert_buf.set(ImportedHexCertBuf, 4);


    var keyHandle_buf = new Uint8Array(keyHandleBuf.length + 4);
    keyHandle_buf[0] = 0xDF;
    keyHandle_buf[1] = 0x19;
    keyHandle_buf[2] = keyHandleBuf.length >> 8;
    keyHandle_buf[3] = keyHandleBuf.length;
    keyHandle_buf.set(new Uint8Array(keyHandleBuf), 4);


    var keyId_buf = new Uint8Array(KeyIDBuf.length + 4);
    keyId_buf[0] = 0xDF;
    keyId_buf[1] = 0x18;
    keyId_buf[2] = KeyIDBuf.length >> 8;
    keyId_buf[3] = KeyIDBuf.length;
    keyId_buf.set(toUTF8Array(KeyIDBuf), 4);



    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + cert_buf.byteLength +
        keyHandle_buf
        .byteLength + keyId_buf.byteLength);

    var pki_payload_length = cert_buf.byteLength + keyHandle_buf.byteLength + keyId_buf
        .byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = 0xE7;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;

    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(cert_buf), gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(keyId_buf), gtheaderbuffer.byteLength + 3 + cert_buf
        .byteLength);
    pki_buffer.set(new Uint8Array(keyHandle_buf), gtheaderbuffer.byteLength + 3 + cert_buf
        .byteLength +
        keyId_buf.byteLength);

    console.log("Import cert command: " + bufToHex(pki_buffer));

    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "discouraged"
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('Import cert command getAssertionChallenge', getAssertionChallenge);

    return await new Promise(resolve => {
        navigator.credentials.get({
                'publicKey': getAssertionChallenge
            })
            .then((newCredentialInfo) => {

                console.log('SUCCESS', newCredentialInfo)
                console.log("Sign", newCredentialInfo.response.signature)
                const sign = newCredentialInfo.response.signature;
                resolve(sign);
            })
            .catch((error) => {
                alert(error)
                console.log('FAIL', error)
            })

    });

}

async function ImportCertificate2(keyHandleBuf, KeyIDBuf, ImportedHexCertBuf) {

    console.log('key_handle', bufToHex(keyHandleBuf));
    console.log('key_id', bufToHex(KeyIDBuf));
    console.log('hexCert', bufToHex(ImportedHexCertBuf));

    var pki_buffer = [];
    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var cert_buf = new Uint8Array(ImportedHexCertBuf.length + 4);
    cert_buf[0] = 0xDF
    cert_buf[1] = 0x17;
    cert_buf[2] = ImportedHexCertBuf.length >> 8;
    cert_buf[3] = ImportedHexCertBuf.length;
    cert_buf.set(ImportedHexCertBuf, 4);


    var keyHandle_buf = new Uint8Array(keyHandleBuf.length + 4);
    keyHandle_buf[0] = 0xDF;
    keyHandle_buf[1] = 0x19;
    keyHandle_buf[2] = keyHandleBuf.length >> 8;
    keyHandle_buf[3] = keyHandleBuf.length;
    keyHandle_buf.set(new Uint8Array(keyHandleBuf), 4);


    var keyId_buf = new Uint8Array(KeyIDBuf.length + 4);
    keyId_buf[0] = 0xDF;
    keyId_buf[1] = 0x18;
    keyId_buf[2] = KeyIDBuf.length >> 8;
    keyId_buf[3] = KeyIDBuf.length;
    keyId_buf.set(toUTF8Array(KeyIDBuf), 4);



    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + cert_buf.byteLength +
        keyHandle_buf
        .byteLength + keyId_buf.byteLength);

    var pki_payload_length = cert_buf.byteLength + keyHandle_buf.byteLength + keyId_buf
        .byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = 0xE7;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;

    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(cert_buf), gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(keyId_buf), gtheaderbuffer.byteLength + 3 + cert_buf
        .byteLength);
    pki_buffer.set(new Uint8Array(keyHandle_buf), gtheaderbuffer.byteLength + 3 + cert_buf
        .byteLength +
        keyId_buf.byteLength);

    console.log("Import cert command: " + bufToHex(pki_buffer));

    // use randomly id as user id 
    var userID = 'Kosv9fPtkDoh4Oz7Yq/pVgWHS8HhdlCto5cR0aBoVMw='
    var id = Uint8Array.from(window.atob(userID), c => c.charCodeAt(0))
    var createCredentialOptions = {
        'challenge': challenge,
        'rp': {
            'name': 'GoTrustID Inc.',
        },

        'user': {
            'id': id,
            'name': 'GoTrustID Inc.',
            'displayName': 'Alice von Wunderland'
        },

        "authenticatorSelection": {
            "requireResidentKey": false,
            "userVerification": "required",
            "authenticatorAttachment": "cross-platform"

        },

        'attestation': "none",
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
    var idList = [{
        id: pki_buffer,
        type: "public-key"
    }];

    createCredentialOptions.excludeCredentials = idList;
    console.log('Import cert command createCredentialOptions', createCredentialOptions);

    return await new Promise(resolve => {
        navigator.credentials.create({
                'publicKey': createCredentialOptions
            })
            .then((newCredentialInfo) => {

                console.log('SUCCESS', newCredentialInfo)
                console.log('ClientDataJSON: ', bufferToString(newCredentialInfo.response.clientDataJSON))
                let attestationObject = CBOR.decode(newCredentialInfo.response.attestationObject);
                console.log('AttestationObject: ', attestationObject)
                let authData = parseAuthData(attestationObject.authData);
                console.log('AuthData: ', authData);
                console.log('CredID: ', bufToHex(authData.credID));
                console.log('AAGUID: ', bufToHex(authData.aaguid));
                console.log('PublicKey', CBOR.decode(authData.COSEPublicKey.buffer));
                resolve(authData.credID);

            })
            .catch((error) => {
                alert(error)
                console.log('FAIL', error)
            })

    });

}

function base64EncodeURL(byteArray) {
    return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
        return String.fromCharCode(val);
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
};

function toUTF8Array(str) {

    var utf8 = [];
    for (var i = 0; i < str.length; i++) {
        var charcode = str.charCodeAt(i);
        if (charcode < 0x80) utf8.push(charcode);
        else if (charcode < 0x800) {
            utf8.push(0xc0 | (charcode >> 6),
                0x80 | (charcode & 0x3f));
        } else if (charcode < 0xd800 || charcode >= 0xe000) {
            utf8.push(0xe0 | (charcode >> 12),
                0x80 | ((charcode >> 6) & 0x3f),
                0x80 | (charcode & 0x3f));
        }
        // surrogate pair
        else {
            i++;
            // UTF-16 encodes 0x10000-0x10FFFF by
            // subtracting 0x10000 and splitting the
            // 20 bits of 0x0-0xFFFFF into two halves
            charcode = 0x10000 + (((charcode & 0x3ff) << 10) |
                (str.charCodeAt(i) & 0x3ff));
            utf8.push(0xf0 | (charcode >> 18),
                0x80 | ((charcode >> 12) & 0x3f),
                0x80 | ((charcode >> 6) & 0x3f),
                0x80 | (charcode & 0x3f));
        }
    }
    return utf8;
}

function hexStringToArrayBuffer(hexString) {
    // remove the leading 0x
    hexString = hexString.replace(/^0x/, '');

    // ensure even number of characters
    if (hexString.length % 2 != 0) {
        console.log('WARNING: expecting an even number of characters in the hexString');
    }

    // check for some non-hex characters
    var bad = hexString.match(/[G-Z\s]/i);
    if (bad) {
        console.log('WARNING: found non-hex characters', bad);
    }

    // split the string into pairs of octets
    var pairs = hexString.match(/[\dA-F]{2}/gi);

    // convert the octets to integers
    var integers = pairs.map(function (s) {
        return parseInt(s, 16);
    });

    var array = new Uint8Array(integers);
    console.log(array);

    return array;
}


var parsePKIoverFIDOResponse = (buffer, cmd) => {


    // check directly return 256 bytes which doesn't  include header and status code; 
    //let testData = CBOR.decode(buffer);
    //console.log("check point1",testData)    
    let status = undefined;
    let signature = undefined;
    let retries = undefined;

    //meaning this is directly return signature
    if (buffer.byteLength == 256) {
        signature = new Uint8Array(buffer);
        status = CTAP1_ERR_SUCCESS;
    } else {
        let GTheaderBuf = buffer.slice(0, 16);
        if (String.fromCharCode.apply(null, new Uint8Array(GTheaderBuf)) === GTheaderStr) {
            buffer = buffer.slice(16);
            let totalLenBuf = buffer.slice(0, 2);
            let totalLen = readBE16(new Uint8Array(totalLenBuf));
            buffer = buffer.slice(2);
            let statusCodeBuf = buffer.slice(0, 1);
            let statusCode = new Uint8Array(statusCodeBuf);
            buffer = buffer.slice(1);
            status = statusCode;

            if (status[0] === CTAP1_ERR_SUCCESS) {
                let responseDataBuf = buffer.slice(0, (totalLen - 1));
                let responseData = CBOR.decode(responseDataBuf);
                signature = responseData;
            } else {
                status = status[0];

            }
        } else {

            signature = new Uint8Array(buffer);
            status = CTAP1_ERR_SUCCESS;


        }
    }



    return {
        signature,
        status
    };
}


async function ReadCertByIndexFunction2(index) {

    var pki_buffer = [];

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var command_buf = new Uint8Array(5);
    command_buf[0] = 0xDF;
    command_buf[1] = 0x02;
    command_buf[2] = 0x00;
    command_buf[3] = 0x01;
    command_buf[4] = index;



    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + command_buf.byteLength);
    var pki_payload_length = command_buf.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = CMD_ReadCertificate;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(command_buf), gtheaderbuffer.byteLength + 3);


    console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "discouraged",
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('SignDataByIndex', getAssertionChallenge)

    return await new Promise(resolve => {
        navigator.credentials.get({
            'publicKey': getAssertionChallenge
        }).then((read_cert_response) => {
            resolve(read_cert_response.response.signature);

        })
    });
}


async function ReadCertByLableFunction2(strLable) {

    var pki_buffer = [];

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var command_bufer = new Uint8Array(strLable.length + 4);
    command_bufer[0] = 0xDF
    command_bufer[1] = 0x01;
    command_bufer[2] = strLable.length >> 8;
    command_bufer[3] = strLable.length;
    command_bufer.set(toUTF8Array(strLable), 4);



    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + command_bufer.byteLength);
    var pki_payload_length = command_bufer.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = CMD_ReadCertificate;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(command_bufer), gtheaderbuffer.byteLength + 3);


    console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "discouraged",
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('SignDataByIndex', getAssertionChallenge)

    return await new Promise(resolve => {
        navigator.credentials.get({
            'publicKey': getAssertionChallenge
        }).then((read_cert_response) => {
            resolve(read_cert_response.response.signature);

        })
    });
}


async function GetTokenInfo() {

    var pki_buffer = [];

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);
    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3);
    var pki_payload_length = 0;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = CMD_TokenInfo;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);


    console.log("GetTokenInfo", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "discouraged",
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('GetTokenInfo', getAssertionChallenge)

    return await new Promise(resolve => {
        navigator.credentials.get({
            'publicKey': getAssertionChallenge
        }).then((read_cert_response) => {
            resolve(read_cert_response.response.signature);

        })
    });


}



async function TestExtendsToReadSign(index, plain) {

    var pki_buffer = [];
    let certIndex = document.getElementById('use-index').certIndex.value;

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

    var pki_header = new Uint8Array(3);

    //PKI Command
    var command_buf = new Uint8Array(5);
    command_buf[0] = 0xDF;
    command_buf[1] = 0x02;
    command_buf[2] = 0x00;
    command_buf[3] = 0x01;
    command_buf[4] = index;

    var alg_buf = new Uint8Array(5);
    alg_buf[0] = 0xDF;
    alg_buf[1] = 0x03;
    alg_buf[2] = 0x00;
    alg_buf[3] = 0x01;
    alg_buf[4] = 2;

    var signDataBuf = new Uint8Array(4 + plain.byteLength);
    signDataBuf[0] = 0xDF;
    signDataBuf[1] = 0x06;
    signDataBuf[2] = plain.length >> 8;
    signDataBuf[3] = plain.length;
    signDataBuf.set(plain, 4);


    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + command_buf.byteLength + alg_buf
        .byteLength + signDataBuf.byteLength);
    var pki_payload_length = command_buf.byteLength + alg_buf.byteLength + signDataBuf.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = CMD_Sign;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(command_buf), gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(alg_buf), gtheaderbuffer.byteLength + 3 + command_buf.byteLength);
    pki_buffer.set(new Uint8Array(signDataBuf), gtheaderbuffer.byteLength + 3 + command_buf
        .byteLength + alg_buf.byteLength);

    console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        'extensions': {
            // An "entry key" identifying the "webauthnExample_foobar" extension, 
            // whose value is a map with two input parameters:
            "hmac-secret": {
                'foo': 42,
                'bar': "barfoo"
            }
        }

    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('SignDataByIndex', getAssertionChallenge)


    return await new Promise(resolve => {
        navigator.credentials.get({
                'publicKey': getAssertionChallenge
            })
            .then((newCredentialInfo) => {

                console.log('SUCCESS', newCredentialInfo);
                console.log("Sign", newCredentialInfo.response.signature);

                const sign = newCredentialInfo.response.signature;
                resolve(sign);
            })
            .catch((error) => {
                alert(error)
                console.log('FAIL', error)
            })

    });


}


var parsePKIoverFIDOResponse2 = (buffer, cmd) => {



    let status = undefined;
    let signature = undefined;
    let retries = undefined;



    let GTheaderBuf = buffer.slice(0, 16);

    if (String.fromCharCode.apply(null, new Uint8Array(GTheaderBuf)) === GTheaderStr) {

        buffer = buffer.slice(16);
        let totalLenBuf = buffer.slice(0, 2);
        let totalLen = readBE16(new Uint8Array(totalLenBuf));
        buffer = buffer.slice(2);
        let statusCodeBuf = buffer.slice(0, 1);
        let statusCode = new Uint8Array(statusCodeBuf);
        buffer = buffer.slice(1);
        status = statusCode;

        if (status[0] === CTAP1_ERR_SUCCESS) {
            let responseDataBuf = buffer.slice(0, (totalLen - 1));
            let responseData = CBOR.decode(responseDataBuf);

            switch (cmd) {

                case CMD_KeyAgreement:

                    break;
                case CMD_ReadCertificate:

                    break;
                case CMD_TokenInfo:
                    let FW = ConverVersionFormat(responseData[1]);
                    let SW = ConverVersionFormat(responseData[2]);
                    let PINRetries = responseData[3];
                    let NumOfCredential = responseData[4];
                    let SN = ConverSNFormat(responseData[5]);
                    let RN = ConverSNFormat(responseData[6]);
                    let ECPublic = ConverSNFormat(responseData[7]);
                    return {
                        status, FW, SW, PINRetries, NumOfCredential, SN, RN, ECPublic
                    };
                    break;
                case CMD_Sign:

                    break;
                case CMD_SignWithPIN:

                    break;
                case CMD_GenRsaKeyPair:

                    break;
                case CMD_ImportCertificate:

                default:

            }
        }
    } else if (buffer.byteLength == 256) {
        signature = new Uint8Array(buffer);
        status = CTAP1_ERR_SUCCESS;
        return {
            signature,
            status
        };
    }

}


var ConverVersionFormat = (buffer) => {

    var result = "";

    for (var i = 0; i < buffer.length; i++) {
        result += buffer[i].toString(16);
        result += ".";
    }
    return result;

}



var ConverSNFormat = (buffer) => {

    var result = "";

    for (var i = 0; i < buffer.length; i++) {
        if (buffer[i] < 16) {
            result += '0';
        }
        result += buffer[i].toString(16);
    }
    return result;
}


async function GTIDEM_ChangeUserPIN(oldPIN, newPIN, serialNumber) {

    //Convert string to byte array

    var bOldPin = new Uint8Array(oldPIN);
    var bNewPin = new Uint8Array(newPIN);

    var bSerialNumber = new Uint8Array(serialNumber);
    var bECPointFromToken;

    //Get device insered PC, and compare serial number if it is exist.
    bECPointFromToken = await GetTokenInfo().then((newCredentialInfo) => {
        console.log('GTIDEM_ChangeUserPIN start');

        let responseData = parsePKIoverFIDOResponse2(newCredentialInfo, CMD_TokenInfo);

        //compare serial number 
        if (responseData.SN !== bSerialNumber) {
            console.log('Serial number different.');
        }


        //Get EC point
        //var bECPointFromToken = responseData.ECPublic;
       return responseData.ECPublic;


    }).catch((error) => {
        alert(error)
        console.log('FAIL', error)
    });

    await computingSessionKey("123456", "88888888", bECPointFromToken);

    //Compution session Key and encrypt oldPIN and new pin.



    //run change PIN
}

async function computingSessionKey(oldPIN, newPIN, ecpointXY) {



    //Convert oldPIN to sha256 value

    var oldPINHash =  crypto.subtle.digest("SHA-256",data);
    console.log("oldPINHash  ", oldPINHash);

    //During encryption, newPin is padded with trailing 0x00 bytes and is of minimum 64 bytes length. 
    var newPINBuffer= new Uint8Array(64);
    newPINBuffer.fill(0);
    let bNewPIN = hexStringToArrayBuffer(newPIN);
    for (const obj of bNewPIN) {
        newPINBuffer.push(copy(obj));
    }


    

    
    var newPINHash ;

    var ECPublicKey;
    var EncryptOlDPIN;

    let ecpoint = hexStringToArrayBuffer(ecpointXY);

    var externalECPublicKeyX = base64EncodeURL(ecpoint.slice(1, 33));
    var externalECPublicKeyY = base64EncodeURL(ecpoint.slice(33, 65));
    var exportECPublicKeyArray;
    var externalECPublicKey;


    var importedECKey = await window.crypto.subtle.importKey(
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


    var encryptedOldPIN;
    var encryptedNEWPIN;

    window.crypto.subtle.importKey(
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
        ).then(function (external_public) {
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
        }).then(function (sessionKeyBytes) {
            console.log("pinEncKeyBytes", bufToHex(sessionKeyBytes));
            return crypto.subtle.importKey("raw",
            sessionKeyBytes,
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
 //       }).then(function (cipherPIN) {


        })
        .catch(function (err) {
            console.error(err);
        });
}