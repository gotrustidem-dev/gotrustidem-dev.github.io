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
const CMD_CHANGE_PIN = 0xE8;
const CMD_UNLOCK_PIN = 0xE9;
const CMD_REQUESTCSR = 0xEA;
const CMD_DELEE_CERT= 0xEB;
const CMD_CLEAR_TOKEN = 0xEC;





var g_encryptedPIN;
var g_platformECpublickey;

const ALG_RSA2048SHA256 = 0x02;
const ALG_RSA2048SHA256_PreHash = 0x12;





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
    return new Uint8Array(utf8);
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
    //console.log(array);

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
                    if(responseData[6]!=undefined){
                        let RN = ConverSNFormat(responseData[6]);
                        let ECPublic = ConverSNFormat(responseData[7]);
                        return {
                            status, FW, SW, PINRetries, NumOfCredential, SN, RN, ECPublic
                        };
                    }else{
                        return {
                            status, FW, SW, PINRetries, NumOfCredential, SN
                        };
                    }
                
                    
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


/**
 * 修改使用者密碼。
 * @param {Uint8Array} bOldPIN 舊密碼
 * @param {Uint8Array} bNewPIN 新密碼
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @returns 
 */
async function GTIDEM_ChangeUserPIN(bOldPIN, bNewPIN, bSerialNumber) {


    var gtidemA = await GTIDEM_GetTokenInfo(bSerialNumber).then((fido) => {
        return fido;
    });

    if(gtidemA.statusCode != CTAP1_ERR_SUCCESS){
        return gtidemA;
    }

    if(gtidemA.pinRetry == 0){
        gtidemA.statusCode = CTAP2_ERR_PIN_BLOCKED;
        return gtidemA;
    }
    var bECPointFromToken = gtidemA.ecpoint;

    var sn_buf;
    if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){
        sn_buf = new Uint8Array(0);
    }else{
        sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
        sn_buf[0] = 0xDF;
        sn_buf[1] = 0x20;
        sn_buf[2] = bSerialNumber.byteLength >> 8;
        sn_buf[3] = bSerialNumber.byteLength;
        sn_buf.set(bSerialNumber, 4);
    }
    

    //Compution session Key and encrypt oldPIN and new pin.
   var prepareUpdate = await computingSessionKey(bOldPIN, bNewPIN, bECPointFromToken);
   console.log("exportECPublicKeyArray",bufToHex(prepareUpdate.bExportECPublicKeyArray));
   console.log("encryptedOldPINHash",bufToHex(prepareUpdate.bEcryptedOldPINHash));
   console.log("encryptedNEWPIN",bufToHex(prepareUpdate.bEncryptedNEWPIN));


   var challenge = new Uint8Array(32);
   window.crypto.getRandomValues(challenge);
   var ecpubkey_buf = new Uint8Array(4 + prepareUpdate.bExportECPublicKeyArray.byteLength);
   ecpubkey_buf[0] = 0xDF;
   ecpubkey_buf[1] = 0x04;
   ecpubkey_buf[2] = prepareUpdate.bExportECPublicKeyArray.byteLength >> 8;
   ecpubkey_buf[3] = prepareUpdate.bExportECPublicKeyArray.byteLength;
   ecpubkey_buf.set(new Uint8Array(prepareUpdate.bExportECPublicKeyArray), 4);

   var encryptedOldPINHash_buf = new Uint8Array(4 + prepareUpdate.bEcryptedOldPINHash.byteLength);
   encryptedOldPINHash_buf[0] = 0xDF;
   encryptedOldPINHash_buf[1] = 0x05;
   encryptedOldPINHash_buf[2] = prepareUpdate.bEcryptedOldPINHash.byteLength >> 8;
   encryptedOldPINHash_buf[3] = prepareUpdate.bEcryptedOldPINHash.byteLength;
   encryptedOldPINHash_buf.set(new Uint8Array(prepareUpdate.bEcryptedOldPINHash), 4);
  
   var encryptedNewPIN_buf = new Uint8Array(4 + prepareUpdate.bEncryptedNEWPIN.byteLength);
   encryptedNewPIN_buf[0] = 0xDF;
   encryptedNewPIN_buf[1] = 0x07;
   encryptedNewPIN_buf[2] = prepareUpdate.bEncryptedNEWPIN.byteLength >> 8;
   encryptedNewPIN_buf[3] = prepareUpdate.bEncryptedNEWPIN.byteLength;
   encryptedNewPIN_buf.set(new Uint8Array(prepareUpdate.bEncryptedNEWPIN), 4);


    var payloadLen = sn_buf.byteLength+ecpubkey_buf.byteLength+encryptedOldPINHash_buf.byteLength+encryptedNewPIN_buf.byteLength;

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_CHANGE_PIN;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,ecpubkey_buf);
   pki_buffer = _appendBuffer(pki_buffer,encryptedOldPINHash_buf);
   pki_buffer = _appendBuffer(pki_buffer,encryptedNewPIN_buf);



   console.log("Change_pin_command: " + bufToHex(pki_buffer));

   var getAssertionChallenge = {
       'challenge': challenge,
       "userVerification": "discouraged"
       //"userVerification": "required"
   }
   var idList = [{
       id: pki_buffer,
       transports: ["usb"],
       type: "public-key"
   }];

   getAssertionChallenge.allowCredentials = idList;
   console.log('List getAssertionChallenge', getAssertionChallenge)

   return await navigator.credentials.get({
       'publicKey': getAssertionChallenge
   }).then((fido) => {
           
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_CHANGE_PIN);
        return gtidem;
    }).catch((error) => {
        //console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name);
        return gtidem;
    });

}

async function computingSessionKey(bOldPIN, bNewPIN, ecpointXY) {

    //Convert oldPIN to sha256 value
    var oldPINHash = await crypto.subtle.digest("SHA-256", bOldPIN);
    console.log("oldPINHash  ", oldPINHash);

    //During encryption, newPin is padded with trailing 0x00 bytes and is of minimum 64 bytes length. 
    var newPINBuffer = new Uint8Array(64);
    newPINBuffer.fill(0);
    newPINBuffer.set(bNewPIN, 0);

    var iv = new Uint8Array(16);
    iv.fill(0);


    var newPINHash;
    var ECPublicKey;
    var EncryptOlDPIN;

    //let ecpoint = hexStringToArrayBuffer(ecpointXY);
    let ecpoint = ecpointXY;
    var externalECPublicKeyX = base64EncodeURL(ecpoint.slice(1, 33));
    var externalECPublicKeyY = base64EncodeURL(ecpoint.slice(33, 65));
   
    var exportECPublicKeyArray;
    var encryptedOldPINHash;
    var encryptedNEWPIN;


    var importedECPublicKey = await window.crypto.subtle.importKey(
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

    var CryptoECKeyPair = await window.crypto.subtle.generateKey({
            name: "ECDH",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
        },
        true, //whether the key is extractable (i.e. can be used in exportKey)
        ["deriveKey", "deriveBits"] //can be any combination of "deriveKey" and "deriveBits"
    );

    exportECPublicKeyArray = await window.crypto.subtle.exportKey("raw", CryptoECKeyPair.publicKey);

    //Computing session Key
    var CryptoSessionKey = await window.crypto.subtle.deriveBits({
            name: "ECDH",
            namedCurve: "P-256", //can be "P-256", "P-384", or "P-521"
            public: importedECPublicKey, //an ECDH public key from generateKey or importKey

        },
        CryptoECKeyPair.privateKey, //from generateKey or importKey above
        256 //the number of bits you want to derive
    ).then(function (keybits) { //convert share secret to pinEncKey
        return crypto.subtle.digest(
            "SHA-256",
            new Uint8Array(keybits)
        );
    }).then(function (sessionKeyBytes) {
        console.log("sessionKeyBytes", bufToHex(sessionKeyBytes));
        return crypto.subtle.importKey("raw",
            sessionKeyBytes,
            "aes-cbc", false, ["encrypt"]);
    });


    encryptedOldPINHash = await crypto.subtle.encrypt({
        name: "aes-cbc",
        iv
    }, CryptoSessionKey, new Uint8Array(oldPINHash));


    encryptedNEWPIN = await crypto.subtle.encrypt({
        name: "aes-cbc",
        iv
    }, CryptoSessionKey, new Uint8Array(newPINBuffer));

    var bExportECPublicKeyArray = new Uint8Array(exportECPublicKeyArray);
    var bEcryptedOldPINHash = new Uint8Array(encryptedOldPINHash.slice(0,16));
    var bEncryptedNEWPIN = new Uint8Array(encryptedNEWPIN).slice(0,64);
    return {bExportECPublicKeyArray, bEcryptedOldPINHash, bEncryptedNEWPIN};
}

/**
 * 產生 RSA 2048 金鑰對，會組合成 CSR 格式回傳
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @param {Uint8Array｜undefined} bKeyID 用來關聯金鑰對，若是不替換則填入 undefined 或是空陣列。若不使用 KeyID,則載具會產生預設的 KeyHandle。
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_GenRSA2048CSR(bSerialNumber,bKeyID) {

   
   //var bKeyID = toUTF8Array(keyID);

   var challenge = new Uint8Array(32);
   window.crypto.getRandomValues(challenge);

   var keyid_buf;
   if((bKeyID==undefined)||(bKeyID.byteLength==0)){

        keyid_buf = new Uint8Array(0);
    }else{
        keyid_buf = new Uint8Array(4 + bKeyID.byteLength);
        keyid_buf[0] = 0xDF;
        keyid_buf[1] = 0x18;
        keyid_buf[2] = bKeyID.byteLength >> 8;
        keyid_buf[3] = bKeyID.byteLength;
        keyid_buf.set(bKeyID, 4);
    }



   var sn_buf;
   if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){

        sn_buf = new Uint8Array(0);
   }else{
        sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
        sn_buf[0] = 0xDF;
        sn_buf[1] = 0x20;
        sn_buf[2] = bSerialNumber.byteLength >> 8;
        sn_buf[3] = bSerialNumber.byteLength;
        sn_buf.set(bSerialNumber, 4);
   }



   var payloadLen = keyid_buf.byteLength+sn_buf.byteLength

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_REQUESTCSR;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,keyid_buf);
  



   console.log("Request_command: " + bufToHex(pki_buffer));

   var webauth_request = {
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
        "userVerification": "required",
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
   console.log('webauth_request', webauth_request)

   return await navigator.credentials.create({
        'publicKey': webauth_request
    }).then((fido) => {

        let attestationObject = CBOR.decode(fido.response.attestationObject);
        let authData = parseAuthData(attestationObject.authData);
        let credID = authData.credID;
        let bPKIoverFIDOResponse= credID.buffer.slice(credID.byteOffset, credID.byteLength + credID.byteOffset);

        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(bPKIoverFIDOResponse,CMD_REQUESTCSR);
        return gtidem;
    }).catch((error) => {
        //console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name);
        return gtidem;
    });
}
/**
 * 產生 RSA 2048 金鑰對，並回傳 raw data
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @param {Uint8Array｜undefined} bKeyID 用來關聯金鑰對，若是不替換則填入 undefined 或是空陣列。若不使用 KeyID,則載具會產生預設的 KeyHandle。
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_GenRSA2048(bSerialNumber,bKeyID) {


 
    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
 
    var sn_buf;
    if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){

        sn_buf = new Uint8Array(0);
    }else{
        sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
        sn_buf[0] = 0xDF;
        sn_buf[1] = 0x20;
        sn_buf[2] = bSerialNumber.byteLength >> 8;
        sn_buf[3] = bSerialNumber.byteLength;
        sn_buf.set(bSerialNumber, 4);
    }
    var keyid_buf;
    if((bKeyID==undefined)||(bKeyID.byteLength==0)){
 
         keyid_buf = new Uint8Array(0);
     }else{
         keyid_buf = new Uint8Array(4 + bKeyID.byteLength);
         keyid_buf[0] = 0xDF;
         keyid_buf[1] = 0x18;
         keyid_buf[2] = bKeyID.byteLength >> 8;
         keyid_buf[3] = bKeyID.byteLength;
         keyid_buf.set(bKeyID, 4);
     }


    var payloadLen = keyid_buf.byteLength+sn_buf.byteLength
 
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
  
    var pki_header = new Uint8Array(3);
    pki_header[0] = CMD_GenRsaKeyPair;
    pki_header[1] = payloadLen>>8
    pki_header[2] = payloadLen;
 
    var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
    pki_buffer = _appendBuffer(pki_buffer,sn_buf);
    pki_buffer = _appendBuffer(pki_buffer,keyid_buf);
   
 
 
 
    console.log("Request_command: " + bufToHex(pki_buffer));
 
    var webauth_request = {
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
         "userVerification": "required",
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
    console.log('webauth_request', webauth_request)
 
    return await navigator.credentials.create({
         'publicKey': webauth_request
     }).then((fido) => {
           
        let attestationObject = CBOR.decode(fido.response.attestationObject);
        let authData = parseAuthData(attestationObject.authData);
        let credID = authData.credID;
        let bPKIoverFIDOResponse= credID.buffer.slice(credID.byteOffset, credID.byteLength + credID.byteOffset);

        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(bPKIoverFIDOResponse,CMD_GenRsaKeyPair);
        return gtidem;
    }).catch((error) => {
        //console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name);
        return gtidem;
    });
 }

/**
 * 指定 KeyHandle 匯入憑證。若在 GTIDEM_GenRSA2048 或是 GTIDEM_GenRSA2048CSR 已使用 KeyID 則此處的 KeyHandle 要使用已指定的 KeyID。
 * 
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @param {Uint8Array} keyHandle  匯入憑證
 * @param {Uint8Array｜undefined} keyID 用來替換 KeyHandle，若是不替換則填入 undefined 或是空陣列
 * @param {Uint8Array} HexCert 欲匯入的憑證
 * @param {Uint8Array｜undefined} bPlain 使用匯入的憑證金鑰簽名並用 ALG_RSA2048SHA256_PreHash演算法對填入的資料簽名，所以資料長度必須為32 bytes，可做為確認憑證和金鑰對的匹配。若不需此功能，則可填入 undefined 或是空陣列。
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_ImportCertificate(bSerialNumber,keyHandle,keyID,HexCert, bPlain) {


    var bKeyID = keyID;
    var bKeyHandle = keyHandle;
    var bHexCert = HexCert;
    //var bHexCert = Uint8Array.from(window.atob(Base64Cert), c => c.charCodeAt(0));
    //var bPlainText = toUTF8Array(plaintext);

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);

    var sn_buf;
    if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){

        sn_buf = new Uint8Array(0);
    }else{
        sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
        sn_buf[0] = 0xDF;
        sn_buf[1] = 0x20;
        sn_buf[2] = bSerialNumber.byteLength >> 8;
        sn_buf[3] = bSerialNumber.byteLength;
        sn_buf.set(bSerialNumber, 4);
    }
    var keyid_buf;

    if((bKeyID==undefined)||(bKeyID.byteLength==0)){

        keyid_buf = new Uint8Array(4 + bKeyHandle.byteLength);
        keyid_buf[0] = 0xDF;
        keyid_buf[1] = 0x20;
        keyid_buf[2] = bKeyHandle.byteLength >> 8;
        keyid_buf[3] = bKeyHandle.byteLength;
        keyid_buf.set(bKeyHandle, 4);
    }else{
        keyid_buf = new Uint8Array(4 + bKeyID.length);
        keyid_buf[0] = 0xDF;
        keyid_buf[1] = 0x18;
        keyid_buf[2] = bKeyID.byteLength >> 8;
        keyid_buf[3] = bKeyID.byteLength;
        keyid_buf.set(bKeyID, 4);
    }

    
    var keyhandle_buf = new Uint8Array(4 + bKeyHandle.length);
    keyhandle_buf[0] = 0xDF;
    keyhandle_buf[1] = 0x19;
    keyhandle_buf[2] = bKeyHandle.byteLength >> 8;
    keyhandle_buf[3] = bKeyHandle.byteLength;
    keyhandle_buf.set(bKeyHandle, 4);
    

    var hexCert_buf = new Uint8Array(4 + bHexCert.length);
    hexCert_buf[0] = 0xDF;
    hexCert_buf[1] = 0x17;
    hexCert_buf[2] = bHexCert.byteLength >> 8;
    hexCert_buf[3] = bHexCert.byteLength;
    hexCert_buf.set(bHexCert, 4);

    var signDataBuf;
    if((bPlain==undefined)||(bPlain.byteLength==0)){
        var signDataBuf =  new Uint8Array(0);
    }else{
        var signDataBuf = new Uint8Array(4 + bPlain.byteLength);
        signDataBuf[0] = 0xDF;
        signDataBuf[1] = 0x06;
        signDataBuf[2] = bPlain.length >> 8;
        signDataBuf[3] = bPlain.length;
        signDataBuf.set(bPlain, 4);
    }

   var payloadLen = keyid_buf.byteLength+sn_buf.byteLength+hexCert_buf.length+signDataBuf.byteLength+keyhandle_buf.byteLength;

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_ImportCertificate;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,keyid_buf);
   pki_buffer = _appendBuffer(pki_buffer,keyhandle_buf);
   pki_buffer = _appendBuffer(pki_buffer,hexCert_buf);
   pki_buffer = _appendBuffer(pki_buffer,signDataBuf);

   

   console.log("Import request_command: " + bufToHex(pki_buffer));

   var getAssertionChallenge = {
    'challenge': challenge,
    "userVerification": "required"
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('List getAssertionChallenge', getAssertionChallenge)

    return await navigator.credentials.get({
        'publicKey': getAssertionChallenge
    }).then((fido) => {
           
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_ImportCertificate);
        return gtidem;
    }).catch((error) => {
        //console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name);
        return gtidem;
    });

}

/**
 * 刪除特定標籤的金鑰對和憑證，需要驗證使用者密碼
 * 
 * @param {Uint8Array} bLabel  指定標籤
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_DeleteCertByLabel(bLabel, bSerialNumber) {



    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
 
    var label_buf = new Uint8Array(4 + bLabel.length);
    label_buf[0] = 0xDF;
    label_buf[1] = 0x01;
    label_buf[2] = bLabel.byteLength >> 8;
    label_buf[3] = bLabel.byteLength;
    label_buf.set(bLabel, 4);
 
    var sn_buf;
    if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){
        sn_buf = new Uint8Array(0);
    }else{
        sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
        sn_buf[0] = 0xDF;
        sn_buf[1] = 0x20;
        sn_buf[2] = bSerialNumber.byteLength >> 8;
        sn_buf[3] = bSerialNumber.byteLength;
        sn_buf.set(bSerialNumber, 4);
    }
    


   var payloadLen = label_buf.byteLength+sn_buf.byteLength;

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_DELEE_CERT;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,label_buf);
   

   console.log("Delete cert by label request_command: " + bufToHex(pki_buffer));


    var getAssertionChallenge = {
        'challenge': challenge,
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('DeleteCertByLabel', getAssertionChallenge)


    return  await navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_DELEE_CERT);
        return gtidem;
    }).catch((error) => {
        //console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name);
        return gtidem;
    });
       
}


/**
 * 清除載具中的所有憑證和金鑰，需要驗證使用者密碼
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_ClearToken( bSerialNumber) {

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
 
    var sn_buf;
    if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){

        sn_buf = new Uint8Array(0);
    }else{
        sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
        sn_buf[0] = 0xDF;
        sn_buf[1] = 0x20;
        sn_buf[2] = bSerialNumber.byteLength >> 8;
        sn_buf[3] = bSerialNumber.byteLength;
        sn_buf.set(bSerialNumber, 4);
    }
    

   var payloadLen = sn_buf.byteLength;

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_CLEAR_TOKEN;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);

   console.log("Clear Token equest_command: " + bufToHex(pki_buffer));


    var getAssertionChallenge = {
        'challenge': challenge,
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('DeleteCertByIndex', getAssertionChallenge)


    return  await navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_CLEAR_TOKEN);
        return gtidem;
    }).catch((error) => {
        //console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name);
        return gtidem;
    });
       
}

/**
 * 回傳載具資訊
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_GetTokenInfo(bSerialNumber) {

    var pki_buffer = [];

    var sn_buf;

    if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){
        sn_buf = new Uint8Array(0);
    }else{
        sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
        sn_buf[0] = 0xDF;
        sn_buf[1] = 0x20;
        sn_buf[2] = bSerialNumber.byteLength >> 8;
        sn_buf[3] = bSerialNumber.byteLength;
        sn_buf.set(bSerialNumber, 4);
    }
    

    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var payloadLen = sn_buf.byteLength;
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
    var pki_header = new Uint8Array(3);
    pki_header[0] = CMD_TokenInfo;
    pki_header[1] = payloadLen>>8
    pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);

    console.log("GetTokenInfo", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "discouraged",
        timeout: 15000,  
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('GetTokenInfo', getAssertionChallenge)

    return await navigator.credentials.get({
            'publicKey': getAssertionChallenge
        }).then((fido) => {
           
            let gtidem = new GTIdemJs();
            gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_TokenInfo);
            return gtidem;
        }).catch((error) => {
            //console.log(error.name);
            let gtidem = new GTIdemJs();
            gtidem.ConvertWebError(error.name);
            return gtidem;
        });


}

/**
 * 使用特定位址的金鑰對資料簽名，會出現瀏覽器或是系統畫面 PIN 視窗，要求驗證密碼。
 * 
 * @param {number} index  指定位址的金鑰對
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @param {number} alg_number 簽名演算法,  ALG_RSA2048SHA256 或者 ALG_RSA2048SHA256_PreHash
 * @param {Uint8Array} bPlain 被簽名的資料
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_SignDataByIndex(index, bSerialNumber ,alg_number, bPlain) {

    var pki_buffer = [];
    var sn_buf;
    if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){

        sn_buf = new Uint8Array(0);
    }else{
        sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
        sn_buf[0] = 0xDF;
        sn_buf[1] = 0x20;
        sn_buf[2] = bSerialNumber.byteLength >> 8;
        sn_buf[3] = bSerialNumber.byteLength;
        sn_buf.set(bSerialNumber, 4);
    }

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

    var alg_buf;
    var signDataBuf;
    if(alg_number==ALG_RSA2048SHA256){
        await crypto.subtle.digest("SHA-256", new Uint8Array(bPlain)).then(function (signHashedDataPayload) {

            alg_buf = new Uint8Array(5);
            alg_buf[0] = 0xDF;
            alg_buf[1] = 0x03;
            alg_buf[2] = 0x00;
            alg_buf[3] = 0x01;
            alg_buf[4] = ALG_RSA2048SHA256_PreHash;

            var bHashData = new Uint8Array(signHashedDataPayload)
            signDataBuf = new Uint8Array(4 + bHashData.byteLength);
            signDataBuf[0] = 0xDF;
            signDataBuf[1] = 0x06;
            signDataBuf[2] = bHashData.length >> 8;
            signDataBuf[3] = bHashData.length;
            signDataBuf.set(bHashData, 4);
            return;
        });

    }else{

        alg_buf = new Uint8Array(5);
        alg_buf[0] = 0xDF;
        alg_buf[1] = 0x03;
        alg_buf[2] = 0x00;
        alg_buf[3] = 0x01;
        alg_buf[4] = alg_number;
    

        signDataBuf = new Uint8Array(4 + bPlain.byteLength);
        signDataBuf[0] = 0xDF;
        signDataBuf[1] = 0x06;
        signDataBuf[2] = bPlain.length >> 8;
        signDataBuf[3] = bPlain.length;
        signDataBuf.set(bPlain, 4);
    }

    
    var pki_payload_length = sn_buf.byteLength+command_buf.byteLength + alg_buf.byteLength + signDataBuf.byteLength;

    pki_header[0] = CMD_Sign;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;

    var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
    pki_buffer = _appendBuffer(pki_buffer,sn_buf);
    pki_buffer = _appendBuffer(pki_buffer,command_buf);
    pki_buffer = _appendBuffer(pki_buffer,alg_buf);
    pki_buffer = _appendBuffer(pki_buffer,signDataBuf);
    
    
    console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "required"

    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('SignDataByIndex', getAssertionChallenge)


    return await 
        navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
                let gtidem = new GTIdemJs();
                gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_Sign);
                return gtidem;
            }).catch((error) => {
                //console.log(error.name);
                let gtidem = new GTIdemJs();
                gtidem.ConvertWebError(error.name);
                return gtidem;
            });


}

/**
 * 使用特定標籤的金鑰對資料簽名，會出現瀏覽器或是系統畫面 PIN 視窗，要求驗證密碼。
 * 
 * @param {Uint8Array} bLabel  指定標籤
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @param {number} alg_number 簽名演算法,  ALG_RSA2048SHA256 或者 ALG_RSA2048SHA256_PreHash
 * @param {Uint8Array} bPlain 被簽名的資料
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_SignDataByLabel(bLabel, bSerialNumber ,alg_number, bPlain) {

    var pki_buffer = [];


    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
    var pki_header = new Uint8Array(3);


    var sn_buf;
    var token_sn = undefined;
    // if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){

    //     //call get token info if sn feild is empty
    //     // sn_buf = new Uint8Array(0);
    //     var gtidemA = await GTIDEM_GetTokenInfo(bSerialNumber).then((fido) => {
    //             return fido;
    //     });

    //     if(gtidemA.statusCode != CTAP1_ERR_SUCCESS){
    //         return gtidemA;
    //     }else{
    //         token_sn = new Uint8Array(gtidemA.sn)
    //         sn_buf = new Uint8Array(4 + token_sn.byteLength);
    //         sn_buf[0] = 0xDF;
    //         sn_buf[1] = 0x20;
    //         sn_buf[2] = token_sn.byteLength >> 8;
    //         sn_buf[3] = token_sn.byteLength;
    //         sn_buf.set(token_sn, 4);
    //     }
    // }else{
    //     sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
    //     sn_buf[0] = 0xDF;
    //     sn_buf[1] = 0x20;
    //     sn_buf[2] = bSerialNumber.byteLength >> 8;
    //     sn_buf[3] = bSerialNumber.byteLength;
    //     sn_buf.set(bSerialNumber, 4);
    // }

    if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){
        var gtidemA = await GTIDEM_GetTokenInfo(bSerialNumber).then((fido) => {
            return fido;
       });
       if(gtidemA.statusCode != CTAP1_ERR_SUCCESS){
           return gtidemA;
       }else{
           token_sn = new Uint8Array(gtidemA.sn);
       }
    }else{
        token_sn =  new Uint8Array(bSerialNumber);
    }

    sn_buf = new Uint8Array(4 + token_sn.byteLength);
    sn_buf[0] = 0xDF;
    sn_buf[1] = 0x20;
    sn_buf[2] = token_sn.byteLength >> 8;
    sn_buf[3] = token_sn.byteLength;
    sn_buf.set(token_sn, 4);



    //PKI Command

    var command_bufer = new Uint8Array(bLabel.byteLength + 4);
    command_bufer[0] = 0xDF
    command_bufer[1] = 0x01;
    command_bufer[2] = bLabel.byteLength >> 8;
    command_bufer[3] = bLabel.byteLength;
    command_bufer.set(bLabel, 4);


    var alg_buf = new Uint8Array(5);
    alg_buf[0] = 0xDF;
    alg_buf[1] = 0x03;
    alg_buf[2] = 0x00;
    alg_buf[3] = 0x01;
    alg_buf[4] = alg_number;

    var alg_buf;
    var signDataBuf;
    if(alg_number==ALG_RSA2048SHA256){
        await crypto.subtle.digest("SHA-256", new Uint8Array(bPlain)).then(function (signHashedDataPayload) {

            alg_buf = new Uint8Array(5);
            alg_buf[0] = 0xDF;
            alg_buf[1] = 0x03;
            alg_buf[2] = 0x00;
            alg_buf[3] = 0x01;
            alg_buf[4] = ALG_RSA2048SHA256_PreHash;

            var bHashData = new Uint8Array(signHashedDataPayload)
            signDataBuf = new Uint8Array(4 + bHashData.byteLength);
            signDataBuf[0] = 0xDF;
            signDataBuf[1] = 0x06;
            signDataBuf[2] = bHashData.length >> 8;
            signDataBuf[3] = bHashData.length;
            signDataBuf.set(bHashData, 4);
            return;
        });

    }else{

        alg_buf = new Uint8Array(5);
        alg_buf[0] = 0xDF;
        alg_buf[1] = 0x03;
        alg_buf[2] = 0x00;
        alg_buf[3] = 0x01;
        alg_buf[4] = alg_number;
    

        signDataBuf = new Uint8Array(4 + bPlain.byteLength);
        signDataBuf[0] = 0xDF;
        signDataBuf[1] = 0x06;
        signDataBuf[2] = bPlain.length >> 8;
        signDataBuf[3] = bPlain.length;
        signDataBuf.set(bPlain, 4);
    }



    var pki_payload_length = sn_buf.byteLength+command_bufer.byteLength + alg_buf.byteLength + signDataBuf.byteLength;

    pki_header[0] = CMD_Sign;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;

    var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
    pki_buffer = _appendBuffer(pki_buffer,sn_buf);
    pki_buffer = _appendBuffer(pki_buffer,command_bufer);
    pki_buffer = _appendBuffer(pki_buffer,alg_buf);
    pki_buffer = _appendBuffer(pki_buffer,signDataBuf);
    
    
    console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "required"

    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('SignDataByIndex', getAssertionChallenge);

    return await 
        navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
                let gtidem = new GTIdemJs();
                gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_Sign);
                if(gtidemA.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
                    gtidem.sn =token_sn;
                }
                return gtidem;
            }).catch((error) => {
                //console.log(error.name);
                let gtidem = new GTIdemJs();
                gtidem.ConvertWebError(error.name);
                return gtidem;
            });

}

/**
 * 不需要使用者密碼，就讀取特定位址的憑證。
 * 
 * @param {Number} bindex 指定標籤
 * @param {Uint8Array} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_ReadCertByIndexWithoutPIN(index, bSerialNumber) {

    var pki_buffer = [];
    var sn_buf;
    if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){

        sn_buf = new Uint8Array(0);
    }else{
        sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
        sn_buf[0] = 0xDF;
        sn_buf[1] = 0x20;
        sn_buf[2] = bSerialNumber.byteLength >> 8;
        sn_buf[3] = bSerialNumber.byteLength;
        sn_buf.set(bSerialNumber, 4);
    }

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

 

    var pki_payload_length = sn_buf.byteLength+command_buf.byteLength;

    pki_header[0] = CMD_ReadCertificate;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;

    var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
    pki_buffer = _appendBuffer(pki_buffer,sn_buf);
    pki_buffer = _appendBuffer(pki_buffer,command_buf);
    
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


    return await 
        navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
                let gtidem = new GTIdemJs();
                gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_ReadCertificate);
                return gtidem;
            }).catch((error) => {
                //console.log(error.name);
                let gtidem = new GTIdemJs();
                gtidem.ConvertWebError(error.name);
                return gtidem;
            });


}

/**
 * 不需要使用者密碼，就讀取特定標籤的憑證。
 * 
 * @param {Uint8Array} bLabel 指定標籤
 * @param {Uint8Array} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_ReadCertByLabelWithoutPIN(bLabel, bSerialNumber) {

    var pki_buffer = [];


 


    var challenge = new Uint8Array(32);
    window.crypto.getRandomValues(challenge);
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
    var pki_header = new Uint8Array(3);


    var sn_buf;
    var token_sn = undefined;
     var token_sn = undefined;
    // if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){

    //     //call get token info if sn feild is empty
    //     // sn_buf = new Uint8Array(0);
    //     var gtidemA = await GTIDEM_GetTokenInfo(bSerialNumber).then((fido) => {
    //             return fido;
    //     });

    //     if(gtidemA.statusCode != CTAP1_ERR_SUCCESS){
    //         return gtidemA;
    //     }else{
    //         token_sn = new Uint8Array(gtidemA.sn)
    //         sn_buf = new Uint8Array(4 + token_sn.byteLength);
    //         sn_buf[0] = 0xDF;
    //         sn_buf[1] = 0x20;
    //         sn_buf[2] = token_sn.byteLength >> 8;
    //         sn_buf[3] = token_sn.byteLength;
    //         sn_buf.set(token_sn, 4);
    //     }
    // }else{
    //     sn_buf = new Uint8Array(4 + bSerialNumber.byteLength);
    //     sn_buf[0] = 0xDF;
    //     sn_buf[1] = 0x20;
    //     sn_buf[2] = bSerialNumber.byteLength >> 8;
    //     sn_buf[3] = bSerialNumber.byteLength;
    //     sn_buf.set(bSerialNumber, 4);
    // }

    if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){
        var gtidemA = await GTIDEM_GetTokenInfo(bSerialNumber).then((fido) => {
            return fido;
       });
       if(gtidemA.statusCode != CTAP1_ERR_SUCCESS){
           return gtidemA;
       }else{
           token_sn = new Uint8Array(gtidemA.sn);
       }
    }else{
        token_sn =  new Uint8Array(bSerialNumber);
    }
    
    sn_buf = new Uint8Array(4 + token_sn.byteLength);
    sn_buf[0] = 0xDF;
    sn_buf[1] = 0x20;
    sn_buf[2] = token_sn.byteLength >> 8;
    sn_buf[3] = token_sn.byteLength;
    sn_buf.set(token_sn, 4);





    //PKI Command

    var command_bufer = new Uint8Array(bLabel.byteLength + 4);
    command_bufer[0] = 0xDF
    command_bufer[1] = 0x01;
    command_bufer[2] = bLabel.byteLength >> 8;
    command_bufer[3] = bLabel.byteLength;
    command_bufer.set(bLabel, 4);


  

    var pki_payload_length = sn_buf.byteLength+command_bufer.byteLength;

    pki_header[0] = CMD_ReadCertificate;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;

    var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
    pki_buffer = _appendBuffer(pki_buffer,sn_buf);
    pki_buffer = _appendBuffer(pki_buffer,command_bufer);
    
    
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
    console.log('SignDataByIndex', getAssertionChallenge);

    return await 
        navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
                let gtidem = new GTIdemJs();
                gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_ReadCertificate);
                if(gtidemA.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
                    gtidem.sn =token_sn;
                }
                
                return gtidem;
            }).catch((error) => {
                //console.log(error.name);
                let gtidem = new GTIdemJs();
                gtidem.ConvertWebError(error.name);
                return gtidem;
            });


}




/**
 * Creates a new Uint8Array based on two different ArrayBuffers
 *
 * @private
 * @param {ArrayBuffers} buffer1 The first buffer.
 * @param {ArrayBuffers} buffer2 The second buffer.
 * @return {ArrayBuffers} The new ArrayBuffer created out of the two.
 */
 var _appendBuffer = function(buffer1, buffer2) {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
  };
