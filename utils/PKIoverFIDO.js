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

/*
async function requestSignDataWithPINByKEYHANDLE(keyhandle, platformECpublickey, encryptedPIN, plaintext) {


    var exportECPublicKeyArray = platformECpublickey;
    var EncryptedPINArray = encryptedPIN;
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
    alg_buf[4] = 0x02;


    var ecpubkey_buf = new Uint8Array(4 + exportECPublicKeyArray.byteLength);
    ecpubkey_buf[0] = 0xDF;
    ecpubkey_buf[1] = 0x04;
    ecpubkey_buf[2] = exportECPublicKeyArray.byteLength >> 8;
    ecpubkey_buf[3] = exportECPublicKeyArray.byteLength;
    ecpubkey_buf.set(new Uint8Array(exportECPublicKeyArray), 4);


    var encryptedPIN_buf = new Uint8Array(4 + EncryptedPINArray.byteLength);
    encryptedPIN_buf[0] = 0xDF;
    encryptedPIN_buf[1] = 0x05;
    encryptedPIN_buf[2] = EncryptedPINArray.byteLength >> 8;
    encryptedPIN_buf[3] = EncryptedPINArray.byteLength;
    encryptedPIN_buf.set(new Uint8Array(EncryptedPINArray), 4);


    var signDataBuf = new Uint8Array(4 + signDataPayload.byteLength);
    signDataBuf[0] = 0xDF;
    signDataBuf[1] = 0x06;
    signDataBuf[2] = signDataPayload.length >> 8;
    signDataBuf[3] = signDataPayload.length;
    signDataBuf.set(signDataPayload, 4);



    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + keyHandle_buf.byteLength +
        alg_buf.byteLength + ecpubkey_buf.byteLength + encryptedPIN_buf.byteLength +
        signDataBuf.byteLength);
    var pki_payload_length = keyHandle_buf.byteLength + alg_buf.byteLength + ecpubkey_buf
        .byteLength + encryptedPIN_buf.byteLength + signDataBuf.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = 0xE5;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(keyHandle_buf), gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(alg_buf), gtheaderbuffer.byteLength + 3 + keyHandle_buf
        .byteLength);
    pki_buffer.set(new Uint8Array(ecpubkey_buf), gtheaderbuffer.byteLength + 3 + keyHandle_buf
        .byteLength + alg_buf.byteLength);
    pki_buffer.set(new Uint8Array(encryptedPIN_buf), gtheaderbuffer.byteLength + 3 +
        keyHandle_buf.byteLength + alg_buf.byteLength + ecpubkey_buf.byteLength);
    pki_buffer.set(new Uint8Array(signDataBuf), gtheaderbuffer.byteLength + 3 + keyHandle_buf
        .byteLength + alg_buf.byteLength + ecpubkey_buf.byteLength + encryptedPIN_buf
        .byteLength);

    console.log("sign-keyhandle: " + bufToHex(pki_buffer));

    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "discouraged"
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('List getAssertionChallenge', getAssertionChallenge)

    return await new Promise(resolve => {
        navigator.credentials.get({
                'publicKey': getAssertionChallenge
            })
            .then((newCredentialInfo) => {
                resolve(newCredentialInfo);
            })
            .catch((error) => {
                alert(error)
                console.log('FAIL', error)
            })
    });

}
*/



async function requestSignDataByKEYHANDLE(keyhandle, plaintext) {


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
    alg_buf[4] = 0x02;

    var signDataBuf = new Uint8Array(4 + signDataPayload.byteLength);
    signDataBuf[0] = 0xDF;
    signDataBuf[1] = 0x06;
    signDataBuf[2] = signDataPayload.length >> 8;
    signDataBuf[3] = signDataPayload.length;
    signDataBuf.set(signDataPayload, 4);



    var pki_buffer = new Uint8Array(gtheaderbuffer.byteLength + 3 + keyHandle_buf.byteLength +
        alg_buf.byteLength +signDataBuf.byteLength);
    var pki_payload_length = keyHandle_buf.byteLength + alg_buf.byteLength + signDataBuf.byteLength;
    pki_buffer.set(new Uint8Array(gtheaderbuffer), 0);
    pki_header[0] = 0xE3;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;
    pki_buffer.set(new Uint8Array(pki_header), gtheaderbuffer.byteLength);
    pki_buffer.set(new Uint8Array(keyHandle_buf), gtheaderbuffer.byteLength + 3);
    pki_buffer.set(new Uint8Array(alg_buf), gtheaderbuffer.byteLength + 3 + keyHandle_buf
        .byteLength);
    pki_buffer.set(new Uint8Array(signDataBuf), gtheaderbuffer.byteLength + 3 + keyHandle_buf
        .byteLength + alg_buf.byteLength );

    console.log("sign-keyhandle: " + bufToHex(pki_buffer));

    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "discouraged"
    }
    var idList = [{
        id: pki_buffer,
        transports: ["usb", "nfc"],
        type: "public-key"
    }];

    getAssertionChallenge.allowCredentials = idList;
    console.log('List getAssertionChallenge', getAssertionChallenge)

    return await new Promise(resolve => {
        navigator.credentials.get({
                'publicKey': getAssertionChallenge
            })
            .then((newCredentialInfo) => {
                resolve(newCredentialInfo);
            })
            .catch((error) => {
                alert(error)
                console.log('FAIL', error)
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
    pki_header[0] = 0xE1;
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
    pki_header[0] = 0xE1;
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
            "userVerification": "discouraged",
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


function ReadCertByLable() {


}