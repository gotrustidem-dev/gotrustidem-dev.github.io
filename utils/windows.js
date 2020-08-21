

document.getElementById('find-index').addEventListener('submit', function (event) {
            event.preventDefault();
            var pki_buffer = [];
            let certIndex = document.getElementById('use-index').certIndex.value;

            var challenge = new Uint8Array(32);
            window.crypto.getRandomValues(challenge);

            //Prepare PKI commmand
            //Header
            var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));

            var pki_header = new Uint8Array(3);

            //PKI Command
            var command_bufer = new Uint8Array(4);
            command_bufer[0] = 0xDF;
            command_bufer[1] = 0x02;
            command_bufer[2] = 01;
            command_bufer[3] = certIndex;

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
                    
                    showCertificMessage(authData.credID);
                    

                    const sliced = new Uint8Array(authData.credID.slice(1, authData.credID.length));
                    var strCert = "-----BEGIN CERTIFICATE-----\n" +
                        btoa(String.fromCharCode.apply(null, sliced)) +
                        "\n-----END CERTIFICATE-----"

                    console.log('Certificatie : \n', strCert)
                    displayCert(strCert)

                })
                .catch((error) => {
                    alert(error)
                    console.log('FAIL', error)
                })
        })