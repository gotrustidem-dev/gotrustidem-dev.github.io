




class GTIdemJs {

    constructor() {
        this.statusCode = 123;
        this.fw = undefined;
        this.sw = undefined;
        this.pinRetry = undefined;
        this.sn = undefined;
        this.rn = undefined;
        this.ecpoint = undefined;
        this.signature = undefined;
        this.certicficate = undefined;
        this.credentialNum = undefined;
        this.keyhandle = undefined;
        this.keyid = undefined;
        this.csr = undefined;
        this.rsakeypair = undefined;
    }

    parsePKIoverFIDOResponse(buffer, cmd){

        var GTheaderStr = "GoTrust-Idem-PKI";


        let GTheaderBuf = buffer.slice(0, 16);

        if (cmd == CMD_ReadCertificate) {
            //has error
            if (String.fromCharCode.apply(null, new Uint8Array(GTheaderBuf)) === GTheaderStr) {
                buffer = buffer.slice(16);
            } else {
                let certNumBuf = buffer.slice(0, 1);
                this.credentialNum = certNumBuf[0];
                buffer = buffer.slice(1);
                this.certicficate = buffer;
            }
        } else if (String.fromCharCode.apply(null, new Uint8Array(GTheaderBuf)) === GTheaderStr) {

            buffer = buffer.slice(16);

            let totalLenBuf = buffer.slice(0, 2);
            let totalLen = readBE16(new Uint8Array(totalLenBuf));
            buffer = buffer.slice(2);
            let statusCodeBuf = buffer.slice(0, 1);
            this.statusCode = statusCodeBuf[0];

            buffer = buffer.slice(1);

            if((totalLen - 1)>0){//has payload
                let payloadDataBuf = buffer.slice(0, (totalLen - 1));
                let responseData = CBOR.decode(payloadDataBuf);
                if (this.statusCode == CTAP2_ERR_PIN_INVALID) {

                    this.pinRetry = responseData[1];

                } else if (this.statusCode == CTAP1_ERR_SUCCESS) {
                    switch (cmd) {
                        case CMD_TokenInfo:
                            this.fw= responseData[1];
                            this.sw = responseData[2];
                            this.pinRetry = responseData[3];
                            this.credentialNum = responseData[4];
                            this.sn = responseData[5];
                            this.rn= responseData[6];
                            this.ecpoint = responseData[7];
                            
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
            }
        } else if (value.byteLength == 256) {

            this.signature = new Uint8Array(buffer);
            this.statusCode = CTAP1_ERR_SUCCESS;
        } else {
            // 無法判斷

        }
    }


}