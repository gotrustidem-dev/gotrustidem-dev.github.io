




class GTIdemJs {
    

    constructor() {
        this.statusCode = undefined;
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

    ConvertWebError(error){

        if(error == "AbortError "){

            this.statusCode = WEB_ERR_OperationAbort;
        }

        if(error == "NotAllowedError"){
            this.statusCode = WEB_ERR_UserCancelorTimeout;
        }

        if(error == "TimeoutError"){
            this.statusCode = WEB_ERR_Timeout;
        }

        if(error == "UnknownError"){
            this.statusCode = WEB_ERR_Unknow;
        }

        if(error == "InvalidStateError"){
            this.statusCode = WEB_ERR_InvalidState;
        }

    }
    parsePKIoverFIDOResponse(buffer, cmd){

        var GTheaderStr = "GoTrust-Idem-PKI";


        let GTheaderBuf = buffer.slice(0, 16);

        if (String.fromCharCode.apply(null, new Uint8Array(GTheaderBuf)) === GTheaderStr) {

            buffer = buffer.slice(16);

            let totalLenBuf = buffer.slice(0, 2);
            let totalLen = readBE16(new Uint8Array(totalLenBuf));
            buffer = buffer.slice(2);
            let statusCodeBuf = new Uint8Array(buffer.slice(0, 1));
            this.statusCode = statusCodeBuf[0];

            buffer = buffer.slice(1);

            if((totalLen - 1)>0){//has payload
                let payloadDataBuf = buffer.slice(0, (totalLen - 1));
                let responseData = CBOR.decode(payloadDataBuf);
                if (this.statusCode == CTAP2_ERR_PIN_INVALID) {

                    this.pinRetry = responseData[1];

                }else if (this.statusCode == CTAP1_ERR_SUCCESS) {
                    switch (cmd) {
                        case CMD_TokenInfo:

                        if( responseData[1]!=undefined){
                            this.fw= responseData[1];
                            this.sw = responseData[2];
                            this.pinRetry = responseData[3];
                            this.credentialNum = responseData[4];
                            this.sn = responseData[5];
                            this.rn= responseData[6];
                            this.ecpoint = responseData[7];
                        }else{ //support 3.0.8+
                            this.fw= responseData['fw'];
                            this.sw = responseData['sw'];
                            this.pinRetry = responseData['pinRetry'];
                            this.credentialNum = responseData['credNum'];
                            this.sn = responseData['sn'];
                            this.rn= responseData['rn'];
                            this.ecpoint = responseData['ecPoint'];
                        }
                            break;
                        case CMD_Sign:
                            this.signature = responseData['sig'];
                            break;
                        case CMD_SignWithPIN:
                            this.signature = responseData['sig'];
                            break;
                        case CMD_GenRsaKeyPair:
                            if( responseData[2]!=undefined){
                                this.keyhandle= new Uint8Array( responseData[1]);
                                this.rsakeypair= new Uint8Array( responseData[2]);
                            }else{
                                this.keyhandle= new Uint8Array( responseData['id']);
                                this.rsakeypair= new Uint8Array( responseData['rsaPubKey']);
                            }
                            break;
                        case CMD_REQUESTCSR:
                            if( responseData[2]!=undefined){
                                this.keyhandle= new Uint8Array( responseData[1]);
                                this.csr= new Uint8Array( responseData[2]);
                            }else{
                                this.keyhandle= new Uint8Array( responseData['id']);
                                this.csr= new Uint8Array( responseData['csr']);
                            }
                            break;
                        case CMD_ImportCertificate:
                            this.signature = responseData['sig'];
                            break;
                        case CMD_CHANGE_PIN:
                            this.pinRetry = responseData[1];

                            break;
                        default:
                    }                
                }

                //Each api always get serial_number
               if(responseData['sn']!=undefined){                                
                   this.sn = responseData['sn'];
               }

                            
            }
        } else if (cmd == CMD_ReadCertificate) {
            this.statusCode = CTAP1_ERR_SUCCESS;
            let bCERTBuf = new Uint8Array(buffer);
            let num  = bCERTBuf.slice(0, 1);
            if(num[0]==0x30){ //only cert
                this.certicficate = bCERTBuf;
            }else{{
                this.credentialNum = num[0];
                this.certicficate = bCERTBuf.slice(1);

            }}

  
            
        } else if (buffer.byteLength == 256) {

            this.signature = new Uint8Array(buffer);
            this.statusCode = CTAP1_ERR_SUCCESS;
        } else {
            // 無法判斷

        }
    }


}


var showErrorMessage = (gtidem)=>{



    var msg="";


    switch(gtidem.statusCode){



    }


}