'use strict';

const CTAP1_ERR_SUCCESS = 0;
const CTAP1_ERR_INVALID_COMMAND = 1;
const CTAP2_ERR_CBOR_PARSING = 0x10; //Error while parsing CBOR.
const CTAP2_ERR_CBOR_UNEXPECTED_TYPE = 0x11; //Invalid/unexpected CBOR error.
const CTAP2_ERR_INVALID_CBOR = 0x12; //Error when parsing CBOR.
const CTAP2_ERR_INVALID_CBOR_TYPE = 0x13; //Invalid or unexpected CBOR type.
const CTAP2_ERR_MISSING_PARAMETER = 0x14; //Missing non-optional parameter.
const CTAP2_ERR_LIMIT_EXCEEDED = 0x15; //Limit for number of items exceeded.
const CTAP2_ERR_UNSUPPORTED_EXTENSION = 0x16; //Unsupported extension.
const CTAP2_ERR_TOO_MANY_ELEMENTS = 0x17; //Limit for number of items exceeded.
const CTAP2_ERR_EXTENSION_NOT_SUPPORTED = 0x18; //Unsupported extension.
const CTAP2_ERR_CREDENTIAL_EXCLUDED = 0x19; //Valid credential found in the exludeList.
const CTAP2_ERR_CREDENTIAL_NOT_VALID = 0x20; //Credential not valid for authenticator.
const CTAP2_ERR_PROCESSING = 0x21; //Processing (Lengthy operation is in progress).
const CTAP2_ERR_INVALID_CREDENTIAL = 0x22; //Credential not valid for the authenticator.
const CTAP2_ERR_USER_ACTION_PENDING = 0x23; //Authentication is waiting for user interaction.
const CTAP2_ERR_OPERATION_PENDING = 0x24; //Processing, lengthy operation is in progress.
const CTAP2_ERR_NO_OPERATIONS = 0x25; //No request is pending.
const CTAP2_ERR_UNSUPPORTED_ALGORITHM = 0x26; //Authenticator does not support requested algorithm.
const CTAP2_ERR_OPERATION_DENIED = 0x27; //Not authorized for requested operation.
const CTAP2_ERR_KEY_STORE_FULL = 0x28; //Internal key storage is full.
const CTAP2_ERR_NOT_BUSY = 0x29; //Authenticator cannot cancel as it is not busy.
const CTAP2_ERR_NO_OPERATION_PENDING = 0x2A; //No outstanding operations.
const CTAP2_ERR_UNSUPPORTED_OPTION = 0x2B; //Unsupported option.
const CTAP2_ERR_INVALID_OPTION = 0x2C; //Unsupported option.
const CTAP2_ERR_KEEPALIVE_CANCEL = 0x2D; //Pending keep alive was cancelled.
const CTAP2_ERR_NO_CREDENTIALS = 0x2E; //No valid credentials provided.
const CTAP2_ERR_USER_ACTION_TIMEOUT = 0x2F; //Timeout waiting for user interaction.
const CTAP2_ERR_NOT_ALLOWED = 0x30; //Continuation command, such as, authenticatorGetNextAssertion notallowed.
const CTAP2_ERR_PIN_INVALID = 0x31; //PIN Invaild
const CTAP2_ERR_PIN_BLOCKED = 0x32; //PIN Blocked.
const CTAP2_ERR_PIN_AUTH_INVALID = 0x33; //PIN authentication,pinAuth, verification failed.
const CTAP2_ERR_PIN_AUTH_BLOCKED = 0x34; //PIN authentication,pinAuth, blocked. Requires power recycle to reset.
const CTAP2_ERR_PIN_NOT_SET = 0x35; //No PIN has been set.
const CTAP2_ERR_PIN_REQUIRED = 0x36; //PIN is required for the selected operation.
const CTAP2_ERR_PIN_POLICY_VIOLATION = 0x37; //PIN policy violation. Currently only enforces minimum length.
const CTAP2_ERR_PIN_TOKEN_EXPIRED = 0x38; //pinToken expired on authenticator.
const CTAP2_ERR_REQUEST_TOO_LARGE = 0x39; //Authenticator cannot handle this request due to memory constraints.
const CTAP2_ERR_ACTION_TIMEOUT = 0x3a; //The current operation has timed out.
const CTAP2_ERR_UP_REQUIRED = 0x3b; //User presence is required for the requested operation.
const CTAP1_ERR_OTHER = 0x7F; //Other unspecified error.
const CTAP2_ERR_SPEC_LAST = 0xDF; //CTAP 2 spec last error.
const CTAP2_ERR_EXTENSION_FIRST = 0xE0; //Extension specific error.
const CTAP2_ERR_EXTENSION_LAST = 0xEF; //Extension specific error.
const CTAP2_ERR_VENDOR_FIRST = 0xF0; //Vendor specific error.
const CTAP2_ERR_VENDOR_LAST = 0xFF; //Vendor specific error.

const CTAP2_VENDOR_ERROR_TOKEN = 0xF2;
const CTAP2_VENDOR_ERROR_LENGTH = 0xF3;
const CTAP2_ERR_VENDOR_ERROR_NO_USER    = 0xF4;    //Vendor specific error.
const CTAP2_ERR_VENDOR_ERROR_CREDENTIAL_EXIST    =0xF5;    //Vendor specific error.

const ErrorMsg_OK = "No ERROR";
const ErrorMsg_PIN_INVALID = "PIN invalid.";
const ErrorMsg_PIN_BLOCKED = "PIN blocked.";
const ErrorMsg_PIN_REQUIRED = "The request has to verify PIN.";
const ErrorMsg_NO_CREDENTIALS = "Not found the credential.";
const ErrorMsg_UNKNOW = "Unknow error. ";
const Msg_PIN_Trial_Counter = "The retries counter is ";


/**
 * Ref:https://www.w3.org/TR/webauthn-2/#sctn-privacy-considerations-client.
 * This error from brower or native api
 */

 const WEB_ERR_UserCancelorTimeout = 0xE001;
 const WEB_ERR_OperationAbrot = 0xE002;

 const WEB_ERR_Timeout = 0xE003;
 const WEB_ERR_Unknow= 0xE004;


var showFIDOErrorMessage = (gtidem) => {

    var errorMsg ='錯誤碼:'+gtidem.statusCode;+'.   ';
    switch (gtidem.statusCode) {

        case CTAP2_ERR_PIN_INVALID:
            errorMsg += "密碼錯誤！" + "剩餘次數:" + gtidem.pinRetry;
            break;
        case CTAP2_ERR_PIN_BLOCKED:
            errorMsg +='超過嘗試次數，密碼鎖定';
            break;
        case CTAP2_ERR_KEY_STORE_FULL:
            errorMsg +='憑證空間已滿';
            break;
        case CTAP2_ERR_NO_CREDENTIALS:
            errorMsg += '要求物件不存在';
            break;
        case CTAP2_ERR_CREDENTIAL_EXCLUDED:
            errorMsg +='要求物件已存在';
            break;
        case CTAP2_VENDOR_ERROR_TOKEN:
            errorMsg += '序號錯誤.';
            if(gtidem.sn!= undefined){
                errorMsg += '該裝置序號為'+ ConverSNFormat(gtidem.sn);
            }    
            break;

        case CTAP2_ERR_VENDOR_ERROR_CREDENTIAL_EXIST:
            errorMsg += '憑證已經存在';  
            break;

        case WEB_ERR_UserCancelorTimeout:
            errorMsg += '操作取消';
            break;
        case WEB_ERR_OperationAbrot:
            errorMsg += '操作拒絕';
            break;
        case WEB_ERR_Timeout:
            errorMsg += '網頁沒有回應';
            break;
        case WEB_ERR_Unknow:
            errorMsg += '發生不預期錯誤';
            break;
        default:
            errorMsg += '不能判別的錯誤。';
            break;
    }
    return errorMsg;

}


// Command Header GoTrust-Idem-PKI
var GTheaderStr = "GoTrust-Idem-PKI";

var showCertificMessage = (buffer) => {

    let gtHeader = buffer.slice(0, 16);
    buffer = buffer.slice(16);

    if (String.fromCharCode.apply(null, new Uint8Array(gtHeader)) === GTheaderStr) { //This is error handle

        //var total = buffer.slice(0, 1);            buffer = buffer.slice(1);
        //var status  = buffer.slice(0, 1);            buffer = buffer.slice(1);


        var total = new Uint8Array(buffer.slice(0, 2));
        buffer = buffer.slice(2);
        var status = new Uint8Array(buffer.slice(0, 1))[0];
        buffer = buffer.slice(1);


        var errorMsg = undefined;
        switch (status) {

            case CTAP2_ERR_NO_CREDENTIALS:

                errorMsg = ErrorMsg_NO_CREDENTIALS;
                break;
            case CTAP2_ERR_PIN_INVALID:


                let retrial = buffer.slice(0, 3);
                buffer = buffer.slice(3);
                errorMsg = ErrorMsg_PIN_INVALID + bufToHex(retrial);
                break;
            case CTAP2_ERR_PIN_BLOCKED:

                errorMsg = ErrorMsg_PIN_BLOCKED;
                break;
            case CTAP2_ERR_PIN_REQUIRED:

                errorMsg = ErrorMsg_PIN_REQUIRED;
                break;
            case CTAP2_ERR_MISSING_PARAMETER:

                errorMsg = "Command error!";
                break;
            default:
                errorMsg = ErrorMsg_UNKNOW + status;
        }
        alert(errorMsg);
    } else { // show normal message
        console.log("show normal message!!");
    }
}

var showSignMessage = (buffer) => {

    let gtHeader = buffer.slice(0, 16);
    console.log('gtHeader', bufToHex(gtHeader));
    if (String.fromCharCode.apply(null, new Uint8Array(gtHeader)) === GTheaderStr) { //This is error handle

        buffer = buffer.slice(16);

        var totalLen = new Uint8Array(buffer.slice(0, 2));
        buffer = buffer.slice(2);
        var status = new Uint8Array(buffer.slice(0, 1))[0];
        buffer = buffer.slice(1);

        var errorMsg = undefined;

        console.log('status', status);
        switch (status) {

            case CTAP2_ERR_NO_CREDENTIALS:

                errorMsg = ErrorMsg_NO_CREDENTIALS;
                break;
            case CTAP2_ERR_PIN_INVALID:


                let retrial = buffer.slice(0, 3);
                buffer = buffer.slice(3);
                let number = new Uint8Array(retrial)[2]
                errorMsg = ErrorMsg_PIN_INVALID + "\n" + Msg_PIN_Trial_Counter + number

                break;
            case CTAP2_ERR_PIN_BLOCKED:

                errorMsg = ErrorMsg_PIN_BLOCKED;
                break;
            case CTAP2_ERR_PIN_REQUIRED:

                errorMsg = ErrorMsg_PIN_REQUIRED;
                break;
            case CTAP2_ERR_MISSING_PARAMETER:

                errorMsg = "Command error!";
                break;
            case CTAP1_ERR_SUCCESS:

                errorMsg = ErrorMsg_OK;
                break;
            default:
                errorMsg = ErrorMsg_UNKNOW + status;
        }
        alert(errorMsg);
    } else { // show normal message


        var str = String.fromCharCode.apply(null, new Uint8Array(buffer));
        alert("Signature:" + "\n" + btoa(str));
        console.log("show normal message!!");
    }


}



var showRSAKeyPair = (buffer) => {

    let gtHeader = buffer.slice(0, 16);
    console.log('gtHeader', bufToHex(gtHeader));
    if (String.fromCharCode.apply(null, new Uint8Array(gtHeader)) === GTheaderStr) {
        buffer = buffer.slice(16);


        var totalLen = new Uint8Array(buffer.slice(0, 2));
        buffer = buffer.slice(2);
        var status = new Uint8Array(buffer.slice(0, 1))[0];
        buffer = buffer.slice(1);

        var Msg = undefined;
        switch (status) {

            case CTAP1_ERR_SUCCESS:
                //var keydata = 

                let data = CBOR.decode(buffer.buffer);
                return data;

                break;
            case CTAP2_ERR_NO_CREDENTIALS:

                Msg = ErrorMsg_NO_CREDENTIALS;
                break;
            case CTAP2_ERR_PIN_INVALID:


                let retrial = buffer.slice(0, 3);
                buffer = buffer.slice(3);
                Msg = ErrorMsg_PIN_INVALID + bufToHex(retrial);
                break;
            case CTAP2_ERR_PIN_BLOCKED:

                Msg = ErrorMsg_PIN_BLOCKED;
                break;
            case CTAP2_ERR_PIN_REQUIRED:

                Msg = ErrorMsg_PIN_REQUIRED;
                break;
            case CTAP2_ERR_MISSING_PARAMETER:

                Msg = "Command error!";
                break;
            default:
                Msg = ErrorMsg_UNKNOW + status;
        }
        alert(Msg);
    }
}
var isErrorMessage = (buffer) => {

    let gtHeader = buffer.slice(0, 16);
    console.log('gtHeader', bufToHex(gtHeader));
    if (String.fromCharCode.apply(null, new Uint8Array(gtHeader)) === GTheaderStr) {

        return 1;
    }

    return 0;
}