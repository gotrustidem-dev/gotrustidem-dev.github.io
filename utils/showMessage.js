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
const CTAP2_ERR_VENDOR_ERROR_INVALID_DATA    =0xF6;    //Vendor specific error.
const CTAP2_ERR_VENDOR_ERROR_NOT_ALLOWED_RPID    =0xF7;    //Vendor specific error.
const CTAP2_ERR_VENDOR_ERROR_PIN_EXPIRED    =0xF8;    //Vendor specific error.
const CTAP2_ERR_VENDOR_ERROR_PIN_LEN    =0xF9;    //Vendor specific error.
const CTAP2_ERR_VENDOR_ERROR_PIN_REUSE    =0xFA;    //Vendor specific error.

const IKP_ERR_SETTING_SOPIN_LEN      = 0x81;  //Other unspecified error.
const IKP_ERR_SETTING_USERPIN_LEN    = 0x82;  //Other unspecified error.
const IKP_ERR_SETTING_RETRY          = 0x83;  //Other unspecified error.
const IKP_ERR_SETTING_DOMAIN         = 0x84;  //Other unspecified error.
const IKP_ERR_SETTING_LEN_RANGE      = 0x85;  //Other unspecified error.
	 

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
 const WEB_ERR_OperationAbort = 0xE002;
 const WEB_ERR_Timeout = 0xE003;
 const WEB_ERR_Unknow= 0xE004;
 const WEB_ERR_InvalidState= 0xE005;

 
 const SETTING_ERR_USERPIN_SAME= 0xC001;
 const SETTING_ERR_USERPIN_LEN= 0xC002;
 const SETTING_ERR_USERPIN_LEVEL= 0xC003;


var showFIDOErrorMessage = (gtidem) => {

    console.log(gtidem);
    var errorMsg ='錯誤碼:'+gtidem.statusCode;+'.   ';
    switch (gtidem.statusCode) {

        case CTAP2_ERR_PIN_INVALID:
            errorMsg += "密碼錯誤！";
            if(gtidem.pinRetry!=undefined){
                errorMsg+= "User PIN剩餘次數:" + gtidem.pinRetry;
            }else if(gtidem.sopinRetry!=undefined){
                errorMsg+= "SO PIN剩餘次數:" + gtidem.sopinRetry;
            }
            
            break;
        case CTAP2_ERR_PIN_BLOCKED:
            errorMsg +='超過嘗試次數，密碼鎖定';
            if(gtidem.pinRetry!=undefined){
                errorMsg+= "User PIN剩餘次數:" + gtidem.pinRetry;
            }else if(gtidem.sopinRetry!=undefined){
                errorMsg+= "SO PIN剩餘次數:" + gtidem.sopinRetry;
            }
            break;

        case CTAP2_ERR_PIN_POLICY_VIOLATION:
            errorMsg = "密碼不符合要求";
            break; 
            
        case CTAP2_ERR_MISSING_PARAMETER:
            errorMsg = "缺少必要的參數";
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
            break;
        case CTAP2_ERR_VENDOR_ERROR_INVALID_DATA:
            errorMsg+= '不可用的初始化資料.';
            break;
        case CTAP2_ERR_VENDOR_ERROR_CREDENTIAL_EXIST:
            errorMsg += '憑證已經存在';  
            break;
        case CTAP2_ERR_VENDOR_ERROR_NOT_ALLOWED_RPID:
            errorMsg += '此網站不能使用載具'; 
            break;    
        case CTAP2_ERR_VENDOR_ERROR_PIN_EXPIRED:
            errorMsg += '密碼到期。需變更密碼'; 
            break;    
        case CTAP2_ERR_VENDOR_ERROR_PIN_REUSE:
            errorMsg += '無法變更為預設密碼'; 
            break;
        case CTAP2_ERR_UNSUPPORTED_ALGORITHM:
            errorMsg += '不支援的演算法'; 
            break;        
        case CTAP2_VENDOR_ERROR_LENGTH:
            errorMsg += '資料長度錯誤'; 
            break;    

        case IKP_ERR_SETTING_SOPIN_LEN:
            errorMsg += '管理者密碼長度錯誤'; 
            break;    
        case IKP_ERR_SETTING_USERPIN_LEN:
            errorMsg += '使用者密碼長度錯誤'; 
            break;    
        case IKP_ERR_SETTING_RETRY:
            errorMsg += '密碼重試次數參數錯誤'; 
            break;    
        case IKP_ERR_SETTING_DOMAIN:
            errorMsg += '載具允許網域設定錯誤'; 
            break;    
        case IKP_ERR_SETTING_LEN_RANGE:
            errorMsg += '密碼長度參數超出允許範圍'; 
            break;    
    
        case WEB_ERR_UserCancelorTimeout:
            errorMsg += '操作取消';
            break;
            
        case WEB_ERR_OperationAbort:
            errorMsg += '操作拒絕';
            break;
        case WEB_ERR_Timeout:
            errorMsg += '網頁沒有回應';
            break;
        case WEB_ERR_Unknow:
            errorMsg += '發生不預期錯誤';
            break;
        case WEB_ERR_InvalidState:
             errorMsg += '無效的操作';
            break;
        case SETTING_ERR_USERPIN_SAME:
            errorMsg += '新舊密碼必須不同';
           break;
        case SETTING_ERR_USERPIN_LEN:
            errorMsg += '新密碼長度不合';
           break;
        case SETTING_ERR_USERPIN_LEVEL:
            errorMsg += '新密碼複雜度不合';
           break;   
           
        default:
            errorMsg += '不能判別的錯誤。';
            break;
    }

    if(gtidem.sn!= undefined){
        errorMsg += '\n該裝置序號為'+ ConverSNFormat(gtidem.sn);
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