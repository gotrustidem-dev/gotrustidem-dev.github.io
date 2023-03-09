

/**
 * GoTrsutID'sJavascript libary for Idem Key+
 */


 'use strict';

const VERSION = "1.11.3"
const DEFAULT_TIMEOUT = 120000
const VERIFY_DEFAULT_TIMEOUT = 300000
const AUTHENTICATOR_TRANSPORTS = ["usb"]


// Command Header GoTrust-Idem-PKI
const GTheader = 'R29UcnVzdC1JZGVtLVBLSQ==';
var sUserName = 'GoTrustID.com';

const TOKEN_MIN_PIN_LEN = 4;
const TOKEN_MAX_PIN_LEN = 63;

const  TOKEN_MAX_SOPIN_LEN = 16;
const  TOKEN_MIN_SOPIN_LEN = 8;

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
const CMD_INIT_TOKEN = 0xED;
const CMD_GenKeyPair = 0xEE;
const CMD_FactoryReset = 0xEF;
const CMD_ImportCertificate2 = 0xF7;

const CMD_REQUESTP256CSR = 0xC1;
const CMD_REQUESTP384CSR = 0xC2;
const CMD_REQUESTP521CSR = 0xC3;



var g_encryptedPIN;
var g_platformECpublickey;

const ALG_RSA2048SHA1 = 0x01;
const ALG_RSA2048SHA256 = 0x02;
const ALG_RSA2048SHA384 = 0x03;
const ALG_RSA2048SHA512 = 0x04;
const ALG_RSA2048SHA1_PSS = 0x05;
const ALG_RSA2048SHA256_PSS = 0x06;
const ALG_RSA2048SHA384_PSS = 0x07;
const ALG_RSA2048SHA512_PSS = 0x08;
const ALG_ECDSASHA1 = 0x09;
const ALG_ECDSASHA256 = 0x0a;
const ALG_ECDSASHA384 = 0x0b;
const ALG_ECDSASHA512 = 0x0c;

const ALG_RSA2048SHA1_PreHash = 0x11;
const ALG_RSA2048SHA256_PreHash = 0x12;
const ALG_RSA2048SHA384_PreHash = 0x13;
const ALG_RSA2048SHA512_PreHash = 0x14;
const ALG_RSA2048SHA1_PSS_PreHash = 0x15;
const ALG_RSA2048SHA256_PSS_PreHash = 0x16;
const ALG_RSA2048SHA384_PSS_PreHash = 0x17;
const ALG_RSA2048SHA512_PSS_PreHash = 0x18;
const ALG_ECDSASHA1_PreHash = 0x19;
const ALG_ECDSASHA256_PreHash = 0x1a;
const ALG_ECDSASHA384_PreHash = 0x1b;
const ALG_ECDSASHA512_PreHash = 0x1c;

const PIN_FORMAT_FREE =0x00;
const PIN_FORMAT_NUMBER =0x01;
const PIN_FORMAT_LOWERCASE =0x02;
const PIN_FORMAT_HIGERCASE =0x04;
const PIN_FORMAT_SYMBOL =0x08;

const PIN_SETUP_ENG_MASK = 0xf0;
const PIN_SETUP_ENG_OK = 0x00;
const PIN_SETUP_ENG_ASK = 0x80;
const PIN_SETUP_ENG_NO = 0x40;
const PIN_SETUP_ENG_SPEC = 0xC0;

const PIN_SETUP_ENG_HIGHCASE = 0x20;
const PIN_SETUP_ENG_LOWCASE = 0x10;

const PIN_SETUP_NUM_MASK = 0x03;
const PIN_SETUP_NUM_OK = 0x00;
const PIN_SETUP_NUM_ASK = 0x01;
const PIN_SETUP_NUM_NO = 0x03;

const PIN_SETUP_SYM_MASK = 0x0C;
const PIN_SETUP_SYM_OK = 0x00;
const PIN_SETUP_SYM_ASK = 0x04;
const PIN_SETUP_SYM_NO = 0x0C;

const RSA_2048 = 1;
const EC_secp256r1 = 2;
const EC_secp384r1 = 3;
const EC_secp521r1 = 4;


const OutputType_RAW =1;
const OutputType_CSR =2;


const TOKEN_FLAGS_PINEXPIRED = 0X1;
const TOKEN_FLAGS_INITIALIZED = 0X2;

function IKPException(statusCode) {
    this.code = statusCode;
 }


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
        //console.log('WARNING: expecting an even number of characters in the hexString');
    }

    // check for some non-hex characters
    var bad = hexString.match(/[G-Z\s]/i);
    if (bad) {
        //console.log('WARNING: found non-hex characters', bad);
    }

    // split the string into pairs of octets
    var pairs = hexString.match(/[\dA-F]{2}/gi);

    // convert the octets to integers
    var integers = pairs.map(function (s) {
        return parseInt(s, 16);
    });

    var array = new Uint8Array(integers);
    ////console.log(array);

    return array;
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

async function computingSessionKey(bOldPIN, bNewPIN, ecpointXY) {

    //Convert oldPIN to sha256 value
    var oldPINHash = await crypto.subtle.digest("SHA-256", bOldPIN);
    //console.log("oldPINHash  ", oldPINHash);

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
        //console.log("sessionKeyBytes", bufToHex(sessionKeyBytes));
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

function isAllowedSymbol(value) {

    if((value>=33)&&(value<=47)){
        return true;
    }

    if((value>=58)&&(value<=64)){
        return true;
    }

    if((value>=91)&&(value<=96)){
        return true;
    }

    if((value>=123)&&(value<=126)){
        return true;
    }
    return false;
    
} 

function checkPINFormatLevel(bNewPIN, level){
    var localLevel  = 0 ; 
    if(level == PIN_FORMAT_FREE)
        return true;

    for(var i =0; i<bNewPIN.byteLength;i++){
        var value = bNewPIN[i];
        if ((value >= 48) && (value <= 57)) { //[0-9]
            localLevel |= PIN_FORMAT_NUMBER;
        }else if ((value >= 97) && (value <= 122)) {//[a-z]
            localLevel |= PIN_FORMAT_LOWERCASE;
        }else if ((value >= 65) && (value <= 90)) {//[A-Z]
            localLevel |= PIN_FORMAT_HIGERCASE;
        }else if (isAllowedSymbol(value)) {//special symbol
            localLevel |= PIN_FORMAT_SYMBOL;
        }
    }
     //check english
        switch(level&0xc0){
        
        case 0x80: //英文必要
            
            if((level&0x30)==0x00){//英文必要，大小寫都可

                if((localLevel&(PIN_FORMAT_HIGERCASE|PIN_FORMAT_LOWERCASE))==0x00){
                    return false;
                } 
            }
        
            if((level&0x30)==0x10){//英文必要，小寫必要
                if((localLevel&PIN_FORMAT_LOWERCASE)==0x00){
                    return false;
                }
            }
        
            if((level&0x30)==0x20){//英文必要，大寫必要
                if((localLevel&PIN_FORMAT_HIGERCASE)==0x00){
                    return false;
                }
            }
            
            if((level&0x30)==0x30){//英文必要，大小寫皆必要
                if((localLevel&(PIN_FORMAT_HIGERCASE|PIN_FORMAT_LOWERCASE))!=(PIN_FORMAT_HIGERCASE|PIN_FORMAT_LOWERCASE)){
                    return false;
                }
            }
            break;
        case 0x40: //英文禁止
        

            if((level&0x30)==0x30){//英文大小寫都禁止
                if((localLevel&(PIN_FORMAT_HIGERCASE|PIN_FORMAT_LOWERCASE))!=0x00){
                    return false;
                }
            }
        
            if((level&0x10)==0x10){//小寫禁止, 大寫允許
                if((localLevel&PIN_FORMAT_LOWERCASE)!=0x00){
                    return false;
                }
            }
                
            if((level&0x10)==0x20){//大寫禁止, 小寫允許
                if((localLevel&PIN_FORMAT_HIGERCASE)!=0x00){
                    return false;
                }
            }
            break;
        case 0xC0: //特殊
            if((level&0x20)==0x20){//	大寫必要，小寫禁止
                if(((localLevel&PIN_FORMAT_HIGERCASE)==0x00)||((localLevel&PIN_FORMAT_LOWERCASE)==PIN_FORMAT_LOWERCASE)){
                    return false;
                }   
            }
            
            if((level&0x10)==0x10){//		大寫禁止，小寫必要
                if(((localLevel&PIN_FORMAT_HIGERCASE)==PIN_FORMAT_HIGERCASE)||((localLevel&PIN_FORMAT_LOWERCASE)==0x00)){
                    return false;
                }     
            }
            break;
    }
    
    //check number
    switch(level&0x03){
    
        case 0x01: //樹字必要
            
            if((localLevel&PIN_FORMAT_NUMBER)!=PIN_FORMAT_NUMBER){
                return false; 
            }
            break;
        case  0x03: //樹字禁止
        
            if((localLevel&PIN_FORMAT_NUMBER)==PIN_FORMAT_NUMBER){
                    return false; 
            }
            break;
    }
    
    //check symbol
    switch(level&0x0C){
        
        case 0x04: //福號必要
            
            if((localLevel&PIN_FORMAT_SYMBOL)!=PIN_FORMAT_SYMBOL){
                    return false; 
            }
            break;
        case 0x0c: //福號禁止
        
            if((localLevel&PIN_FORMAT_SYMBOL)==PIN_FORMAT_SYMBOL){
                    return false; 
            }
            break;
    }
        
    return true;
}

function checkPINFormatLevel_V2(bNewPIN, level){
    var result = CTAP1_ERR_SUCCESS;
    var localLevel  = 0 ; 
    if(level == PIN_FORMAT_FREE)
        return result;

    for(var i =0; i<bNewPIN.byteLength;i++){
        var value = bNewPIN[i];
        if ((value >= 48) && (value <= 57)) { //[0-9]
            localLevel |= PIN_FORMAT_NUMBER;
        }else if ((value >= 97) && (value <= 122)) {//[a-z]
            localLevel |= PIN_FORMAT_LOWERCASE;
        }else if ((value >= 65) && (value <= 90)) {//[A-Z]
            localLevel |= PIN_FORMAT_HIGERCASE;
        }else if (isAllowedSymbol(value)) {//special symbol
            localLevel |= PIN_FORMAT_SYMBOL;
        }
    }
     //check english
        switch(level&0xc0){
        
        case 0x80: //英文必要
            
            if((level&0x30)==0x00){//英文必要，大小寫都可

                if((localLevel&(PIN_FORMAT_HIGERCASE|PIN_FORMAT_LOWERCASE))==0x00){
                    return SETTING_ERR_USERPIN_NEED_LETTER;
                } 
            }
        
            if((level&0x30)==0x10){//英文必要，小寫必要
                if((localLevel&PIN_FORMAT_LOWERCASE)==0x00){
                    return SETTING_ERR_USERPIN_NEED_LOWERCASE;
                }
            }
        
            if((level&0x30)==0x20){//英文必要，大寫必要
                if((localLevel&PIN_FORMAT_HIGERCASE)==0x00){
                    return SETTING_ERR_USERPIN_NEED_UPPERCASE;
                }
            }
            
            if((level&0x30)==0x30){//英文必要，大小寫皆必要
                if((localLevel&(PIN_FORMAT_HIGERCASE|PIN_FORMAT_LOWERCASE))!=(PIN_FORMAT_HIGERCASE|PIN_FORMAT_LOWERCASE)){
                    return SETTING_ERR_USERPIN_NEED_LETTER;
                }
            }
            break;
        case 0x40: //英文禁止
        

            if((level&0x30)==0x30){//英文大小寫都禁止
                if((localLevel&(PIN_FORMAT_HIGERCASE|PIN_FORMAT_LOWERCASE))!=0x00){
                    return SETTING_ERR_USERPIN_BAN_LETTER;
                }
            }
        
            if((level&0x10)==0x10){//小寫禁止, 大寫允許
                if((localLevel&PIN_FORMAT_LOWERCASE)!=0x00){
                    return SETTING_ERR_USERPIN_BAN_LOWERCASE;
                }
            }
                
            if((level&0x10)==0x20){//大寫禁止, 小寫允許
                if((localLevel&PIN_FORMAT_HIGERCASE)!=0x00){
                    return SETTING_ERR_USERPIN_BAN_UPPERCASE;
                }
            }
            break;
        case 0xC0: //特殊
            if((level&0x20)==0x20){//	大寫必要，小寫禁止
                if((localLevel&PIN_FORMAT_HIGERCASE)==0x00){
                    return SETTING_ERR_USERPIN_NEED_UPPERCASE;
                }
                
                if((localLevel&PIN_FORMAT_LOWERCASE)==PIN_FORMAT_LOWERCASE){
                    return SETTING_ERR_USERPIN_BAN_LOWERCASE;
                }   
            }
            
            if((level&0x10)==0x10){//		大寫禁止，小寫必要
                if((localLevel&PIN_FORMAT_HIGERCASE)==PIN_FORMAT_HIGERCASE){
                    return SETTING_ERR_USERPIN_BAN_UPPERCASE;
                }
                
                if((localLevel&PIN_FORMAT_LOWERCASE)==0x00){
                    return SETTING_ERR_USERPIN_NEED_LOWERCASE;
                }     
            }
            break;
    }
    
    //check number
    switch(level&0x03){
    
        case 0x01: //樹字必要
            
            if((localLevel&PIN_FORMAT_NUMBER)!=PIN_FORMAT_NUMBER){
                return SETTING_ERR_USERPIN_NEED_NUMBER; 
            }
            break;
        case  0x03: //樹字禁止
        
            if((localLevel&PIN_FORMAT_NUMBER)==PIN_FORMAT_NUMBER){
                    return SETTING_ERR_USERPIN_BAN_NUMBER; 
            }
            break;
    }
    
    //check symbol
    switch(level&0x0C){
        
        case 0x04: //符號必要
            
            if((localLevel&PIN_FORMAT_SYMBOL)!=PIN_FORMAT_SYMBOL){
                    return SETTING_ERR_USERPIN_NEED_SYMBOL; 
            }
            break;
        case 0x0c: //符號禁止
        
            if((localLevel&PIN_FORMAT_SYMBOL)==PIN_FORMAT_SYMBOL){
                    return SETTING_ERR_USERPIN_BAN_SYMBOL; 
            }
            break;
    }
        
    return result;
}

/**
 * 檢查初始化參數是否符合標準
 */
function GTIDEM_isValidTokenParams(bInitToken, commandType){
    var InitData ;
    let gtidem = new GTIdemJs();
    gtidem.statusCode = CTAP1_ERR_SUCCESS
    try{
        InitData = (CBOR.decode(bInitToken.buffer));
    }catch(e){
        gtidem.statusCode = SETTING_ERR_CBOR_PARSING
        return gtidem;
    }
     
    if(commandType===CMD_INIT_TOKEN){
        //check must params
        var pinExpired = false

        if(InitData['pinExpired']!=undefined){
            pinExpired = InitData['pinExpired'];
            if (typeof pinExpired !== 'boolean') {
                gtidem.statusCode = SETTING_ERR_CBOR_UNEXPECTED_TYPE
                return gtidem;;
            }
        }else{
            gtidem.statusCode =  CTAP2_ERR_MISSING_PARAMETER
            return gtidem;;
        }

        if(InitData['soPIN']!=undefined){
            if(InitData['soPIN'].byteLength> TOKEN_MAX_SOPIN_LEN){
                gtidem.statusCode =  SETTING_ERR_SOPIN_LEN_TOO_LONG
                return gtidem;;
            }

            if((InitData['soPIN'].byteLength < TOKEN_MIN_SOPIN_LEN)){
                gtidem.statusCode =  SETTING_ERR_SOPIN_LEN_TOO_SHORT
                return gtidem;;
            }
            
        }else{
            gtidem.statusCode =  CTAP2_ERR_MISSING_PARAMETER
            return gtidem;;
        }

        if(InitData['userPIN']!=undefined){
            if(InitData['userPIN'].byteLength< TOKEN_MIN_PIN_LEN){
                gtidem.statusCode =  SETTING_ERR_USERPIN_LEN_TOO_SHORT
                return gtidem;;
            }

            if((InitData['userPIN'].byteLength > TOKEN_MAX_PIN_LEN)){
                gtidem.statusCode =   SETTING_ERR_USERPIN_LEN_TOO_LONG
                return gtidem;;
            }
        }else{
            gtidem.statusCode =  CTAP2_ERR_MISSING_PARAMETER
            return;
        }

        if(InitData['allowedRPID']!=undefined){
            if((InitData['allowedRPID'].byteLength%8)!=0){
                gtidem.statusCode =  SETTING_ERR_INVAILD_DOMAINS
                return;
            }
        }else{
            gtidem.statusCode =  CTAP2_ERR_MISSING_PARAMETER
            return gtidem;;
        }

        if(InitData['pinLevel']!=undefined){
            if(InitData['pinLevel']==PIN_FORMAT_FREE){
                gtidem.statusCode = SETTING_ERR_USERPIN_ALLOW_ALL
                return gtidem;;
            }
            if(InitData['pinLevel']==(PIN_SETUP_ENG_NO|PIN_SETUP_ENG_HIGHCASE|PIN_SETUP_ENG_LOWCASE|PIN_SETUP_NUM_NO|PIN_SETUP_SYM_NO)){
                gtidem.statusCode = SETTING_ERR_USERPIN_REJECT_ALL
                return gtidem;;
            }
            
        }else{
            gtidem.statusCode = CTAP2_ERR_MISSING_PARAMETER
            return gtidem;;
        }

        if(InitData['pinRetry']!=undefined){
            if((InitData['pinRetry']==0)||(InitData['pinRetry']>15)){
                gtidem.statusCode = SETTING_ERR_INVAILD_USERPIN_RETRY
                return gtidem;;
            }
        }else{
            gtidem.statusCode = CTAP2_ERR_MISSING_PARAMETER
            return gtidem;;
        }

        if(InitData['pinMinLen']!=undefined){
            if((InitData['pinMinLen']< TOKEN_MIN_PIN_LEN )||(InitData['pinMinLen']> TOKEN_MAX_PIN_LEN )){
                gtidem.statusCode = SETTING_ERR_INVAILD_USERPIN_MIN_LEN
                return gtidem;;
            }
        }else{
            gtidem.statusCode = CTAP2_ERR_MISSING_PARAMETER
            return gtidem;;
        }
        return gtidem;
    }else if(commandType===CMD_UNLOCK_PIN){
        var pinExpired = false

        if(InitData['pinExpired']!=undefined){
            pinExpired = InitData['pinExpired'];
            if (typeof pinExpired !== 'boolean') {
                gtidem.statusCode = SETTING_ERR_CBOR_UNEXPECTED_TYPE
                return gtidem;;
            }
        }else{
            gtidem.statusCode = CTAP2_ERR_MISSING_PARAMETER
            return gtidem;;
        }

        if(InitData['userPIN']!=undefined){
            if(InitData['userPIN'].byteLength<TOKEN_MIN_PIN_LEN){
                gtidem.statusCode = SETTING_ERR_USERPIN_LEN_TOO_SHORT
                return gtidem;;
            }

            if((InitData['userPIN'].byteLength>TOKEN_MAX_PIN_LEN)){
                gtidem.statusCode = SETTING_ERR_USERPIN_LEN_TOO_LONG
                return gtidem;;
            }
        }else{
            gtidem.statusCode = CTAP2_ERR_MISSING_PARAMETER
            return gtidem;
        }
        return gtidem;
    } 
}


/**
 * 判別新密碼是否符合載具的密碼要求。
 * @param {Uint8Array} bNewPIN 新的使用者密碼
 * @param {Uint8Array} bPinFlag 載具的密碼參數，由 GTIDEM_GetTokenInfo 的 flags 取得
 */
 function GTIDEM_isValidPIN(bNewPIN, bPinFlag){

    if ((bNewPIN.length < bPinFlag[2]) || (bNewPIN.length > bPinFlag[3])) {
        return false;
    }
    if (!checkPINFormatLevel(bNewPIN, bPinFlag[1])) {
        return false;
    }

    return true;
}

/**
 * 判別新密碼是否符合載具的密碼要求。
 * @param {Uint8Array} bNewPIN 新的使用者密碼
 * @param {Uint8Array} bPinFlag 載具的密碼參數，由 GTIDEM_GetTokenInfo 的 flags 取得
 */
 function GTIDEM_isValidPIN_V2(bNewPIN, bPinFlag){


    let gtidem = new GTIdemJs();
    gtidem.statusCode = CTAP1_ERR_SUCCESS

   
    if (bNewPIN.length < bPinFlag[2]){
        gtidem.statusCode = IKP_ERR_SETTING_USERPIN_LEN;
    }else if(bNewPIN.length > bPinFlag[3]){
        gtidem.statusCode = IKP_ERR_SETTING_USERPIN_LEN;
    }else{
        gtidem.statusCode = checkPINFormatLevel_V2(bNewPIN, bPinFlag[1]);
    }
    
    return gtidem;

}


/**
 * 修改使用者密碼。
 * @param {Uint8Array} bOldPIN 舊密碼
 * @param {Uint8Array} bNewPIN 新密碼
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @returns 
 */

 async function GTIDEM_GenPINParams(bSerialNumber, bOldPIN, bNewPIN) {


    var gtidem = await GTIDEM_GetTokenInfo(bSerialNumber).then((fido) => {
        return fido;
    });

    if(gtidem.statusCode != CTAP1_ERR_SUCCESS){
        return gtidem;
    }

    if(gtidem.pinRetry == 0){
        gtidem.statusCode = CTAP2_ERR_PIN_BLOCKED;
        return gtidem;
    }
    var bECPointFromToken = gtidem.ecpoint;
    var flags = gtidem.flags;
    if((JSON.stringify(bOldPIN)==JSON.stringify(bNewPIN))){
        gtidem.statusCode = SETTING_ERR_USERPIN_SAME;
        return gtidem;
    }
    if(flags!=undefined){

        var statusCode = checkPINFormatLevel_V2(bNewPIN, flags[1])
        if(statusCode!=CTAP1_ERR_SUCCESS){
            gtidem.statusCode = statusCode;
            return gtidem;
        }
        if (bNewPIN.length < flags[2]){
            gtidem.statusCode = SETTING_ERR_USERPIN_LEN_TOO_SHORT
            return gtidem;
        }
        if(bNewPIN.length > flags[3]){
            gtidem.statusCode = SETTING_ERR_USERPIN_LEN_TOO_LONG
            return gtidem;
        }
    }else{
        gtidem.statusCode = WEB_ERR_OperationAbort;
        return gtidem;
    }
    var pinParams = await computingSessionKey(bOldPIN, bNewPIN, bECPointFromToken);
    //return prepareUpdate.bExportECPublicKeyArray, prepareUpdate.bEcryptedOldPINHash,prepareUpdate.bEncryptedNEWPIN;

    gtidem.statusCode = CTAP1_ERR_SUCCESS;
    gtidem.encOldPINHashed = pinParams.bEcryptedOldPINHash;
    gtidem.encNewPIN = pinParams.bEncryptedNEWPIN;
    gtidem.hostEcpoint = pinParams.bExportECPublicKeyArray;

    return gtidem;
}

/**
 * 修改使用者密碼。
 * @param {Uint8Array} bOldPIN 舊密碼
 * @param {Uint8Array} bNewPIN 新密碼
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @returns 
 */
 async function GTIDEM_ChangeUserPINwithInterval(bOldPIN, bNewPIN, bSerialNumber, callback) {

    var prepareUpdate = undefined;
    var result = undefined;
    // var gtidem = await GTIDEM_GetTokenInfo(bSerialNumber).then((fido) => {
    //     return fido;
    // });
    var gtidem = await GTIDEM_GetTokenInfo(bSerialNumber);

    if(gtidem.statusCode != CTAP1_ERR_SUCCESS){
        if(callback!=undefined)
            callback(gtidem);
        return gtidem;
    }

    if(gtidem.pinRetry == 0){
        gtidem.statusCode = CTAP2_ERR_PIN_BLOCKED;
        if(callback!=undefined)
            callback(gtidem);
        return gtidem;
    }
    var bECPointFromToken = gtidem.ecpoint;
    var flags = gtidem.flags;
    if((JSON.stringify(bOldPIN)==JSON.stringify(bNewPIN))){
        gtidem.statusCode = SETTING_ERR_USERPIN_SAME;
        if(callback!=undefined)
            callback(gtidem);
        return gtidem;
    }
    if(flags!=undefined){

        var statusCode = checkPINFormatLevel_V2(bNewPIN, flags[1])
        if(statusCode!=CTAP1_ERR_SUCCESS){
            gtidem.statusCode = statusCode;
            if(callback!=undefined)
            callback(gtidem);
        return gtidem;
        }
        if (bNewPIN.length < flags[2]){
            gtidem.statusCode = SETTING_ERR_USERPIN_LEN_TOO_SHORT
            if(callback!=undefined)
            callback(gtidem);
        return gtidem;
        }
        if(bNewPIN.length > flags[3]){
            gtidem.statusCode = SETTING_ERR_USERPIN_LEN_TOO_LONG
            if(callback!=undefined)
            callback(gtidem);
        return gtidem;
        }
    }else{
        gtidem.statusCode = WEB_ERR_OperationAbort;
       
        if(callback!=undefined)
            callback(gtidem);
        return gtidem;
    }

    // let timer_id = setInterval(  async  function () {
    //     console.log("setInterval start:",new Date().getTime());
    //     if(prepareUpdate==undefined){
    //         return;
    //     }
    //     console.log("Has focuse?: "+document.hasFocus());
    //     console.log("Who Has focuse: "+document.activeElement);
    //     console.log("Who Has focuse: "+document.activeElement.className);
    //     console.log("Who Has focuse: "+document.activeElement.id);
    //     if(!document.hasFocus()){
    //         document.activeElement.blur();
    //         window.focus();
    //         console.log("After focused?: "+document.hasFocus());
    //     }
    //     clearInterval(timer_id); 
    //     await GTIDEM_ChangeUserPIN_V1(bSerialNumber, prepareUpdate.bExportECPublicKeyArray, prepareUpdate.bEcryptedOldPINHash,prepareUpdate.bEncryptedNEWPIN).then((result) => {
          
    //         if(callback!=undefined)
    //             callback(result);
    //         return result;
    //     });
   
    // }, 100);
    //Generate 
    console.log("computingSessionKey:",new Date().getTime());
    prepareUpdate = await computingSessionKey(bOldPIN, bNewPIN, bECPointFromToken);
    console.log("computingSessionKey OK:",new Date().getTime());
    console.log("2.Has focuse?: "+document.hasFocus());
    console.log("2.Who Has focuse: "+document.activeElement);
    console.log("2.Who Has focuse: "+document.activeElement.className);
    console.log("2.Who Has focuse: "+document.activeElement.id);
    if(!document.hasFocus()){
        //document.activeElement.blur();
        //window.focus();
        console.log("2.After focused?: "+document.hasFocus());
    }

    let timer_id = setInterval(  async  function () {
        console.log("setInterval start:",new Date().getTime());
        if(prepareUpdate==undefined){
            return;
        }
        console.log("1.Has focuse?: "+document.hasFocus());
        console.log("1.Who Has focuse: "+document.activeElement);
        console.log("1.Who Has focuse: "+document.activeElement.className);
        console.log("1.Who Has focuse: "+document.activeElement.id);
        if(!document.hasFocus()){
            //document.activeElement.blur();
            //window.focus();
            console.log("1.After focused?: "+document.hasFocus());
        }
        clearInterval(timer_id); 
        await GTIDEM_ChangeUserPIN_V1(bSerialNumber, prepareUpdate.bExportECPublicKeyArray, prepareUpdate.bEcryptedOldPINHash,prepareUpdate.bEncryptedNEWPIN).then((result) => {
          
            if(callback!=undefined)
                callback(result);
            return result;
        });
   
    }, 150);
    
}

/**
 * 修改使用者密碼。
 * @param {Uint8Array} bOldPIN 舊密碼
 * @param {Uint8Array} bNewPIN 新密碼
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @returns 
 */
 async function GTIDEM_ChangeUserPIN(bOldPIN, bNewPIN, bSerialNumber, callback) {


    var browser=get_browser(); // browser.name = 'Chrome'
    if((browser.name=="Safari")&&(parseInt(browser.major)>=15)){

        return await GTIDEM_ChangeUserPINwithInterval(bOldPIN, bNewPIN, bSerialNumber,callback);
    }else{
        var gtidem = await GTIDEM_GetTokenInfo(bSerialNumber);

        if(gtidem.statusCode != CTAP1_ERR_SUCCESS){
            if(callback!=undefined)
                    callback(gtidem);
            return gtidem;
        }

        if(gtidem.pinRetry == 0){
            gtidem.statusCode = CTAP2_ERR_PIN_BLOCKED;
            if(callback!=undefined)
                    callback(gtidem);
            return gtidem;
        }
        var bECPointFromToken = gtidem.ecpoint;
        var flags = gtidem.flags;
        if((JSON.stringify(bOldPIN)==JSON.stringify(bNewPIN))){
            gtidem.statusCode = SETTING_ERR_USERPIN_SAME;
            if(callback!=undefined)
                    callback(gtidem);
                return gtidem;
        }
        if(flags!=undefined){

            var statusCode = checkPINFormatLevel_V2(bNewPIN, flags[1])
            if(statusCode!=CTAP1_ERR_SUCCESS){
                gtidem.statusCode = statusCode;
                if(callback!=undefined)
                    callback(gtidem);
                return gtidem;
            }
            if (bNewPIN.length < flags[2]){
                gtidem.statusCode = SETTING_ERR_USERPIN_LEN_TOO_SHORT
                if(callback!=undefined)
                    callback(gtidem);
                return gtidem;
            }
            if(bNewPIN.length > flags[3]){
                gtidem.statusCode = SETTING_ERR_USERPIN_LEN_TOO_LONG
                if(callback!=undefined)
                    callback(gtidem);
                return gtidem;
            }
        }else{
            gtidem.statusCode = WEB_ERR_OperationAbort;
            return gtidem;
        }
        var prepareUpdate = await computingSessionKey(bOldPIN, bNewPIN, bECPointFromToken);
        return await GTIDEM_ChangeUserPIN_V1(bSerialNumber, prepareUpdate.bExportECPublicKeyArray, prepareUpdate.bEcryptedOldPINHash,prepareUpdate.bEncryptedNEWPIN).then((response) => {
                if(callback!=undefined)
                    callback(response);
                return response;
            });
    }
    

}

/**
 * 修改使用者密碼，使用PINProtocolV1 保護資料
 * @param {Uint8Array} bOldPIN 舊密碼
 * @param {Uint8Array} bNewPIN 新密碼
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @returns 
 */
 async function GTIDEM_ChangeUserPIN_V1(bSerialNumber, bECPoint,bEcryptedOldPINHash,bEncryptedNEWPIN) {

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
   var ecpubkey_buf = new Uint8Array(4 + bECPoint.byteLength);
   ecpubkey_buf[0] = 0xDF;
   ecpubkey_buf[1] = 0x04;
   ecpubkey_buf[2] = bECPoint.byteLength >> 8;
   ecpubkey_buf[3] = bECPoint.byteLength;
   ecpubkey_buf.set(new Uint8Array(bECPoint), 4);

   var encryptedOldPINHash_buf = new Uint8Array(4 +bEcryptedOldPINHash.byteLength);
   encryptedOldPINHash_buf[0] = 0xDF;
   encryptedOldPINHash_buf[1] = 0x05;
   encryptedOldPINHash_buf[2] = bEcryptedOldPINHash.byteLength >> 8;
   encryptedOldPINHash_buf[3] = bEcryptedOldPINHash.byteLength;
   encryptedOldPINHash_buf.set(new Uint8Array(bEcryptedOldPINHash), 4);
  
   var encryptedNewPIN_buf = new Uint8Array(4 + bEncryptedNEWPIN.byteLength);
   encryptedNewPIN_buf[0] = 0xDF;
   encryptedNewPIN_buf[1] = 0x07;
   encryptedNewPIN_buf[2] = bEncryptedNEWPIN.byteLength >> 8;
   encryptedNewPIN_buf[3] = bEncryptedNEWPIN.byteLength;
   encryptedNewPIN_buf.set(new Uint8Array(bEncryptedNEWPIN), 4);


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



   //console.log("Change_pin_command: " + bufToHex(pki_buffer));

   var getAssertionChallenge = {
       'challenge': challenge,
       "userVerification": "discouraged",
       timeout: DEFAULT_TIMEOUT, 
       
   }
   var idList = [{
       id: pki_buffer,
       type: "public-key",
       transports:AUTHENTICATOR_TRANSPORTS
   }];

   getAssertionChallenge.allowCredentials = idList;
   //console.log('List getAssertionChallenge', getAssertionChallenge)
   ////console.log("GTIDEM_ChangeUserPIN_V1:",new Date().getTime());
   return await navigator.credentials.get({
       'publicKey': getAssertionChallenge
   }).then((fido) => {
           
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_CHANGE_PIN);
        return gtidem;
    }).catch((error) => {
        ////console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
        return gtidem;
    });

}

async function GTIDEM_GenP256CSR(bSerialNumber,bCommonName){


   var challenge = new Uint8Array(32);
   window.crypto.getRandomValues(challenge);

   var commonName_buf;
   if((bCommonName==undefined)||(bCommonName.byteLength==0)){

    commonName_buf = new Uint8Array(0);
    }else{
        commonName_buf = new Uint8Array(4 + bCommonName.byteLength);
        commonName_buf[0] = 0xDF;
        commonName_buf[1] = 0x26;
        commonName_buf[2] = bCommonName.byteLength >> 8;
        commonName_buf[3] = bCommonName.byteLength;
        commonName_buf.set(bCommonName, 4);
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
	
   if((sn_buf.byteLength+commonName_buf.byteLength)>45){ //over buffer length
        let gtidem = new GTIdemJs();
        gtidem.statusCode = SETTING_ERR_OVER_BUFFER_LENGTH;
        return gtidem;
    }

    if((commonName_buf.byteLength)>44){ //over buffer length
        let gtidem = new GTIdemJs();
        gtidem.statusCode = SETTING_ERR_OVER_BUFFER_LENGTH;
        return gtidem;
    }
   var payloadLen = commonName_buf.byteLength+sn_buf.byteLength

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_REQUESTP256CSR;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,commonName_buf);

   var webauth_request = {
        'challenge': challenge,

        'rp': {
            'name': 'GoTrustID Inc.',
        },

        'user': {
            'id': pki_buffer,
            'name': sUserName,
            'displayName': sUserName,
        },

        "authenticatorSelection": {
            "userVerification": "required",
            "requireResidentKey": false,
            "residentKey": "discouraged",
            "authenticatorAttachment": "cross-platform"

        },
        timeout: VERIFY_DEFAULT_TIMEOUT, 
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
   //console.log('webauth_request', webauth_request)

   return await navigator.credentials.create({
        'publicKey': webauth_request
    }).then((fido) => {

        let attestationObject = CBOR.decode(fido.response.attestationObject);
        let authData = parseAuthData(attestationObject.authData);
        let credID = authData.credID;
        let bPKIoverFIDOResponse= credID.buffer.slice(credID.byteOffset, credID.byteLength + credID.byteOffset);

        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(bPKIoverFIDOResponse,CMD_REQUESTCSR);
        // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
        //     gtidem.sn =token_sn;
        // }
        return gtidem;
    }).catch((error) => {
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
        return gtidem;
    });

}

async function GTIDEM_GenP384CSR(bSerialNumber,bCommonName){


   var challenge = new Uint8Array(32);
   window.crypto.getRandomValues(challenge);

   var commonName_buf;
   if((bCommonName==undefined)||(bCommonName.byteLength==0)){

    commonName_buf = new Uint8Array(0);
    }else{
        commonName_buf = new Uint8Array(4 + bCommonName.byteLength);
        commonName_buf[0] = 0xDF;
        commonName_buf[1] = 0x26;
        commonName_buf[2] = bCommonName.byteLength >> 8;
        commonName_buf[3] = bCommonName.byteLength;
        commonName_buf.set(bCommonName, 4);
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
    
   if((sn_buf.byteLength+commonName_buf.byteLength)>45){ //over buffer length
        let gtidem = new GTIdemJs();
        gtidem.statusCode = SETTING_ERR_OVER_BUFFER_LENGTH;
        return gtidem;
   }

   if((commonName_buf.byteLength)>44){ //over buffer length
        let gtidem = new GTIdemJs();
        gtidem.statusCode = SETTING_ERR_OVER_BUFFER_LENGTH;
        return gtidem;
    }
   var payloadLen = commonName_buf.byteLength+sn_buf.byteLength

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_REQUESTP384CSR;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,commonName_buf);

   var webauth_request = {
        'challenge': challenge,

        'rp': {
            'name': 'GoTrustID Inc.',
        },

        'user': {
            'id': pki_buffer,
            'name': sUserName,
            'displayName': sUserName,
        },

        "authenticatorSelection": {
            "userVerification": "required",
            "requireResidentKey": false,
            "residentKey": "discouraged",
            "authenticatorAttachment": "cross-platform"

        },
        timeout: VERIFY_DEFAULT_TIMEOUT, 
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
   //console.log('webauth_request', webauth_request)

   return await navigator.credentials.create({
        'publicKey': webauth_request
    }).then((fido) => {

        let attestationObject = CBOR.decode(fido.response.attestationObject);
        let authData = parseAuthData(attestationObject.authData);
        let credID = authData.credID;
        let bPKIoverFIDOResponse= credID.buffer.slice(credID.byteOffset, credID.byteLength + credID.byteOffset);

        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(bPKIoverFIDOResponse,CMD_REQUESTCSR);
        // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
        //     gtidem.sn =token_sn;
        // }
        return gtidem;
    }).catch((error) => {
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
        return gtidem;
    });

}

async function GTIDEM_GenP521CSR(bSerialNumber,bCommonName){


   var challenge = new Uint8Array(32);
   window.crypto.getRandomValues(challenge);

   var commonName_buf;
   if((bCommonName==undefined)||(bCommonName.byteLength==0)){

    commonName_buf = new Uint8Array(0);
    }else{
        commonName_buf = new Uint8Array(4 + bCommonName.byteLength);
        commonName_buf[0] = 0xDF;
        commonName_buf[1] = 0x26;
        commonName_buf[2] = bCommonName.byteLength >> 8;
        commonName_buf[3] = bCommonName.byteLength;
        commonName_buf.set(bCommonName, 4);
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
	
   if((sn_buf.byteLength+commonName_buf.byteLength)>45){ //over buffer length
        let gtidem = new GTIdemJs();
        gtidem.statusCode = SETTING_ERR_OVER_BUFFER_LENGTH;
        return gtidem;
    }

    if((commonName_buf.byteLength)>44){ //over buffer length
        let gtidem = new GTIdemJs();
        gtidem.statusCode = SETTING_ERR_OVER_BUFFER_LENGTH;
        return gtidem;
    }
   var payloadLen = commonName_buf.byteLength+sn_buf.byteLength

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_REQUESTP521CSR;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,commonName_buf);

   var webauth_request = {
        'challenge': challenge,

        'rp': {
            'name': 'GoTrustID Inc.',
        },

        'user': {
            'id': pki_buffer,
            'name': sUserName,
            'displayName': sUserName,
        },

        "authenticatorSelection": {
            "userVerification": "required",
            "requireResidentKey": false,
            "residentKey": "discouraged",
            "authenticatorAttachment": "cross-platform"

        },
        timeout: VERIFY_DEFAULT_TIMEOUT, 
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
   //console.log('webauth_request', webauth_request)

   return await navigator.credentials.create({
        'publicKey': webauth_request
    }).then((fido) => {

        let attestationObject = CBOR.decode(fido.response.attestationObject);
        let authData = parseAuthData(attestationObject.authData);
        let credID = authData.credID;
        let bPKIoverFIDOResponse= credID.buffer.slice(credID.byteOffset, credID.byteLength + credID.byteOffset);

        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(bPKIoverFIDOResponse,CMD_REQUESTCSR);
        // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
        //     gtidem.sn =token_sn;
        // }
        return gtidem;
    }).catch((error) => {
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
        return gtidem;
    });
}

/**
 * 產生 RSA 2048 金鑰對，會組合成 CSR 格式回傳
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @param {Uint8Array｜undefined} bKeyID 用來關聯金鑰對，若是不替換則填入 undefined 或是空陣列。若不使用 KeyID,則載具會產生預設的 KeyHandle。
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_GenRSA2048CSR(bSerialNumber,bCommonName) {

   
   //var bKeyID = toUTF8Array(keyID);

   var challenge = new Uint8Array(32);
   window.crypto.getRandomValues(challenge);

   var commonName_buf;
   if((bCommonName==undefined)||(bCommonName.byteLength==0)){

    commonName_buf = new Uint8Array(0);
    }else{
        commonName_buf = new Uint8Array(4 + bCommonName.byteLength);
        commonName_buf[0] = 0xDF;
        commonName_buf[1] = 0x26;
        commonName_buf[2] = bCommonName.byteLength >> 8;
        commonName_buf[3] = bCommonName.byteLength;
        commonName_buf.set(bCommonName, 4);
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
	
   if((sn_buf.byteLength+commonName_buf.byteLength)>45){ //over buffer length
        let gtidem = new GTIdemJs();
        gtidem.statusCode = SETTING_ERR_OVER_BUFFER_LENGTH;
        return gtidem;
    }

    if((commonName_buf.byteLength)>44){ //over buffer length
        let gtidem = new GTIdemJs();
        gtidem.statusCode = SETTING_ERR_OVER_BUFFER_LENGTH;
        return gtidem;
    }


   var payloadLen = commonName_buf.byteLength+sn_buf.byteLength

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_REQUESTCSR;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,commonName_buf);
  



   //console.log("Request_command: " + bufToHex(pki_buffer));

   var webauth_request = {
    'challenge': challenge,

    'rp': {
        'name': 'GoTrustID Inc.',
    },

    'user': {
        'id': pki_buffer,
        'name': sUserName,
        'displayName': sUserName,
    },
    "authenticatorSelection": {
        "userVerification": "required",
        "requireResidentKey": false,
        "residentKey": "discouraged",
        "authenticatorAttachment": "cross-platform"

    },
    "timeout": VERIFY_DEFAULT_TIMEOUT, 
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
   //console.log('webauth_request', webauth_request)

   return await navigator.credentials.create({
        'publicKey': webauth_request
    }).then((fido) => {

        let attestationObject = CBOR.decode(fido.response.attestationObject);
        let authData = parseAuthData(attestationObject.authData);
        let credID = authData.credID;
        let bPKIoverFIDOResponse= credID.buffer.slice(credID.byteOffset, credID.byteLength + credID.byteOffset);

        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(bPKIoverFIDOResponse,CMD_REQUESTCSR);
        // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
        //     gtidem.sn =token_sn;
        // }
        return gtidem;
    }).catch((error) => {
        console.log(error)
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
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
	// var token_sn = undefined;
    // if((bSerialNumber==undefined)||(bSerialNumber.byteLength==0)){
    //     var gtidem = await GTIDEM_GetTokenInfo(bSerialNumber).then((fido) => {
    //         return fido;
    //    });
    //    if(gtidem.statusCode != CTAP1_ERR_SUCCESS){
    //        return gtidem;
    //    }else{
    //        token_sn = new Uint8Array(gtidem.sn);
    //    }
    // }else{
    //     token_sn =  new Uint8Array(bSerialNumber);
    // }

    // sn_buf = new Uint8Array(4 + token_sn.byteLength);
    // sn_buf[0] = 0xDF;
    // sn_buf[1] = 0x20;
    // sn_buf[2] = token_sn.byteLength >> 8;
    // sn_buf[3] = token_sn.byteLength;
    // sn_buf.set(token_sn, 4);


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
   
 
 
 
    //console.log("Request_command: " + bufToHex(pki_buffer));
 
    var webauth_request = {
     'challenge': challenge,
 
     'rp': {
         'name': 'GoTrustID Inc.',
     },
 
     'user': {
         'id': pki_buffer,
         'name': sUserName,
         'displayName': sUserName,
     },
 
     "authenticatorSelection": {
         "userVerification": "required",
         "requireResidentKey": false,
         "residentKey": "discouraged",
         "authenticatorAttachment": "cross-platform"
 
     },
     timeout: VERIFY_DEFAULT_TIMEOUT, 
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
    //console.log('webauth_request', webauth_request)
 
    return await navigator.credentials.create({
         'publicKey': webauth_request
     }).then((fido) => {
           
        let attestationObject = CBOR.decode(fido.response.attestationObject);
        let authData = parseAuthData(attestationObject.authData);
        let credID = authData.credID;
        let bPKIoverFIDOResponse= credID.buffer.slice(credID.byteOffset, credID.byteLength + credID.byteOffset);

        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(bPKIoverFIDOResponse,CMD_GenRsaKeyPair);
        // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
        //     gtidem.sn =token_sn;
        // }

        return gtidem;
    }).catch((error) => {
        ////console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
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


    var browser = get_browser(); // browser.name = 'Chrome'
     if((browser.name=="Safari")&&(parseInt(browser.major)>=15)){ //only for sarari 15+
        return await GTIDEM_ImportCertificate2(bSerialNumber, keyHandle, keyID, HexCert, bPlain);
    } else {

        var bKeyID = keyID;
        var bKeyHandle = keyHandle;
        var bHexCert = HexCert;
       
    
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

    

    //console.log("Import request_command: " + bufToHex(pki_buffer));

    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "required",
        timeout: VERIFY_DEFAULT_TIMEOUT, 
        }
        var idList = [{
            id: pki_buffer,
            type: "public-key",
            transports:AUTHENTICATOR_TRANSPORTS
        }];

        getAssertionChallenge.allowCredentials = idList;
        //console.log('List getAssertionChallenge', getAssertionChallenge)

        return await navigator.credentials.get({
            'publicKey': getAssertionChallenge
        }).then((fido) => {
            
            let gtidem = new GTIdemJs();
            gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_ImportCertificate);
            // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
            //     gtidem.sn =token_sn;
            // }
            return gtidem;
        }).catch((error) => {
            ////console.log(error.name);
            let gtidem = new GTIdemJs();
            gtidem.ConvertWebError(error.name,error.message);
            return gtidem;
        });
    }

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
 async function GTIDEM_ImportCertificate2(bSerialNumber,keyHandle,keyID,HexCert, bPlain) {


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
 
   var pki_cmd = new Uint8Array(3);
   pki_cmd[0] = CMD_ImportCertificate2;
   pki_cmd[1] = 0x00
   pki_cmd[2] = 0x00;
   var pki_cmdBuffer = _appendBuffer(gtheaderbuffer,pki_cmd);



   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_ImportCertificate2;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,keyid_buf);
   pki_buffer = _appendBuffer(pki_buffer,keyhandle_buf);
   pki_buffer = _appendBuffer(pki_buffer,hexCert_buf);
   pki_buffer = _appendBuffer(pki_buffer,signDataBuf);

   
   var webauth_request = {
        'challenge': challenge,

        'rp': {
            'name': 'GoTrustID Inc.',
        },

        'user': {
            'id': pki_cmdBuffer,
            'name': sUserName,
            'displayName': sUserName,
        },
        timeout: VERIFY_DEFAULT_TIMEOUT, 
        "authenticatorSelection": {
            "userVerification": "required",
            "requireResidentKey": false,
            "residentKey": "discouraged",
            "authenticatorAttachment": "cross-platform"

        },
        "excludeCredentials": [
            {"id": pki_buffer, "type": "public-key"}
        ],
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
    return await navigator.credentials.create({
        'publicKey': webauth_request
    }).then((fido) => {
        let attestationObject = CBOR.decode(fido.response.attestationObject);
        let authData = parseAuthData(attestationObject.authData);
        let credID = authData.credID;
        let bPKIoverFIDOResponse= credID.buffer.slice(credID.byteOffset, credID.byteLength + credID.byteOffset);

        
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(bPKIoverFIDOResponse,CMD_ImportCertificate);
      
        return gtidem;
    }).catch((error) => {
        ////console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
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
   

   //console.log("Delete cert by label request_command: " + bufToHex(pki_buffer));


    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "required",
        timeout: VERIFY_DEFAULT_TIMEOUT, 
    }
    var idList = [{
        id: pki_buffer,
        type: "public-key",
        transports:AUTHENTICATOR_TRANSPORTS
    }];

    getAssertionChallenge.allowCredentials = idList;
    //console.log('DeleteCertByLabel', getAssertionChallenge)


    return  await navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_DELEE_CERT);
        // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
        //     gtidem.sn =token_sn;
        // }
        return gtidem;
    }).catch((error) => {
        ////console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
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

   //console.log("Clear Token equest_command: " + bufToHex(pki_buffer));


    var getAssertionChallenge = {
        'challenge': challenge,  
        "userVerification": "required",
        timeout: VERIFY_DEFAULT_TIMEOUT, 

    }
    var idList = [{
        id: pki_buffer,
        type: "public-key",
        transports:AUTHENTICATOR_TRANSPORTS
    }];

    getAssertionChallenge.allowCredentials = idList;
    //console.log('DeleteCertByIndex', getAssertionChallenge)


    return  await navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_CLEAR_TOKEN);
        // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
        //     gtidem.sn =token_sn;
        // }
        return gtidem;
    }).catch((error) => {
        ////console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
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

    ////console.log("GetTokenInfo", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "discouraged",
        timeout: DEFAULT_TIMEOUT,  
    }
    var idList = [{
        id: pki_buffer,
        type: "public-key",
        transports:AUTHENTICATOR_TRANSPORTS
    }];

    getAssertionChallenge.allowCredentials = idList;
   ////('GetTokenInfo', getAssertionChallenge);

    return await navigator.credentials.get({
            'publicKey': getAssertionChallenge
        }).then((fido) => {
           
            let gtidem = new GTIdemJs();
            gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_TokenInfo);
            return gtidem;
        }).catch((error) => {
            ////console.log(error.name);
            let gtidem = new GTIdemJs();
            gtidem.ConvertWebError(error.name,error.message);
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

    //check Hash Data Length
   
//     const ALG_RSA2048SHA1_PreHash = 0x11;
// const ALG_RSA2048SHA256_PreHash = 0x12;
// const ALG_RSA2048SHA384_PreHash = 0x13;
// const ALG_RSA2048SHA512_PreHash = 0x14;
// const ALG_RSA2048SHA1_PSS_PreHash = 0x15;
// const ALG_RSA2048SHA256_PSS_PreHash = 0x16;
// const ALG_RSA2048SHA384_PSS_PreHash = 0x17;
// const ALG_RSA2048SHA512_PSS_PreHash = 0x18;

        
    /*if(alg_number==ALG_RSA2048SHA256){
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

    }else{*/

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
    //}


    
    var pki_payload_length = sn_buf.byteLength+command_buf.byteLength + alg_buf.byteLength + signDataBuf.byteLength;

    pki_header[0] = CMD_Sign;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;

    var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
    pki_buffer = _appendBuffer(pki_buffer,sn_buf);
    pki_buffer = _appendBuffer(pki_buffer,command_buf);
    pki_buffer = _appendBuffer(pki_buffer,alg_buf);
    pki_buffer = _appendBuffer(pki_buffer,signDataBuf);
    
    
    //console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "required",
        timeout: VERIFY_DEFAULT_TIMEOUT, 
        

    }
    var idList = [{
        id: pki_buffer,
        type: "public-key",
        transports:AUTHENTICATOR_TRANSPORTS
    }];

    getAssertionChallenge.allowCredentials = idList;
    //console.log('SignDataByIndex', getAssertionChallenge)


    return await 
        navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
                let gtidem = new GTIdemJs();
                gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_Sign);
                // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
                //     gtidem.sn =token_sn;
                // }
                return gtidem;
            }).catch((error) => {
                ////console.log(error.name);
                let gtidem = new GTIdemJs();
                gtidem.ConvertWebError(error.name,error.message);
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


    //PKI Command

    var command_bufer = new Uint8Array(bLabel.byteLength + 4);
    command_bufer[0] = 0xDF
    command_bufer[1] = 0x01;
    command_bufer[2] = bLabel.byteLength >> 8;
    command_bufer[3] = bLabel.byteLength;
    command_bufer.set(bLabel, 4);

    var alg_buf;
    var signDataBuf;

    var alg_buf = new Uint8Array(5);
    alg_buf[0] = 0xDF;
    alg_buf[1] = 0x03;
    alg_buf[2] = 0x00;
    alg_buf[3] = 0x01;
    alg_buf[4] = alg_number;




    // if(alg_number==ALG_RSA2048SHA256){
    //     await crypto.subtle.digest("SHA-256", new Uint8Array(bPlain)).then(function (signHashedDataPayload) {

    //         alg_buf = new Uint8Array(5);
    //         alg_buf[0] = 0xDF;
    //         alg_buf[1] = 0x03;
    //         alg_buf[2] = 0x00;
    //         alg_buf[3] = 0x01;
    //         alg_buf[4] = ALG_RSA2048SHA256_PreHash;

    //         var bHashData = new Uint8Array(signHashedDataPayload)
    //         signDataBuf = new Uint8Array(4 + bHashData.byteLength);
    //         signDataBuf[0] = 0xDF;
    //         signDataBuf[1] = 0x06;
    //         signDataBuf[2] = bHashData.length >> 8;
    //         signDataBuf[3] = bHashData.length;
    //         signDataBuf.set(bHashData, 4);
    //         return;
    //     });

    // }else{

        // alg_buf = new Uint8Array(5);
        // alg_buf[0] = 0xDF;
        // alg_buf[1] = 0x03;
        // alg_buf[2] = 0x00;
        // alg_buf[3] = 0x01;
        // alg_buf[4] = alg_number;
    

    var signDataBuf = new Uint8Array(4 + bPlain.byteLength);
        signDataBuf[0] = 0xDF;
        signDataBuf[1] = 0x06;
        signDataBuf[2] = bPlain.length >> 8;
        signDataBuf[3] = bPlain.length;
        signDataBuf.set(bPlain, 4);
    //}



    var pki_payload_length = sn_buf.byteLength+command_bufer.byteLength + alg_buf.byteLength + signDataBuf.byteLength;

    pki_header[0] = CMD_Sign;
    pki_header[1] = pki_payload_length >> 8
    pki_header[2] = pki_payload_length;

    var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
    pki_buffer = _appendBuffer(pki_buffer,sn_buf);
    pki_buffer = _appendBuffer(pki_buffer,command_bufer);
    pki_buffer = _appendBuffer(pki_buffer,alg_buf);
    pki_buffer = _appendBuffer(pki_buffer,signDataBuf);
    
    
    //console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "required",
        timeout: VERIFY_DEFAULT_TIMEOUT, 

    }
    var idList = [{
        id: pki_buffer,
        type: "public-key",
        transports:AUTHENTICATOR_TRANSPORTS
    }];

    getAssertionChallenge.allowCredentials = idList;
    //console.log('SignDataByIndex', getAssertionChallenge);

    return await 
        navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
                let gtidem = new GTIdemJs();
                gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_Sign);
                // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
                //     gtidem.sn =token_sn;
                // }
                return gtidem;
            }).catch((error) => {
                ////console.log(error.name);
                let gtidem = new GTIdemJs();
                gtidem.ConvertWebError(error.name,error.message);
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
    
    //console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "discouraged",
        timeout: DEFAULT_TIMEOUT, 

    }
    var idList = [{
        id: pki_buffer,
        type: "public-key",
        transports:AUTHENTICATOR_TRANSPORTS
    }];

    getAssertionChallenge.allowCredentials = idList;
    //console.log('SignDataByIndex', getAssertionChallenge)


    return await 
        navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
                let gtidem = new GTIdemJs();
                gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_ReadCertificate);
                // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
                //     gtidem.sn =token_sn;
                // }
                return gtidem;
            }).catch((error) => {
                ////console.log(error.name);
                let gtidem = new GTIdemJs();
                gtidem.ConvertWebError(error.name,error.message);
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
    
    
    //console.log("SignDataByIndex", bufToHex(pki_buffer));
    var getAssertionChallenge = {
        'challenge': challenge,
        "userVerification": "discouraged",
        timeout: DEFAULT_TIMEOUT, 
    }
    var idList = [{
        id: pki_buffer,
        type: "public-key",
        transports:AUTHENTICATOR_TRANSPORTS
    }];

    getAssertionChallenge.allowCredentials = idList;
    //console.log('SignDataByIndex', getAssertionChallenge);

    return await 
        navigator.credentials.get({'publicKey': getAssertionChallenge}).then((fido) => {
           
                let gtidem = new GTIdemJs();
                gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_ReadCertificate);
                // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
                //     gtidem.sn =token_sn;
                // }
                
                return gtidem;
            }).catch((error) => {
                ////console.log(error.name);
                let gtidem = new GTIdemJs();
                gtidem.ConvertWebError(error.name,error.message);
                return gtidem;
            });


}
/**
 * 設定用戶名稱，目前只有 Windows 10 的瀏覽器有作用
 * @param {text} sName
 * 
 */
function GTIDEM_SetName(sName){

    sUserName = sName;
}



/**
 * 
 * @param {Uint8Array} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @param {Uint8Array} encrypted_InitData 
 * @param {Uint8Array} HmacValueOfInitData 
 * @returns 
 */
 async function GTIDEM_InitToken(bSerialNumber, encrypted_InitData, HmacValueOfInitData) {

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
   var encryptedInitData_buf = new Uint8Array(4 + encrypted_InitData.byteLength);
   encryptedInitData_buf[0] = 0xDF;
   encryptedInitData_buf[1] = 0x21;
   encryptedInitData_buf[2] = encrypted_InitData.byteLength >> 8;
   encryptedInitData_buf[3] = encrypted_InitData.byteLength;
   encryptedInitData_buf.set(new Uint8Array(encrypted_InitData), 4);

   var hmacInitData_buf = new Uint8Array(4 + HmacValueOfInitData.byteLength);
   hmacInitData_buf[0] = 0xDF;
   hmacInitData_buf[1] = 0x22;
   hmacInitData_buf[2] = HmacValueOfInitData.byteLength >> 8;
   hmacInitData_buf[3] = HmacValueOfInitData.byteLength;
   hmacInitData_buf.set(new Uint8Array(HmacValueOfInitData), 4);
  
   var payloadLen = sn_buf.byteLength+encryptedInitData_buf.byteLength+hmacInitData_buf.byteLength;

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_INIT_TOKEN;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,encryptedInitData_buf);
   pki_buffer = _appendBuffer(pki_buffer,hmacInitData_buf);



   //console.log("Token_init_command: " + bufToHex(pki_buffer));

   var getAssertionChallenge = {
       'challenge': challenge,
       "userVerification": "discouraged",
       timeout: DEFAULT_TIMEOUT,  
   }
   var idList = [{
       id: pki_buffer,
       type: "public-key",
        transports:AUTHENTICATOR_TRANSPORTS
   }];

   getAssertionChallenge.allowCredentials = idList;

   return await navigator.credentials.get({
       'publicKey': getAssertionChallenge
   }).then((fido) => {
           
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_INIT_TOKEN);
        return gtidem;
    }).catch((error) => {
        ////console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
        return gtidem;
    });

}

/**
 * 
 * @param {Uint8Array} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @param {Uint8Array} encrypted_InitData 
 * @param {Uint8Array} HmacValueOfInitData 
 * @returns 
 */
 async function GTIDEM_UnlockPIN(bSerialNumber, encrypted_InitData, HmacValueOfInitData) {

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
   var encryptedInitData_buf = new Uint8Array(4 + encrypted_InitData.byteLength);
   encryptedInitData_buf[0] = 0xDF;
   encryptedInitData_buf[1] = 0x21;
   encryptedInitData_buf[2] = encrypted_InitData.byteLength >> 8;
   encryptedInitData_buf[3] = encrypted_InitData.byteLength;
   encryptedInitData_buf.set(new Uint8Array(encrypted_InitData), 4);

   var hmacInitData_buf = new Uint8Array(4 + HmacValueOfInitData.byteLength);
   hmacInitData_buf[0] = 0xDF;
   hmacInitData_buf[1] = 0x22;
   hmacInitData_buf[2] = HmacValueOfInitData.byteLength >> 8;
   hmacInitData_buf[3] = HmacValueOfInitData.byteLength;
   hmacInitData_buf.set(new Uint8Array(HmacValueOfInitData), 4);
  
   var payloadLen = sn_buf.byteLength+encryptedInitData_buf.byteLength+hmacInitData_buf.byteLength;

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_UNLOCK_PIN;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,encryptedInitData_buf);
   pki_buffer = _appendBuffer(pki_buffer,hmacInitData_buf);



   //console.log("Token_init_command: " + bufToHex(pki_buffer));

   var getAssertionChallenge = {
       'challenge': challenge,
       "userVerification": "discouraged",
       'timeout': DEFAULT_TIMEOUT, 
   }
   var idList = [{
       id: pki_buffer,
       type: "public-key",
        transports:AUTHENTICATOR_TRANSPORTS
   }];

   getAssertionChallenge.allowCredentials = idList;

   return await navigator.credentials.get({
       'publicKey': getAssertionChallenge
   }).then((fido) => {
           
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_UNLOCK_PIN);
        return gtidem;
    }).catch((error) => {
        ////console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
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


  /**
 * 產生非對稱金鑰對，依照要求回傳 RAW 或是 CSR
 * @param {Uint8Array｜undefined} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @param {Uint8Array｜undefined} bKeyID 用來關聯金鑰對，若是不替換則填入 undefined 或是空陣列。若不使用 KeyID,則載具會產生預設的 KeyHandle。
 * @param {Number} keytype 金鑰類型
 * @param {Number} outputformat 指定回傳的資料格式，CSR 或是 RAW 
 * @returns {GTIdemJs} 回傳結果的集合
 */
async function GTIDEM_GenKeyPair(bSerialNumber,bKeyID, keytype, outputformat) {


 
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

     var keytype_buf;
     keytype_buf = new Uint8Array(4 + 1);
     keytype_buf[0] = 0xDF;
     keytype_buf[1] = 0x23;
     keytype_buf[2] = 0x00
     keytype_buf[3] = 0x01;
     keytype_buf[4] = keytype;

     var outputformat_buf;
     outputformat_buf = new Uint8Array(4 + 1);
     outputformat_buf[0] = 0xDF;
     outputformat_buf[1] = 0x24;
     outputformat_buf[2] = 0x00;
     outputformat_buf[3] = 0x01;
     outputformat_buf[4] = outputformat;

    var payloadLen = keyid_buf.byteLength+sn_buf.byteLength+keytype_buf.length+outputformat_buf.length
 
    var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
  
    var pki_header = new Uint8Array(3);
    pki_header[0] = CMD_GenKeyPair;
    pki_header[1] = payloadLen>>8
    pki_header[2] = payloadLen;
 
    var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
    pki_buffer = _appendBuffer(pki_buffer,sn_buf);
    pki_buffer = _appendBuffer(pki_buffer,keyid_buf);
    pki_buffer = _appendBuffer(pki_buffer,keytype_buf);
    pki_buffer = _appendBuffer(pki_buffer,outputformat_buf);
 
 
 
    //console.log("Request_command: " + bufToHex(pki_buffer));
 
    var webauth_request = {
        'challenge': challenge,
    
        'rp': {
            'name': 'GoTrustID Inc.',
        },
    
        'user': {
            'id': pki_buffer,
            'name': sUserName,
            'displayName': sUserName,
        },
        'timeout': VERIFY_DEFAULT_TIMEOUT, 
        "authenticatorSelection": {
            "userVerification": "required",
            "requireResidentKey": false,
            "residentKey": "discouraged",
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
    //console.log('webauth_request', webauth_request)
 
    return await navigator.credentials.create({
         'publicKey': webauth_request
     }).then((fido) => {
           
        let attestationObject = CBOR.decode(fido.response.attestationObject);
        let authData = parseAuthData(attestationObject.authData);
        let credID = authData.credID;
        let bPKIoverFIDOResponse= credID.buffer.slice(credID.byteOffset, credID.byteLength + credID.byteOffset);

        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(bPKIoverFIDOResponse,CMD_GenKeyPair);
        // if(gtidem.statusCode != CTAP2_VENDOR_ERROR_TOKEN){
        //     gtidem.sn =token_sn;
        // }

        return gtidem;
    }).catch((error) => {
        ////console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
        return gtidem;
    });
 }


/**
 * 
 * @param {Uint8Array} bSerialNumber 指定序號序號。若不指定載具序號，則可填入 undefined 或是空陣列
 * @param {Uint8Array} encrypted_InitData 
 * @param {Uint8Array} HmacValueOfInitData 
 * @returns 
 */
 async function GTIDEM_FactoryResetToken(bSerialNumber, bEncChallenge) {

    console.log("cp3:",event);
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

   var bEncChallengeBuf = new Uint8Array(4 + bEncChallenge.byteLength);
   bEncChallengeBuf[0] = 0xDF;
   bEncChallengeBuf[1] = 0x25;
   bEncChallengeBuf[2] = bEncChallenge.byteLength >> 8;
   bEncChallengeBuf[3] = bEncChallenge.byteLength;
   bEncChallengeBuf.set(new Uint8Array(bEncChallenge), 4);

  
   var payloadLen = sn_buf.byteLength+bEncChallengeBuf.byteLength;

   var gtheaderbuffer = Uint8Array.from(window.atob(GTheader), c => c.charCodeAt(0));
 
   var pki_header = new Uint8Array(3);
   pki_header[0] = CMD_FactoryReset;
   pki_header[1] = payloadLen>>8
   pki_header[2] = payloadLen;

   var pki_buffer = _appendBuffer(gtheaderbuffer,pki_header);
   pki_buffer = _appendBuffer(pki_buffer,sn_buf);
   pki_buffer = _appendBuffer(pki_buffer,bEncChallengeBuf);



   //console.log("Token_init_command: " + bufToHex(pki_buffer));

   var getAssertionChallenge = {
       'challenge': challenge,
       "userVerification": "discouraged",
       timeout: DEFAULT_TIMEOUT, 
   }
   var idList = [{
       id: pki_buffer,
       type: "public-key",
        transports:AUTHENTICATOR_TRANSPORTS
   }];

   getAssertionChallenge.allowCredentials = idList;

   return await navigator.credentials.get({
       'publicKey': getAssertionChallenge
   }).then((fido) => {
           
        let gtidem = new GTIdemJs();
        gtidem.parsePKIoverFIDOResponse(fido.response.signature,CMD_CHANGE_PIN);
        return gtidem;
    }).catch((error) => {
        ////console.log(error.name);
        let gtidem = new GTIdemJs();
        gtidem.ConvertWebError(error.name,error.message);
        return gtidem;
    });

}
/**
 * 回傳JS library 版本
 * @returns 
 */

function GTIDEM_GetJSVersion() {

    return VERSION;
 }



/*
  async function GTIDEM_GenRSA2048CSRAfterClearCard(bSerialNumber,bCommonName, callback) {

    var gtidem = undefined;
    let timer_id = setInterval( () => {
        if(gtidem==undefined){
            return;
        }

        if(gtidem.statusCode != CTAP1_ERR_SUCCESS){
            clearTimeout(timer_id);   
            return;
        }
        clearTimeout(timer_id);        
        GTIDEM_GenRSA2048CSR(bSerialNumber,bCommonName).then((result) => {
            return callback(result);
        });
   
    }, 200);

    var gtidem = await GTIDEM_ClearToken(bSerialNumber);

    if(gtidem.statusCode != CTAP1_ERR_SUCCESS){
        return callback(gtidem);
    }


}

*/