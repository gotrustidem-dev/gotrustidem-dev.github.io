/**
 * GoTrustID's JavaScript Library for Idem Key+
 * Modern ES6+ version with module support
 * @version 1.14.0
 * @license MIT
 */

'use strict';

// ============================================================================
// Constants
// ============================================================================

export const VERSION = '1.14.0';
export const DEFAULT_TIMEOUT = 120000;
export const VERIFY_DEFAULT_TIMEOUT = 300000;
export const AUTHENTICATOR_TRANSPORTS = ['usb'];

// Command Header GoTrust-Idem-PKI
const GT_HEADER = 'R29UcnVzdC1JZGVtLVBLSQ==';
const DEFAULT_USERNAME = 'GoTrustID.com';

// Token PIN constraints
export const TOKEN_MIN_PIN_LEN = 4;
export const TOKEN_MAX_PIN_LEN = 63;
export const TOKEN_MAX_SOPIN_LEN = 16;
export const TOKEN_MIN_SOPIN_LEN = 8;

// Command codes
export const Commands = {
  KEY_AGREEMENT: 0xE0,
  READ_CERTIFICATE: 0xE1,
  TOKEN_INFO: 0xE2,
  SIGN: 0xE3,
  SIGN_WITH_PIN: 0xE5,
  IMPORT_CERTIFICATE: 0xE7,
  CHANGE_PIN: 0xE8,
  UNLOCK_PIN: 0xE9,
  DELETE_CERT: 0xEB,
  CLEAR_TOKEN: 0xEC,
  INIT_TOKEN: 0xED,
  GEN_KEY_PAIR: 0xEE,
  FACTORY_RESET: 0xEF,
  IMPORT_CERTIFICATE2: 0xF7,
  GET_CERT_EXTRAS: 0xB2,
  REQUEST_CSR: 0xEA,
  GEN_RSA_KEY_PAIR: 0xE6,
  REQUEST_P256_CSR: 0xC1,
  REQUEST_P384_CSR: 0xC2,
  REQUEST_P521_CSR: 0xC3,
  GEN_RSA_KEY_PAIR_AFTER_CLEAR: 0xC4,
  REQUEST_CSR_AFTER_CLEAR: 0xC5,
  REQUEST_P256_CSR_AFTER_CLEAR: 0xC6,
  REQUEST_P384_CSR_AFTER_CLEAR: 0xC7,
  REQUEST_P521_CSR_AFTER_CLEAR: 0xC8,
};

// Algorithm types
export const Algorithms = {
  RSA2048_SHA1: 0x01,
  RSA2048_SHA256: 0x02,
  RSA2048_SHA384: 0x03,
  RSA2048_SHA512: 0x04,
  RSA2048_SHA1_PSS: 0x05,
  RSA2048_SHA256_PSS: 0x06,
  RSA2048_SHA384_PSS: 0x07,
  RSA2048_SHA512_PSS: 0x08,
  ECDSA_SHA1: 0x09,
  ECDSA_SHA256: 0x0a,
  ECDSA_SHA384: 0x0b,
  ECDSA_SHA512: 0x0c,
  RSA2048_SHA1_PREHASH: 0x11,
  RSA2048_SHA256_PREHASH: 0x12,
  RSA2048_SHA384_PREHASH: 0x13,
  RSA2048_SHA512_PREHASH: 0x14,
  RSA2048_SHA1_PSS_PREHASH: 0x15,
  RSA2048_SHA256_PSS_PREHASH: 0x16,
  RSA2048_SHA384_PSS_PREHASH: 0x17,
  RSA2048_SHA512_PSS_PREHASH: 0x18,
  ECDSA_SHA1_PREHASH: 0x19,
  ECDSA_SHA256_PREHASH: 0x1a,
  ECDSA_SHA384_PREHASH: 0x1b,
  ECDSA_SHA512_PREHASH: 0x1c,
};

// Key types
export const KeyTypes = {
  RSA_2048: 1,
  EC_SECP256R1: 2,
  EC_SECP384R1: 3,
  EC_SECP521R1: 4,
};

// Output types
export const OutputTypes = {
  RAW: 1,
  CSR: 2,
};

// PIN format flags
export const PinFormats = {
  FREE: 0x00,
  NUMBER: 0x01,
  LOWERCASE: 0x02,
  UPPERCASE: 0x04,
  SYMBOL: 0x08,
};

// Token flags
export const TokenFlags = {
  PIN_EXPIRED: 0x1,
  INITIALIZED: 0x2,
};

// ============================================================================
// Custom Error Classes
// ============================================================================

/**
 * Custom error class for IdemKey operations
 */
export class IdemKeyError extends Error {
  /**
   * @param {number} statusCode - The status code from the device
   * @param {string} message - Error message
   */
  constructor(statusCode, message = '') {
    super(message || `IdemKey error: ${statusCode}`);
    this.name = 'IdemKeyError';
    this.statusCode = statusCode;
  }
}

// ============================================================================
// Response Parser Class
// ============================================================================

/**
 * Class to parse and handle PKI over FIDO responses
 */
export class GTIdemResponse {
  constructor() {
    this.statusCode = null;
    this.statusMessage = '';
    this.data = null;
    this.rawResponse = null;
  }

  /**
   * Parse the FIDO response signature
   * @param {ArrayBuffer} signature - The signature from FIDO response
   * @param {number} commandType - The command type that was executed
   */
  parsePKIoverFIDOResponse(signature, commandType) {
    // Implementation would go here
    // This is a placeholder for the actual parsing logic
    this.rawResponse = signature;
  }

  /**
   * Convert WebAuthn error to IdemKey error
   * @param {string} errorName - Error name from WebAuthn
   * @param {string} errorMessage - Error message from WebAuthn
   */
  convertWebError(errorName, errorMessage) {
    this.statusMessage = `${errorName}: ${errorMessage}`;
  }

  /**
   * Check if the operation was successful
   * @returns {boolean}
   */
  isSuccess() {
    return this.statusCode === 0;
  }
}

// ============================================================================
// Utility Functions
// ============================================================================

/**
 * Convert string to UTF-8 byte array
 * @param {string} str - Input string
 * @returns {Uint8Array}
 */
export function toUTF8Array(str) {
  const utf8 = [];
  for (let i = 0; i < str.length; i++) {
    let charcode = str.charCodeAt(i);
    if (charcode < 0x80) {
      utf8.push(charcode);
    } else if (charcode < 0x800) {
      utf8.push(0xc0 | (charcode >> 6), 0x80 | (charcode & 0x3f));
    } else if (charcode < 0xd800 || charcode >= 0xe000) {
      utf8.push(
        0xe0 | (charcode >> 12),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f)
      );
    } else {
      // surrogate pair
      i++;
      charcode =
        0x10000 + (((charcode & 0x3ff) << 10) | (str.charCodeAt(i) & 0x3ff));
      utf8.push(
        0xf0 | (charcode >> 18),
        0x80 | ((charcode >> 12) & 0x3f),
        0x80 | ((charcode >> 6) & 0x3f),
        0x80 | (charcode & 0x3f)
      );
    }
  }
  return new Uint8Array(utf8);
}

/**
 * Convert hex string to ArrayBuffer
 * @param {string} hexString - Hex string to convert
 * @returns {Uint8Array}
 */
export function hexStringToArrayBuffer(hexString) {
  hexString = hexString.replace(/^0x/, '');

  if (hexString.length % 2 !== 0) {
    console.warn('WARNING: expecting an even number of characters in the hexString');
  }

  const bad = hexString.match(/[G-Z\s]/i);
  if (bad) {
    console.warn('WARNING: found non-hex characters', bad);
  }

  const pairs = hexString.match(/[\dA-F]{2}/gi);
  const integers = pairs.map((s) => parseInt(s, 16));

  return new Uint8Array(integers);
}

/**
 * Convert buffer to hex string
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string}
 */
export function bufferToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert version buffer to formatted string
 * @param {Uint8Array} buffer
 * @returns {string}
 */
export function convertVersionFormat(buffer) {
  return Array.from(buffer)
    .map((byte) => byte.toString(16))
    .join('.');
}

/**
 * Convert serial number buffer to formatted string
 * @param {Uint8Array} buffer
 * @returns {string}
 */
export function convertSNFormat(buffer) {
  return Array.from(buffer)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Base64 URL encode
 * @param {ArrayBuffer|Uint8Array} buffer
 * @returns {string}
 */
export function base64EncodeURL(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// ============================================================================
// Main API Class
// ============================================================================

/**
 * Main class for IdemKey+ operations
 */
export class IdemKeyPlusAPI {
  constructor() {
    this.username = DEFAULT_USERNAME;
    this.encryptedPIN = null;
    this.platformECPublicKey = null;
  }

  /**
   * Set username for FIDO operations
   * @param {string} name - Username to set
   */
  setUsername(name) {
    this.username = name;
  }

  /**
   * Get the library version
   * @returns {string}
   */
  getVersion() {
    return VERSION;
  }

  /**
   * Validate PIN format
   * @param {Uint8Array} pin - PIN to validate
   * @param {number} pinFlag - PIN format flags
   * @returns {boolean}
   */
  isValidPIN(pin, pinFlag) {
    if (pin.length < TOKEN_MIN_PIN_LEN || pin.length > TOKEN_MAX_PIN_LEN) {
      return false;
    }
    // Additional validation logic would go here
    return true;
  }

  /**
   * Generate session key for PIN encryption
   * @param {Uint8Array} oldPIN - Old PIN
   * @param {Uint8Array} newPIN - New PIN
   * @param {Uint8Array} ecpointXY - EC point from device
   * @returns {Promise<Object>}
   * @private
   */
  async computeSessionKey(oldPIN, newPIN, ecpointXY) {
    const oldPINHash = await crypto.subtle.digest('SHA-256', oldPIN);

    const newPINBuffer = new Uint8Array(64);
    newPINBuffer.fill(0);
    newPINBuffer.set(newPIN, 0);

    const iv = new Uint8Array(16);
    iv.fill(0);

    const externalECPublicKeyX = base64EncodeURL(ecpointXY.slice(1, 33));
    const externalECPublicKeyY = base64EncodeURL(ecpointXY.slice(33, 65));

    const importedECPublicKey = await crypto.subtle.importKey(
      'jwk',
      {
        kty: 'EC',
        crv: 'P-256',
        x: externalECPublicKeyX,
        y: externalECPublicKeyY,
        ext: true,
      },
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      []
    );

    const cryptoECKeyPair = await crypto.subtle.generateKey(
      {
        name: 'ECDH',
        namedCurve: 'P-256',
      },
      true,
      ['deriveKey', 'deriveBits']
    );

    const exportECPublicKeyArray = await crypto.subtle.exportKey(
      'raw',
      cryptoECKeyPair.publicKey
    );

    const sessionKey = await crypto.subtle
      .deriveBits(
        {
          name: 'ECDH',
          namedCurve: 'P-256',
          public: importedECPublicKey,
        },
        cryptoECKeyPair.privateKey,
        256
      )
      .then((keybits) => crypto.subtle.digest('SHA-256', new Uint8Array(keybits)))
      .then((sessionKeyBytes) =>
        crypto.subtle.importKey('raw', sessionKeyBytes, 'aes-cbc', false, ['encrypt'])
      );

    const encryptedOldPINHash = await crypto.subtle.encrypt(
      { name: 'aes-cbc', iv },
      sessionKey,
      oldPINHash
    );

    const encryptedNewPIN = await crypto.subtle.encrypt(
      { name: 'aes-cbc', iv },
      sessionKey,
      newPINBuffer
    );

    return {
      ecPublicKey: exportECPublicKeyArray,
      encryptedOldPINHash: new Uint8Array(encryptedOldPINHash),
      encryptedNewPIN: new Uint8Array(encryptedNewPIN),
    };
  }

  /**
   * Get token information
   * @param {Uint8Array} serialNumber - Device serial number
   * @returns {Promise<GTIdemResponse>}
   */
  async getTokenInfo(serialNumber) {
    // Implementation would follow the pattern from original
    throw new Error('Not implemented - refer to original implementation');
  }

  /**
   * Change user PIN
   * @param {Uint8Array} oldPIN - Current PIN
   * @param {Uint8Array} newPIN - New PIN
   * @param {Uint8Array} serialNumber - Device serial number
   * @returns {Promise<GTIdemResponse>}
   */
  async changeUserPIN(oldPIN, newPIN, serialNumber) {
    // Implementation would follow the pattern from original
    throw new Error('Not implemented - refer to original implementation');
  }

  /**
   * Generate P256 CSR
   * @param {Uint8Array} serialNumber - Device serial number
   * @param {Uint8Array} commonName - Certificate common name
   * @param {boolean} afterClear - Whether to clear token first
   * @returns {Promise<GTIdemResponse>}
   */
  async genP256CSR(serialNumber, commonName, afterClear = false) {
    // Implementation would follow the pattern from original
    throw new Error('Not implemented - refer to original implementation');
  }

  /**
   * Generate RSA 2048 CSR
   * @param {Uint8Array} serialNumber - Device serial number
   * @param {Uint8Array} commonName - Certificate common name
   * @param {boolean} afterClear - Whether to clear token first
   * @returns {Promise<GTIdemResponse>}
   */
  async genRSA2048CSR(serialNumber, commonName, afterClear = false) {
    // Implementation would follow the pattern from original
    throw new Error('Not implemented - refer to original implementation');
  }

  /**
   * Sign data by certificate index
   * @param {number} index - Certificate index
   * @param {Uint8Array} serialNumber - Device serial number
   * @param {number} algorithm - Algorithm to use
   * @param {Uint8Array} data - Data to sign
   * @returns {Promise<GTIdemResponse>}
   */
  async signDataByIndex(index, serialNumber, algorithm, data) {
    // Implementation would follow the pattern from original
    throw new Error('Not implemented - refer to original implementation');
  }

  /**
   * Read certificate by index without PIN
   * @param {number} index - Certificate index
   * @param {Uint8Array} serialNumber - Device serial number
   * @returns {Promise<GTIdemResponse>}
   */
  async readCertByIndexWithoutPIN(index, serialNumber) {
    // Implementation would follow the pattern from original
    throw new Error('Not implemented - refer to original implementation');
  }

  /**
   * Initialize token
   * @param {Uint8Array} serialNumber - Device serial number
   * @param {Uint8Array} encryptedInitData - Encrypted initialization data
   * @param {Uint8Array} hmacValue - HMAC value of init data
   * @returns {Promise<GTIdemResponse>}
   */
  async initToken(serialNumber, encryptedInitData, hmacValue) {
    // Implementation would follow the pattern from original
    throw new Error('Not implemented - refer to original implementation');
  }

  /**
   * Clear token
   * @param {Uint8Array} serialNumber - Device serial number
   * @returns {Promise<GTIdemResponse>}
   */
  async clearToken(serialNumber) {
    // Implementation would follow the pattern from original
    throw new Error('Not implemented - refer to original implementation');
  }

  /**
   * Factory reset token
   * @param {Uint8Array} serialNumber - Device serial number
   * @param {Uint8Array} encChallenge - Encrypted challenge
   * @returns {Promise<GTIdemResponse>}
   */
  async factoryResetToken(serialNumber, encChallenge) {
    // Implementation would follow the pattern from original
    throw new Error('Not implemented - refer to original implementation');
  }
}

// ============================================================================
// Default Export
// ============================================================================

/**
 * Create a new instance of the IdemKey+ API
 * @returns {IdemKeyPlusAPI}
 */
export function createIdemKeyAPI() {
  return new IdemKeyPlusAPI();
}

// Default instance for convenience
export const idemKeyAPI = createIdemKeyAPI();

// For CommonJS compatibility
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    IdemKeyPlusAPI,
    GTIdemResponse,
    IdemKeyError,
    createIdemKeyAPI,
    idemKeyAPI,
    VERSION,
    Commands,
    Algorithms,
    KeyTypes,
    OutputTypes,
    PinFormats,
    TokenFlags,
    // Utility functions
    toUTF8Array,
    hexStringToArrayBuffer,
    bufferToHex,
    convertVersionFormat,
    convertSNFormat,
    base64EncodeURL,
  };
}
