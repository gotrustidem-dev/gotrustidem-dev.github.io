/**
 * Type definitions for GoTrustID IdemKey+ JavaScript Library
 * @version 1.12.3
 */

// ============================================================================
// Constants
// ============================================================================

export const VERSION: string;
export const DEFAULT_TIMEOUT: number;
export const VERIFY_DEFAULT_TIMEOUT: number;
export const AUTHENTICATOR_TRANSPORTS: readonly string[];

export const TOKEN_MIN_PIN_LEN: number;
export const TOKEN_MAX_PIN_LEN: number;
export const TOKEN_MAX_SOPIN_LEN: number;
export const TOKEN_MIN_SOPIN_LEN: number;

// ============================================================================
// Enums and Constants Objects
// ============================================================================

export const Commands: {
  readonly KEY_AGREEMENT: 0xE0;
  readonly READ_CERTIFICATE: 0xE1;
  readonly TOKEN_INFO: 0xE2;
  readonly SIGN: 0xE3;
  readonly SIGN_WITH_PIN: 0xE5;
  readonly IMPORT_CERTIFICATE: 0xE7;
  readonly CHANGE_PIN: 0xE8;
  readonly UNLOCK_PIN: 0xE9;
  readonly DELETE_CERT: 0xEB;
  readonly CLEAR_TOKEN: 0xEC;
  readonly INIT_TOKEN: 0xED;
  readonly GEN_KEY_PAIR: 0xEE;
  readonly FACTORY_RESET: 0xEF;
  readonly IMPORT_CERTIFICATE2: 0xF7;
  readonly GET_CERT_EXTRAS: 0xB2;
  readonly REQUEST_CSR: 0xEA;
  readonly GEN_RSA_KEY_PAIR: 0xE6;
  readonly REQUEST_P256_CSR: 0xC1;
  readonly REQUEST_P384_CSR: 0xC2;
  readonly REQUEST_P521_CSR: 0xC3;
  readonly GEN_RSA_KEY_PAIR_AFTER_CLEAR: 0xC4;
  readonly REQUEST_CSR_AFTER_CLEAR: 0xC5;
  readonly REQUEST_P256_CSR_AFTER_CLEAR: 0xC6;
  readonly REQUEST_P384_CSR_AFTER_CLEAR: 0xC7;
  readonly REQUEST_P521_CSR_AFTER_CLEAR: 0xC8;
};

export const Algorithms: {
  readonly RSA2048_SHA1: 0x01;
  readonly RSA2048_SHA256: 0x02;
  readonly RSA2048_SHA384: 0x03;
  readonly RSA2048_SHA512: 0x04;
  readonly RSA2048_SHA1_PSS: 0x05;
  readonly RSA2048_SHA256_PSS: 0x06;
  readonly RSA2048_SHA384_PSS: 0x07;
  readonly RSA2048_SHA512_PSS: 0x08;
  readonly ECDSA_SHA1: 0x09;
  readonly ECDSA_SHA256: 0x0a;
  readonly ECDSA_SHA384: 0x0b;
  readonly ECDSA_SHA512: 0x0c;
  readonly RSA2048_SHA1_PREHASH: 0x11;
  readonly RSA2048_SHA256_PREHASH: 0x12;
  readonly RSA2048_SHA384_PREHASH: 0x13;
  readonly RSA2048_SHA512_PREHASH: 0x14;
  readonly RSA2048_SHA1_PSS_PREHASH: 0x15;
  readonly RSA2048_SHA256_PSS_PREHASH: 0x16;
  readonly RSA2048_SHA384_PSS_PREHASH: 0x17;
  readonly RSA2048_SHA512_PSS_PREHASH: 0x18;
  readonly ECDSA_SHA1_PREHASH: 0x19;
  readonly ECDSA_SHA256_PREHASH: 0x1a;
  readonly ECDSA_SHA384_PREHASH: 0x1b;
  readonly ECDSA_SHA512_PREHASH: 0x1c;
};

export const KeyTypes: {
  readonly RSA_2048: 1;
  readonly EC_SECP256R1: 2;
  readonly EC_SECP384R1: 3;
  readonly EC_SECP521R1: 4;
};

export const OutputTypes: {
  readonly RAW: 1;
  readonly CSR: 2;
};

export const PinFormats: {
  readonly FREE: 0x00;
  readonly NUMBER: 0x01;
  readonly LOWERCASE: 0x02;
  readonly UPPERCASE: 0x04;
  readonly SYMBOL: 0x08;
};

export const TokenFlags: {
  readonly PIN_EXPIRED: 0x1;
  readonly INITIALIZED: 0x2;
};

// ============================================================================
// Error Classes
// ============================================================================

export class IdemKeyError extends Error {
  statusCode: number;
  constructor(statusCode: number, message?: string);
}

// ============================================================================
// Response Classes
// ============================================================================

export class GTIdemResponse {
  statusCode: number | null;
  statusMessage: string;
  data: any;
  rawResponse: ArrayBuffer | null;

  constructor();
  parsePKIoverFIDOResponse(signature: ArrayBuffer, commandType: number): void;
  convertWebError(errorName: string, errorMessage: string): void;
  isSuccess(): boolean;
}

// ============================================================================
// Utility Functions
// ============================================================================

export function toUTF8Array(str: string): Uint8Array;
export function hexStringToArrayBuffer(hexString: string): Uint8Array;
export function bufferToHex(buffer: ArrayBuffer | Uint8Array): string;
export function convertVersionFormat(buffer: Uint8Array): string;
export function convertSNFormat(buffer: Uint8Array): string;
export function base64EncodeURL(buffer: ArrayBuffer | Uint8Array): string;

// ============================================================================
// Session Key Result
// ============================================================================

interface SessionKeyResult {
  ecPublicKey: ArrayBuffer;
  encryptedOldPINHash: Uint8Array;
  encryptedNewPIN: Uint8Array;
}

// ============================================================================
// Main API Class
// ============================================================================

export class IdemKeyPlusAPI {
  username: string;
  encryptedPIN: any;
  platformECPublicKey: any;

  constructor();

  /**
   * Set username for FIDO operations
   */
  setUsername(name: string): void;

  /**
   * Get the library version
   */
  getVersion(): string;

  /**
   * Validate PIN format
   */
  isValidPIN(pin: Uint8Array, pinFlag: number): boolean;

  /**
   * Generate session key for PIN encryption (private method)
   */
  computeSessionKey(
    oldPIN: Uint8Array,
    newPIN: Uint8Array,
    ecpointXY: Uint8Array
  ): Promise<SessionKeyResult>;

  /**
   * Get token information
   */
  getTokenInfo(serialNumber: Uint8Array): Promise<GTIdemResponse>;

  /**
   * Change user PIN
   */
  changeUserPIN(
    oldPIN: Uint8Array,
    newPIN: Uint8Array,
    serialNumber: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Generate P256 CSR
   */
  genP256CSR(
    serialNumber: Uint8Array,
    commonName: Uint8Array,
    afterClear?: boolean
  ): Promise<GTIdemResponse>;

  /**
   * Generate P384 CSR
   */
  genP384CSR(
    serialNumber: Uint8Array,
    commonName: Uint8Array,
    afterClear?: boolean
  ): Promise<GTIdemResponse>;

  /**
   * Generate P521 CSR
   */
  genP521CSR(
    serialNumber: Uint8Array,
    commonName: Uint8Array,
    afterClear?: boolean
  ): Promise<GTIdemResponse>;

  /**
   * Generate RSA 2048 CSR
   */
  genRSA2048CSR(
    serialNumber: Uint8Array,
    commonName: Uint8Array,
    afterClear?: boolean
  ): Promise<GTIdemResponse>;

  /**
   * Sign data by certificate index
   */
  signDataByIndex(
    index: number,
    serialNumber: Uint8Array,
    algorithm: number,
    data: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Sign data by certificate label
   */
  signDataByLabel(
    label: Uint8Array,
    serialNumber: Uint8Array,
    algorithm: number,
    data: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Read certificate by index without PIN
   */
  readCertByIndexWithoutPIN(
    index: number,
    serialNumber: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Read certificate by label without PIN
   */
  readCertByLabelWithoutPIN(
    label: Uint8Array,
    serialNumber: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Initialize token
   */
  initToken(
    serialNumber: Uint8Array,
    encryptedInitData: Uint8Array,
    hmacValue: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Unlock PIN
   */
  unlockPIN(
    serialNumber: Uint8Array,
    encryptedInitData: Uint8Array,
    hmacValue: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Clear token
   */
  clearToken(serialNumber: Uint8Array): Promise<GTIdemResponse>;

  /**
   * Factory reset token
   */
  factoryResetToken(
    serialNumber: Uint8Array,
    encChallenge: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Delete certificate by label
   */
  deleteCertByLabel(
    label: Uint8Array,
    serialNumber: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Import certificate
   */
  importCertificate(
    serialNumber: Uint8Array,
    keyHandle: Uint8Array,
    keyID: Uint8Array,
    hexCert: string,
    plain?: Uint8Array,
    extraData?: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Generate key pair
   */
  genKeyPair(
    serialNumber: Uint8Array,
    keyID: Uint8Array,
    keyType: number,
    outputFormat: number
  ): Promise<GTIdemResponse>;

  /**
   * Read certificate extra with index
   */
  readCertExtraWithIndex(
    index: number,
    serialNumber: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Read certificate extra with label
   */
  readCertExtraWithLabel(
    label: Uint8Array,
    serialNumber: Uint8Array
  ): Promise<GTIdemResponse>;

  /**
   * Read all certificate extras
   */
  readAllCertExtra(serialNumber: Uint8Array): Promise<GTIdemResponse>;
}

// ============================================================================
// Factory Function
// ============================================================================

export function createIdemKeyAPI(): IdemKeyPlusAPI;

// ============================================================================
// Default Instance
// ============================================================================

export const idemKeyAPI: IdemKeyPlusAPI;

// ============================================================================
// Default Export (for CommonJS)
// ============================================================================

export default IdemKeyPlusAPI;
