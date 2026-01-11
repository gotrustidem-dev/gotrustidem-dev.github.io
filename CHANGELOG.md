# Changelog

All notable changes to the GoTrust IdemKey+ JavaScript Library will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.13.1] - 2026-01-12

### Current Version Features

#### Added
- Complete FIDO2/WebAuthn integration for PKI operations
- Support for multiple elliptic curves (P-256, P-384, P-521)
- RSA-2048 key pair generation and CSR creation
- Certificate management (read, import, delete)
- PIN code management with ECDH encryption
- Token initialization and factory reset capabilities
- Digital signature operations with and without PIN
- Multiple algorithm support (RSA2048-SHA256, PreHash mode)
- Comprehensive API documentation (PDF format v1.1-v1.6)

#### Security Features
- ECDH (P-256) key agreement for secure PIN transmission
- AES-CBC encryption for PIN protection
- SHA-256 hashing for PIN verification
- HMAC validation for token initialization
- Support for both user PIN and SO (Security Officer) PIN

#### API Functions (30+ async functions)
- Certificate Operations: `ReadCertByIndex`, `ReadCertByLabel`, `DeleteCertByLabel`
- Signature Operations: `SignDataByIndex`, `SignDataByLabel`, `SignDataWithPIN`
- Key Generation: `GenRSA2048KeyPair`, `GTIDEM_GenRSA2048CSR`
- PIN Management: `GTIDEM_ChangeUserPIN`, `GTIDEM_UnlockPIN`
- Token Management: `GTIDEM_GetTokenInfo`, `GTIDEM_InitToken`, `GTIDEM_ClearToken`

#### Command Set
- `CMD_ReadCertificate` (0xE1) - Read certificates from token
- `CMD_Sign` (0xE3) - Digital signature without PIN
- `CMD_SignWithPIN` (0xE5) - Digital signature with PIN verification
- `CMD_CHANGE_PIN` (0xE8) - Change user PIN
- `CMD_UNLOCK_PIN` (0xE9) - Unlock blocked PIN
- `CMD_REQUESTCSR` (0xEA) - Generate certificate signing request
- `CMD_DELEE_CERT` (0xEB) - Delete certificate
- `CMD_CLEAR_TOKEN` (0xEC) - Clear all token data
- `CMD_INIT_TOKEN` (0xED) - Initialize token
- `CMD_GenKeyPair` (0xEE) - Generate key pair
- `CMD_ImportCertificate` (0xE7) - Import certificate
- `CMD_TokenInfo` (0xE2) - Get token information

#### HTML Demo Pages
- Read Certificate Without PIN
- Sign Data with hardware key
- Change PIN code
- Get Token Information
- Delete Certificates
- Request CSR (Certificate Signing Request)
- Request RSA 2048 Key Pair
- Initialize Token
- Unlock PIN

#### Utilities
- `cbor.js` - CBOR encoding/decoding for FIDO2 protocol
- `helpers.js` - Buffer conversion and utility functions
- `response.js` - Response handling and parsing
- `showMessage.js` - User notification system

### Version History

#### Supported Versions
- v1.13 (Current) - Latest stable release
- v1.12 - Previous stable
- v1.11 - Previous stable
- v1.10 - Previous stable
- v1.9 - Previous stable
- v1.8 - Previous stable
- v1.7 - Previous stable
- Beta/Develop - Development branches

### Browser Compatibility
- Chrome 67+ (WebAuthn support)
- Firefox 60+ (WebAuthn support)
- Edge 18+ (WebAuthn support)
- Opera 54+ (WebAuthn support)
- Safari 13+ (WebAuthn support)

### Hardware Requirements
- GoTrust IdemKey+ hardware security key
- USB port for hardware key connection
- FIDO2/WebAuthn compliant authenticator

### Known Limitations
- Requires HTTPS connection (except localhost)
- Browser must support WebAuthn API
- User interaction required for PIN operations
- Timeout defaults: 120s (standard), 300s (PIN verification)

---

## Template for Future Releases

## [Unreleased]

### Added
- New features that have been added

### Changed
- Changes to existing functionality

### Deprecated
- Features that will be removed in upcoming releases

### Removed
- Features that have been removed

### Fixed
- Bug fixes

### Security
- Security vulnerability fixes

---

## Version Numbering

Version format: `MAJOR.MINOR.PATCH`

- **MAJOR**: Incompatible API changes
- **MINOR**: Backward-compatible functionality additions
- **PATCH**: Backward-compatible bug fixes

---

## Links

- [Documentation](files/GTIDEM_JS_Library_v1.6.pdf)
- [GitHub Pages](https://gotrustidem-dev.github.io/)
- [License](LICENSE)
