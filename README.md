# GoTrust IdemKey+ JavaScript Library

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.13.1-green.svg)](CHANGELOG.md)

A comprehensive JavaScript library for integrating GoTrust IdemKey+ hardware security keys with web applications using FIDO2/WebAuthn standards for PKI operations.

## 🔑 Features

- **FIDO2/WebAuthn Integration**: Full support for W3C WebAuthn API
- **PKI Operations**: Complete certificate lifecycle management
- **Digital Signatures**: RSA and ECDSA signature algorithms
- **Secure PIN Management**: ECDH-based PIN encryption
- **Key Generation**: RSA-2048, P-256, P-384, P-521 support
- **Browser-Based**: No backend required, runs entirely in the browser
- **Multiple Versions**: Parallel version support (v1.7 - v1.13)

## 📋 Requirements

### Browser Support
- Chrome 67+
- Firefox 60+
- Edge 18+
- Safari 13+
- Opera 54+

### Hardware
- GoTrust IdemKey+ hardware security key
- USB port

### Protocol Support
- FIDO2/WebAuthn
- HTTPS (required, except localhost)

## 🚀 Quick Start

### Basic Usage

```html
<!DOCTYPE html>
<html>
<head>
    <script src="https://gotrustidem-dev.github.io/utils/cbor.js"></script>
    <script src="https://gotrustidem-dev.github.io/utils/helpers.js"></script>
    <script src="https://gotrustidem-dev.github.io/utils/PKIoverFIDO.js"></script>
</head>
<body>
    <script>
        // Read certificate without PIN
        GTIDEM_ReadCertByIndexWithoutPIN(0, serialNumber)
            .then(result => {
                console.log('Certificate:', result);
            });
    </script>
</body>
</html>
```

## 📚 Core API

### Certificate Management

```javascript
// Read certificate by index
await ReadCertByIndex(index);

// Read certificate by label
await ReadCertByLabel(label);

// Delete certificate
await GTIDEM_DeleteCertByLabel(label, serialNumber);
```

### Digital Signature

```javascript
// Sign data by index
await SignDataByIndex(index, algorithmNumber, plaintext);

// Sign data by label
await SignDataByLabel(label, algorithmNumber, plaintext);

// Sign with PIN verification
await GTIDEM_SignDataByIndex(index, serialNumber, algorithmNumber, plaintext);
```

### Key Generation

```javascript
// Generate RSA-2048 key pair
await GenRSA2048KeyPair();

// Generate CSR
await GTIDEM_GenRSA2048CSR(serialNumber, keyID);
```

### PIN Management

```javascript
// Change PIN
await GTIDEM_ChangeUserPIN(oldPIN, newPIN, serialNumber);

// Unlock PIN
await GTIDEM_UnlockPIN(serialNumber, encryptedData, hmacValue);
```

### Token Operations

```javascript
// Get token information
await GTIDEM_GetTokenInfo(serialNumber);

// Initialize token
await GTIDEM_InitToken(serialNumber, encryptedInitData, hmacValue);

// Clear token
await GTIDEM_ClearToken(serialNumber);
```

## 🎯 Demo Pages

### Available Demos
- [Read Certificate Without PIN](https://gotrustidem-dev.github.io/views/ReadCertWithoutPIN.html)
- [Sign Data](https://gotrustidem-dev.github.io/views/SignData.html)
- [Change PIN](https://gotrustidem-dev.github.io/views/ChangePIN.html)
- [Get Token Info](https://gotrustidem-dev.github.io/views/GetTokenInfo.html)
- [Delete Certificates](https://gotrustidem-dev.github.io/views/DeleteCerts.html)
- [Request CSR](https://gotrustidem-dev.github.io/views/RequestCSR.html)
- [Initialize Token](https://gotrustidem-dev.github.io/views/RequestInitToken.html)

## 🔐 Security Features

### PIN Encryption Flow
1. **ECDH Key Agreement**: Establish shared secret using P-256 curve
2. **PIN Hashing**: SHA-256 hash of user PIN
3. **AES Encryption**: AES-CBC encryption of PIN hash
4. **Secure Transmission**: Encrypted PIN sent via FIDO2 channel

### Supported Algorithms
- **RSA-2048-SHA256**: RSA signature with SHA-256
- **RSA-2048-SHA256-PreHash**: Pre-hashed data signature
- **ECDSA-P256**: NIST P-256 curve
- **ECDSA-P384**: NIST P-384 curve
- **ECDSA-P521**: NIST P-521 curve

## 📖 Documentation

- [API Documentation v1.6](files/GTIDEM_JS_Library_v1.6.pdf)
- [API Documentation v1.5](files/GTIDEM_JS_Library_v1.5.pdf)
- [API Documentation v1.4](files/GTIDEM_JS_Library_v1.4.pdf)
- [Changelog](CHANGELOG.md)

## 🏗️ Project Structure

```
gotrustidem-dev.github.io/
├── utils/                      # Core library files
│   ├── PKIoverFIDO.js         # Main library (latest)
│   ├── PKIoverFIDO_1_13.js    # Version 1.13
│   ├── PKIoverFIDO_1_12.js    # Version 1.12
│   ├── cbor.js                # CBOR encoding/decoding
│   ├── helpers.js             # Utility functions
│   └── response.js            # Response handlers
├── views/                      # Demo pages (latest)
│   ├── ReadCertWithoutPIN.html
│   ├── SignData.html
│   ├── ChangePIN.html
│   └── ...
├── views_1_13/                # Version-specific demos
├── views_1_12/
├── test/                      # Test cases
├── files/                     # Documentation PDFs
└── library/                   # Third-party libraries
```

## 🔧 Command Reference

### PKI Commands

| Command | Code | Description |
|---------|------|-------------|
| `CMD_ReadCertificate` | 0xE1 | Read certificate from token |
| `CMD_TokenInfo` | 0xE2 | Get token information |
| `CMD_Sign` | 0xE3 | Sign data without PIN |
| `CMD_SignWithPIN` | 0xE5 | Sign data with PIN |
| `CMD_ImportCertificate` | 0xE7 | Import certificate |
| `CMD_CHANGE_PIN` | 0xE8 | Change user PIN |
| `CMD_UNLOCK_PIN` | 0xE9 | Unlock PIN |
| `CMD_REQUESTCSR` | 0xEA | Request CSR |
| `CMD_DELEE_CERT` | 0xEB | Delete certificate |
| `CMD_CLEAR_TOKEN` | 0xEC | Clear token |
| `CMD_INIT_TOKEN` | 0xED | Initialize token |
| `CMD_GenKeyPair` | 0xEE | Generate key pair |

## ⚙️ Configuration

### Timeouts
```javascript
const DEFAULT_TIMEOUT = 120000;        // 120 seconds
const VERIFY_DEFAULT_TIMEOUT = 300000; // 300 seconds (PIN verification)
```

### PIN Requirements
```javascript
const TOKEN_MIN_PIN_LEN = 4;      // Minimum PIN length
const TOKEN_MAX_PIN_LEN = 63;     // Maximum PIN length
const TOKEN_MIN_SOPIN_LEN = 8;    // Minimum SO PIN length
const TOKEN_MAX_SOPIN_LEN = 16;   // Maximum SO PIN length
```

## 🧪 Testing

Run test cases in the browser:
- [Test Case: Generate Key](test/TestCase_GenKey.html)
- [Test Case: Get Token Info](test/TestCase_GetTokenInfo.html)
- [Test Case: Read Certificate](test/TestCase_ReadCert.html)
- [Integration Tests](TestGroup_IdemKeyPlus.html)

## 🤝 Use Cases

- **Electronic Signatures**: Hardware-based document signing
- **Certificate Management**: PKI certificate lifecycle
- **Two-Factor Authentication**: Strong authentication with FIDO2
- **Banking/Finance**: High-security identity verification
- **Enterprise PKI**: Hardware security key integration

## 📝 License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

## 🔗 Links

- **GitHub Pages**: [https://gotrustidem-dev.github.io/](https://gotrustidem-dev.github.io/)
- **Main Demo**: [IdemKeyPlus.html](https://gotrustidem-dev.github.io/IdemKeyPlus.html)

## 📞 Support

For technical support and documentation:
- Review the [API Documentation](files/GTIDEM_JS_Library_v1.6.pdf)
- Check the [Changelog](CHANGELOG.md) for version history
- Test with the provided demo pages

---

**Version**: 1.13.1  
**Last Updated**: January 12, 2026  
**Maintained by**: GoTrust ID
