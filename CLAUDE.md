# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

GoTrust IdemKey+ JavaScript Library — a browser-side JS library for integrating GoTrust IdemKey+ hardware security keys with web applications using FIDO2/WebAuthn for PKI operations. Deployed as a static GitHub Pages site at https://gotrustidem-dev.github.io/.

## Build & Development

There is **no build step**. The project uses raw HTML + JavaScript (ES6 modules) served directly via GitHub Pages. No bundler, no npm install required.

- **Serve locally**: Use any static HTTP server (e.g., `python -m http.server 8000`). HTTPS is required for WebAuthn except on localhost.
- **Lint/Format** (optional, not currently active): `eslint utils/PKIoverFIDO_1_12.modern.js` / `prettier --write ...` — see `package.json.example` for config.
- **Testing**: All tests are manual, browser-based HTML pages. Open test files directly in a browser with a connected IdemKey+ device:
  - `test/TestCase_GenKey.html`, `test/TestCase_GetTokenInfo.html`, `test/TestCase_ReadCert.html`
  - `TestGroup_IdemKeyPlus.html` (integration tests)
- **Python utility**: `check_low_s.py` validates ECDSA low-S signatures (requires `cryptography` package; `.venv/` exists).

## Architecture

### Two API Generations

1. **Legacy (v1.7–v1.13)**: Global functions like `GTIDEM_ReadCertByIndexWithoutPIN()`. Files: `utils/PKIoverFIDO.js` (~116KB), `utils/PKIoverFIDO_1_13.js`, etc. Each version is a standalone monolithic file that includes CBOR, helpers, and response handling inline.

2. **Modern (v1.14)**: ES6 module with a class-based API (`IdemKeyPlusAPI`). Files:
   - `utils/PKIoverFIDO_1_14.js` (~18KB) — main library, exports `IdemKeyPlusAPI`, `Commands`, `Algorithms`, `KeyTypes`, `IdemKeyError`, `GTIdemResponse`
   - `utils/PKIoverFIDO_1_14.d.ts` — TypeScript type definitions
   - `utils/PKIoverFIDO_1_12.modern.js` / `.d.ts` — transitional modern version of v1.12

### Shared Utility Modules (used by modern API)

- `utils/cbor.js` — CBOR encoder/decoder for FIDO2 CTAP protocol
- `utils/helpers.js` — Buffer conversion, endian reading, authenticator data parsing
- `utils/response.js` — Response parsing and status code mapping
- `utils/showMessage.js` — UI notification system

### View/Demo Pages

Each library version has its own view directory with interactive demo HTML pages:
- `views/` — latest version demos (ReadCertWithoutPIN, SignData, ChangePIN, GetTokenInfo, DeleteCerts, RequestCSR, etc.)
- `views_1_14/`, `views_1_12/`, `views_1_11/`, ... — version-specific demos

The main entry point `index.html` is a modern dashboard UI (v1.14) with Chinese language interface and real-time device connection status.

### Communication Flow

All operations follow this pattern:
1. Browser calls WebAuthn API (`navigator.credentials.create/get`) with CBOR-encoded command extensions
2. IdemKey+ hardware processes the PKI command and returns CBOR-encoded response
3. Library decodes CBOR response and returns structured result (`GTIdemResponse`)

PIN-protected operations add: ECDH P-256 key agreement → SHA-256 PIN hash → AES-CBC encryption → send encrypted PIN via FIDO2 channel.

## Key Conventions

- **Naming**: Classes use PascalCase (`IdemKeyPlusAPI`), constants use UPPER_SNAKE_CASE, methods use camelCase
- **Commands**: Hex codes in 0xE0–0xEF range (core) and 0xB2/0xC1–0xC8/0xF7 (extended)
- **Versioning**: Each major version keeps its own `PKIoverFIDO_X_XX.js` file and `views_X_XX/` directory — older versions are preserved, not overwritten
- **UI language**: Demo pages use Chinese (Traditional) for labels and instructions
- **Timeouts**: 120s default, 300s for PIN verification operations
- **PIN constraints**: User PIN 4–63 chars, SO PIN 8–16 chars
