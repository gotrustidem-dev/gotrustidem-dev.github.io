---
name: browser-test
description: Run IdemKey+ cross-browser tests with Playwright. Use when user wants to test views_1_12 pages, run browser tests, or validate device functionality across Chrome/Edge/Firefox/Safari.
argument-hint: "[--browser chrome|edge|firefox|safari|all] [--test test_name] [--list]"
disable-model-invocation: true
allowed-tools: Bash, Read, Write, Edit, Glob, Grep
---

# IdemKey+ Cross-Browser Test Runner

Run automated browser tests for IdemKey+ hardware security key web pages using Playwright.

## Setup

- Test framework: `tests/` directory
- Report output: `tests/reports/`
- Runner script: `run_tests.py`
- Local server required: `python -m http.server 8000` (start if not running)

## Available Tests

All tests use the All-in-One page `views_1_12/TestAll.html`. Each file = one feature tab in the report.

| Test File | Report Tab | Tests | Description |
|-----------|------------|-------|-------------|
| `test_get_token_info` | Get Token Info | 4 | No SN, with SN, wrong SN, RN uniqueness |
| `test_gen_csr_import` | Gen Csr Import | 5 | P256/P384/P521/RSA2048 key types + clear flag |
| `test_read_cert` | Read Cert | 1 | Read certificate by index |
| `test_sign_data` | Sign Data | 1 | ECDSA SHA256 signature |
| `test_delete_cert` | Delete Cert | 2 | Delete by label + clear all certs |
| `test_change_pin` | Change Pin | 1 | Change PIN and restore to default |
| `test_unlock_pin` | Unlock Pin | 2 | Unlock PIN + unlock with expired flag |

## How to Run

Parse `$ARGUMENTS` for options:

### List available tests
If `$ARGUMENTS` contains `--list`, list all test files in `tests/` matching `test_*.py` and show their test functions.

### Run tests
1. **Ensure local server is running** on port 8000. Check with `curl -s http://localhost:8000/ > /dev/null 2>&1` — if not running, start it in background: `python -m http.server 8000`

2. **Run the test command (Windows uses UAC elevation automatically):**

   `run_tests.py` includes automatic administrator elevation on Windows via `ctypes.windll.shell32.ShellExecuteW` with `runas`. When not already admin, it triggers a UAC prompt and re-launches itself in a **new elevated window**. Therefore:

   ```
   cd "<project_root>"
   python run_tests.py [--browser BROWSER] [--test TEST_NAME]
   ```

   - Default browser: `all` (Chrome + Edge + Firefox on Windows; + Safari on macOS)
   - Default test: all test files
   - On Windows: the script auto-elevates via UAC. Tests run in a **new administrator window**, not in the current terminal. Inform the user that results will appear in the new window and in the report file.

3. **Show results** to user:
   - On Windows: remind user that output is in the elevated window since tests run in a separate process
   - Pass/fail counts per browser
   - Path to generated HTML report in `tests/reports/`
   - If any tests failed, show the failure details

### Examples from $ARGUMENTS
- (empty) → run all tests, all browsers
- `--browser chrome` → run all tests on Chrome only
- `--test test_get_token_info` → run GetTokenInfo tests on all browsers
- `--browser edge --test test_get_token_info` → run GetTokenInfo on Edge only
- `--list` → list available tests without running

## Notes on Interactive Tests

Some tests require user interaction:
- **EC Point re-plug test**: Shows a browser prompt asking user to unplug and re-plug the IdemKey+ device, then click "繼續測試" button
- **Wrong SN test**: May trigger alert dialogs in the browser

When running these tests, inform the user they need to watch the browser window for prompts.

## Report

Each run generates an HTML report with:
- **Overview tab**: Features, test counts, pass/fail per browser
- **Feature tabs**: Detailed per-test results with browser breakdown
- Report path format: `tests/reports/report_{os}_{browser}_{timestamp}.html`

## Adding New Tests

To add a test for a new page (e.g., `SignDataWithPIN`):
1. Create `tests/test_sign_data_with_pin.py`
2. Use fixtures: `page`, `base_url`, `browser_name`, `browser_config`
3. Follow existing test patterns in `tests/test_get_token_info.py`
4. The report plugin auto-discovers new test files

## Device Configuration

- Device SN: defined as `DEVICE_SN` in each test file
- Base URL: `http://localhost:8000` (configured in `tests/conftest.py`)
- WebAuthn timeout: 120 seconds
- Supported browsers per platform defined in `tests/conftest.py`
