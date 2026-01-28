# IdemKey+ JavaScript Library - 現代化版本

## 概述

這是 GoTrustID IdemKey+ JavaScript 庫的現代化版本，從原始的 `PKIoverFIDO_1_12.js` 重構而來，符合現代 JavaScript/TypeScript 最佳實踐。

## 主要改進

### 1. **ES6 模組系統**
- ✅ 使用 `export` 和 `import` 語法
- ✅ 支援樹搖（tree-shaking）
- ✅ 更好的代碼分割

### 2. **類別導向設計**
- ✅ 主要功能封裝在 `IdemKeyPlusAPI` 類別中
- ✅ 消除全域變數污染
- ✅ 更好的狀態管理

### 3. **TypeScript 支援**
- ✅ 完整的 `.d.ts` 類型定義文件
- ✅ 更好的 IDE 自動完成
- ✅ 編譯時類型檢查

### 4. **改進的命名規範**
```javascript
// 舊版
const CMD_ReadCertificate = 0xE1;
const ALG_RSA2048SHA256 = 0x02;

// 新版
const Commands = {
  READ_CERTIFICATE: 0xE1,
};
const Algorithms = {
  RSA2048_SHA256: 0x02,
};
```

### 5. **自定義錯誤類別**
```javascript
// 舊版
function IKPException(statusCode) {
  this.code = statusCode;
}

// 新版
export class IdemKeyError extends Error {
  constructor(statusCode, message = '') {
    super(message || `IdemKey error: ${statusCode}`);
    this.statusCode = statusCode;
  }
}
```

### 6. **雙模組系統支援**
- ✅ ES6 模組 (ESM)
- ✅ CommonJS (CJS)
- ✅ 瀏覽器全域變數（如需要）

### 7. **JSDoc 註解**
- ✅ 完整的 API 文檔
- ✅ 參數和返回值類型
- ✅ 使用示例

## 安裝

### 瀏覽器 (ES6 模組)

```html
<script type="module">
  import { IdemKeyPlusAPI, Algorithms, Commands } from './utils/PKIoverFIDO_1_12.modern.js';
  
  const api = new IdemKeyPlusAPI();
  // 使用 API...
</script>
```

### Node.js (CommonJS)

```javascript
const { IdemKeyPlusAPI, Algorithms, Commands } = require('./utils/PKIoverFIDO_1_12.modern.js');

const api = new IdemKeyPlusAPI();
```

### Node.js (ES6 模組)

```javascript
import { IdemKeyPlusAPI, Algorithms, Commands } from './utils/PKIoverFIDO_1_12.modern.js';

const api = new IdemKeyPlusAPI();
```

## 使用範例

### 基本設置

```javascript
import { createIdemKeyAPI } from './utils/PKIoverFIDO_1_12.modern.js';

// 方式 1: 使用工廠函數
const api = createIdemKeyAPI();

// 方式 2: 直接實例化
import { IdemKeyPlusAPI } from './utils/PKIoverFIDO_1_12.modern.js';
const api = new IdemKeyPlusAPI();

// 方式 3: 使用預設實例
import { idemKeyAPI } from './utils/PKIoverFIDO_1_12.modern.js';
```

### 設置用戶名

```javascript
api.setUsername('MyApplication');
```

### 獲取版本

```javascript
const version = api.getVersion();
console.log(`Library version: ${version}`);
```

### 獲取 Token 資訊

```javascript
import { toUTF8Array } from './utils/PKIoverFIDO_1_12.modern.js';

const serialNumber = toUTF8Array('your-serial-number');

try {
  const response = await api.getTokenInfo(serialNumber);
  
  if (response.isSuccess()) {
    console.log('Token info:', response.data);
  } else {
    console.error('Error:', response.statusMessage);
  }
} catch (error) {
  if (error instanceof IdemKeyError) {
    console.error('IdemKey error:', error.statusCode, error.message);
  }
}
```

### 更改 PIN

```javascript
const oldPIN = toUTF8Array('1234');
const newPIN = toUTF8Array('5678');
const serialNumber = toUTF8Array('SN123456');

try {
  const response = await api.changeUserPIN(oldPIN, newPIN, serialNumber);
  
  if (response.isSuccess()) {
    console.log('PIN changed successfully');
  } else {
    console.error('Failed to change PIN:', response.statusMessage);
  }
} catch (error) {
  console.error('Error:', error);
}
```

### 生成 CSR

```javascript
import { KeyTypes } from './utils/PKIoverFIDO_1_12.modern.js';

const serialNumber = toUTF8Array('SN123456');
const commonName = toUTF8Array('My Certificate');

// 生成 P256 CSR
const p256Response = await api.genP256CSR(serialNumber, commonName);

// 生成 RSA 2048 CSR
const rsaResponse = await api.genRSA2048CSR(serialNumber, commonName);

// 在清除 token 後生成
const response = await api.genP256CSR(serialNumber, commonName, true);
```

### 簽名資料

```javascript
import { Algorithms } from './utils/PKIoverFIDO_1_12.modern.js';

const certIndex = 0;
const serialNumber = toUTF8Array('SN123456');
const dataToSign = toUTF8Array('Data to sign');

const response = await api.signDataByIndex(
  certIndex,
  serialNumber,
  Algorithms.ECDSA_SHA256,
  dataToSign
);

if (response.isSuccess()) {
  console.log('Signature:', response.data);
}
```

### 讀取憑證

```javascript
const certIndex = 0;
const serialNumber = toUTF8Array('SN123456');

// 依索引讀取
const response = await api.readCertByIndexWithoutPIN(certIndex, serialNumber);

// 依標籤讀取
const label = toUTF8Array('MyCert');
const labelResponse = await api.readCertByLabelWithoutPIN(label, serialNumber);

if (response.isSuccess()) {
  console.log('Certificate:', response.data);
}
```

## TypeScript 使用

```typescript
import { 
  IdemKeyPlusAPI, 
  GTIdemResponse, 
  Algorithms,
  toUTF8Array 
} from './utils/PKIoverFIDO_1_12.modern.js';

async function signData(): Promise<void> {
  const api = new IdemKeyPlusAPI();
  const serialNumber: Uint8Array = toUTF8Array('SN123456');
  const data: Uint8Array = toUTF8Array('Hello World');
  
  const response: GTIdemResponse = await api.signDataByIndex(
    0,
    serialNumber,
    Algorithms.ECDSA_SHA256,
    data
  );
  
  if (response.isSuccess()) {
    console.log('Signature created successfully');
  }
}
```

## API 參考

### 類別

#### `IdemKeyPlusAPI`
主要 API 類別，提供所有 IdemKey+ 功能。

#### `GTIdemResponse`
回應物件，包含操作狀態和資料。

#### `IdemKeyError`
自定義錯誤類別。

### 常數

#### `Commands`
所有命令代碼的物件。

#### `Algorithms`
所有支援的演算法。

#### `KeyTypes`
支援的金鑰類型（RSA 2048, P256, P384, P521）。

#### `OutputTypes`
輸出格式類型（RAW, CSR）。

#### `PinFormats`
PIN 格式標誌。

#### `TokenFlags`
Token 狀態標誌。

### 工具函數

- `toUTF8Array(str)` - 將字串轉換為 UTF-8 位元組陣列
- `hexStringToArrayBuffer(hexString)` - 十六進位字串轉 ArrayBuffer
- `bufferToHex(buffer)` - ArrayBuffer 轉十六進位字串
- `convertVersionFormat(buffer)` - 格式化版本號
- `convertSNFormat(buffer)` - 格式化序列號
- `base64EncodeURL(buffer)` - Base64 URL 編碼

## 遷移指南

### 從舊版本遷移

#### 1. 更新引入語句

```javascript
// 舊版 (全域變數)
// <script src="PKIoverFIDO_1_12.js"></script>
// GTIDEM_GetTokenInfo(...)

// 新版 (ES6 模組)
import { IdemKeyPlusAPI } from './PKIoverFIDO_1_12.modern.js';
const api = new IdemKeyPlusAPI();
api.getTokenInfo(...);
```

#### 2. 更新常數使用

```javascript
// 舊版
const algo = ALG_ECDSASHA256;
const cmd = CMD_ReadCertificate;

// 新版
import { Algorithms, Commands } from './PKIoverFIDO_1_12.modern.js';
const algo = Algorithms.ECDSA_SHA256;
const cmd = Commands.READ_CERTIFICATE;
```

#### 3. 更新函數調用

```javascript
// 舊版 (全域函數)
await GTIDEM_GetTokenInfo(serialNumber);
await GTIDEM_ChangeUserPIN(oldPIN, newPIN, serialNumber);

// 新版 (類別方法)
const api = new IdemKeyPlusAPI();
await api.getTokenInfo(serialNumber);
await api.changeUserPIN(oldPIN, newPIN, serialNumber);
```

#### 4. 錯誤處理

```javascript
// 舊版
try {
  const result = await GTIDEM_GetTokenInfo(sn);
  if (result.statusCode !== 0) {
    // 錯誤處理
  }
} catch (e) {
  console.error(e);
}

// 新版
import { IdemKeyError } from './PKIoverFIDO_1_12.modern.js';

try {
  const response = await api.getTokenInfo(sn);
  if (!response.isSuccess()) {
    // 錯誤處理
  }
} catch (error) {
  if (error instanceof IdemKeyError) {
    console.error('IdemKey error:', error.statusCode);
  }
}
```

## 瀏覽器兼容性

此庫需要支援以下功能的現代瀏覽器：

- ✅ WebAuthn API
- ✅ Web Crypto API
- ✅ ES6+ (Promise, async/await, class)
- ✅ ES6 Modules (如使用模組版本)

支援的瀏覽器：
- Chrome/Edge 67+
- Firefox 60+
- Safari 13+

## 建構和打包

### 使用 Rollup

```javascript
// rollup.config.js
export default {
  input: 'utils/PKIoverFIDO_1_12.modern.js',
  output: [
    {
      file: 'dist/idemkey.esm.js',
      format: 'esm'
    },
    {
      file: 'dist/idemkey.cjs.js',
      format: 'cjs'
    },
    {
      file: 'dist/idemkey.umd.js',
      format: 'umd',
      name: 'IdemKeyPlus'
    }
  ]
};
```

### 使用 Webpack

```javascript
// webpack.config.js
module.exports = {
  entry: './utils/PKIoverFIDO_1_12.modern.js',
  output: {
    filename: 'idemkey.bundle.js',
    library: 'IdemKeyPlus',
    libraryTarget: 'umd'
  }
};
```

## 最佳實踐

### 1. 單一實例

```javascript
// 推薦：在應用程式中使用單一實例
import { idemKeyAPI } from './PKIoverFIDO_1_12.modern.js';

// 在整個應用程式中使用
export { idemKeyAPI };
```

### 2. 錯誤處理

```javascript
import { IdemKeyError } from './PKIoverFIDO_1_12.modern.js';

async function safeOperation() {
  try {
    const response = await api.getTokenInfo(serialNumber);
    
    if (!response.isSuccess()) {
      // 處理操作失敗
      throw new Error(response.statusMessage);
    }
    
    return response.data;
  } catch (error) {
    if (error instanceof IdemKeyError) {
      // 處理 IdemKey 特定錯誤
      console.error('Device error:', error.statusCode);
    } else {
      // 處理其他錯誤
      console.error('General error:', error.message);
    }
    throw error;
  }
}
```

### 3. 類型安全（TypeScript）

```typescript
import type { GTIdemResponse } from './PKIoverFIDO_1_12.modern.js';

interface TokenInfo {
  version: string;
  serialNumber: string;
  // ... 其他欄位
}

async function getTokenInfoTyped(
  serialNumber: Uint8Array
): Promise<TokenInfo> {
  const response: GTIdemResponse = await api.getTokenInfo(serialNumber);
  
  if (!response.isSuccess()) {
    throw new Error('Failed to get token info');
  }
  
  return response.data as TokenInfo;
}
```

## 常見問題

### Q: 為什麼要使用現代化版本？

**A:** 現代化版本提供：
- 更好的代碼組織和維護性
- TypeScript 支援
- 樹搖優化（減少打包大小）
- 更好的 IDE 支援
- 符合現代 JavaScript 標準

### Q: 可以在 Node.js 中使用嗎？

**A:** 部分功能可以，但由於依賴 WebAuthn 和 Web Crypto API，完整功能僅在瀏覽器中可用。

### Q: 向後兼容嗎？

**A:** 這是一個重構版本，API 有所改變。請參考遷移指南進行更新。

### Q: 如何處理離線場景？

**A:** 此庫設計為客戶端庫，所有加密操作在瀏覽器中進行。確保在使用前檢查網路狀態和設備可用性。

## 授權

與原始庫相同的授權條款。

## 支援

如有問題或建議，請聯繫 GoTrustID 技術支援。

## 版本歷史

### 1.12.3-modern (2026-01)
- 初始現代化版本
- ES6 模組支援
- TypeScript 類型定義
- 改進的 API 設計
- 完整文檔

---

**注意：** 這是基於原始 `PKIoverFIDO_1_12.js` 的現代化重構。部分功能實現需要參考原始文件完成。
