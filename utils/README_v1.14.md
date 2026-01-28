# IdemKey+ JavaScript Library v1.14

## 🎉 版本更新說明

### Version 1.14.0 (2026-01)

這是 **現代化、模組化** 的 IdemKey+ JavaScript API，從 1.12.3 版本重構並升級至 1.14.0。

---

## 📦 核心文件

### 主要文件

| 檔案 | 說明 |
|------|------|
| `PKIoverFIDO_1_14.js` | 主要 API 文件（ES6 模組） |
| `PKIoverFIDO_1_14.d.ts` | TypeScript 類型定義 |
| `example_modern_usage.html` | 互動式使用範例 |

---

## 🚀 快速開始

### 1. 基本引入

```html
<script type="module">
  import { IdemKeyPlusAPI } from './utils/PKIoverFIDO_1_14.js';
  
  const api = new IdemKeyPlusAPI();
  console.log(`版本: ${api.getVersion()}`); // 1.14.0
</script>
```

### 2. 使用預設實例

```javascript
import { idemKeyAPI } from './utils/PKIoverFIDO_1_14.js';

// 直接使用
const version = idemKeyAPI.getVersion();
```

### 3. TypeScript 支援

```typescript
import { 
  IdemKeyPlusAPI, 
  GTIdemResponse,
  Algorithms 
} from './utils/PKIoverFIDO_1_14.js';

const api: IdemKeyPlusAPI = new IdemKeyPlusAPI();
```

---

## 💡 主要特點

### ✅ 完全模組化

```javascript
// 只引入需要的部分
import { toUTF8Array, bufferToHex } from './utils/PKIoverFIDO_1_14.js';

// 或引入所有功能
import * as IdemKey from './utils/PKIoverFIDO_1_14.js';
```

### ✅ 類別導向設計

```javascript
const api = new IdemKeyPlusAPI();

// 所有方法都是實例方法
await api.getTokenInfo(serialNumber);
await api.changeUserPIN(oldPIN, newPIN, serialNumber);
await api.signDataByIndex(index, serialNumber, algorithm, data);
```

### ✅ 現代化常數組織

```javascript
import { Commands, Algorithms, KeyTypes } from './utils/PKIoverFIDO_1_14.js';

// 清晰的命名空間
const cmd = Commands.TOKEN_INFO;
const algo = Algorithms.ECDSA_SHA256;
const keyType = KeyTypes.EC_SECP256R1;
```

### ✅ 改進的錯誤處理

```javascript
import { IdemKeyError } from './utils/PKIoverFIDO_1_14.js';

try {
  const response = await api.getTokenInfo(serialNumber);
  if (!response.isSuccess()) {
    console.error('操作失敗:', response.statusMessage);
  }
} catch (error) {
  if (error instanceof IdemKeyError) {
    console.error('IdemKey 錯誤碼:', error.statusCode);
  }
}
```

---

## 📖 完整 API 參考

### 核心類別

#### `IdemKeyPlusAPI`

主要 API 類別，提供所有 IdemKey+ 功能。

```javascript
const api = new IdemKeyPlusAPI();
```

**屬性:**
- `username: string` - FIDO 操作使用的用戶名

**方法:**

##### 基本操作
- `setUsername(name: string): void` - 設置用戶名
- `getVersion(): string` - 獲取 API 版本

##### Token 管理
- `getTokenInfo(serialNumber: Uint8Array): Promise<GTIdemResponse>`
- `initToken(serialNumber, encryptedInitData, hmacValue): Promise<GTIdemResponse>`
- `clearToken(serialNumber: Uint8Array): Promise<GTIdemResponse>`
- `factoryResetToken(serialNumber, encChallenge): Promise<GTIdemResponse>`

##### PIN 管理
- `isValidPIN(pin: Uint8Array, pinFlag: number): boolean`
- `changeUserPIN(oldPIN, newPIN, serialNumber): Promise<GTIdemResponse>`

##### 密鑰與憑證
- `genP256CSR(serialNumber, commonName, afterClear?): Promise<GTIdemResponse>`
- `genP384CSR(serialNumber, commonName, afterClear?): Promise<GTIdemResponse>`
- `genP521CSR(serialNumber, commonName, afterClear?): Promise<GTIdemResponse>`
- `genRSA2048CSR(serialNumber, commonName, afterClear?): Promise<GTIdemResponse>`
- `readCertByIndexWithoutPIN(index, serialNumber): Promise<GTIdemResponse>`
- `readCertByLabelWithoutPIN(label, serialNumber): Promise<GTIdemResponse>`

##### 簽章操作
- `signDataByIndex(index, serialNumber, algorithm, data): Promise<GTIdemResponse>`
- `signDataByLabel(label, serialNumber, algorithm, data): Promise<GTIdemResponse>`

---

### 常數對象

#### `Commands`
所有命令代碼的枚舉對象。

```javascript
Commands.TOKEN_INFO          // 0xE2
Commands.CHANGE_PIN          // 0xE8
Commands.READ_CERTIFICATE    // 0xE1
// ... 更多命令
```

#### `Algorithms`
支援的簽章演算法。

```javascript
Algorithms.ECDSA_SHA256         // 0x0a
Algorithms.RSA2048_SHA256       // 0x02
Algorithms.RSA2048_SHA256_PSS   // 0x06
// ... 更多演算法
```

#### `KeyTypes`
支援的密鑰類型。

```javascript
KeyTypes.RSA_2048      // 1
KeyTypes.EC_SECP256R1  // 2
KeyTypes.EC_SECP384R1  // 3
KeyTypes.EC_SECP521R1  // 4
```

---

### 工具函數

```javascript
// 字串轉換
toUTF8Array(str: string): Uint8Array

// 十六進位處理
hexStringToArrayBuffer(hexString: string): Uint8Array
bufferToHex(buffer: ArrayBuffer | Uint8Array): string

// 格式化
convertVersionFormat(buffer: Uint8Array): string
convertSNFormat(buffer: Uint8Array): string

// Base64 編碼
base64EncodeURL(buffer: ArrayBuffer | Uint8Array): string
```

---

## 📝 使用範例

### 獲取 Token 資訊

```javascript
import { IdemKeyPlusAPI, toUTF8Array } from './utils/PKIoverFIDO_1_14.js';

const api = new IdemKeyPlusAPI();
const serialNumber = toUTF8Array('YOUR_SERIAL_NUMBER');

const response = await api.getTokenInfo(serialNumber);
if (response.isSuccess()) {
  console.log('Token 資訊:', response.data);
} else {
  console.error('錯誤:', response.statusMessage);
}
```

### 生成 P256 憑證簽署請求

```javascript
const serialNumber = toUTF8Array('SN123456');
const commonName = toUTF8Array('My Certificate');

const response = await api.genP256CSR(serialNumber, commonName);

if (response.isSuccess()) {
  const csrHex = bufferToHex(response.data);
  console.log('CSR (Hex):', csrHex);
}
```

### 數位簽章

```javascript
import { Algorithms } from './utils/PKIoverFIDO_1_14.js';

const certIndex = 0;
const serialNumber = toUTF8Array('SN123456');
const dataToSign = toUTF8Array('Important Document');

const response = await api.signDataByIndex(
  certIndex,
  serialNumber,
  Algorithms.ECDSA_SHA256,
  dataToSign
);

if (response.isSuccess()) {
  const signature = bufferToHex(response.data);
  console.log('簽章:', signature);
}
```

### 變更 PIN

```javascript
const oldPIN = toUTF8Array('1234');
const newPIN = toUTF8Array('5678');
const serialNumber = toUTF8Array('SN123456');

const response = await api.changeUserPIN(oldPIN, newPIN, serialNumber);

if (response.isSuccess()) {
  console.log('✅ PIN 變更成功！');
} else {
  console.error('❌ PIN 變更失敗:', response.statusMessage);
}
```

---

## 🔄 從舊版本遷移

### 從 1.12.x 遷移

#### 1. 更新引入路徑

```javascript
// 舊版 (1.12)
import { ... } from './PKIoverFIDO_1_12.modern.js';

// 新版 (1.14)
import { ... } from './utils/PKIoverFIDO_1_14.js';
```

#### 2. API 保持兼容

所有 API 方法名稱和參數保持不變，只需更新引入路徑即可。

```javascript
// 這些方法在 1.14 中完全相同
await api.getTokenInfo(serialNumber);
await api.changeUserPIN(oldPIN, newPIN, serialNumber);
await api.genP256CSR(serialNumber, commonName);
```

#### 3. 版本檢查

```javascript
const api = new IdemKeyPlusAPI();
console.log(api.getVersion()); // "1.14.0"
```

---

## 🛠️ 開發工具配置

### TypeScript 配置 (tsconfig.json)

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "module": "ES2020",
    "moduleResolution": "node",
    "allowSyntheticDefaultImports": true,
    "esModuleInterop": true
  }
}
```

### Package.json 配置

```json
{
  "type": "module",
  "exports": {
    ".": {
      "import": "./utils/PKIoverFIDO_1_14.js",
      "types": "./utils/PKIoverFIDO_1_14.d.ts"
    }
  }
}
```

---

## 🌐 瀏覽器兼容性

### 支援的瀏覽器

| 瀏覽器 | 最低版本 |
|--------|---------|
| Chrome | 67+ |
| Firefox | 60+ |
| Safari | 13+ |
| Edge | 79+ |

### 必要 API

- ✅ WebAuthn API
- ✅ Web Crypto API (crypto.subtle)
- ✅ ES6 Modules
- ✅ Async/Await
- ✅ Class syntax

---

## ⚡ 效能優化建議

### 1. 使用單一實例

```javascript
// ✅ 推薦：使用預設實例
import { idemKeyAPI } from './utils/PKIoverFIDO_1_14.js';

// ❌ 避免：每次都創建新實例
// const api = new IdemKeyPlusAPI();
```

### 2. 批次操作

```javascript
// ✅ 批次讀取多個憑證
const promises = [0, 1, 2].map(index => 
  api.readCertByIndexWithoutPIN(index, serialNumber)
);
const results = await Promise.all(promises);
```

### 3. 錯誤處理最佳實踐

```javascript
async function safeOperation() {
  try {
    const response = await api.getTokenInfo(serialNumber);
    
    if (!response.isSuccess()) {
      throw new Error(response.statusMessage);
    }
    
    return response.data;
  } catch (error) {
    if (error instanceof IdemKeyError) {
      // 處理設備特定錯誤
      console.error('設備錯誤:', error.statusCode);
    } else {
      // 處理一般錯誤
      console.error('一般錯誤:', error.message);
    }
    throw error;
  }
}
```

---

## 🔐 安全性建議

### 1. PIN 處理

```javascript
// ✅ 使用完後清除敏感資料
const pinArray = toUTF8Array(userInputPIN);
try {
  await api.changeUserPIN(oldPIN, pinArray, serialNumber);
} finally {
  pinArray.fill(0); // 清除記憶體中的 PIN
}
```

### 2. 序列號驗證

```javascript
function validateSerialNumber(sn) {
  // 實作序列號格式驗證
  if (!sn || sn.length === 0) {
    throw new Error('無效的序列號');
  }
  return toUTF8Array(sn);
}
```

### 3. 錯誤訊息處理

```javascript
// ❌ 避免洩漏敏感資訊
console.log('錯誤詳情:', error.message);

// ✅ 僅記錄必要資訊
console.log('操作失敗，錯誤代碼:', error.statusCode);
```

---

## 📊 版本歷史

### v1.14.0 (2026-01-26)
- ✨ 從 1.12.3 現代化重構
- ✅ 完整 ES6 模組支援
- ✅ TypeScript 類型定義
- ✅ 改進的 API 設計
- ✅ 更好的錯誤處理
- ✅ 完整的 JSDoc 文檔
- 📦 統一的檔案命名規範

### v1.12.3 (原始版本)
- 基礎功能實現
- 傳統全域函數設計

---

## ❓ 常見問題

### Q: 如何檢查設備是否連接？

```javascript
try {
  const response = await api.getTokenInfo(serialNumber);
  if (response.isSuccess()) {
    console.log('✅ 設備已連接');
  }
} catch (error) {
  console.log('❌ 設備未連接或不支援');
}
```

### Q: 如何處理超時？

WebAuthn API 預設有超時機制（120秒）。可以通過修改 `DEFAULT_TIMEOUT` 常數來調整。

### Q: 可以在 Node.js 中使用嗎？

由於依賴 WebAuthn 和 Web Crypto API，完整功能僅在瀏覽器中可用。工具函數可在 Node.js 使用。

### Q: 如何除錯？

```javascript
// 啟用詳細日誌
const api = new IdemKeyPlusAPI();
api.setUsername('MyApp-Debug');

// 檢查回應
const response = await api.getTokenInfo(serialNumber);
console.log('狀態碼:', response.statusCode);
console.log('狀態訊息:', response.statusMessage);
console.log('原始回應:', response.rawResponse);
```

---

## 📞 技術支援

### 資源

- 📄 [完整文檔](./MODERNIZATION_README.md)
- 🎯 [使用範例](./example_modern_usage.html)
- 📦 [原始碼](./utils/PKIoverFIDO_1_14.js)

### 聯繫方式

如有問題或建議，請聯繫 GoTrustID 技術支援團隊。

---

## 📄 授權

MIT License - 與原始庫相同的授權條款。

---

**版本 1.14.0** - 現代化、模組化、類型安全的 IdemKey+ JavaScript API

🚀 **現在就開始使用！** 打開 [example_modern_usage.html](./example_modern_usage.html) 查看互動式範例。
