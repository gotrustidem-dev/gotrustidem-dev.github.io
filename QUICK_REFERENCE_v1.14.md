# 🚀 IdemKey+ v1.14 快速參考

## 📥 引入方式

```javascript
// 方式 1: 引入完整 API
import { IdemKeyPlusAPI } from './utils/PKIoverFIDO_1_14.js';
const api = new IdemKeyPlusAPI();

// 方式 2: 引入預設實例
import { idemKeyAPI } from './utils/PKIoverFIDO_1_14.js';

// 方式 3: 引入特定功能
import { toUTF8Array, bufferToHex, Algorithms } from './utils/PKIoverFIDO_1_14.js';
```

---

## 🎯 常用操作

### 1. 初始化
```javascript
import { IdemKeyPlusAPI } from './utils/PKIoverFIDO_1_14.js';

const api = new IdemKeyPlusAPI();
api.setUsername('MyApp');
console.log(api.getVersion()); // "1.14.0"
```

### 2. 獲取 Token 資訊
```javascript
import { toUTF8Array } from './utils/PKIoverFIDO_1_14.js';

const sn = toUTF8Array('YOUR_SERIAL_NUMBER');
const response = await api.getTokenInfo(sn);

if (response.isSuccess()) {
  console.log('Token 資訊:', response.data);
}
```

### 3. 變更 PIN
```javascript
const oldPIN = toUTF8Array('1234');
const newPIN = toUTF8Array('5678');
const sn = toUTF8Array('SN123456');

const response = await api.changeUserPIN(oldPIN, newPIN, sn);
if (response.isSuccess()) {
  console.log('✅ PIN 變更成功');
}
```

### 4. 生成 CSR
```javascript
const sn = toUTF8Array('SN123456');
const cn = toUTF8Array('My Certificate');

// P256
const p256 = await api.genP256CSR(sn, cn);

// RSA 2048
const rsa = await api.genRSA2048CSR(sn, cn);
```

### 5. 數位簽章
```javascript
import { Algorithms, bufferToHex } from './utils/PKIoverFIDO_1_14.js';

const data = toUTF8Array('Document to sign');
const response = await api.signDataByIndex(
  0,                          // 憑證索引
  sn,                         // 序列號
  Algorithms.ECDSA_SHA256,    // 演算法
  data                        // 資料
);

if (response.isSuccess()) {
  const signature = bufferToHex(response.data);
  console.log('簽章:', signature);
}
```

### 6. 讀取憑證
```javascript
// 依索引讀取
const cert = await api.readCertByIndexWithoutPIN(0, sn);

// 依標籤讀取
const label = toUTF8Array('MyCert');
const cert2 = await api.readCertByLabelWithoutPIN(label, sn);
```

---

## 🔢 常用常數

### Commands
```javascript
import { Commands } from './utils/PKIoverFIDO_1_14.js';

Commands.TOKEN_INFO          // 0xE2
Commands.CHANGE_PIN          // 0xE8
Commands.READ_CERTIFICATE    // 0xE1
Commands.SIGN                // 0xE3
Commands.CLEAR_TOKEN         // 0xEC
```

### Algorithms
```javascript
import { Algorithms } from './utils/PKIoverFIDO_1_14.js';

Algorithms.ECDSA_SHA256         // 0x0a
Algorithms.ECDSA_SHA384         // 0x0b
Algorithms.RSA2048_SHA256       // 0x02
Algorithms.RSA2048_SHA256_PSS   // 0x06
```

### KeyTypes
```javascript
import { KeyTypes } from './utils/PKIoverFIDO_1_14.js';

KeyTypes.RSA_2048       // 1
KeyTypes.EC_SECP256R1   // 2
KeyTypes.EC_SECP384R1   // 3
KeyTypes.EC_SECP521R1   // 4
```

---

## 🛠️ 工具函數

```javascript
// 字串轉換
toUTF8Array('Hello')              // Uint8Array

// Hex 處理
hexStringToArrayBuffer('AABBCC')  // Uint8Array
bufferToHex(buffer)               // 'aabbcc'

// Base64
base64EncodeURL(buffer)           // URL 安全的 Base64

// 格式化
convertVersionFormat(buffer)      // '1.14.0'
convertSNFormat(buffer)          // 'a1b2c3d4'
```

---

## ⚠️ 錯誤處理

```javascript
import { IdemKeyError } from './utils/PKIoverFIDO_1_14.js';

try {
  const response = await api.getTokenInfo(sn);
  
  if (!response.isSuccess()) {
    console.error('操作失敗:', response.statusMessage);
  }
  
} catch (error) {
  if (error instanceof IdemKeyError) {
    console.error('IdemKey 錯誤:', error.statusCode);
  } else {
    console.error('一般錯誤:', error.message);
  }
}
```

---

## 📱 TypeScript

```typescript
import type { 
  IdemKeyPlusAPI, 
  GTIdemResponse 
} from './utils/PKIoverFIDO_1_14.js';

const api: IdemKeyPlusAPI = new IdemKeyPlusAPI();

async function getInfo(sn: Uint8Array): Promise<any> {
  const response: GTIdemResponse = await api.getTokenInfo(sn);
  return response.data;
}
```

---

## 🎨 完整範例

```html
<!DOCTYPE html>
<html>
<head>
    <title>IdemKey+ v1.14 範例</title>
</head>
<body>
    <h1>IdemKey+ Demo</h1>
    <button id="getInfo">Get Token Info</button>
    <pre id="result"></pre>

    <script type="module">
        import { 
            IdemKeyPlusAPI, 
            toUTF8Array, 
            bufferToHex 
        } from './utils/PKIoverFIDO_1_14.js';

        const api = new IdemKeyPlusAPI();
        api.setUsername('DemoApp');

        document.getElementById('getInfo').addEventListener('click', async () => {
            try {
                const sn = toUTF8Array('SN123456');
                const response = await api.getTokenInfo(sn);
                
                if (response.isSuccess()) {
                    document.getElementById('result').textContent = 
                        JSON.stringify(response.data, null, 2);
                } else {
                    alert('錯誤: ' + response.statusMessage);
                }
            } catch (error) {
                alert('異常: ' + error.message);
            }
        });
    </script>
</body>
</html>
```

---

## 📚 完整文檔連結

- **[完整 API 文檔](utils/README_v1.14.md)** - 所有 API 詳細說明
- **[發布說明](VERSION_1.14_RELEASE.md)** - 版本更新內容
- **[文件總覽](INDEX_v1.14.md)** - 所有文件索引
- **[互動範例](example_modern_usage.html)** - 實際操作示範

---

## 🔥 最佳實踐

### ✅ 推薦做法

```javascript
// 使用預設實例（單例模式）
import { idemKeyAPI } from './utils/PKIoverFIDO_1_14.js';

// 錯誤處理完整
try {
  const response = await idemKeyAPI.getTokenInfo(sn);
  if (!response.isSuccess()) {
    throw new Error(response.statusMessage);
  }
} catch (error) {
  // 處理錯誤
}

// 清除敏感資料
const pin = toUTF8Array(userInput);
try {
  await api.changeUserPIN(oldPIN, pin, sn);
} finally {
  pin.fill(0); // 清除
}
```

### ❌ 避免做法

```javascript
// ❌ 每次都創建新實例
const api1 = new IdemKeyPlusAPI();
const api2 = new IdemKeyPlusAPI();

// ❌ 忽略錯誤處理
await api.getTokenInfo(sn); // 沒有 try-catch

// ❌ 硬編碼敏感資訊
const pin = toUTF8Array('1234'); // 不安全
```

---

**版本:** 1.14.0  
**更新:** 2026-01-26  
**授權:** MIT
