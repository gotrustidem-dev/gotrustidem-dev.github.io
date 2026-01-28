# 📦 IdemKey+ v1.14 版本文件總覽

## 🎯 版本資訊

**版本號:** 1.14.0  
**發布日期:** 2026-01-26  
**類型:** 現代化重構版本

---

## 📁 核心文件清單

### 1. 主要 API 文件

#### [utils/PKIoverFIDO_1_14.js](utils/PKIoverFIDO_1_14.js)
- **類型:** JavaScript ES6 Module
- **大小:** ~18 KB
- **說明:** 現代化的主要 API 文件
- **特點:**
  - ✅ ES6 模組導出
  - ✅ 類別導向設計
  - ✅ 完整 JSDoc 註解
  - ✅ 支援 CommonJS 和 ESM

**使用:**
```javascript
import { IdemKeyPlusAPI } from './utils/PKIoverFIDO_1_14.js';
const api = new IdemKeyPlusAPI();
```

---

#### [utils/PKIoverFIDO_1_14.d.ts](utils/PKIoverFIDO_1_14.d.ts)
- **類型:** TypeScript 類型定義
- **大小:** ~7 KB
- **說明:** 完整的 TypeScript 類型支援
- **特點:**
  - ✅ 所有類別的類型定義
  - ✅ 完整的方法簽名
  - ✅ IDE 自動完成支援
  - ✅ 編譯時類型檢查

**使用:**
```typescript
import { IdemKeyPlusAPI, GTIdemResponse } from './utils/PKIoverFIDO_1_14.js';
const api: IdemKeyPlusAPI = new IdemKeyPlusAPI();
```

---

### 2. 文檔文件

#### [utils/README_v1.14.md](utils/README_v1.14.md)
- **類型:** Markdown 文檔
- **大小:** ~15 KB
- **說明:** 完整的 API 使用文檔
- **內容:**
  - 快速開始指南
  - 完整 API 參考
  - 使用範例
  - 遷移指南
  - 常見問題

---

#### [VERSION_1.14_RELEASE.md](VERSION_1.14_RELEASE.md)
- **類型:** Markdown 文檔
- **大小:** ~12 KB
- **說明:** 版本發布說明
- **內容:**
  - 新功能介紹
  - 改進項目
  - 版本對比
  - 遷移步驟
  - 更新日誌

---

### 3. 範例文件

#### [example_modern_usage.html](example_modern_usage.html)
- **類型:** HTML + JavaScript
- **大小:** ~15 KB
- **說明:** 互動式使用範例（已更新至 v1.14）
- **功能:**
  - 🎨 完整的 UI 界面
  - 🔧 所有主要功能演示
  - ✨ 實時錯誤處理
  - 📱 響應式設計

**使用:** 直接在瀏覽器中打開即可

---

## 🔗 文件關聯圖

```
IdemKey+ v1.14
│
├── 📄 核心 API
│   ├── PKIoverFIDO_1_14.js ────────► 主要 JavaScript API
│   └── PKIoverFIDO_1_14.d.ts ──────► TypeScript 類型定義
│
├── 📚 文檔
│   ├── README_v1.14.md ────────────► 使用文檔
│   ├── VERSION_1.14_RELEASE.md ────► 發布說明
│   └── INDEX_v1.14.md ─────────────► 本文件（總覽）
│
└── 🎯 範例
    └── example_modern_usage.html ──► 互動式範例
```

---

## 🚀 快速開始

### 方式 1: 查看範例（推薦新手）

1. 打開 `example_modern_usage.html`
2. 按照頁面指示進行操作
3. 查看實時結果

### 方式 2: 閱讀文檔

1. 閱讀 `README_v1.14.md` 了解完整 API
2. 參考範例代碼
3. 在項目中整合

### 方式 3: 直接使用

```html
<!DOCTYPE html>
<html>
<head>
    <title>IdemKey+ v1.14 示例</title>
</head>
<body>
    <script type="module">
        import { IdemKeyPlusAPI, toUTF8Array } from './utils/PKIoverFIDO_1_14.js';
        
        const api = new IdemKeyPlusAPI();
        console.log(`版本: ${api.getVersion()}`); // 1.14.0
        
        // 您的代碼...
    </script>
</body>
</html>
```

---

## 📋 功能清單

### 核心功能

| 功能 | 方法名 | 文件位置 |
|------|--------|----------|
| 獲取版本 | `getVersion()` | PKIoverFIDO_1_14.js |
| Token 資訊 | `getTokenInfo(sn)` | PKIoverFIDO_1_14.js |
| 變更 PIN | `changeUserPIN(old, new, sn)` | PKIoverFIDO_1_14.js |
| 生成 P256 CSR | `genP256CSR(sn, cn)` | PKIoverFIDO_1_14.js |
| 生成 RSA CSR | `genRSA2048CSR(sn, cn)` | PKIoverFIDO_1_14.js |
| 數位簽章 | `signDataByIndex(i, sn, alg, d)` | PKIoverFIDO_1_14.js |
| 讀取憑證 | `readCertByIndexWithoutPIN(i, sn)` | PKIoverFIDO_1_14.js |

### 工具函數

| 功能 | 方法名 | 用途 |
|------|--------|------|
| 字串轉 UTF-8 | `toUTF8Array(str)` | 準備輸入資料 |
| Hex 轉 Buffer | `hexStringToArrayBuffer(hex)` | 處理十六進位 |
| Buffer 轉 Hex | `bufferToHex(buf)` | 顯示結果 |
| Base64 編碼 | `base64EncodeURL(buf)` | URL 安全編碼 |

---

## 🎓 學習路徑

### 初學者

1. **第一步:** 打開 `example_modern_usage.html`
   - 查看即時演示
   - 了解基本操作

2. **第二步:** 閱讀 `README_v1.14.md` 前半部分
   - 快速開始指南
   - 基本使用範例

3. **第三步:** 開始編寫簡單代碼
   - 獲取 Token 資訊
   - 讀取憑證

### 進階使用者

1. **研究完整 API:** 閱讀 `README_v1.14.md`
2. **查看類型定義:** 參考 `PKIoverFIDO_1_14.d.ts`
3. **整合到項目:** 使用打包工具優化

### 專家級

1. **源碼研究:** 查看 `PKIoverFIDO_1_14.js` 實現
2. **性能優化:** 研究最佳實踐
3. **擴展功能:** 基於 API 開發自定義功能

---

## 🔄 與其他版本對比

| 版本 | 文件名 | 特點 | 推薦用途 |
|------|--------|------|----------|
| **1.14.0** | PKIoverFIDO_1_14.js | 現代化、模組化 | ✅ **新專案推薦** |
| 1.12.3-modern | PKIoverFIDO_1_12.modern.js | 過渡版本 | 測試用途 |
| 1.12.3 | PKIoverFIDO_1_12.js | 原始版本 | 舊專案維護 |

---

## 📊 技術規格

### API 規格

- **語言:** JavaScript ES2020+
- **模組系統:** ES6 Modules + CommonJS
- **類型支援:** TypeScript
- **文檔格式:** JSDoc 3.0
- **瀏覽器 API:** WebAuthn, Web Crypto

### 文件規格

| 項目 | 規格 |
|------|------|
| 字元編碼 | UTF-8 |
| 行結尾 | LF (Unix) |
| 縮排 | 2 空格 |
| 最大行長 | 100 字元 |

---

## 🛠️ 開發環境建議

### 推薦工具

1. **編輯器:**
   - Visual Studio Code
   - WebStorm

2. **擴展（VS Code）:**
   - JavaScript and TypeScript Nightly
   - Path Intellisense
   - ESLint

3. **瀏覽器:**
   - Chrome DevTools
   - Firefox Developer Tools

### 配置文件

#### jsconfig.json
```json
{
  "compilerOptions": {
    "module": "ES2020",
    "target": "ES2020",
    "checkJs": true
  },
  "include": ["utils/**/*"]
}
```

#### .editorconfig
```ini
root = true

[*.js]
charset = utf-8
end_of_line = lf
indent_style = space
indent_size = 2
insert_final_newline = true
```

---

## 📦 部署建議

### 開發環境

```
project/
├── utils/
│   ├── PKIoverFIDO_1_14.js
│   └── PKIoverFIDO_1_14.d.ts
├── src/
│   └── your-app.js
└── index.html
```

### 生產環境

建議使用打包工具：

1. **Rollup** - 適合庫打包
2. **Webpack** - 適合應用打包
3. **Vite** - 現代開發服務器

---

## ⚡ 效能指標

### 檔案大小

| 文件 | 原始大小 | Gzip | Brotli |
|------|---------|------|--------|
| PKIoverFIDO_1_14.js | 18 KB | 6 KB | 5 KB |
| PKIoverFIDO_1_14.d.ts | 7 KB | 2 KB | 1.5 KB |

### 載入時間（估計）

- **3G 網路:** ~200ms
- **4G 網路:** ~50ms
- **WiFi:** ~10ms
- **本地:** <1ms

---

## 🔐 安全性檢查清單

使用前請確認：

- ✅ 使用 HTTPS 協議
- ✅ 驗證設備序列號
- ✅ 清除敏感資料（PIN）
- ✅ 錯誤訊息不洩漏資訊
- ✅ 實施速率限制
- ✅ 記錄安全事件

---

## 📞 獲取幫助

### 文檔資源

1. **API 文檔:** [README_v1.14.md](utils/README_v1.14.md)
2. **發布說明:** [VERSION_1.14_RELEASE.md](VERSION_1.14_RELEASE.md)
3. **範例代碼:** [example_modern_usage.html](example_modern_usage.html)

### 常見問題

查看 `README_v1.14.md` 中的「常見問題」章節

### 技術支援

聯繫 GoTrustID 技術支援團隊

---

## 📝 更新資訊

### 版本檢查

```javascript
import { VERSION } from './utils/PKIoverFIDO_1_14.js';
console.log(`當前版本: ${VERSION}`); // "1.14.0"
```

### 後續更新

關注 `CHANGELOG.md` 獲取最新更新資訊

---

## 🎉 總結

IdemKey+ v1.14 提供：

✨ **現代化** - ES6+ 模組系統  
🎯 **類型安全** - 完整 TypeScript 支援  
📚 **完整文檔** - 詳細的使用說明  
🚀 **高效能** - 優化的打包體積  
🔧 **易用性** - 清晰的 API 設計  

**立即開始使用 v1.14！**

---

**最後更新:** 2026-01-26  
**維護者:** GoTrustID Team  
**授權:** MIT License
