# 🛡️ Window Nginx Auto Ban System

自動監控 Nginx 日誌，偵測惡意攻擊並透過 Windows 防火牆自動封禁攻擊 IP。

---

## 📋 功能特色

- **即時監控** — 每秒掃描 Nginx 日誌增量變化，即時偵測攻擊
- **多層次偵測** — 整合攻擊狀態碼（429/502/503/504）、可疑 URL 路徑、已知掃描器 User-Agent、403 大量掃描
- **自動封禁** — 達到閾值自動將 IP 加入 Windows 防火牆黑名單
- **子網封鎖** — 支援 `auto`（智慧升級）/ `force`（強制 /24）/ `off` 三種模式
- **Web 管理介面** — 內建儀表板，檢視封禁列表、審查可疑 IP、管理偵測規則、查閱日誌
- **郵件告警** — 首次封鎖 IP 時發送 HTML/純文字雙格式通知
- **IP 地理位置** — 離線查詢攻擊 IP 的國家/地區資訊（geoip-lite）
- **白名單** — 支援單一 IP 及 CIDR 格式的白名單
- **跨日換檔** — 自動偵測 Nginx 日誌輪轉，無縫切換新日誌檔
- **管理員權限處理** — 自動偵測權限，非管理員時以 UAC 提權執行防火牆操作

---

## 🏗️ 架構

```
window-nginx-auto-ban/
├── src/
│   ├── index.ts          # 主程式入口、監控排程、封鎖邏輯
│   ├── config.ts         # 環境變數設定載入
│   ├── types.ts          # TypeScript 型別定義
│   ├── logParser.ts      # Nginx 日誌解析與攻擊偵測
│   ├── firewall.ts       # Windows 防火牆操作（netsh / PowerShell）
│   ├── email.ts          # 郵件通知（nodemailer）
│   ├── webServer.ts      # Web 管理介面後端
│   ├── ipLocation.ts     # IP 地理位置查詢（geoip-lite）
│   └── logger.ts         # 彩色終端機日誌
├── public/
│   └── index.html        # Web 管理介面前端
├── patterns.json         # 可疑路徑模式與掃描器 UA 設定檔
├── banned_ips.json       # 已封禁 IP 記錄（自動產生）
├── suspicious_ips.json   # 可疑 IP 審查記錄（自動產生）
├── .env                  # 環境變數設定
├── package.json
└── tsconfig.json
```

---

## 🚀 快速開始

### 前置需求

- **Node.js** ≥ 18
- **pnpm**（建議）或 npm
- **Windows**（防火牆操作依賴 Windows Firewall）
- **系統管理員權限**（用於防火牆規則操作，非管理員會彈出 UAC 視窗）

### 安裝

```bash
# 安裝依賴
pnpm install

# 編譯 TypeScript
pnpm build
```

### 設定環境變數

建立 `.env` 檔案：

```env
# Nginx 日誌目錄（程式會自動拼接 access-YYYY-MM-DD.log）
NGINX_LOG_PATH=C:/nginx/logs/

# 封禁閾值：每分鐘可疑請求次數
BAN_THRESHOLD=30

# 監控模式：true=即時監控，false=定時掃描
REAL_TIME_MONITORING=true

# 定時掃描間隔（秒，僅 REAL_TIME_MONITORING=false 時生效）
SCAN_INTERVAL=60

# 自動封禁開關：false 僅記錄不封鎖（手動審查模式）
AUTO_BAN=true

# 子網封鎖模式：off=僅封單IP, auto=智慧升級, force=強制封/24
BAN_SUBNET=auto

# IP 白名單（逗號分隔）
WHITELIST=127.0.0.1,192.168.1.0/24

# 郵件通知
SMTP_ENABLED=true
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
ALERT_EMAIL=admin@example.com

# Web 管理介面
WEB_ENABLED=true
WEB_PORT=3001
WEB_USERNAME=admin
WEB_PASSWORD=admin123

# 除錯模式
DEBUG=false

# 自訂模式檔路徑（可選，預設為 patterns.json）
PATTERNS_FILE=./patterns.json
```

### 執行

```bash
# 開發模式（ts-node 直接執行）
pnpm dev

# 生產模式（先編譯再執行）
pnpm build && pnpm start

# PM2 守護程序
pnpm pm2:start
pnpm pm2:logs
```

---

## 🔍 攻擊偵測邏輯

系統採用**多層次偵測**，符合任一條件即標記為可疑：

| 層級 | 偵測方式 | 說明 |
|------|----------|------|
| 1 | 攻擊狀態碼 | 429（限流）、502、503、504 |
| 2 | 可疑 URL 路徑 | 比對 `patterns.json` 中的模式（如 `.env`、`wp-admin`、`phpMyAdmin` 等） |
| 3 | 掃描器 User-Agent | 比對已知工具（如 sqlmap、nmap、nessus、burpsuite 等） |
| 4 | 403 大量掃描 | 大量回傳 403 的請求 |

### 封鎖條件（滿足其一即觸發）

1. 1 分鐘內可疑請求數 ≥ `BAN_THRESHOLD`
2. 匹配 ≥ 3 種不同的可疑路徑模式

---

## 🖥️ Web 管理介面

啟動後瀏覽 `http://localhost:3001`（預設帳密：`admin` / `admin123`）

### 功能頁籤

| 頁籤 | 功能 |
|------|------|
| 📊 **儀表板** | 已封禁 IP 數、待審查數、今日封禁統計 |
| 🚫 **封禁列表** | 檢視/解除已封禁 IP，支援手動封禁 |
| ⚠️ **可疑審查** | 審查未達閾值的可疑 IP，可手動封鎖或忽略 |
| 🛠️ **模式管理** | 新增/刪除可疑路徑模式和掃描器 UA |
| 📋 **日誌檢視** | 依日期查看 Nginx 日誌，按類別篩選 |

---

## ⚙️ 子網封鎖模式

| 模式 | 行為 |
|------|------|
| `off` | 僅封鎖單一 IP |
| `auto` | 同一 /24 子網內有 ≥3 個 IP 被封鎖時，自動升級為封鎖整個 /24 子網 |
| `force` | 一律封鎖整個 /24 子網 |

---

## 📧 郵件通知

- 僅在**首次封鎖** IP 時發送告警郵件
- 已封鎖 IP 再次攻擊時**不再重複發送**電郵
- 郵件包含：攻擊 IP、地理位置、封禁原因、請求次數、攻擊請求範例（最多 30 筆）
- 支援 HTML + 純文字雙格式

---

## 🔧 模式管理

`patterns.json` 是可疑偵測規則的設定檔，可透過 Web UI 或直接編輯：

```json
{
  "suspiciousPatterns": [
    ".env",
    "wp-login.php",
    "wp-admin",
    "phpMyAdmin",
    ".git/config",
    ...
  ],
  "scannerUserAgents": [
    "sqlmap",
    "nmap",
    "nessus",
    "burpsuite",
    ...
  ]
}
```

修改後即時生效，無需重啟服務。

---

## 🛠️ 可用的 npm scripts

| 指令 | 說明 |
|------|------|
| `pnpm dev` | ts-node 開發模式 |
| `pnpm build` | TypeScript 編譯 |
| `pnpm start` | 執行編譯後的 JS |
| `pnpm pm2:start` | PM2 守護程序啟動 |
| `pnpm pm2:stop` | PM2 停止 |
| `pnpm pm2:restart` | PM2 重啟 |
| `pnpm pm2:logs` | PM2 日誌檢視 |

---

## 📝 授權

MIT License
