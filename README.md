# 🛡️ Window Nginx Auto Ban System

自動監控 Nginx 日誌，偵測惡意攻擊並透過 Windows 防火牆自動封禁攻擊 IP。

---

## 📋 功能特色

- **即時監控** — 每秒掃描 Nginx 日誌增量變化，即時偵測攻擊
- **多層次偵測** — 高/低風險分級：明顯攻擊（`.env`、`wp-admin`）直接判定；低風險模式（`.php`、`/backup/`）需搭配 403/429/掃描器 UA 才判定
- **自動封禁** — 達到閾值自動將 IP 加入 Windows 防火牆黑名單
- **自動解封** — 可設定封鎖時效（`AUTO_UNBAN_HOURS`），到期自動解除防火牆規則
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

# 自動解封時數：0=關閉（永久封鎖），>0=封鎖 N 小時後自動解除
AUTO_UNBAN_HOURS=0

# 子網封鎖模式：off=僅封單IP, auto=智慧升級, force=強制封/24
BAN_SUBNET=auto

# IP 白名單（逗號分隔）
WHITELIST=127.0.0.1

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

系統採用**高/低風險分級**的多層次偵測，避免將正常流量（如未登入的 403、rate-limiting 的 429）誤判為攻擊：

| 優先級 | 層級 | 偵測方式 | 說明 |
|--------|------|----------|------|
| 1 | 🔴 攻擊狀態碼 | 502 / 503 / 504 | 伺服器端異常，直接判定 |
| 2 | 🔴 高風險路徑 | `.env`、`wp-admin`、`.git`、`phpMyAdmin` 等 | 明顯攻擊路徑，**直接判定**（不問狀態碼） |
| 3 | 🔴 掃描器 UA | sqlmap、nmap、burpsuite 等 | 已知攻擊工具，直接判定 |
| 4 | 🟡 低風險 + 403 | `.php`、`/backup/`、`config.js` 等 + 403 | **需組合判定**：低風險路徑且返回 403 |
| 5 | 🟡 低風險 + 429 | 同上 + 429 | **需組合判定**：低風險路徑且被限流 |

> ⚠️ **重要**：單純的 403（如未登入 API 呼叫）或單純的 429（正常 rate-limiting）**不會**被判定為攻擊，避免誤封正常用戶。

### 封鎖條件（滿足其一即觸發）

1. 1 分鐘內可疑請求數 ≥ `BAN_THRESHOLD`（預設 30 次）
2. 命中 ≥ 3 種**高風險**模式，且累積 ≥ 5 次請求

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
| `auto` | 同一 /24 子網內有 ≥2 個 IP 被封鎖時，自動升級為封鎖整個 /24 子網 |
| `force` | 一律封鎖整個 /24 子網 |

---

## 📧 郵件通知

- 僅在**首次封鎖** IP 時發送告警郵件
- 已封鎖 IP 再次攻擊時**不再重複發送**電郵
- 郵件包含：攻擊 IP、地理位置、封禁原因、請求次數、攻擊請求範例（最多 30 筆）
- 支援 HTML + 純文字雙格式

---

## 🔧 模式管理

`patterns.json` 是可疑偵測規則的設定檔，分為高/低風險兩級：

```json
{
  "highConfidencePatterns": [
    ".env", "wp-login.php", "wp-admin", "phpMyAdmin",
    ".git/config", "/.git/", "wp-config", "phpinfo",
    "/cgi-bin/", "/oauth/token", ...
  ],
  "suspiciousPatterns": [
    "/backup/", "/includes/", "/modules/", ".php",
    ".bak", ".old", "config.js", "sitemap.xml", ...
  ],
  "scannerUserAgents": [
    "sqlmap", "nmap", "nessus", "burpsuite", ...
  ]
}
```

| 分類 | 行為 | 管理方式 |
|------|------|----------|
| 🔴 `highConfidencePatterns` | 命中即判定攻擊 | 僅能手動編輯 JSON 檔 |
| 🟡 `suspiciousPatterns` | 需搭配 403/429/掃描器 UA | Web UI 或手動編輯 |

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
