import fs from "fs";
import dotenv from "dotenv";
import path from "path";
import { Config } from "./types";

dotenv.config();

function loadPatternsFromFile(): {
  suspiciousPatterns: string[];
  scannerUserAgents: string[];
} {
  const patternsFile =
    process.env.PATTERNS_FILE || path.join(process.cwd(), "patterns.json");

  // 優先從 JSON 檔案載入（可自由編輯）
  if (fs.existsSync(patternsFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(patternsFile, "utf8"));
      const suspiciousPatterns = (
        data.suspiciousPatterns || []
      ).map((s: string) => s.trim().toLowerCase());
      const scannerUserAgents = (
        data.scannerUserAgents || []
      ).map((s: string) => s.trim().toLowerCase());
      if (suspiciousPatterns.length > 0 && scannerUserAgents.length > 0) {
        return { suspiciousPatterns, scannerUserAgents };
      }
    } catch {
      // 檔案損毀時 fallback 到預設值
    }
  }

  // Fallback: 從環境變數載入
  const suspiciousPatterns = (
    process.env.SUSPICIOUS_PATTERNS ||
    ".env,wp-login.php,wp-admin,adminer-,phpMyAdmin,xmlrpc.php,.git/config,/SDK/,/backup/,/wp-content/,/includes/,/modules/,/components/,/.well-known/,security.txt,sitemap.xml,llms.txt,adminMember,adminexec,adminnav,CDGServer3,/oauth/token,/hmc/,/WebInterface/,/cgi-bin/,/.git/,.php,wp-config,phpinfo,credentials,.bak,.old,.save,.backup,.staging,.local,aws-config,aws.config,config.php,config.js"
  )
    .split(",")
    .map((s) => s.trim().toLowerCase());

  const scannerUserAgents = (
    process.env.SCANNER_UA ||
    "Osmedeus,sqlmap,nmap,nessus,gobuster,dirbuster,nikto,wpscan,masscan,acunetix,netsparker,openvas,burpsuite,zap,appscan,awvs"
  )
    .split(",")
    .map((s) => s.trim().toLowerCase());

  return { suspiciousPatterns, scannerUserAgents };
}

export function loadConfig(): Config {
  const whitelistStr = process.env.WHITELIST || "127.0.0.1";
  const whitelist = whitelistStr.split(",").map((ip) => ip.trim());
  const { suspiciousPatterns, scannerUserAgents } = loadPatternsFromFile();

  return {
    nodeEnv: process.env.NODE_ENV || "development",
    nginxLogPath: process.env.NGINX_LOG_PATH || "C:/nginx/logs/",
    banThreshold: parseInt(process.env.BAN_THRESHOLD || "30"),
    scanInterval: parseInt(process.env.SCAN_INTERVAL || "60"),
    realTimeMonitoring: process.env.REAL_TIME_MONITORING !== "false",
    bannedFile:
      process.env.BANNED_FILE || path.join(process.cwd(), "banned_ips.json"),
    whitelist,
    smtp: {
      enabled: process.env.SMTP_ENABLED === "true",
      host: process.env.SMTP_HOST || "smtp.gmail.com",
      port: parseInt(process.env.SMTP_PORT || "587"),
      secure: process.env.SMTP_SECURE === "true",
      auth: {
        user: process.env.SMTP_USER || "",
        pass: process.env.SMTP_PASS || "",
      },
      from: process.env.SMTP_USER || "",
      to: process.env.ALERT_EMAIL || "admin@localhost.com",
    },
    web: {
      enabled: process.env.WEB_ENABLED !== "false",
      port: parseInt(process.env.WEB_PORT || "3001"),
      username: process.env.WEB_USERNAME || "admin",
      password: process.env.WEB_PASSWORD || "amentam",
    },
    debug: process.env.DEBUG === "true",
    autoBan: process.env.AUTO_BAN !== "false",
    banSubnet:
      process.env.BAN_SUBNET === "force"
        ? "force"
        : process.env.BAN_SUBNET === "off"
          ? "off"
          : "auto",
    suspiciousFile:
      process.env.SUSPICIOUS_FILE ||
      path.join(process.cwd(), "suspicious_ips.json"),
    suspiciousPatterns,
    scannerUserAgents,
  };
}

export const config = loadConfig();
