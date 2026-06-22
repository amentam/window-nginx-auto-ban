import fs from "fs";
import dotenv from "dotenv";
import path from "path";
import { Config } from "./types";

dotenv.config();

function loadPatternsFromFile(): {
  highConfidencePatterns: string[];
  suspiciousPatterns: string[];
  scannerUserAgents: string[];
} {
  const patternsFile =
    process.env.PATTERNS_FILE || path.join(process.cwd(), "patterns.json");

  // 優先從 JSON 檔案載入（可自由編輯）
  if (fs.existsSync(patternsFile)) {
    try {
      const data = JSON.parse(fs.readFileSync(patternsFile, "utf8"));
      const highConfidencePatterns = (
        data.highConfidencePatterns || []
      ).map((s: string) => s.trim().toLowerCase());
      const suspiciousPatterns = (
        data.suspiciousPatterns || []
      ).map((s: string) => s.trim().toLowerCase());
      const scannerUserAgents = (
        data.scannerUserAgents || []
      ).map((s: string) => s.trim().toLowerCase());
      if (highConfidencePatterns.length > 0 && suspiciousPatterns.length > 0 && scannerUserAgents.length > 0) {
        return { highConfidencePatterns, suspiciousPatterns, scannerUserAgents };
      }
    } catch {
      // 檔案損毀時 fallback 到預設值
    }
  }

  // Fallback: 從環境變數載入
  const highConfidencePatterns = (
    process.env.HIGH_CONFIDENCE_PATTERNS ||
    ".env,wp-login.php,wp-admin,adminer-,phpMyAdmin,xmlrpc.php,.git/config,/SDK/,/wp-content/,/.well-known/,/.git/,wp-config,phpinfo,/cgi-bin/,/hmc/,/WebInterface/,CDGServer3,adminMember,adminexec,adminnav,/oauth/token"
  )
    .split(",")
    .map((s) => s.trim().toLowerCase());

  const suspiciousPatterns = (
    process.env.SUSPICIOUS_PATTERNS ||
    "/backup/,/includes/,/modules/,/components/,security.txt,sitemap.xml,llms.txt,.php,.bak,.old,.save,.backup,.staging,.local,aws-config,aws.config,config.php,config.js"
  )
    .split(",")
    .map((s) => s.trim().toLowerCase());

  const scannerUserAgents = (
    process.env.SCANNER_UA ||
    "Osmedeus,sqlmap,nmap,nessus,gobuster,dirbuster,nikto,wpscan,masscan,acunetix,netsparker,openvas,burpsuite,zap,appscan,awvs"
  )
    .split(",")
    .map((s) => s.trim().toLowerCase());

  return { highConfidencePatterns, suspiciousPatterns, scannerUserAgents };
}

export function loadConfig(): Config {
  const whitelistStr = process.env.WHITELIST || "127.0.0.1";
  const whitelist = whitelistStr.split(",").map((ip) => ip.trim());
  const { highConfidencePatterns, suspiciousPatterns, scannerUserAgents } = loadPatternsFromFile();

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
    highConfidencePatterns,
    suspiciousPatterns,
    scannerUserAgents,
    autoUnbanHours: parseInt(process.env.AUTO_UNBAN_HOURS || "0"),
    autoUnbanSubnet: process.env.AUTO_UNBAN_SUBNET === "true",
    permanentBanFile:
      process.env.PERMANENT_BAN_FILE ||
      path.join(process.cwd(), "permanent_bans.json"),
  };
}

export const config = loadConfig();
