import fs from "fs";
import readline from "readline";
import { LogEntry, AttackStats, DetectionResult } from "./types";

export class LogParser {
  private attackStats: Map<string, AttackStats> = new Map();

  constructor(
    private highConfidencePatterns: string[],
    private suspiciousPatterns: string[],
    private scannerUserAgents: string[],
  ) {}

  /** 執行情更新可疑路徑模式（Web UI 新增/刪除後呼叫） */
  updatePatterns(highConfidence: string[], lowConfidence: string[], userAgents: string[]): void {
    this.highConfidencePatterns = highConfidence.map((s) => s.trim().toLowerCase());
    this.suspiciousPatterns = lowConfidence.map((s) => s.trim().toLowerCase());
    this.scannerUserAgents = userAgents.map((s) => s.trim().toLowerCase());
  }

  getPatterns(): string[] {
    return [...this.highConfidencePatterns, ...this.suspiciousPatterns];
  }

  getHighConfidencePatterns(): string[] {
    return [...this.highConfidencePatterns];
  }

  getSuspiciousPatterns(): string[] {
    return [...this.suspiciousPatterns];
  }

  getUserAgents(): string[] {
    return [...this.scannerUserAgents];
  }

  parseLine(line: string): LogEntry | null {
    // 匹配 Nginx 日誌格式
    const pattern =
      /^(\d+\.\d+\.\d+\.\d+)\s+-\s+-\s+\[(.*?)\]\s+"(.*?)"\s+(\d{3})\s+(\d+)\s+"(.*?)"\s+"(.*?)"/;
    const match = line.match(pattern);

    if (match) {
      const status = parseInt(match[4]);
      return {
        ip: match[1],
        time: match[2],
        request: match[3],
        status: status,
        referer: match[6],
        userAgent: match[7],
      };
    }
    return null;
  }

  /**
   * 傳統攻擊狀態碼偵測
   */
  isAttackStatus(status: number): boolean {
    // 只保留真正的伺服器端異常：502/503/504
    // 429 移至下方與可疑路徑組合判斷，避免正常 rate-limiting 誤判
    return [502, 503, 504].includes(status);
  }

  /**
   * 檢查請求路徑是否匹配高風險模式（明顯攻擊，如 .env、wp-admin）
   */
  isHighConfidencePath(request: string): DetectionResult {
    const lowerRequest = request.toLowerCase();

    for (const pattern of this.highConfidencePatterns) {
      if (lowerRequest.includes(pattern)) {
        return { isSuspicious: true, reason: "高風險攻擊路徑", matchedPattern: pattern };
      }
    }
    return { isSuspicious: false, reason: "" };
  }

  /**
   * 檢查請求路徑是否匹配低風險可疑模式（可能為正常流量）
   */
  isSuspiciousPath(request: string): DetectionResult {
    const lowerRequest = request.toLowerCase();

    for (const pattern of this.suspiciousPatterns) {
      if (lowerRequest.includes(pattern)) {
        return { isSuspicious: true, reason: "可疑路徑", matchedPattern: pattern };
      }
    }
    return { isSuspicious: false, reason: "" };
  }

  /**
   * 檢查 User-Agent 是否為已知掃描器
   */
  isScannerUserAgent(ua?: string): DetectionResult {
    if (!ua) return { isSuspicious: false, reason: "" };
    const lowerUA = ua.toLowerCase();

    for (const scanner of this.scannerUserAgents) {
      if (lowerUA.includes(scanner)) {
        return {
          isSuspicious: true,
          reason: "已知掃描器工具",
          matchedPattern: scanner,
        };
      }
    }
    return { isSuspicious: false, reason: "" };
  }

  /**
   * 多層次可疑請求偵測（高/低風險分級）
   *
   * 🔴 高風險（明顯攻擊）→ 直接判定，不問狀態碼
   * 🟡 低風險（可能正常）→ 需搭配 403/429/掃描器 UA 才判定
   *
   * 整合：狀態碼 + URL 路徑 + User-Agent
   */
  analyzeEntry(entry: LogEntry): DetectionResult {
    // 1. 傳統攻擊狀態碼（502/503/504）→ 直接判定
    if (this.isAttackStatus(entry.status)) {
      return { isSuspicious: true, reason: `攻擊狀態碼 ${entry.status}` };
    }

    // 2. 🔴 高風險路徑（.env、wp-admin、.git 等明顯攻擊）→ 直接判定
    const highCheck = this.isHighConfidencePath(entry.request);
    if (highCheck.isSuspicious) {
      return highCheck;
    }

    // 3. 已知掃描器 User-Agent → 直接判定
    const uaCheck = this.isScannerUserAgent(entry.userAgent);
    if (uaCheck.isSuspicious) {
      return uaCheck;
    }

    // 4. 🟡 低風險路徑 + 403/429/掃描器 UA → 組合判定
    const lowCheck = this.isSuspiciousPath(entry.request);
    if (lowCheck.isSuspicious) {
      if (entry.status === 403) {
        return { isSuspicious: true, reason: `403 + 可疑路徑 (${lowCheck.matchedPattern})` };
      }
      if (entry.status === 429) {
        return { isSuspicious: true, reason: `429 + 可疑路徑 (${lowCheck.matchedPattern})` };
      }
      // 低風險路徑但狀態碼正常 → 不判定（避免誤判正常流量）
    }

    // 5. 403 + 高風險路徑（已在步驟 2 涵蓋，此處為冗餘保護）
    if (entry.status === 403) {
      const hcCheck = this.isHighConfidencePath(entry.request);
      if (hcCheck.isSuspicious) {
        return { isSuspicious: true, reason: `403 禁止訪問 (${hcCheck.matchedPattern})` };
      }
    }

    // 6. 429 + 掃描器 UA（已在步驟 3 涵蓋，此處處理僅 429 無 UA 的情況）
    if (entry.status === 429) {
      // 429 單獨出現（無可疑路徑、無掃描器 UA）→ 可能是正常 rate-limiting，不判定
    }

    return { isSuspicious: false, reason: "" };
  }

  async scanLogFile(
    filePath: string,
    lastPosition: number,
    onEntries: (entries: LogEntry[]) => void,
  ): Promise<number> {
    const stats = fs.statSync(filePath);
    const newSize = stats.size;

    if (newSize <= lastPosition) {
      return lastPosition;
    }

    const entries: LogEntry[] = [];
    const stream = fs.createReadStream(filePath, {
      start: lastPosition,
      end: newSize,
      encoding: "utf8",
    });

    const rl = readline.createInterface({
      input: stream,
      crlfDelay: Infinity,
    });

    for await (const line of rl) {
      const entry = this.parseLine(line);
      if (entry) {
        entries.push(entry);
      }
    }

    if (entries.length > 0) {
      onEntries(entries);
    }

    return newSize;
  }

  /**
   * 進階分析：對所有請求進行多層次偵測
   * 回傳每個 IP 的攻擊統計（不再只限於傳統攻擊狀態碼）
   */
  analyzeEntries(
    entries: LogEntry[],
    threshold: number,
    now: Date,
  ): Map<string, AttackStats> {
    const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);
    const stats = new Map<string, AttackStats>();

    for (const entry of entries) {
      // 多層次偵測
      const detection = this.analyzeEntry(entry);
      if (!detection.isSuspicious) continue;

      // "16/Jun/2026:13:11:55 +0800" → "16 Jun 2026 13:11:55 +0800"
      const dateStr = entry.time.replace(/\//g, " ").replace(/:/, " ");
      const logTime = new Date(dateStr);
      if (logTime < oneMinuteAgo) continue;

      const existing = stats.get(entry.ip);
      const requestWithReason = `[${detection.reason}] ${entry.request}`;

      if (existing) {
        existing.count++;
        existing.lastSeen = logTime;
        existing.sampleRequest = requestWithReason;
        // 保留最近 30 筆範例請求
        if (existing.sampleRequests.length < 30) {
          existing.sampleRequests.push(requestWithReason);
        }
      } else {
        stats.set(entry.ip, {
          count: 1,
          sampleRequest: requestWithReason,
          sampleRequests: [requestWithReason],
          firstSeen: logTime,
          lastSeen: logTime,
        });
      }
    }

    return stats;
  }

  resetStats(): void {
    this.attackStats.clear();
  }
}
