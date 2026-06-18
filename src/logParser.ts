import fs from "fs";
import readline from "readline";
import { LogEntry, AttackStats, DetectionResult } from "./types";

export class LogParser {
  private attackStats: Map<string, AttackStats> = new Map();

  constructor(
    private suspiciousPatterns: string[],
    private scannerUserAgents: string[],
  ) {}

  /** 執行情更新可疑路徑模式（Web UI 新增/刪除後呼叫） */
  updatePatterns(patterns: string[], userAgents: string[]): void {
    this.suspiciousPatterns = patterns.map((s) => s.trim().toLowerCase());
    this.scannerUserAgents = userAgents.map((s) => s.trim().toLowerCase());
  }

  getPatterns(): string[] {
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
    return [429, 502, 503, 504].includes(status);
  }

  /**
   * 檢查請求路徑是否匹配可疑模式
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
   * 多層次可疑請求偵測
   * 整合：狀態碼 + URL 路徑 + User-Agent
   */
  analyzeEntry(entry: LogEntry): DetectionResult {
    // 1. 傳統攻擊狀態碼
    if (this.isAttackStatus(entry.status)) {
      return { isSuspicious: true, reason: `攻擊狀態碼 ${entry.status}` };
    }

    // 2. 可疑 URL 路徑（即使狀態碼是 200/307/403）
    const pathCheck = this.isSuspiciousPath(entry.request);
    if (pathCheck.isSuspicious) {
      return pathCheck;
    }

    // 3. 已知掃描器 User-Agent
    const uaCheck = this.isScannerUserAgent(entry.userAgent);
    if (uaCheck.isSuspicious) {
      return uaCheck;
    }

    // 4. 403 + 可疑路徑組合：只標記同時滿足 403 且匹配已知攻擊路徑的請求
    //    避免將正常應用的 403（如未登入的 API 呼叫）誤判為攻擊
    if (entry.status === 403) {
      const pathCheck = this.isSuspiciousPath(entry.request);
      if (pathCheck.isSuspicious) {
        return { isSuspicious: true, reason: `403 禁止訪問 (${pathCheck.matchedPattern})` };
      }
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
