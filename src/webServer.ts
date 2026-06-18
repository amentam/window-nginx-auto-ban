import fs from "fs";
import path from "path";
import http from "http";
import url from "url";
import { FirewallManager } from "./firewall";
import { logger } from "./logger";
import { SuspiciousRecord } from "./types";
import { LogParser } from "./logParser";
import { config } from "./config";

export class WebServer {
  private server: http.Server | null = null;
  private patternsFile: string;
  private logParser: LogParser;
  private getLogPath: (date?: string) => string;

  constructor(
    private port: number,
    private username: string,
    private password: string,
    private firewall: FirewallManager,
    private getSuspiciousRecords: () => SuspiciousRecord[],
    private banSuspicious: (ip: string) => Promise<boolean>,
    private ignoreSuspicious: (ip: string) => void,
    private updatePatterns: (highConfidence: string[], lowConfidence: string[], userAgents: string[]) => void,
    private banManual: (ip: string) => Promise<boolean>,
    logParser: LogParser,
    getLogPath: (date?: string) => string,
  ) {
    this.logParser = logParser;
    this.getLogPath = getLogPath;
    this.patternsFile =
      process.env.PATTERNS_FILE || path.join(process.cwd(), "patterns.json");
  }

  start(): void {
    if (!this.port) return;

    this.server = http.createServer(async (req, res) => {
      const parsedUrl = url.parse(req.url || "/", true);

      // 簡單認證
      const auth = req.headers.authorization;
      if (!this.checkAuth(auth)) {
        res.writeHead(401, {
          "WWW-Authenticate": 'Basic realm="Nginx Security Monitor"',
        });
        res.end("Unauthorized");
        return;
      }

      if (parsedUrl.pathname === "/" || parsedUrl.pathname === "/index.html") {
        await this.serveStatic(req, res);
      } else if (parsedUrl.pathname === "/api/banned") {
        await this.handleApiBanned(req, res);
      } else if (parsedUrl.pathname === "/api/banned/with-time") {
        await this.handleApiBannedWithTime(req, res);
      } else if (parsedUrl.pathname === "/api/config") {
        await this.handleApiConfig(req, res);
      } else if (parsedUrl.pathname === "/api/unban") {
        await this.handleApiUnban(req, res, parsedUrl);
      } else if (parsedUrl.pathname === "/api/stats") {
        await this.handleApiStats(req, res);
      } else if (parsedUrl.pathname === "/api/suspicious") {
        await this.handleApiSuspicious(req, res);
      } else if (parsedUrl.pathname === "/api/suspicious/ban") {
        await this.handleApiSuspiciousBan(req, res, parsedUrl);
      } else if (parsedUrl.pathname === "/api/suspicious/ignore") {
        await this.handleApiSuspiciousIgnore(req, res, parsedUrl);
      } else if (parsedUrl.pathname === "/api/patterns") {
        await this.handleApiPatterns(req, res);
      } else if (parsedUrl.pathname === "/api/patterns/add") {
        await this.handleApiPatternsAdd(req, res, parsedUrl);
      } else if (parsedUrl.pathname === "/api/patterns/remove") {
        await this.handleApiPatternsRemove(req, res, parsedUrl);
      } else if (parsedUrl.pathname === "/api/ban") {
        await this.handleApiBan(req, res, parsedUrl);
      } else if (parsedUrl.pathname === "/api/logs/dates") {
        await this.handleApiLogDates(req, res);
      } else if (parsedUrl.pathname === "/api/logs") {
        await this.handleApiLogs(req, res, parsedUrl);
      } else {
        res.writeHead(404);
        res.end("Not Found");
      }
    });

    this.server.listen(this.port, () => {
      logger.info(`Web 管理介面: http://localhost:${this.port}`);
    });
  }

  private checkAuth(auth: string | undefined): boolean {
    if (!auth) return false;

    const base64 = auth.split(" ")[1];
    const credentials = Buffer.from(base64, "base64").toString();
    const [username, password] = credentials.split(":");

    return username === this.username && password === this.password;
  }

  private async serveStatic(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    try {
      const publicDir = path.join(process.cwd(), "public");
      const filePath = path.join(publicDir, "index.html");
      const content = fs.readFileSync(filePath, "utf8");
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(content);
    } catch {
      res.writeHead(500);
      res.end("Internal Server Error");
    }
  }

  private escapeHtml(str: string): string {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  private async handleApiBanned(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const bannedIPs = Array.from(this.firewall.getBannedIPs());
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ bannedIPs }));
  }

  private async handleApiBannedWithTime(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const bannedIPs = this.firewall.getBannedIPsWithTime();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ bannedIPs }));
  }

  private async handleApiConfig(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        autoBan: config.autoBan,
        banSubnet: config.banSubnet,
      }),
    );
  }

  private async handleApiUnban(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    parsedUrl: url.UrlWithParsedQuery,
  ): Promise<void> {
    const ip = parsedUrl.query.ip as string;
    if (ip) {
      await this.firewall.unbanIP(ip);
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true }));
  }

  private async handleApiBan(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    parsedUrl: url.UrlWithParsedQuery,
  ): Promise<void> {
    const ip = parsedUrl.query.ip as string;
    if (!ip) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: "請提供 IP 地址" }));
      return;
    }
    const success = await this.banManual(ip);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success }));
  }

  private async handleApiStats(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const suspiciousList = this.getSuspiciousRecords();
    const pendingCount = suspiciousList.filter((s) => s.status === "pending").length;

    // 計算今日封禁數量
    const now = new Date();
    const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate()).toISOString();
    const bannedRecords = this.firewall.getBannedIPsWithTime();
    let todayBlocks = 0;
    for (const r of bannedRecords) {
      if (r.timestamp && r.timestamp >= todayStart) {
        todayBlocks++;
      }
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(
      JSON.stringify({
        todayBlocks,
        pendingReview: pendingCount,
        uptime: process.uptime(),
      }),
    );
  }

  private async handleApiSuspicious(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const list = this.getSuspiciousRecords();
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ suspiciousIPs: list }));
  }

  private async handleApiSuspiciousBan(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    parsedUrl: url.UrlWithParsedQuery,
  ): Promise<void> {
    const ip = parsedUrl.query.ip as string;
    const success = ip ? await this.banSuspicious(ip) : false;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success }));
  }

  private async handleApiSuspiciousIgnore(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    parsedUrl: url.UrlWithParsedQuery,
  ): Promise<void> {
    const ip = parsedUrl.query.ip as string;
    if (ip) {
      this.ignoreSuspicious(ip);
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true }));
  }

  private loadPatternsFile(): {
    highConfidencePatterns: string[];
    suspiciousPatterns: string[];
    scannerUserAgents: string[];
  } {
    try {
      const data = JSON.parse(fs.readFileSync(this.patternsFile, "utf8"));
      return {
        highConfidencePatterns: data.highConfidencePatterns || [],
        suspiciousPatterns: data.suspiciousPatterns || [],
        scannerUserAgents: data.scannerUserAgents || [],
      };
    } catch {
      return {
        highConfidencePatterns: config.highConfidencePatterns,
        suspiciousPatterns: config.suspiciousPatterns,
        scannerUserAgents: config.scannerUserAgents,
      };
    }
  }

  private savePatternsFile(
    highConfidence: string[],
    suspicious: string[],
    userAgents: string[],
  ): void {
    const data = {
      highConfidencePatterns: highConfidence,
      suspiciousPatterns: suspicious,
      scannerUserAgents: userAgents,
    };
    fs.writeFileSync(this.patternsFile, JSON.stringify(data, null, 2));
    // 即時更新 LogParser 中的規則
    this.updatePatterns(highConfidence, suspicious, userAgents);
  }

  private async handleApiPatterns(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const { highConfidencePatterns, suspiciousPatterns } = this.loadPatternsFile();
    // 合併回傳給前端（維持向後兼容：前端看到的是合併列表）
    const allPatterns = [...highConfidencePatterns, ...suspiciousPatterns];
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ patterns: allPatterns }));
  }

  private async handleApiPatternsAdd(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    parsedUrl: url.UrlWithParsedQuery,
  ): Promise<void> {
    const pattern = (parsedUrl.query.pattern as string || "").trim().toLowerCase();
    if (!pattern) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: "請輸入模式" }));
      return;
    }

    const { highConfidencePatterns, suspiciousPatterns, scannerUserAgents } = this.loadPatternsFile();
    if (highConfidencePatterns.includes(pattern) || suspiciousPatterns.includes(pattern)) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: "該模式已存在" }));
      return;
    }

    // Web UI 新增一律加入低風險清單（高風險清單僅能手動編輯 patterns.json）
    suspiciousPatterns.push(pattern);
    this.savePatternsFile(highConfidencePatterns, suspiciousPatterns, scannerUserAgents);
    logger.info(`Web UI 新增可疑路徑模式: ${pattern}`);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true, reloadNeeded: true }));
  }

  private async handleApiPatternsRemove(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    parsedUrl: url.UrlWithParsedQuery,
  ): Promise<void> {
    const index = parseInt(parsedUrl.query.index as string || "0");
    if (index < 1) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: "無效的索引" }));
      return;
    }

    const { highConfidencePatterns, suspiciousPatterns, scannerUserAgents } = this.loadPatternsFile();
    const allPatterns = [...highConfidencePatterns, ...suspiciousPatterns];
    if (index > allPatterns.length) {
      res.writeHead(400, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ success: false, error: "索引超出範圍" }));
      return;
    }

    const removed = allPatterns[index - 1];
    // 判斷刪除的是高風險還是低風險
    const hcIdx = highConfidencePatterns.indexOf(removed);
    if (hcIdx !== -1) {
      highConfidencePatterns.splice(hcIdx, 1);
    } else {
      const lcIdx = suspiciousPatterns.indexOf(removed);
      if (lcIdx !== -1) suspiciousPatterns.splice(lcIdx, 1);
    }
    this.savePatternsFile(highConfidencePatterns, suspiciousPatterns, scannerUserAgents);
    logger.info(`Web UI 刪除可疑路徑模式: ${removed}`);

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ success: true }));
  }

  private async handleApiLogDates(
    req: http.IncomingMessage,
    res: http.ServerResponse,
  ): Promise<void> {
    const logDir = path.dirname(this.getLogPath());
    const dates: string[] = [];

    if (fs.existsSync(logDir)) {
      const files = fs.readdirSync(logDir);
      const dateRe = /^access-(\d{4}-\d{2}-\d{2})\.log$/;
      for (const f of files) {
        const m = f.match(dateRe);
        if (m) dates.push(m[1]);
      }
      dates.sort().reverse();
    }

    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ dates }));
  }

  private async handleApiLogs(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    parsedUrl: url.UrlWithParsedQuery,
  ): Promise<void> {
    const dateStr = (parsedUrl.query.date as string) || "";
    const logPath = this.getLogPath(dateStr || undefined);

    if (!fs.existsSync(logPath)) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ entries: [], total: 0, error: `找不到日誌檔: ${path.basename(logPath)}` }));
      return;
    }

    try {
      const content = fs.readFileSync(logPath, "utf8");
      const lines = content.split("\n");
      const entries: any[] = [];
      const patterns = this.logParser.getPatterns();

      for (const line of lines) {
        if (!line.trim()) continue;
        const entry = this.logParser.parseLine(line);
        if (!entry) continue;

        const detection = this.logParser.analyzeEntry(entry);
        let category = "normal";
        let matched: string[] = [];

        if (detection.isSuspicious) {
          // 細分類別
          if (detection.matchedPattern) {
            if (patterns.includes(detection.matchedPattern)) {
              category = "suspicious-path";
            } else {
              category = "scanner-ua";
            }
            matched = [detection.matchedPattern];
          } else if (detection.reason.includes("403")) {
            category = "forbidden";
          } else {
            category = "attack-status";
          }
        }

        entries.push({
          ip: entry.ip,
          time: entry.time,
          request: entry.request,
          status: entry.status,
          userAgent: entry.userAgent || "",
          referer: entry.referer || "",
          category,
          matched,
          reason: detection.reason,
        });
      }

      // 排序：最新在前
      entries.reverse();

      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ entries, total: entries.length }));
    } catch (err) {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ entries: [], total: 0, error: "讀取日誌失敗" }));
    }
  }

  stop(): void {
    if (this.server) {
      this.server.close();
    }
  }
}
