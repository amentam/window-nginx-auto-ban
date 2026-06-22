import fs from "fs";
import path from "path";
import moment from "moment";
import { config } from "./config";
import { logger } from "./logger";
import { FirewallManager, ipToCidr, isSubnetWhitelisted } from "./firewall";
import { LogParser } from "./logParser";
import { EmailNotifier } from "./email";
import { WebServer } from "./webServer";
import { SuspiciousRecord } from "./types";
import { getIpLocation, formatIpLocation } from "./ipLocation";

function isWhitelistedIP(ip: string): boolean {
  return config.whitelist.includes(ip);
}

class NginxAutoBan {
  private firewall: FirewallManager;
  private logParser: LogParser;
  private emailNotifier: EmailNotifier;
  private webServer: WebServer | null = null;
  private lastLogPosition: number = 0;
  private isRunning: boolean = true;
  // 可疑 IP 審查佇列（未達自動封鎖閾值，或手動模式）
  private suspiciousRecords: Map<string, SuspiciousRecord> = new Map();

  // 永久封鎖名單（曾解封後再次攻擊 → 永久封鎖，不再自動解封）
  private permanentBans: Set<string> = new Set();

  // 曾自動解封的 IP/子網（用於判斷是否為再犯）
  private previouslyUnbanned: Map<string, string> = new Map(); // ip → unbannedAt ISO string

  /** 即時計算指定 /24 子網中已封鎖的單一 IP 數量（用於 auto 模式升級判斷） */
  private countBannedInSubnet(subnetPrefix: string): number {
    let count = 0;
    for (const ip of this.firewall.getBannedIPs()) {
      if (!ip.includes("/")) {
        const prefix = ip.substring(0, ip.lastIndexOf("."));
        if (prefix === subnetPrefix) count++;
      }
    }
    return count;
  }


  constructor() {
    this.firewall = new FirewallManager(config.bannedFile);
    this.logParser = new LogParser(
      config.highConfidencePatterns,
      config.suspiciousPatterns,
      config.scannerUserAgents,
    );
    this.emailNotifier = new EmailNotifier(config.smtp.enabled, config.smtp);

    // 載入可疑 IP 審查記錄
    this.loadSuspiciousRecords();

    // 載入永久封鎖名單與解封歷史
    this.loadPermanentBans();
    this.loadPreviouslyUnbanned();

    if (config.web.enabled) {
      this.webServer = new WebServer(
        config.web.port,
        config.web.username,
        config.web.password,
        this.firewall,
        // 傳遞可疑 IP 操作回呼給 Web UI
        () => this.getSuspiciousRecords(),
        (ip: string) => this.banFromSuspicious(ip),
        (ip: string) => this.ignoreSuspicious(ip),
        // 傳遞模式管理回呼（新增/刪除後即時更新 LogParser）
        (highConfidence: string[], lowConfidence: string[], userAgents: string[]) => {
          this.logParser.updatePatterns(highConfidence, lowConfidence, userAgents);
        },
        // 傳遞手動封鎖回呼（測試防火牆用）
        (ip: string) => this.banManual(ip),
        // 傳遞 LogParser 實例和日誌路徑取得函數（供 Web UI 日誌查詢）
        this.logParser,
        (date?: string) => this.getLogPathForDate(date),
      );
    }
  }

  private getLogPath(): string {
    return path.join(config.nginxLogPath, `access-${moment().format("YYYY-MM-DD")}.log`);
  }

  private getLogPathForDate(date?: string): string {
    const d = date || moment().format("YYYY-MM-DD");
    return path.join(config.nginxLogPath, `access-${d}.log`);
  }

  private async checkAdmin(): Promise<void> {
    const isAdmin = await FirewallManager.isAdmin();
    this.firewall.setAdmin(isAdmin);
    if (!isAdmin) {
      logger.warn("程式未以系統管理員權限執行！防火牆操作（封禁/解封）將彈出 UAC 確認視窗");
      logger.warn("建議以系統管理員身份執行，以避免每次操作都彈出 UAC 提示");
    } else {
      logger.info("系統管理員權限確認 ✓");
    }
  }

  async start(): Promise<void> {
    this.printBanner();

    // 檢查管理員權限
    await this.checkAdmin();

    // 載入已封禁 IP
    this.loadBannedIPs();

    // 同步防火牆規則（確保 Windows 防火牆與檔案記錄一致）
    await this.firewall.syncFirewallRule();

    // 初始化日誌位置
    this.initLogPosition();

    // 啟動 Web 伺服器
    if (this.webServer) {
      this.webServer.start();
    }

    // 啟動監控
    if (config.realTimeMonitoring) {
      await this.startRealTimeMonitoring();
    } else {
      this.startPeriodicScan();
    }

    // 自動解封：每 10 分鐘檢查一次過期封鎖
    if (config.autoUnbanHours > 0) {
      logger.info(`🔓 自動解封已啟用：封鎖超過 ${config.autoUnbanHours} 小時自動解除`);
      setInterval(async () => {
        if (!this.isRunning) return;
        await this.autoUnbanExpired();
      }, 10 * 60 * 1000);
    }

    // 優雅退出
    this.setupGracefulShutdown();
  }

  private printBanner(): void {
    console.log(`
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ███╗   ██╗ ██████╗ ██╗███╗   ██╗██╗██╗  ██╗               ║
║   ████╗  ██║██╔════╝ ██║████╗  ██║██║╚██╗██╔╝               ║
║   ██╔██╗ ██║██║  ███╗██║██╔██╗ ██║██║ ╚███╔╝                ║
║   ██║╚██╗██║██║   ██║██║██║╚██╗██║██║ ██╔██╗                ║
║   ██║ ╚████║╚██████╔╝██║██║ ╚████║██║██╔╝ ██╗               ║
║   ╚═╝  ╚═══╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═╝               ║
║                                                              ║
║            Bestmark360 Auto Ban System v1.0                  ║
║            即時監控                                          ║
╚══════════════════════════════════════════════════════════════╝
        `);

    const patternsFile =
      process.env.PATTERNS_FILE || path.join(process.cwd(), "patterns.json");
    logger.info(`日誌檔案: ${this.getLogPath()}`);
    const subnetLabel =
      config.banSubnet === "force" ? "（強制子網封鎖 /24）" :
      config.banSubnet === "auto" ? "（自動升級子網封鎖）" : "";
    logger.info(`封禁閾值: ${config.banThreshold} 次/分鐘${subnetLabel}`);
    logger.info(`白名單: ${config.whitelist.join(", ")}`);
    logger.info(`即時監控: ${config.realTimeMonitoring ? "開啟" : "關閉"}`);
    logger.info(`🔴 高風險模式: ${config.highConfidencePatterns.length} 條（直接判定）`);
    logger.info(`🟡 低風險模式: ${config.suspiciousPatterns.length} 條（需搭配 403/429/掃描器UA）`);
    logger.info(`掃描器 UA: ${config.scannerUserAgents.length} 條`);
    if (config.autoUnbanHours > 0) {
      logger.info(`🔓 自動解封: ${config.autoUnbanHours} 小時後`);
      logger.info(`🔓 子網自動解封: ${config.autoUnbanSubnet ? "允許" : "禁止"}`);
      logger.info(`🚫 再犯永久封鎖: 啟用`);
    }
    if (this.permanentBans.size > 0) {
      logger.info(`🔒 永久封鎖名單: ${this.permanentBans.size} 筆`);
    }
    logger.info("=".repeat(50));
  }

  private loadBannedIPs(): void {
    if (fs.existsSync(config.bannedFile)) {
      try {
        const data = JSON.parse(fs.readFileSync(config.bannedFile, "utf8"));
        const rawRecords: { ip: string; timestamp: string }[] = data.bannedRecords || [];
        // 合併 legacy 資料：auto/force 模式下將同一 /24 子網的個別 IP 合併為 CIDR
        const mergedRecords = this.mergeSubnetRecords(rawRecords);
        this.firewall.loadBannedRecords(mergedRecords);

        // 若合併後與原始不同，立即儲存清理後的記錄
        if (mergedRecords.length !== rawRecords.length) {
          this.saveBannedIPs();
          logger.info("已將 legacy 個別 IP 記錄合併為子網 CIDR 並儲存");
        }
      } catch (err) {
        logger.error("載入黑名單失敗:", err as Error);
      }
    }
  }

  /** 載入時合併：auto 模式下 ≥2 個、force 模式下 ≥1 個同 /24 的個別 IP → CIDR */
  private mergeSubnetRecords(
    records: { ip: string; timestamp: string }[],
  ): { ip: string; timestamp: string }[] {
    if (config.banSubnet === "off") return records;

    const cidrMap = new Map<string, string>(); // cidr → latest timestamp
    const groupByPrefix = new Map<string, { ip: string; timestamp: string }[]>();

    for (const rec of records) {
      if (rec.ip.includes("/")) {
        const prev = cidrMap.get(rec.ip);
        if (!prev || rec.timestamp > prev) {
          cidrMap.set(rec.ip, rec.timestamp);
        }
      } else {
        const prefix = rec.ip.substring(0, rec.ip.lastIndexOf("."));
        if (!groupByPrefix.has(prefix)) {
          groupByPrefix.set(prefix, []);
        }
        groupByPrefix.get(prefix)!.push(rec);
      }
    }

    const result: { ip: string; timestamp: string }[] = [];

    // 保留已存在的 CIDR
    for (const [cidr, ts] of cidrMap) {
      result.push({ ip: cidr, timestamp: ts });
    }

    // 處理個別 IP
    for (const [prefix, ips] of groupByPrefix) {
      const minForMerge = config.banSubnet === "force" ? 1 : 2;
      if (ips.length >= minForMerge) {
        const latestTs = ips.reduce(
          (max, r) => (r.timestamp > max ? r.timestamp : max),
          ips[0].timestamp,
        );
        result.push({ ip: `${prefix}.0/24`, timestamp: latestTs });
        logger.info(
          `🔄 載入合併子網: ${ips.map((r) => r.ip).join(", ")} → ${prefix}.0/24`,
        );
      } else {
        for (const rec of ips) {
          result.push(rec);
        }
      }
    }

    return result;
  }

  private saveBannedIPs(): void {
    const records = this.firewall.getBannedIPsWithTime();
    const data = {
      bannedRecords: records,
      timestamp: new Date().toISOString(),
    };
    fs.writeFileSync(config.bannedFile, JSON.stringify(data, null, 2));
  }

  private initLogPosition(): void {
    if (fs.existsSync(this.getLogPath())) {
      const stats = fs.statSync(this.getLogPath());
      this.lastLogPosition = stats.size;
      logger.info(`初始化日誌位置: ${this.lastLogPosition} 位元組`);
    } else {
      logger.warn(`日誌檔案不存在: ${this.getLogPath()}`);
    }
  }

  private currentLogDate: string = "";
  // 跨批次累積攻擊統計（即時監控模式用）
  // 追蹤每個 IP 在 1 分鐘滑動窗口內的累積可疑請求數
  private accumulatedStats: Map<string, { count: number; sampleRequest: string; firstSeen: Date; lastSeen: Date }> = new Map();
  private lastAccumulationCleanup: Date = new Date();

  private async startRealTimeMonitoring(): Promise<void> {
    logger.info("啟動即時監控模式...");

    // 等待日誌檔案出現（最多等 30 秒）
    for (let i = 0; i < 30; i++) {
      if (fs.existsSync(this.getLogPath())) {
        break;
      }
      logger.warn(`等待日誌檔案建立: ${this.getLogPath()} (${i + 1}/30)`);
      await new Promise((r) => setTimeout(r, 1000));
    }

    if (!fs.existsSync(this.getLogPath())) {
      logger.error(`日誌檔案不存在，請檢查路徑: ${config.nginxLogPath}`);
      return;
    }

    this.currentLogDate = moment().format("YYYY-MM-DD");

    // 每 10 秒顯示一次心跳，確認監控存活
    let heartbeatTick = 0;

    // 定時掃描日誌檔案變化
    setInterval(async () => {
      if (!this.isRunning) return;

      try {
        // 檢查日期是否改變（跨日換檔）
        const today = moment().format("YYYY-MM-DD");
        if (today !== this.currentLogDate) {
          this.currentLogDate = today;
          this.lastLogPosition = 0;

          // 等待新日誌檔出現
          const newPath = this.getLogPath();
          for (let i = 0; i < 30; i++) {
            if (fs.existsSync(newPath)) break;
            await new Promise((r) => setTimeout(r, 1000));
          }

          if (!fs.existsSync(newPath)) {
            logger.warn(`新日誌檔案尚未建立: ${newPath}`);
            return;
          }

          logger.info(`切換至新日誌檔案: ${newPath}`);
        }

        const currentPath = this.getLogPath();
        const newPosition = await this.logParser.scanLogFile(
          currentPath,
          this.lastLogPosition,
          async (entries) => {
            if (entries.length > 0 && config.debug) {
              logger.debug(`掃描到 ${entries.length} 筆新日誌`);
            }
            await this.processEntries(entries);
          },
        );

        // 心跳：Debug 模式每 10 秒，否則每小時顯示狀態
        heartbeatTick++;
        const heartbeatInterval = config.debug ? 10 : 3600;
        if (heartbeatTick >= heartbeatInterval) {
          heartbeatTick = 0;
          const fileSize = fs.existsSync(currentPath)
            ? fs.statSync(currentPath).size
            : 0;
          if (config.debug) {
            logger.info(
              `📡 即時監控運作中 | 檔案: ${path.basename(currentPath)} | ${fileSize} 位元組 | 掃描位置: ${newPosition}`,
            );
          } else {
            const bannedCount = this.firewall.getBannedIPs().size;
            logger.info(
              `📡 [每小時報告] 已掃描 ${fileSize} 位元組 | 已封禁 ${bannedCount} 個 IP | 監控中: ${path.basename(currentPath)}`,
            );
          }
        }

        this.lastLogPosition = newPosition;
      } catch (err) {
        logger.error("掃描日誌失敗:", err as Error);
      }
    }, 1000);

    logger.success("📡 即時監控已啟動");
  }

  private periodicLogDate: string = "";

  private startPeriodicScan(): void {
    logger.info(`啟動定時掃描模式，間隔 ${config.scanInterval} 秒...`);
    this.periodicLogDate = moment().format("YYYY-MM-DD");

    setInterval(async () => {
      if (!this.isRunning) return;

      try {
        // 檢查日期是否改變（跨日換檔）
        const today = moment().format("YYYY-MM-DD");
        if (today !== this.periodicLogDate) {
          this.periodicLogDate = today;
          logger.info(`切換至新日誌檔案: ${this.getLogPath()}`);
        }

        if (!fs.existsSync(this.getLogPath())) {
          return;
        }

        const content = fs.readFileSync(this.getLogPath(), "utf8");
        const lines = content.split("\n");
        const entries = [];

        for (const line of lines) {
          const entry = this.logParser.parseLine(line);
          if (entry) {
            entries.push(entry);
          }
        }

        await this.processEntries(entries);
      } catch (err) {
        logger.error("掃描失敗:", err as Error);
      }
    }, config.scanInterval * 1000);

    logger.success("定時掃描已啟動");
  }

  private async processEntries(entries: any[]): Promise<void> {
    const now = new Date();
    const stats = this.logParser.analyzeEntries(
      entries,
      config.banThreshold,
      now,
    );

    // 即時監控模式：將新批次累積到跨批次統計中
    for (const [ip, attackStats] of stats) {
      const existing = this.accumulatedStats.get(ip);
      if (existing) {
        existing.count += attackStats.count;
        existing.lastSeen = attackStats.lastSeen;
        existing.sampleRequest = attackStats.sampleRequest;
      } else {
        this.accumulatedStats.set(ip, {
          count: attackStats.count,
          sampleRequest: attackStats.sampleRequest,
          firstSeen: attackStats.firstSeen,
          lastSeen: attackStats.lastSeen,
        });
      }
    }

    // 每分鐘清理一次過期的累積記錄（超過 1 分鐘的清除） 
    const cleanupInterval = 60 * 1000;
    if (now.getTime() - this.lastAccumulationCleanup.getTime() > cleanupInterval) {
      const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);
      for (const [ip, acc] of this.accumulatedStats) {
        if (acc.lastSeen < oneMinuteAgo) {
          this.accumulatedStats.delete(ip);
        }
      }
      this.lastAccumulationCleanup = now;

      // 每小時清理一次過期記錄
      this.purgeStaleSuspiciousRecords(now);
      this.purgeStalePreviouslyUnbanned(now);
    }

    // 將所有可疑 IP 記錄到審查佇列（忽略白名單 IP）
    for (const [ip, attackStats] of stats) {
      if (isWhitelistedIP(ip)) continue;
      const accCount = this.accumulatedStats.get(ip)?.count || attackStats.count;
      const existing = this.suspiciousRecords.get(ip);

      // 收集匹配到的模式
      const patterns: string[] = [];
      for (const pattern of config.suspiciousPatterns) {
        if (attackStats.sampleRequest.toLowerCase().includes(pattern)) {
          patterns.push(pattern);
        }
      }

      if (existing) {
        existing.count = Math.max(existing.count, accCount);
        existing.lastSeen = attackStats.lastSeen.toISOString();
        existing.sampleRequest = attackStats.sampleRequest;
        if (existing.status === "pending") {
          // 保留最新的模式清單
          const merged = new Set([...existing.matchedPatterns, ...patterns]);
          existing.matchedPatterns = Array.from(merged);
        }
      } else {
        this.suspiciousRecords.set(ip, {
          ip,
          count: accCount,
          sampleRequest: attackStats.sampleRequest,
          firstSeen: attackStats.firstSeen.toISOString(),
          lastSeen: attackStats.lastSeen.toISOString(),
          matchedPatterns: patterns,
          status: "pending",
        });
      }
    }

    // 儲存可疑 IP 記錄到檔案
    this.saveSuspiciousRecords();

    // 自動封鎖模式：檢查累積統計是否達標
    if (config.autoBan) {
      // 追蹤本次呼叫內剛封鎖的目標，避免同一批次內發送重複告警
      const freshlyBannedInThisCall = new Set<string>();

      for (const [ip, attackStats] of stats) {
        if (isWhitelistedIP(ip)) continue;
        const accCount = this.accumulatedStats.get(ip)?.count || attackStats.count;
        const suspiciousRec = this.suspiciousRecords.get(ip);

        // 只統計高風險模式命中數（低風險模式需要搭配 403/429 才會觸發，不單獨計入）
        const highConfidenceHits = suspiciousRec?.matchedPatterns?.filter(
          (p) => config.highConfidencePatterns.includes(p),
        ).length || 0;

        // 封鎖條件：次數達標 OR 命中 3+ 種高風險模式且累積 ≥ 5 次（避免單次誤判）
        const shouldBan =
          accCount >= config.banThreshold ||
          (highConfidenceHits >= 3 && accCount >= 5);

        if (shouldBan) {
          // 決定目標：off=單一IP, force=整個/24, auto=先單一後升級
          const subnetPrefix = ip.substring(0, ip.lastIndexOf("."));
          let targetIP: string;
          let isSubnetBan = false;

          if (config.banSubnet === "force") {
            targetIP = ipToCidr(ip);
            isSubnetBan = true;
          } else if (config.banSubnet === "auto") {
            // auto 模式：即時計算該子網中已封鎖的單一 IP 數量
            const existingCount = this.countBannedInSubnet(subnetPrefix);
            if (existingCount >= 1) {
              // 已有 1+ 個不同 IP 被封 → 升級為子網封鎖
              targetIP = ipToCidr(ip);
              isSubnetBan = true;
            } else {
              targetIP = ip;
            }
          } else {
            targetIP = ip;
          }

          // 白名單檢查
          let isWhitelisted = false;
          if (isSubnetBan) {
            isWhitelisted = isSubnetWhitelisted(targetIP, config.whitelist);
          } else {
            isWhitelisted = await this.firewall.isWhitelisted(ip, config.whitelist);
          }

          // 檢查是否已封鎖：exact match + CIDR 覆蓋檢查（個別 IP 是否被既有 CIDR 涵蓋）
          const isAlreadyBanned =
            this.firewall.getBannedIPs().has(targetIP) ||
            this.isCoveredByExistingCIDR(targetIP);

          if (!isWhitelisted && !isAlreadyBanned) {
            // === 檢查是否為再犯（曾解封後再次攻擊 → 永久封鎖） ===
            const isRepeatOffender =
              this.previouslyUnbanned.has(targetIP) ||
              (isSubnetBan && this.previouslyUnbanned.has(targetIP)) ||
              this.previouslyUnbanned.has(ip) ||
              Array.from(this.previouslyUnbanned.keys()).some(
                (k) => k.includes("/") && ip.startsWith(k.split("/")[0].substring(0, k.split("/")[0].lastIndexOf("."))),
              );

            if (isRepeatOffender) {
              this.permanentBans.add(targetIP);
              this.savePermanentBans();
              logger.warn(`🚫 ${targetIP} 為再犯 IP，已標記為永久封鎖（不再自動解封）`);
            }

            // === 首次封鎖 ===
            const reasonByPattern = highConfidenceHits >= 3
              ? `匹配 ${highConfidenceHits} 種高風險攻擊模式（${suspiciousRec?.matchedPatterns?.join(", ") || ""}）`
              : `${accCount}次攻擊請求（閾值 ${config.banThreshold} 次/分鐘）`;

            const banRecord: any = {
              ip: targetIP,
              reason: isRepeatOffender
                ? `⚠️ 永久封鎖：曾解封後再次攻擊 - ${isSubnetBan ? `子網 ${targetIP} 出現多次攻擊，升級封鎖 - ` : ""}${reasonByPattern}`
                : isSubnetBan
                  ? `子網 ${targetIP} 出現多次攻擊，升級封鎖 - ${reasonByPattern}`
                  : reasonByPattern,
              sampleRequest: attackStats.sampleRequest,
              sampleRequests: attackStats.sampleRequests,
              timestamp: new Date().toISOString(),
              requestCount: accCount,
              ruleName: `AutoBan_${targetIP.replace(/[\.\/]/g, "_")}`,
              permanent: isRepeatOffender,
            };

            // 查詢 IP 地理位置
            const location = getIpLocation(ip);
            if (location) {
              banRecord.ipLocation = formatIpLocation(ip, location);
              banRecord.ipCountry = location.country;
            }

            // 若升級為子網封鎖，先移除該子網下所有單一 IP 的防火牆規則
            if (isSubnetBan) {
              const ipsToRemove: string[] = [];
              for (const banned of this.firewall.getBannedIPs()) {
                if (!banned.includes("/") && banned.startsWith(subnetPrefix + ".")) {
                  ipsToRemove.push(banned);
                }
              }
              if (ipsToRemove.length > 0) {
                await this.firewall.removeMultipleIPs(ipsToRemove);
              }
            }

            const banned = await this.firewall.banIP(banRecord);
            if (banned) {
              // 標記為本次呼叫內剛封鎖，防止同一批次內觸發重複告警
              freshlyBannedInThisCall.add(targetIP);

              // 更新審查記錄狀態
              const rec = this.suspiciousRecords.get(ip);
              if (rec) rec.status = "banned";
              this.saveSuspiciousRecords();

              await this.emailNotifier.sendBanAlert(banRecord);
              this.saveBannedIPs();
            }
          } else if (!isWhitelisted && isAlreadyBanned) {
            // 已封鎖 IP 再次攻擊 → 僅更新審查記錄，不再發送重複告警電郵
            // 若本次呼叫內剛封鎖此目標，跳過（同一批次內不重複處理）
            if (freshlyBannedInThisCall.has(targetIP)) continue;

            const existingRec = this.suspiciousRecords.get(ip);
            if (existingRec) {
              existingRec.lastSeen = attackStats.lastSeen.toISOString();
              existingRec.count = Math.max(existingRec.count, accCount);
              this.saveSuspiciousRecords();
            }
          }
        }
      }
    } else {
      // 手動模式：記錄已達標但未封鎖的 IP
      for (const [ip, attackStats] of stats) {
        const accCount = this.accumulatedStats.get(ip)?.count || attackStats.count;
        if (accCount >= config.banThreshold) {
          const isBanned = this.firewall.getBannedIPs().has(ip);
          if (!isBanned) {
            logger.warn(`⚠️ [待審查] IP ${ip} 可疑請求 ${accCount} 次（閾值 ${config.banThreshold}），請至管理介面決定是否封鎖`);
          }
        }
      }
    }
  }

  /** 檢查個別 IP 是否已被既有 CIDR 封鎖涵蓋（例如 185.177.72.99 是否被 185.177.72.0/24 覆蓋） */
  private isCoveredByExistingCIDR(ip: string): boolean {
    if (ip.includes("/")) return false; // CIDR 本身不檢查覆蓋
    const ipPrefix = ip.substring(0, ip.lastIndexOf("."));
    for (const banned of this.firewall.getBannedIPs()) {
      if (banned.includes("/")) {
        const cidrPrefix = banned.split("/")[0];
        const cidrBase = cidrPrefix.substring(0, cidrPrefix.lastIndexOf("."));
        if (ipPrefix === cidrBase) return true;
      }
    }
    return false;
  }

  private loadSuspiciousRecords(): void {
    if (!fs.existsSync(config.suspiciousFile)) return;
    try {
      const data = JSON.parse(fs.readFileSync(config.suspiciousFile, "utf8"));
      if (data.suspiciousIPs && Array.isArray(data.suspiciousIPs)) {
        for (const rec of data.suspiciousIPs) {
          this.suspiciousRecords.set(rec.ip, rec);
        }
      }
      logger.info(`載入了 ${this.suspiciousRecords.size} 筆可疑 IP 審查記錄`);
    } catch (err) {
      logger.error("載入可疑 IP 記錄失敗:", err as Error);
    }
  }

  private saveSuspiciousRecords(): void {
    const records = Array.from(this.suspiciousRecords.values());
    const data = {
      suspiciousIPs: records,
      timestamp: new Date().toISOString(),
    };
    fs.writeFileSync(config.suspiciousFile, JSON.stringify(data, null, 2));
  }

  /** 清理過期記錄：
   *  - pending/ignored：超過 7 天未處理自動刪除
   *  - banned：超過 30 天自動刪除（記憶體釋放，防火牆規則不受影響） */
  private purgeStaleSuspiciousRecords(now: Date): void {
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    let purged = 0;

    for (const [ip, rec] of this.suspiciousRecords) {
      if (rec.status === "pending" || rec.status === "ignored") {
        const lastSeen = new Date(rec.lastSeen);
        if (lastSeen < sevenDaysAgo) {
          this.suspiciousRecords.delete(ip);
          purged++;
        }
      } else if (rec.status === "banned") {
        const lastSeen = new Date(rec.lastSeen);
        if (lastSeen < thirtyDaysAgo) {
          this.suspiciousRecords.delete(ip);
          purged++;
        }
      }
    }

    if (purged > 0) {
      this.saveSuspiciousRecords();
      logger.info(`🧹 自動清理 ${purged} 筆過期可疑記錄`);
    }
  }

  /** 清理超過 90 天的解封歷史（再犯觀察期已過） */
  private purgeStalePreviouslyUnbanned(now: Date): void {
    const ninetyDaysAgo = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
    let purged = 0;

    for (const [ip, unbannedAt] of this.previouslyUnbanned) {
      if (new Date(unbannedAt) < ninetyDaysAgo) {
        this.previouslyUnbanned.delete(ip);
        purged++;
      }
    }

    if (purged > 0) {
      this.savePreviouslyUnbanned();
      logger.info(`🧹 自動清理 ${purged} 筆超過 90 天的解封歷史`);
    }
  }

  /** 載入永久封鎖名單 */
  private loadPermanentBans(): void {
    if (!fs.existsSync(config.permanentBanFile)) return;
    try {
      const data = JSON.parse(fs.readFileSync(config.permanentBanFile, "utf8"));
      if (data.permanentBans && Array.isArray(data.permanentBans)) {
        for (const ip of data.permanentBans) {
          this.permanentBans.add(ip);
        }
      }
      logger.info(`載入了 ${this.permanentBans.size} 筆永久封鎖記錄`);
    } catch (err) {
      logger.error("載入永久封鎖記錄失敗:", err as Error);
    }
  }

  /** 儲存永久封鎖名單 */
  private savePermanentBans(): void {
    const data = {
      permanentBans: Array.from(this.permanentBans),
      timestamp: new Date().toISOString(),
    };
    fs.writeFileSync(config.permanentBanFile, JSON.stringify(data, null, 2));
  }

  /** 載入曾解封記錄 */
  private loadPreviouslyUnbanned(): void {
    const file = path.join(path.dirname(config.permanentBanFile), "unbanned_history.json");
    if (!fs.existsSync(file)) return;
    try {
      const data = JSON.parse(fs.readFileSync(file, "utf8"));
      if (data.unbannedRecords && Array.isArray(data.unbannedRecords)) {
        for (const rec of data.unbannedRecords) {
          this.previouslyUnbanned.set(rec.ip, rec.unbannedAt);
        }
      }
      logger.info(`載入了 ${this.previouslyUnbanned.size} 筆解封歷史記錄`);
    } catch (err) {
      logger.error("載入解封歷史記錄失敗:", err as Error);
    }
  }

  /** 儲存曾解封記錄 */
  private savePreviouslyUnbanned(): void {
    const file = path.join(path.dirname(config.permanentBanFile), "unbanned_history.json");
    const records = Array.from(this.previouslyUnbanned.entries()).map(
      ([ip, unbannedAt]) => ({ ip, unbannedAt }),
    );
    const data = {
      unbannedRecords: records,
      timestamp: new Date().toISOString(),
    };
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  }

  /** Web UI 用：取得所有可疑 IP 記錄 */
  getSuspiciousRecords(): SuspiciousRecord[] {
    return Array.from(this.suspiciousRecords.values());
  }

  /** Web UI 用：直接封鎖指定 IP（測試防火牆用） */
  async banManual(ip: string): Promise<boolean> {
    const isForceSubnet = config.banSubnet === "force";
    const targetIP = isForceSubnet ? ipToCidr(ip) : ip;

    if (this.firewall.getBannedIPs().has(targetIP)) {
      logger.warn(`Web UI 手動封鎖失敗: ${targetIP} 已在黑名單中`);
      return false;
    }

    const banRecord: any = {
      ip: targetIP,
      reason: `管理員手動測試封鎖`,
      sampleRequest: "手動測試",
      sampleRequests: ["手動測試封鎖"],
      timestamp: new Date().toISOString(),
      requestCount: 0,
      ruleName: `AutoBan_${targetIP.replace(/[\.\/]/g, "_")}`,
    };

    const location = getIpLocation(ip);
    if (location) {
      banRecord.ipLocation = formatIpLocation(ip, location);
      banRecord.ipCountry = location.country;
    }

    const banned = await this.firewall.banIP(banRecord);
    if (banned) {
      this.saveBannedIPs();
      logger.info(`Web UI 手動封鎖 IP: ${targetIP}`);
      return true;
    }
    return false;
  }

  /** Web UI 用：從審查佇列手動封鎖 IP */
  async banFromSuspicious(ip: string): Promise<boolean> {
    const rec = this.suspiciousRecords.get(ip);
    if (!rec) return false;

    // 自動模式：手動封鎖時不自動升級子網（由管理員決定）
    const isForceSubnet = config.banSubnet === "force";
    const targetIP = isForceSubnet ? ipToCidr(ip) : ip;

    const isAlreadyBanned = this.firewall.getBannedIPs().has(targetIP);
    if (isAlreadyBanned) return false;

    const banRecord: any = {
      ip: targetIP,
      reason: isForceSubnet
        ? `手動封鎖子網：${rec.count}次可疑請求（${rec.matchedPatterns.join(", ")}）`
        : `手動封鎖：${rec.count}次可疑請求（${rec.matchedPatterns.join(", ")}）`,
      sampleRequest: rec.sampleRequest,
      timestamp: new Date().toISOString(),
      requestCount: rec.count,
      ruleName: `AutoBan_${targetIP.replace(/[\.\/]/g, "_")}`,
    };

    // 查詢 IP 地理位置
    const location = getIpLocation(ip);
    if (location) {
      banRecord.ipLocation = formatIpLocation(ip, location);
      banRecord.ipCountry = location.country;
    }

    const banned = await this.firewall.banIP(banRecord);
    if (banned) {
      rec.status = "banned";
      this.saveSuspiciousRecords();
      this.saveBannedIPs();
      logger.info(`已從審查佇列手動封鎖 ${targetIP.includes("/") ? `子網 ${targetIP}` : `IP ${targetIP}`}`);
      return true;
    }
    return false;
  }

  /** Web UI 用：忽略可疑 IP */
  ignoreSuspicious(ip: string): void {
    const rec = this.suspiciousRecords.get(ip);
    if (rec) {
      rec.status = "ignored";
      this.saveSuspiciousRecords();
      logger.info(`已標記為忽略 IP: ${ip}`);
    }
  }

  /** 自動解封過期的封鎖記錄 */
  private async autoUnbanExpired(): Promise<void> {
    const now = new Date();
    const expireMs = config.autoUnbanHours * 60 * 60 * 1000;
    const toUnban: string[] = [];
    const skippedSubnet: string[] = [];
    const skippedPermanent: string[] = [];

    for (const record of this.firewall.getBannedIPsWithTime()) {
      const ip = record.ip;
      const banTime = new Date(record.timestamp);
      if (now.getTime() - banTime.getTime() < expireMs) continue;

      // 檢查是否為永久封鎖
      if (this.permanentBans.has(ip)) {
        skippedPermanent.push(ip);
        continue;
      }

      // 檢查是否為子網封鎖且不允許自動解封子網
      if (ip.includes("/") && !config.autoUnbanSubnet) {
        skippedSubnet.push(ip);
        continue;
      }

      toUnban.push(ip);
    }

    if (skippedSubnet.length > 0) {
      logger.info(`🔒 跳過子網自動解封（AUTO_UNBAN_SUBNET=false）: ${skippedSubnet.join(", ")}`);
    }
    if (skippedPermanent.length > 0) {
      logger.info(`🔒 跳過永久封鎖自動解封: ${skippedPermanent.join(", ")}`);
    }

    if (toUnban.length === 0) return;

    logger.info(`🔓 自動解封 ${toUnban.length} 個過期 IP: ${toUnban.join(", ")}`);

    for (const ip of toUnban) {
      const success = await this.firewall.unbanIP(ip);
      if (success) {
        // 記錄到曾解封名單（再犯時永久封鎖）
        this.previouslyUnbanned.set(ip, now.toISOString());
        this.savePreviouslyUnbanned();

        // 更新審查記錄
        const rec = this.suspiciousRecords.get(ip);
        if (rec) rec.status = "ignored";
      }
    }

    this.saveBannedIPs();
    this.saveSuspiciousRecords();
  }

  private setupGracefulShutdown(): void {
    process.on("SIGINT", () => {
      logger.info("\n收到退出訊號，正在儲存資料...");
      this.isRunning = false;
      this.saveBannedIPs();
      this.saveSuspiciousRecords();
      this.savePermanentBans();
      this.savePreviouslyUnbanned();

      if (this.webServer) {
        this.webServer.stop();
      }

      setTimeout(() => {
        process.exit(0);
      }, 1000);
    });

    process.on("SIGTERM", () => {
      this.isRunning = false;
      this.saveBannedIPs();
      this.saveSuspiciousRecords();
      process.exit(0);
    });
  }
}

// 启动应用
const app = new NginxAutoBan();
app.start().catch((err) => {
  logger.error("啟動失敗:", err);
  process.exit(1);
});
