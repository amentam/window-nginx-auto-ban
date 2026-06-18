import { exec, spawn } from "child_process";
import { promisify } from "util";
import { logger } from "./logger";
import { BanRecord } from "./types";
import fs from "fs";
import path from "path";
import os from "os";

const execPromise = promisify(exec);
const RULE_NAME = "AutoBan_BlockList";

/** 將 IP 轉為 /24 CIDR（例：45.148.10.62 → 45.148.10.0/24） */
export function ipToCidr(ip: string): string {
  const parts = ip.split(".");
  parts[3] = "0";
  return `${parts.join(".")}/24`;
}

/** 判斷 CIDR 區段中是否有任何 IP 在白名單內 */
export function isSubnetWhitelisted(
  cidr: string,
  whitelist: string[],
): boolean {
  for (const wl of whitelist) {
    if (wl.includes("/")) {
      // 如果白名單也是 CIDR，直接比較
      if (wl === cidr) return true;
    } else {
      // 檢查白名單 IP 是否在該 CIDR 區段內
      const cidrParts = cidr.split("/")[0].split(".");
      const wlParts = wl.split(".");
      if (
        cidrParts[0] === wlParts[0] &&
        cidrParts[1] === wlParts[1] &&
        cidrParts[2] === wlParts[2]
      ) {
        return true;
      }
    }
  }
  return false;
}

export class FirewallManager {
  private bannedIPs: Set<string> = new Set();
  private bannedAt: Map<string, string> = new Map();
  private isAdmin: boolean = false;

  constructor(private bannedFile: string) {}

  /** 設定是否為管理員權限（由 index.ts 呼叫） */
  setAdmin(admin: boolean): void {
    this.isAdmin = admin;
  }

  /**
   * 檢查目前處理程序是否以系統管理員權限執行
   */
  static async isAdmin(): Promise<boolean> {
    try {
      await execPromise("net session", { shell: "powershell.exe" });
      return true;
    } catch {
      return false;
    }
  }

  async isWhitelisted(ip: string, whitelist: string[]): Promise<boolean> {
    for (const rule of whitelist) {
      if (rule.includes("/")) {
        // CIDR 匹配
        if (this.isIPInCIDR(ip, rule)) {
          return true;
        }
      } else if (rule === ip) {
        return true;
      }
    }
    return false;
  }

  private isIPInCIDR(ip: string, cidr: string): boolean {
    // 簡化版 CIDR 匹配
    const [network, mask] = cidr.split("/");
    const ipParts = ip.split(".");
    const networkParts = network.split(".");
    const maskBits = parseInt(mask);
    const maskOctets = Math.floor(maskBits / 8);

    for (let i = 0; i < maskOctets; i++) {
      if (ipParts[i] !== networkParts[i]) {
        return false;
      }
    }
    return true;
  }

  /**
   * 執行 PowerShell（管理員直接跑，非管理員用 spawn + temp script 提權）
   */
  private runPS(
    cmd: string,
    captureOutput?: boolean,
  ): Promise<{ stdout: string; stderr: string } | void> {
    const action = this.getActionName(cmd);

    const encodedCmd = Buffer.from(cmd, "utf16le").toString("base64");

    const psArgs = [
      "-NoProfile",
      "-ExecutionPolicy",
      "Bypass",
      "-EncodedCommand",
      encodedCmd,
    ];

    if (this.isAdmin) {
      logger.info(`⚡ 直接執行（管理員）: ${action}`);
      if (captureOutput) {
        return execPromise(`powershell.exe ${psArgs.join(" ")}`, {
          shell: "cmd.exe",
        }).then(
          (r) => ({
            stdout: r.stdout?.trim() || "",
            stderr: r.stderr?.trim() || "",
          }),
          (e: any) => ({ stdout: "", stderr: e.message || "" }),
        );
      }
      return execPromise(`powershell.exe ${psArgs.join(" ")}`, {
        shell: "cmd.exe",
      }).then(() => {});
    }

    // 非管理員：用 spawn + temp script 提權
    logger.info(`🔐 需要管理員權限: ${action}`);
    return this.runWithElevation(cmd, captureOutput);
  }

  private getActionName(cmd: string): string {
    if (cmd.includes("New-NetFirewallRule")) return "新增防火牆規則";
    if (cmd.includes("Set-NetFirewallRule")) return "更新防火牆規則";
    if (cmd.includes("Remove-NetFirewallRule")) return "刪除防火牆規則";
    if (cmd.includes("Get-NetFirewallRule")) return "查詢防火牆規則";
    return "防火牆操作";
  }

  private runWithElevation(
    cmd: string,
    captureOutput?: boolean,
  ): Promise<{ stdout: string; stderr: string } | void> {
    const timestamp = Date.now();
    const tempOutput = path.join(os.tmpdir(), `fw_out_${timestamp}.txt`);
    const tempScript = path.join(os.tmpdir(), `fw_script_${timestamp}.ps1`);
    const markerFile = path.join(os.tmpdir(), `fw_done_${timestamp}.txt`);

    const encodedCmd = Buffer.from(cmd, "utf16le").toString("base64");
    const markerPath = markerFile.replace(/\\/g, "\\\\");

    // elevated script: 先建立 marker 代表 UAC 已授權，再執行命令
    const scriptContent = captureOutput
      ? `New-Item -Path "${markerPath}" -ItemType File -Force | Out-Null; & { powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "${encodedCmd}" } | Out-File "${tempOutput}" -Encoding UTF8 -Force`
      : `New-Item -Path "${markerPath}" -ItemType File -Force | Out-Null; powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand "${encodedCmd}"`;

    fs.writeFileSync(tempScript, scriptContent, "utf8");

    return new Promise<any>((resolve, reject) => {
      const ps = spawn(
        "powershell.exe",
        [
          "-NoProfile",
          "-Command",
          `Start-Process powershell.exe -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','${tempScript}' -Wait -WindowStyle Hidden`,
        ],
        { shell: true, stdio: "ignore" },
      );

      ps.on("close", () => {
        const authorized = fs.existsSync(markerFile);
        try { fs.unlinkSync(tempScript); } catch { /* ignore */ }
        try { fs.unlinkSync(markerFile); } catch { /* ignore */ }

        if (!authorized) {
          const action = this.getActionName(cmd);
          logger.warn(`⚠️ 使用者拒絕 UAC 授權: ${action}`);
          try { fs.unlinkSync(tempOutput); } catch { /* ignore */ }
          reject(new Error(`UAC_DENIED`));
          return;
        }

        let stdout = "";
        if (captureOutput && fs.existsSync(tempOutput)) {
          stdout = fs.readFileSync(tempOutput, "utf8").trim();
        }
        try { fs.unlinkSync(tempOutput); } catch { /* ignore */ }
        if (captureOutput) {
          resolve({ stdout, stderr: "" });
        } else {
          resolve(undefined);
        }
      });

      ps.on("error", (error) => {
        try { fs.unlinkSync(tempScript); } catch { /* ignore */ }
        try { fs.unlinkSync(markerFile); } catch { /* ignore */ }
        try { fs.unlinkSync(tempOutput); } catch { /* ignore */ }
        reject(error);
      });
    });
  }

  /** 讀取規則 RemoteAddress */
  private async getRuleIPs(): Promise<string[]> {
    const cmd = `
            $rule = Get-NetFirewallRule -DisplayName "${RULE_NAME}" -ErrorAction SilentlyContinue;
            if ($rule) {
                $filter = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule;
                if ($filter -and $filter.RemoteAddress) {
                    ($filter.RemoteAddress -join ',')
                } else {
                    ""
                }
            } else {
                ""
            }
        `;
    const result = (await this.runPS(cmd, true)) as
      | { stdout: string; stderr: string }
      | undefined;

    if (!result?.stdout || result.stdout.trim() === "") return [];
    return result.stdout
      .split(",")
      .map((s) => s.trim())
      .filter((s) => s.length > 0 && !s.includes("{") && !s.includes("}"));
  }

  /**
   * 直接寫入防火牆（已知規則是否存在，不再額外查詢）
   */
  private async writeFirewallRule(
    ips: string[],
    ruleExists: boolean,
  ): Promise<void> {
    if (ips.length === 0) {
      logger.info(`所有 IP 已移除，準備刪除防火牆規則 ${RULE_NAME}`);
      await this.runPS(
        `Remove-NetFirewallRule -DisplayName "${RULE_NAME}" -Confirm:$false -ErrorAction SilentlyContinue`,
      );
      return;
    }

    const ipList = ips.map((ip) => `'${ip}'`).join(",");
    const cmd = ruleExists
      ? `Set-NetFirewallRule -DisplayName "${RULE_NAME}" -RemoteAddress ${ipList}`
      : `New-NetFirewallRule -DisplayName "${RULE_NAME}" -Direction Inbound -RemoteAddress ${ipList} -Action Block`;

    logger.info(
      `防火牆規則 ${RULE_NAME} ${ruleExists ? "更新" : "新增"}（${ips.length} 個 IP）`,
    );
    await this.runPS(cmd);
  }

  private async replaceFirewallRule(ips: string[]): Promise<void> {
    if (ips.length === 0) {
      logger.info(`所有 IP 已移除，準備刪除防火牆規則 ${RULE_NAME}`);
      await this.runPS(
        `Remove-NetFirewallRule -DisplayName "${RULE_NAME}" -Confirm:$false -ErrorAction SilentlyContinue`,
      );
      return;
    }

    const existingIPs = await this.getRuleIPs();
    const newIPsSorted = [...ips].sort().map(this.normalizeCIDR);
    const existingIPsSorted = [...existingIPs].sort().map(this.normalizeCIDR);

    if (
      existingIPs.length > 0 &&
      JSON.stringify(newIPsSorted) === JSON.stringify(existingIPsSorted)
    ) {
      logger.info(
        `防火牆規則 ${RULE_NAME} IP 一致，無需更新（${newIPsSorted.join(", ")}）`,
      );
      return;
    }

    logger.info(
      `防火牆規則 ${RULE_NAME} ${existingIPs.length > 0 ? "更新" : "新增"}: [${newIPsSorted.join(", ")}]（先前: [${existingIPsSorted.join(", ") || "無"}]）`,
    );
    await this.writeFirewallRule(ips, existingIPs.length > 0);
  }

  async banIP(record: BanRecord): Promise<boolean> {
    const targetIP = record.ip;
    if (this.bannedIPs.has(targetIP)) {
      logger.debug(`IP ${targetIP} 已在黑名單中`);
      return false;
    }

    try {
      // 將新 IP 加入記憶體，然後整條規則重建
      this.bannedIPs.add(targetIP);
      this.bannedAt.set(targetIP, record.timestamp || new Date().toISOString());
      const allIPs = Array.from(this.bannedIPs);
      await this.replaceFirewallRule(allIPs);

      const label = targetIP.includes("/")
        ? `子網 ${targetIP}`
        : `IP ${targetIP}`;
      logger.success(`已封禁 ${label} (${record.requestCount}次攻擊)`);
      return true;
    } catch (error) {
      // 還原記憶體狀態
      this.bannedIPs.delete(targetIP);
      this.bannedAt.delete(targetIP);
      logger.error(`封禁失敗 ${targetIP}:`, error as Error);
      return false;
    }
  }

  async unbanIP(ip: string): Promise<boolean> {
    // 先在記憶體中檢查 IP 是否存在
    if (!this.bannedIPs.has(ip)) {
      logger.debug(`IP ${ip} 不在黑名單中`);
      return false;
    }

    // 先計算移除後的 IP 列表，但不修改記憶體
    const remainingIPs = Array.from(this.bannedIPs).filter((i) => i !== ip);

    try {
      // 先更新防火牆（需要 UAC）
      await this.replaceFirewallRule(remainingIPs);

      // 防火牆更新成功後，才修改記憶體
      this.bannedIPs.delete(ip);
      this.bannedAt.delete(ip);
      logger.info(`已解封 IP: ${ip}`);
      return true;
    } catch (error) {
      logger.error(`解封失敗 ${ip}:`, error as Error);
      return false;
    }
  }

  /** 批次移除多個 IP（用於子網升級時清理單一 IP） */
  async removeMultipleIPs(ips: string[]): Promise<void> {
    if (ips.length === 0) return;
    try {
      // 先計算移除後的列表，不修改記憶體
      const remainingIPs = Array.from(this.bannedIPs).filter(
        (i) => !ips.includes(i),
      );

      // 先更新防火牆
      await this.replaceFirewallRule(remainingIPs);

      // 防火牆更新成功後才修改記憶體
      for (const ip of ips) {
        this.bannedIPs.delete(ip);
        this.bannedAt.delete(ip);
      }
      logger.info(
        `已從防火牆規則移除 ${ips.length} 個單一 IP（升級為子網封鎖）`,
      );
    } catch (error) {
      logger.error(`批次移除 IP 失敗:`, error as Error);
    }
  }

  /** 將 Windows 防火牆的 /255.255.255.0 格式正規化為 /24 */
  private normalizeCIDR(ip: string): string {
    // 例: 185.177.72.0/255.255.255.0 → 185.177.72.0/24
    return ip.replace(/\/255\.255\.255\.0$/, "/24");
  }

  /** 啟動時同步：一次查詢比對，一致就跳過 */
  async syncFirewallRule(): Promise<void> {
    if (this.bannedIPs.size === 0) return;

    // 一次查詢取得防火牆目前的 IP 列表（順便知道規則是否存在）
    const existingIPs = await this.getRuleIPs();
    const memIPs = Array.from(this.bannedIPs).sort().map(this.normalizeCIDR);
    const fwIPs = [...existingIPs].sort().map(this.normalizeCIDR);

    if (
      existingIPs.length > 0 &&
      JSON.stringify(memIPs) === JSON.stringify(fwIPs)
    ) {
      logger.info(`防火牆規則已同步，無需更新（${memIPs.length} 個 IP 一致）`);
      return;
    }

    if (existingIPs.length === 0) {
      logger.warn(`防火牆規則 ${RULE_NAME} 不存在，正在重建...`);
    } else {
      logger.info(
        `防火牆規則需更新（記憶體 ${memIPs.length} vs 防火牆 ${fwIPs.length}）`,
      );
    }

    try {
      await this.writeFirewallRule(memIPs, existingIPs.length > 0);
      logger.info(`防火牆規則已同步，共 ${memIPs.length} 個 IP`);
    } catch (error) {
      logger.error(`防火牆規則同步失敗:`, error as Error);
    }
  }

  getBannedIPs(): Set<string> {
    return this.bannedIPs;
  }

  getBannedIPsWithTime(): { ip: string; timestamp: string }[] {
    return Array.from(this.bannedIPs).map((ip) => ({
      ip,
      timestamp: this.bannedAt.get(ip) || "-",
    }));
  }

  // loadBannedIPs(ips: string[]): void {
  //   this.bannedIPs = new Set(ips);
  //   // 從檔案載入時，若為純 IP 陣列則時間用 "-"
  //   for (const ip of ips) {
  //     if (!this.bannedAt.has(ip)) {
  //       this.bannedAt.set(ip, "-");
  //     }
  //   }
  //   logger.info(`載入了 ${this.bannedIPs.size} 個已封禁 IP`);
  // }

  loadBannedRecords(records: { ip: string; timestamp: string }[]): void {
    this.bannedIPs = new Set(records.map((r) => r.ip));
    this.bannedAt = new Map(records.map((r) => [r.ip, r.timestamp]));
    logger.info(`載入了 ${this.bannedIPs.size} 個已封禁 IP`);
  }
}
