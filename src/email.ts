import nodemailer from "nodemailer";
import { BanRecord } from "./types";
import { logger } from "./logger";

export class EmailNotifier {
  private transporter: nodemailer.Transporter | null = null;

  constructor(
    private enabled: boolean,
    private smtpConfig: any,
  ) {
    if (enabled && smtpConfig.auth.user && smtpConfig.auth.pass) {
      this.transporter = nodemailer.createTransport(smtpConfig);
      logger.info("郵件服務已初始化");
    }
  }

  async sendBanAlert(record: BanRecord): Promise<boolean> {
    if (!this.enabled || !this.transporter) {
      logger.debug("郵件服務未啟用");
      return false;
    }

    const html = this.generateHtmlEmail(record);
    const text = this.generateTextEmail(record);

    try {
      await this.transporter.sendMail({
        from: this.smtpConfig.from,
        to: this.smtpConfig.to,
        subject: `⚠️ Nginx 安全告警 - 已封禁 ${record.ip}${record.ip.includes("/") ? " (子網)" : ""}`,
        text,
        html,
      });
      logger.info(`郵件已發送至 ${this.smtpConfig.to}`);
      return true;
    } catch (error) {
      logger.error("郵件發送失敗:", error as Error);
      return false;
    }
  }

  private generateHtmlEmail(record: BanRecord): string {
    // 生成請求範例列表（最多 30 筆）
    const samples = record.sampleRequests && record.sampleRequests.length > 0
      ? record.sampleRequests
      : record.sampleRequest ? [record.sampleRequest] : [];
    const sampleHtml = samples.map((s, i) =>
      `<div style="background:#eee;padding:6px 10px;margin:4px 0;font-family:monospace;font-size:11px;overflow-x:auto;border-left:3px solid #d32f2f;">${String(i + 1).padStart(2, "0")}. ${this.escapeHtml(s)}</div>`
    ).join("");

    return `
<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; }
        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background: #d32f2f; color: white; padding: 10px; text-align: center; }
        .content { background: #f5f5f5; padding: 20px; }
        .info { margin: 10px 0; }
        .label { font-weight: bold; color: #333; }
        .ip { color: #d32f2f; font-size: 18px; font-family: monospace; }
        .request { background: #eee; padding: 10px; font-family: monospace; font-size: 12px; overflow-x: auto; }
        .footer { text-align: center; color: #999; font-size: 12px; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>⚠️ Nginx 安全告警</h2>
        </div>
        <div class="content">
            <p>檢測到惡意攻擊，已自動封禁 IP 地址：</p>
            <div class="info">
                <div><span class="label">攻擊 IP：</span><span class="ip">${record.ip}</span>${record.ipCountry ? `<span style="font-size:12px;color:#666;margin-left:8px;">🌍 ${record.ipLocation || record.ipCountry}</span>` : ""}</div>
                <div><span class="label">封禁原因：</span>${record.reason}</div>
                <div><span class="label">請求次數：</span>${record.requestCount} 次</div>
                <div><span class="label">封禁時間：</span>${record.timestamp}</div>
                <div><span class="label">防火牆規則：</span>${record.ruleName}</div>
            </div>
            <div class="info">
                <div class="label">攻擊請求範例（最近 ${samples.length} 筆）：</div>
                ${sampleHtml}
            </div>
            <p>該 IP 已被加入 Windows 防火牆黑名單。</p>
        </div>
        <div class="footer">
           Nginx Auto Ban System | ${new Date().toLocaleString()}
        </div>
    </div>
</body>
</html>
        `;
  }

  private generateTextEmail(record: BanRecord): string {
    // 生成請求範例列表（最多 30 筆）
    const samples = record.sampleRequests && record.sampleRequests.length > 0
      ? record.sampleRequests
      : record.sampleRequest ? [record.sampleRequest] : [];
    const sampleText = samples.map((s, i) =>
      `${String(i + 1).padStart(2, " ")}. ${s}`
    ).join("\n");

    return `
Nginx 安全告警
================================

檢測到惡意攻擊，已自動封禁 IP 地址：

攻擊 IP：${record.ip}${record.ipCountry ? `  🌍 ${record.ipLocation || record.ipCountry}` : ""}
封禁原因：${record.reason}
請求次數：${record.requestCount} 次
封禁時間：${record.timestamp}
防火牆規則：${record.ruleName}

攻擊請求範例（最近 ${samples.length} 筆）：
${sampleText}

該 IP 已被加入 Windows 防火牆黑名單。

Nginx Auto Ban System | ${new Date().toLocaleString()}
        `;
  }

  private escapeHtml(text: string): string {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }
}
