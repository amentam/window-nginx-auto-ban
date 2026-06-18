import { config } from "./config";

const colors = {
  reset: "\x1b[0m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
};

type LogLevel = "info" | "warn" | "error" | "debug";

export class Logger {
  private static formatMessage(level: LogLevel, message: string): string {
    const timestamp = new Date().toISOString();
    let color = "";
    let levelStr = level.toUpperCase();

    switch (level) {
      case "info":
        color = colors.green;
        break;
      case "warn":
        color = colors.yellow;
        break;
      case "error":
        color = colors.red;
        break;
      case "debug":
        color = colors.cyan;
        break;
    }

    return `${colors.blue}[${timestamp}]${colors.reset} ${color}[${levelStr}]${colors.reset} ${message}`;
  }

  static info(message: string): void {
    console.log(this.formatMessage("info", message));
  }

  static warn(message: string): void {
    console.warn(this.formatMessage("warn", message));
  }

  static error(message: string, error?: Error): void {
    console.error(this.formatMessage("error", message));
    if (error && config.debug) {
      console.error(error.stack);
    }
  }

  static debug(message: string): void {
    if (config.debug) {
      console.debug(this.formatMessage("debug", message));
    }
  }

  static success(message: string): void {
    console.log(`${colors.green}✅ ${message}${colors.reset}`);
  }
}

export const logger = Logger;
