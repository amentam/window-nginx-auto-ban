export interface LogEntry {
  ip: string;
  time: string;
  request: string;
  status: number;
  userAgent?: string;
  referer?: string;
}

export interface DetectionResult {
  isSuspicious: boolean;
  reason: string;
  matchedPattern?: string;
}

export interface BanRecord {
  ip: string;
  reason: string;
  sampleRequest: string;
  sampleRequests?: string[];
  timestamp: string;
  requestCount: number;
  ruleName: string;
  ipLocation?: string;
  ipCountry?: string;
}

export interface Config {
  nodeEnv: string;
  nginxLogPath: string;
  banThreshold: number;
  scanInterval: number;
  realTimeMonitoring: boolean;
  bannedFile: string;
  whitelist: string[];
  smtp: {
    enabled: boolean;
    host: string;
    port: number;
    secure: boolean;
    auth: {
      user: string;
      pass: string;
    };
    from: string;
    to: string;
  };
  web: {
    enabled: boolean;
    port: number;
    username: string;
    password: string;
  };
  debug: boolean;
  autoBan: boolean;
  banSubnet: "off" | "auto" | "force";
  suspiciousFile: string;
  suspiciousPatterns: string[];
  highConfidencePatterns: string[];
  scannerUserAgents: string[];
  autoUnbanHours: number;
  autoUnbanSubnet: boolean;
  permanentBanFile: string;
}

export interface AttackStats {
  count: number;
  sampleRequest: string;
  sampleRequests: string[];
  firstSeen: Date;
  lastSeen: Date;
}

export interface SuspiciousRecord {
  ip: string;
  count: number;
  sampleRequest: string;
  firstSeen: string;
  lastSeen: string;
  matchedPatterns: string[];
  status: "pending" | "banned" | "ignored";
}
