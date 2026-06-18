import geoip from "geoip-lite";

export interface IpLocation {
  country: string;
  region: string;
  city: string;
  timezone: string;
}

/** 快取：geoip-lite 本身已有記憶體快取，此處僅記錄查詢結果避免重複格式化 */
const displayCache = new Map<string, string>();

/**
 * 查詢 IP 地理位置（使用 geoip-lite 本地資料庫，離線查詢，無需網路）
 */
export function getIpLocation(ip: string): IpLocation | null {
  // 跳過內網/私有 IP
  if (isPrivateIP(ip)) {
    return null;
  }

  const geo = geoip.lookup(ip);
  if (!geo) return null;

  return {
    country: geo.country || "",
    region: geo.region || "",
    city: geo.city || "",
    timezone: geo.timezone || "",
  };
}

/** 格式化地理位置為簡短字串（含快取） */
export function formatIpLocation(ip: string, location: IpLocation | null): string {
  if (!location) return "未知";

  const cached = displayCache.get(ip);
  if (cached) return cached;

  const parts = [location.country, location.region, location.city].filter(Boolean);
  const result = parts.join(" / ") || "未知";

  displayCache.set(ip, result);
  return result;
}

/** 判斷是否為私有/內網 IP */
function isPrivateIP(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4) return true;
  if (parts[0] === 10) return true;
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
  if (parts[0] === 192 && parts[1] === 168) return true;
  if (parts[0] === 127) return true;
  return false;
}
