export const FOOD_CATEGORIES = ["Continental dishes", "Local dishes", "Wine", "Ice cream", "Salad"];

export class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

export function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

// Trim, strip control characters, and limit length.
export function clean(value, max) {
  return String(value ?? "")
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .trim()
    .slice(0, max);
}

export function newId(prefix) {
  return `${prefix}-${crypto.randomUUID()}`;
}

export function normalizeCategory(category) {
  const value = String(category || "").trim();
  return FOOD_CATEGORIES.includes(value) ? value : "Local dishes";
}

export function parsePriceNumber(price) {
  const match = String(price ?? "").replace(/,/g, "").match(/-?\d+(?:\.\d+)?/);
  if (!match) return null;
  const value = Number(match[0]);
  return Number.isFinite(value) ? value : null;
}

// Same logic as the frontend, so the owner sees the same total the customer saw.
export function formatFoodTotal(price, quantity) {
  const unit = parsePriceNumber(price);
  if (unit === null || !Number.isFinite(quantity) || quantity < 1) return "Contact us";
  const total = unit * quantity;
  const prefixMatch = String(price ?? "").match(/^\s*([^0-9-]*)/);
  const prefix = prefixMatch ? prefixMatch[1].trim() : "";
  const amount = total.toLocaleString("en-US", {
    minimumFractionDigits: Number.isInteger(total) ? 0 : 2,
    maximumFractionDigits: 2
  });
  return prefix ? `${prefix} ${amount}` : amount;
}

export function getClientIp(request, context) {
  return (
    (context && context.ip) ||
    request.headers.get("x-nf-client-connection-ip") ||
    (request.headers.get("x-forwarded-for") || "").split(",")[0].trim() ||
    "unknown"
  );
}
