// Same-tab notification only: the account overview must always re-fetch server-authoritative quotas.
// No cached usage numbers, tokens or account identities are passed in this event.
export const ACCOUNT_QUOTA_CHANGED_EVENT = "kango:account-quota-changed";
export function notifyAccountQuotaChanged(reason = "usage") {
  if (typeof window === "undefined" || typeof window.dispatchEvent !== "function") return false;
  window.dispatchEvent(new Event(ACCOUNT_QUOTA_CHANGED_EVENT));
  return true;
}
export function affectsAccountQuota(path, method = "GET") {
  const route = String(path || "").split("?")[0];
  const verb = String(method || "GET").toUpperCase();
  if (verb === "GET") return /^\/api\/mailboxes\/[^/]+\/messages$/.test(route);
  if (!["POST","PUT","PATCH","DELETE"].includes(verb)) return false;
  if (/^\/api\/mailboxes(?:\/|$)/.test(route)) return true;
  if (/^\/api\/large-drops(?:\/|$)/.test(route)) return true;
  if (/^\/api\/upgrade\/(?:reserved-prefixes|experience-vouchers|trial|redeem)(?:\/|$)/.test(route)) return true;
  return false;
}
