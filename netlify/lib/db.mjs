import { getStore } from "@netlify/blobs";

// Netlify Blobs: permanent storage shared by every visitor and every device.
const open = () => getStore({ name: "fizzlesfoods", consistency: "strong" });

const safeId = id => /^[A-Za-z0-9_-]{1,80}$/.test(String(id || ""));

/* ---------- Public site content (foods, events, gallery) ---------- */

const emptySite = () => ({
  foods: [],
  events: [],
  galleryTitles: { 1: "Gallery Box", 2: "Gallery Box" },
  gallery1: [],
  gallery2: [],
  version: "0"
});

export async function getSite() {
  const site = await open().get("site", { type: "json" });
  return site ? { ...emptySite(), ...site } : emptySite();
}

// Every save gets a new version, so open phones notice the change and refresh.
export async function saveSite(site) {
  site.version = Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 8);
  await open().setJSON("site", site);
  return site;
}

/* ---------- Owner login record ---------- */

export async function getAuth() {
  const auth = await open().get("auth", { type: "json" });
  return { hash: null, sessionVersion: 1, resetMarker: "", ...(auth || {}) };
}

export async function saveAuth(auth) {
  await open().setJSON("auth", auth);
}

/* ---------- Bookings (one blob per booking, so simultaneous bookings never overwrite each other) ---------- */

export async function addBooking(booking) {
  await open().setJSON(`booking:${booking.id}`, booking);
}

// Bookings whose date has passed are removed automatically, exactly like the website's
// "active bookings" History. Set KEEP_BOOKINGS_FOREVER=yes in Netlify to keep them all.
export async function listBookings() {
  const store = open();
  const keepForever = String(process.env.KEEP_BOOKINGS_FOREVER || "").toLowerCase() === "yes";
  const now = Date.now();
  const { blobs } = await store.list({ prefix: "booking:" });
  const all = await Promise.all(
    blobs.map(async b => ({ key: b.key, value: await store.get(b.key, { type: "json" }).catch(() => null) }))
  );
  const active = [];
  for (const { key, value } of all) {
    if (!value) continue;
    if (!keepForever && Number(value.expiresAt) <= now) {
      await store.delete(key).catch(() => {});
      continue;
    }
    active.push(value);
  }
  return active.sort(
    (a, b) =>
      String(a.bookingDate).localeCompare(String(b.bookingDate)) || Number(a.sentAt) - Number(b.sentAt)
  );
}

export async function deleteBooking(id) {
  if (safeId(id)) await open().delete(`booking:${id}`);
}

/* ---------- Gallery images ---------- */

export async function putImage(id, data, contentType) {
  await open().set(`img:${id}`, data, { metadata: { contentType } });
}

export async function getImage(id) {
  if (!safeId(id)) return null;
  return open().getWithMetadata(`img:${id}`, { type: "arrayBuffer" });
}

export async function deleteImage(id) {
  if (safeId(id)) await open().delete(`img:${id}`);
}

/* ---------- Simple rate limiting (login attempts, spam bookings) ---------- */

const rlKey = name => `rl:${encodeURIComponent(name)}`;

export async function isLimited(name, limit, windowMs) {
  const rec = await open().get(rlKey(name), { type: "json" });
  if (!rec || Date.now() - rec.start > windowMs) return false;
  return rec.count >= limit;
}

export async function addHit(name, windowMs) {
  const store = open();
  const rec = await store.get(rlKey(name), { type: "json" });
  const now = Date.now();
  if (!rec || now - rec.start > windowMs) await store.setJSON(rlKey(name), { count: 1, start: now });
  else await store.setJSON(rlKey(name), { count: rec.count + 1, start: rec.start });
}

export async function clearHits(name) {
  await open().delete(rlKey(name));
    }
    
