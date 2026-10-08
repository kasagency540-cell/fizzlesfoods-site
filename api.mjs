// FIZZLESFOODS backend — one Netlify Function, data kept in Netlify Blobs.
// Needs two environment variables (set in Netlify → Site configuration → Environment variables):
//   OWNER_PASSWORD  – the first owner password (can be changed later from the Owner panel)
//   AUTH_SECRET     – a long random string used to sign login tokens
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const FOOD_CATEGORIES = ["Continental dishes", "Local dishes", "Wine", "Ice cream", "Salad"];
const TOKEN_TTL_MS = 12 * 60 * 60 * 1000; // owner stays logged in for 12 hours
const MAX_GALLERY_PER_BOX = 40;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
const MAX_BODY_BYTES = 5.5 * 1024 * 1024; // Netlify Functions allow ~6 MB per request

const DEFAULT_CONTENT = {
  foods: [
    { id: "food-1", name: "Food Item 1", category: "Local dishes", price: "Contact us", description: "Add your food and price from the Owner panel." },
    { id: "food-2", name: "Food Item 2", category: "Local dishes", price: "Contact us", description: "Replace this with another food item." },
    { id: "food-3", name: "Food Item 3", category: "Local dishes", price: "Contact us", description: "Replace this with another food item." }
  ],
  events: [
    { id: "event-1", name: "Event Package 1", duration: "Contact us", price: "Contact us", description: "Add your event package from the Owner panel." },
    { id: "event-2", name: "Event Package 2", duration: "Contact us", price: "Contact us", description: "Add another event package." },
    { id: "event-3", name: "Event Package 3", duration: "Contact us", price: "Contact us", description: "Add another event package." }
  ],
  galleryTitles: { 1: "Gallery Box", 2: "Gallery Box" },
  gallery1: [],
  gallery2: []
};

const dataStore = () => getStore({ name: "fizzles-data", consistency: "strong" });
const imageStore = () => getStore({ name: "fizzles-images", consistency: "strong" });

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }
  });

const str = (value, max) => String(value ?? "").trim().slice(0, max);
const newId = prefix => `${prefix}-${Date.now().toString(36)}-${crypto.randomBytes(4).toString("hex")}`;
const sha = value => crypto.createHash("sha256").update(String(value)).digest("hex").slice(0, 32);

async function readBody(req) {
  if (Number(req.headers.get("content-length") || 0) > MAX_BODY_BYTES) throw new HttpError(413, "That upload is too large.");
  try { return await req.json(); } catch { throw new HttpError(400, "Invalid request."); }
}

/* ---------- content ---------- */

async function readContent() {
  const saved = (await dataStore().get("content", { type: "json" })) || {};
  return {
    foods: Array.isArray(saved.foods) ? saved.foods : DEFAULT_CONTENT.foods,
    events: Array.isArray(saved.events) ? saved.events : DEFAULT_CONTENT.events,
    galleryTitles: { ...DEFAULT_CONTENT.galleryTitles, ...(saved.galleryTitles || {}) },
    gallery1: Array.isArray(saved.gallery1) ? saved.gallery1 : [],
    gallery2: Array.isArray(saved.gallery2) ? saved.gallery2 : []
  };
}

const writeContent = content => dataStore().setJSON("content", content);

function publicContent(c) {
  const slides = list => list.map(i => ({ id: i.id, name: i.name, category: i.category || "", url: `/api/image/${i.id}` }));
  return { foods: c.foods, events: c.events, galleryTitles: c.galleryTitles, gallery1: slides(c.gallery1), gallery2: slides(c.gallery2) };
}

function cleanFoods(list) {
  if (!Array.isArray(list)) throw new HttpError(400, "Invalid food list.");
  return list.slice(0, 300).map(f => ({
    id: str(f?.id, 80) || newId("food"),
    name: str(f?.name, 80),
    category: FOOD_CATEGORIES.includes(f?.category) ? f.category : "Local dishes",
    price: str(f?.price, 40),
    description: str(f?.description, 400)
  })).filter(f => f.name);
}

function cleanEvents(list) {
  if (!Array.isArray(list)) throw new HttpError(400, "Invalid event list.");
  return list.slice(0, 100).map(e => ({
    id: str(e?.id, 80) || newId("event"),
    name: str(e?.name, 80),
    duration: str(e?.duration, 60),
    price: str(e?.price, 40),
    description: str(e?.description, 500)
  })).filter(e => e.name);
}

/* ---------- auth ---------- */

function secret() {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 16) throw new HttpError(500, "Server is not configured: set AUTH_SECRET (16+ characters) in Netlify environment variables.");
  return s;
}

const getAuthRecord = () => dataStore().get("auth", { type: "json" });

function hmac(value) {
  return crypto.createHmac("sha256", secret()).update(value).digest();
}

function checkPassword(input, record) {
  const given = String(input ?? "");
  if (record?.hash) {
    const hash = crypto.scryptSync(given, Buffer.from(record.salt, "hex"), 64);
    return crypto.timingSafeEqual(hash, Buffer.from(record.hash, "hex"));
  }
  const initial = process.env.OWNER_PASSWORD;
  if (!initial) throw new HttpError(500, "Server is not configured: set OWNER_PASSWORD in Netlify environment variables.");
  return crypto.timingSafeEqual(hmac(given), hmac(initial));
}

function signToken(version) {
  const body = Buffer.from(JSON.stringify({ exp: Date.now() + TOKEN_TTL_MS, v: version })).toString("base64url");
  const sig = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  return `${body}.${sig}`;
}

async function requireOwner(req) {
  const header = req.headers.get("authorization") || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  const [body, sig] = token.split(".");
  if (!body || !sig) throw new HttpError(401, "Please log in as owner.");
  const expected = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) throw new HttpError(401, "Please log in as owner.");
  let payload;
  try { payload = JSON.parse(Buffer.from(body, "base64url").toString()); } catch { throw new HttpError(401, "Please log in as owner."); }
  const record = await getAuthRecord();
  if (!payload.exp || payload.exp < Date.now() || payload.v !== (record?.version ?? 0)) throw new HttpError(401, "Your session has expired. Please log in again.");
}

/* ---------- simple rate limiting (per visitor IP) ---------- */

async function rateCheck(bucket, ip, max, windowMs) {
  const rec = await dataStore().get(`rl/${bucket}/${sha(ip)}`, { type: "json" });
  if (rec && Date.now() - rec.first < windowMs && rec.count >= max) {
    throw new HttpError(429, "Too many attempts. Please wait a while and try again.");
  }
}
async function rateHit(bucket, ip, windowMs) {
  const key = `rl/${bucket}/${sha(ip)}`;
  let rec = await dataStore().get(key, { type: "json" });
  if (!rec || Date.now() - rec.first >= windowMs) rec = { count: 0, first: Date.now() };
  rec.count += 1;
  await dataStore().setJSON(key, rec);
}

/* ---------- bookings ---------- */

function parseDurationMs(duration) {
  const text = String(duration || "").toLowerCase();
  const hours = Number((text.match(/(\d+(?:\.\d+)?)\s*(?:hours?|hrs?)/) || [])[1] || 0);
  const minutes = Number((text.match(/(\d+)\s*(?:minutes?|mins?)/) || [])[1] || 0);
  const days = Number((text.match(/(\d+(?:\.\d+)?)\s*days?/) || [])[1] || 0);
  return hours * 3600000 + minutes * 60000 + days * 86400000;
}

function bookingExpiry(date, type, duration) {
  const base = new Date(`${date}T23:59:59Z`).getTime();
  return type === "event" ? base + parseDurationMs(duration) : base;
}

async function listBookings() {
  const store = dataStore();
  const { blobs } = await store.list({ prefix: "booking/" });
  const all = await Promise.all(blobs.map(b => store.get(b.key, { type: "json" })));
  const now = Date.now();
  const active = [];
  await Promise.all(all.map(async (item, i) => {
    if (!item) return;
    if (Number(item.expiresAt) > now) active.push(item);
    else await store.delete(blobs[i].key);
  }));
  return active.sort((a, b) => String(a.bookingDate).localeCompare(String(b.bookingDate)) || a.sentAt - b.sentAt);
}

/* ---------- router ---------- */

export default async (req, context) => {
  try {
    const url = new URL(req.url);
    const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
    const [resource, a, b] = parts;
    const method = req.method;
    const ip = context?.ip || req.headers.get("x-nf-client-connection-ip") || "unknown";

    // Public: site content
    if (resource === "content" && method === "GET") {
      return json(publicContent(await readContent()));
    }

    // Public: gallery images
    if (resource === "image" && method === "GET") {
      if (!/^[a-z0-9-]{6,80}$/.test(a || "")) throw new HttpError(404, "Not found.");
      const data = await imageStore().get(a, { type: "arrayBuffer" });
      if (!data) throw new HttpError(404, "Not found.");
      return new Response(data, {
        headers: { "Content-Type": "image/jpeg", "Cache-Control": "public, max-age=31536000, immutable", "X-Content-Type-Options": "nosniff" }
      });
    }

    // Owner login
    if (resource === "login" && method === "POST") {
      await rateCheck("login", ip, 8, 15 * 60 * 1000);
      const body = await readBody(req);
      const record = await getAuthRecord();
      if (!checkPassword(body.password, record)) {
        await rateHit("login", ip, 15 * 60 * 1000);
        await new Promise(r => setTimeout(r, 600));
        throw new HttpError(401, "Incorrect password.");
      }
      await dataStore().delete(`rl/login/${sha(ip)}`);
      return json({ token: signToken(record?.version ?? 0) });
    }

    // Public: customer sends a booking (also saved to owner's history)
    if (resource === "bookings" && method === "POST") {
      await rateCheck("booking", ip, 20, 60 * 60 * 1000);
      const body = await readBody(req);
      const content = await readContent();
      const type = body.type === "event" ? "event" : "food";
      const item = (type === "event" ? content.events : content.foods).find(x => x.id === body.itemId);
      const bookingDate = str(body.bookingDate, 10);
      const customerName = str(body.customerName, 80);
      const customerPhone = str(body.customerPhone, 30);
      if (!item || !/^\d{4}-\d{2}-\d{2}$/.test(bookingDate) || !customerName || !customerPhone) {
        throw new HttpError(400, "Invalid booking.");
      }
      const booking = {
        id: newId("booking"),
        type: type === "event" ? "Event" : "Food",
        selected: item.name,
        price: item.price,
        duration: type === "event" ? item.duration : "",
        customerName,
        customerPhone,
        bookingDate,
        itemQuantity: type === "food" ? Math.min(Math.max(parseInt(body.itemQuantity, 10) || 1, 1), 100000) : null,
        totalCost: type === "food" ? str(body.totalCost, 60) : "",
        notes: str(body.notes, 1000),
        sentAt: Date.now(),
        expiresAt: bookingExpiry(bookingDate, type, item.duration)
      };
      await rateHit("booking", ip, 60 * 60 * 1000);
      await dataStore().setJSON(`booking/${booking.id}`, booking);
      return json({ ok: true }, 201);
    }

    // ---- everything below needs the owner to be logged in ----
    await requireOwner(req);

    if (resource === "content" && method === "PUT") {
      const body = await readBody(req);
      const content = await readContent();
      if ("foods" in body) content.foods = cleanFoods(body.foods);
      if ("events" in body) content.events = cleanEvents(body.events);
      if ("galleryTitles" in body) {
        const t1 = str(body.galleryTitles?.[1], 60), t2 = str(body.galleryTitles?.[2], 60);
        if (!t1 || !t2) throw new HttpError(400, "Please enter a name for both gallery boxes.");
        content.galleryTitles = { 1: t1, 2: t2 };
      }
      await writeContent(content);
      return json(publicContent(content));
    }

    if (resource === "gallery" && method === "POST" && (a === "1" || a === "2")) {
      const body = await readBody(req);
      const prefix = "data:image/jpeg;base64,";
      if (typeof body.data !== "string" || !body.data.startsWith(prefix)) throw new HttpError(400, "Please upload a JPG/PNG/WebP photo.");
      const buf = Buffer.from(body.data.slice(prefix.length), "base64");
      if (buf.length > MAX_IMAGE_BYTES) throw new HttpError(413, "That photo is too large.");
      if (!(buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff)) throw new HttpError(400, "That file is not a valid image.");
      const category = a === "1" ? str(body.category, 40) : "";
      if (a === "1" && !FOOD_CATEGORIES.includes(category)) throw new HttpError(400, "Please choose a food category.");

      const content = await readContent();
      const key = `gallery${a}`;
      if (content[key].length >= MAX_GALLERY_PER_BOX) throw new HttpError(400, `Each gallery box can hold ${MAX_GALLERY_PER_BOX} photos. Delete some first.`);
      const item = { id: newId(`gallery${a}`), name: str(body.name, 120), category, createdAt: Date.now() };
      await imageStore().set(item.id, buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
      content[key].push(item);
      await writeContent(content);
      return json({ id: item.id, name: item.name, category: item.category, url: `/api/image/${item.id}` }, 201);
    }

    if (resource === "gallery" && method === "DELETE" && (a === "1" || a === "2") && b) {
      const content = await readContent();
      const key = `gallery${a}`;
      content[key] = content[key].filter(i => i.id !== b);
      await writeContent(content);
      if (/^[a-z0-9-]{6,80}$/.test(b)) await imageStore().delete(b);
      return json({ ok: true });
    }

    if (resource === "bookings" && method === "GET") {
      return json(await listBookings());
    }

    if (resource === "bookings" && method === "DELETE" && /^[a-z0-9-]{6,80}$/.test(a || "")) {
      await dataStore().delete(`booking/${a}`);
      return json({ ok: true });
    }

    if (resource === "password" && method === "POST") {
      const body = await readBody(req);
      const record = await getAuthRecord();
      if (!checkPassword(body.current, record)) throw new HttpError(403, "Current password is incorrect.");
      const next = String(body.next ?? "");
      if (next.length < 8 || next.length > 100) throw new HttpError(400, "New password must be 8–100 characters.");
      const salt = crypto.randomBytes(16);
      const updated = {
        salt: salt.toString("hex"),
        hash: crypto.scryptSync(next, salt, 64).toString("hex"),
        version: Date.now() // changing the password logs out every other session
      };
      await dataStore().setJSON("auth", updated);
      return json({ token: signToken(updated.version) });
    }

    throw new HttpError(404, "Not found.");
  } catch (err) {
    if (err instanceof HttpError) return json({ error: err.message }, err.status);
    console.error(err);
    return json({ error: "Server error. Please try again." }, 500);
  }
};

export const config = { path: "/api/*" };
  
