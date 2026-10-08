import {
  HttpError, json, clean, newId, normalizeCategory, formatFoodTotal, getClientIp, FOOD_CATEGORIES
} from "../lib/utils.mjs";
import * as db from "../lib/db.mjs";
import {
  verifyOwnerPassword, changeOwnerPassword, createSessionCookie, clearSessionCookie, isOwner
} from "../lib/auth.mjs";

export const config = { path: "/api/*" };

const LOGIN_LIMIT = 5, LOGIN_WINDOW = 15 * 60 * 1000;
const BOOKING_LIMIT = 15, BOOKING_WINDOW = 60 * 60 * 1000;
const MAX_IMAGE_BYTES = 2 * 1024 * 1024;
const MAX_PER_UPLOAD = 10;
const MAX_PER_BOX = 100;

export default async (request, context) => {
  try {
    return await route(request, context);
  } catch (err) {
    if (err instanceof HttpError) return json({ error: err.message }, err.status);
    console.error(err);
    return json({ error: "Server error. Please try again." }, 500);
  }
};

/* ------------------------------ helpers ------------------------------ */

async function readJson(request) {
  if (Number(request.headers.get("content-length") || 0) > 100_000) {
    throw new HttpError(413, "Request too large.");
  }
  try {
    const body = await request.json();
    if (!body || typeof body !== "object") throw new Error("bad");
    return body;
  } catch {
    throw new HttpError(400, "Invalid request.");
  }
}

function decode(part) {
  try { return decodeURIComponent(part); } catch { throw new HttpError(400, "Invalid request."); }
}

function sniffImage(buffer) {
  const b = new Uint8Array(buffer.slice(0, 12));
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
  if (b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 &&
      b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "image/webp";
  return null;
}

function validDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
  const d = new Date(value + "T00:00:00Z");
  if (Number.isNaN(d.getTime()) || d.toISOString().slice(0, 10) !== value) return false;
  const yesterday = Date.now() - 24 * 60 * 60 * 1000; // allow for time-zone differences
  return d.getTime() >= new Date(new Date(yesterday).toISOString().slice(0, 10) + "T00:00:00Z").getTime();
}

// A booking stays in History until its date has passed (plus the event length for events).
function parseDurationMs(duration) {
  const text = String(duration || "").toLowerCase();
  const hours = Number((text.match(/(\d+(?:\.\d+)?)\s*(?:hours?|hrs?)/) || [])[1] || 0);
  const minutes = Number((text.match(/(\d+)\s*(?:minutes?|mins?)/) || [])[1] || 0);
  const days = Number((text.match(/(\d+(?:\.\d+)?)\s*days?/) || [])[1] || 0);
  return hours * 3600000 + minutes * 60000 + days * 86400000;
}

function bookingExpiryAt(dateString, type, duration) {
  const base = new Date(`${dateString}T23:59:59Z`).getTime();
  const extra = type === "event" ? parseDurationMs(duration) : 0;
  return base + extra;
}

// Foods and events share the same add / edit / delete logic.
const KINDS = {
  foods: {
    key: "foods", prefix: "food",
    read: b => ({
      name: clean(b.name, 120),
      category: normalizeCategory(b.category),
      price: clean(b.price, 40),
      description: clean(b.description, 600)
    })
  },
  events: {
    key: "events", prefix: "event",
    read: b => ({
      name: clean(b.name, 120),
      duration: clean(b.duration, 60),
      price: clean(b.price, 40),
      description: clean(b.description, 600)
    })
  }
};

/* ------------------------------- router ------------------------------- */

async function route(request, context) {
  const url = new URL(request.url);
  const parts = url.pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean).map(decode);
  const method = request.method.toUpperCase();

  // Block cross-site form posts (extra protection on top of SameSite cookies).
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const origin = request.headers.get("origin");
    if (origin && origin !== url.origin) throw new HttpError(403, "Request blocked.");
  }

  /* ---------- Public ---------- */

  if (parts[0] === "site" && method === "GET") {
    const site = await db.getSite();
    return json({
      foods: site.foods,
      events: site.events,
      galleryTitles: site.galleryTitles,
      gallery1: site.gallery1,
      gallery2: site.gallery2,
      version: site.version
    });
  }

  if (parts[0] === "img" && parts[1] && method === "GET") {
    const found = await db.getImage(parts[1]);
    if (!found) return new Response("Not found", { status: 404 });
    return new Response(found.data, {
      headers: {
        "Content-Type": (found.metadata && found.metadata.contentType) || "image/jpeg",
        "Cache-Control": "public, max-age=31536000, immutable",
        "X-Content-Type-Options": "nosniff"
      }
    });
  }

  if (parts[0] === "bookings" && !parts[1] && method === "POST") {
    return createBooking(request, context);
  }

  if (parts[0] === "owner") return ownerRoute(parts, method, request, context);

  throw new HttpError(404, "Not found.");
}

/* ------------------------------ bookings ------------------------------ */

async function createBooking(request, context) {
  const ip = getClientIp(request, context);
  if (await db.isLimited("book:" + ip, BOOKING_LIMIT, BOOKING_WINDOW)) {
    throw new HttpError(429, "Too many bookings from this device. Please try again later.");
  }

  const b = await readJson(request);
  const type = b.type === "food" ? "food" : b.type === "event" ? "event" : null;
  if (!type) throw new HttpError(400, "Invalid booking type.");

  const customerName = clean(b.customerName, 100);
  const customerPhone = clean(b.customerPhone, 30);
  const bookingDate = clean(b.bookingDate, 10);
  const notes = clean(b.notes, 600);

  if (!customerName) throw new HttpError(400, "Please enter your name.");
  if (!/^[0-9+()\-\s]{7,30}$/.test(customerPhone)) throw new HttpError(400, "Please enter a valid phone number.");
  if (!validDate(bookingDate)) throw new HttpError(400, "Please choose a valid booking date.");

  const site = await db.getSite();
  const item = (type === "food" ? site.foods : site.events).find(x => x.id === String(b.itemId));
  if (!item) throw new HttpError(404, "Sorry, this item is no longer available.");

  let itemQuantity = "";
  let totalCost = "";
  if (type === "food") {
    itemQuantity = Number.parseInt(b.itemQuantity, 10);
    if (!Number.isFinite(itemQuantity) || itemQuantity < 1 || itemQuantity > 1000) {
      throw new HttpError(400, "Enter at least 1 item.");
    }
    totalCost = formatFoodTotal(item.price, itemQuantity);
  }

  const booking = {
    id: newId("booking"),
    createdAt: new Date().toISOString(),
    type: type === "food" ? "Food" : "Event",
    selected: item.name,
    price: item.price,
    duration: type === "event" ? item.duration || "" : "",
    sentAt: Date.now(),
    expiresAt: bookingExpiryAt(bookingDate, type, type === "event" ? item.duration : ""),
    bookingDate,
    customerName,
    customerPhone,
    itemQuantity,
    totalCost,
    notes
  };

  await db.addBooking(booking);
  await db.addHit("book:" + ip, BOOKING_WINDOW);
  return json({ ok: true, id: booking.id }, 201);
}

/* ------------------------------ owner area ------------------------------ */

async function ownerRoute(parts, method, request, context) {
  const [, resource, id] = parts;

  if (resource === "session" && method === "GET") {
    return json({ authenticated: await isOwner(request) });
  }

  if (resource === "login" && method === "POST") {
    const ip = getClientIp(request, context);
    if (await db.isLimited("login:" + ip, LOGIN_LIMIT, LOGIN_WINDOW)) {
      throw new HttpError(429, "Too many attempts. Please try again in 15 minutes.");
    }
    const body = await readJson(request);
    if (!(await verifyOwnerPassword(body.password))) {
      await db.addHit("login:" + ip, LOGIN_WINDOW);
      throw new HttpError(401, "Incorrect password.");
    }
    await db.clearHits("login:" + ip);
    return json({ ok: true }, 200, { "Set-Cookie": await createSessionCookie() });
  }

  if (resource === "logout" && method === "POST") {
    return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
  }

  // Everything below needs the owner to be logged in.
  if (!(await isOwner(request))) throw new HttpError(401, "Your session ended. Please log in again.");

  if (resource === "password" && method === "POST") {
    const body = await readJson(request);
    const version = await changeOwnerPassword(body.currentPassword, body.newPassword);
    // Keep this device logged in; all other devices are logged out.
    return json({ ok: true }, 200, { "Set-Cookie": await createSessionCookie(version) });
  }

  if (resource === "bookings") {
    if (method === "GET" && !id) return json(await db.listBookings());
    if (method === "DELETE" && id) {
      await db.deleteBooking(id);
      return json({ ok: true });
    }
  }

  if (KINDS[resource]) {
    const kind = KINDS[resource];

    if (method === "POST" && !id) {
      const fields = kind.read(await readJson(request));
      if (!fields.name) throw new HttpError(400, "Please enter a name.");
      const site = await db.getSite();
      const item = { id: newId(kind.prefix), ...fields };
      site[kind.key].push(item);
      await db.saveSite(site);
      return json(item, 201);
    }

    if (method === "PUT" && id) {
      const fields = kind.read(await readJson(request));
      if (!fields.name) throw new HttpError(400, "Please enter a name.");
      const site = await db.getSite();
      const index = site[kind.key].findIndex(x => x.id === id);
      if (index === -1) throw new HttpError(404, "This item no longer exists.");
      site[kind.key][index] = { id, ...fields };
      await db.saveSite(site);
      return json(site[kind.key][index]);
    }

    if (method === "DELETE" && id) {
      const site = await db.getSite();
      site[kind.key] = site[kind.key].filter(x => x.id !== id);
      await db.saveSite(site);
      return json({ ok: true });
    }
  }

  if (resource === "gallery-titles" && method === "PUT") {
    const body = await readJson(request);
    const one = clean(body[1], 60);
    const two = clean(body[2], 60);
    if (!one || !two) throw new HttpError(400, "Please enter a name for both gallery boxes.");
    const site = await db.getSite();
    site.galleryTitles = { 1: one, 2: two };
    await db.saveSite(site);
    return json({ ok: true });
  }

  if (resource === "gallery" && method === "POST" && (id === "1" || id === "2")) {
    return uploadGallery(request, Number(id));
  }

  if (resource === "gallery" && method === "DELETE" && id) {
    const site = await db.getSite();
    const inOne = site.gallery1.some(x => x.id === id);
    const inTwo = site.gallery2.some(x => x.id === id);
    if (!inOne && !inTwo) throw new HttpError(404, "This photo no longer exists.");
    site.gallery1 = site.gallery1.filter(x => x.id !== id);
    site.gallery2 = site.gallery2.filter(x => x.id !== id);
    await db.saveSite(site);
    await db.deleteImage(id);
    return json({ ok: true });
  }

  throw new HttpError(404, "Not found.");
}

async function uploadGallery(request, box) {
  let form;
  try {
    form = await request.formData();
  } catch {
    throw new HttpError(400, "Could not read the upload. Please try fewer photos at a time.");
  }

  let category = "";
  if (box === 1) {
    category = clean(form.get("category"), 40);
    if (!FOOD_CATEGORIES.includes(category)) throw new HttpError(400, "Please choose a food category.");
  }

  const files = form.getAll("images")
    .filter(f => f && typeof f === "object" && typeof f.arrayBuffer === "function")
    .slice(0, MAX_PER_UPLOAD);
  if (!files.length) throw new HttpError(400, "No photos were received.");

  const site = await db.getSite();
  const key = box === 1 ? "gallery1" : "gallery2";
  if (site[key].length + files.length > MAX_PER_BOX) {
    throw new HttpError(400, `A gallery box can hold at most ${MAX_PER_BOX} photos. Delete some first.`);
  }

  const added = [];
  for (const file of files) {
    const data = await file.arrayBuffer();
    if (data.byteLength > MAX_IMAGE_BYTES) throw new HttpError(400, "One of the photos is too large (max 2 MB each).");
    const contentType = sniffImage(data);
    if (!contentType) throw new HttpError(400, "Only JPG, PNG or WebP photos are allowed.");
    const id = newId("img");
    await db.putImage(id, data, contentType);
    added.push({
      id,
      url: `/api/img/${id}`,
      name: clean(String(file.name || "").replace(/\.[^.]+$/, ""), 80),
      category
    });
  }

  site[key].push(...added);
  await db.saveSite(site);
  return json({ ok: true, added: added.length }, 201);
        }
    
