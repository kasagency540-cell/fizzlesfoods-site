import crypto from "node:crypto";
import { HttpError } from "./utils.mjs";
import { getAuth, saveAuth } from "./db.mjs";

const COOKIE = "ff_owner";
const SESSION_SECONDS = 7 * 24 * 60 * 60; // owner stays logged in for 7 days

const sha256 = value => crypto.createHash("sha256").update(String(value)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha256(a), sha256(b));

const scrypt = (password, salt) =>
  new Promise((resolve, reject) =>
    crypto.scrypt(password, salt, 64, (err, key) => (err ? reject(err) : resolve(key)))
  );

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt);
  return `${salt.toString("hex")}:${key.toString("hex")}`;
}

async function verifyHash(password, stored) {
  const [saltHex, keyHex] = String(stored).split(":");
  if (!saltHex || !keyHex) return false;
  const expected = Buffer.from(keyHex, "hex");
  const actual = await scrypt(password, Buffer.from(saltHex, "hex"));
  return expected.length === actual.length && crypto.timingSafeEqual(expected, actual);
}

function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s || s.length < 16) {
    throw new HttpError(500, "The server is not set up yet (SESSION_SECRET is missing).");
  }
  return s;
}

const b64 = value => Buffer.from(value).toString("base64url");
const sign = payload => crypto.createHmac("sha256", secret()).update(payload).digest("base64url");

/* ---------- Password checking ---------- */

export async function verifyOwnerPassword(password) {
  const pw = String(password || "");
  if (!pw || pw.length > 200) return false;
  const auth = await getAuth();

  // Emergency reset: set RESET_PASSWORD in Netlify, redeploy, then log in with it once.
  const resetPw = process.env.RESET_PASSWORD;
  if (resetPw) {
    const marker = sha256(resetPw).toString("hex");
    if (auth.resetMarker !== marker && safeEqual(pw, resetPw)) {
      await saveAuth({
        hash: await hashPassword(resetPw),
        sessionVersion: auth.sessionVersion + 1,
        resetMarker: marker
      });
      return true;
    }
  }

  if (auth.hash) return verifyHash(pw, auth.hash);

  // First-time setup: use the OWNER_PASSWORD variable until the owner changes it.
  const initial = process.env.OWNER_PASSWORD;
  if (!initial) throw new HttpError(500, "The server is not set up yet (OWNER_PASSWORD is missing).");
  return safeEqual(pw, initial);
}

export async function changeOwnerPassword(current, next) {
  if (!(await verifyOwnerPassword(current))) throw new HttpError(401, "Current password is incorrect.");
  const newPw = String(next || "");
  if (newPw.length < 8) throw new HttpError(400, "New password must be at least 8 characters.");
  if (newPw.length > 200) throw new HttpError(400, "New password is too long.");
  const auth = await getAuth();
  const updated = {
    ...auth,
    hash: await hashPassword(newPw),
    sessionVersion: auth.sessionVersion + 1 // logs out every other device
  };
  await saveAuth(updated);
  return updated.sessionVersion;
}

/* ---------- Sessions (signed, HttpOnly cookie) ---------- */

export async function createSessionCookie(version) {
  let v = version;
  if (v === undefined) v = (await getAuth()).sessionVersion;
  const payload = b64(JSON.stringify({ v, exp: Date.now() + SESSION_SECONDS * 1000 }));
  return `${COOKIE}=${payload}.${sign(payload)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${SESSION_SECONDS}`;
}

export const clearSessionCookie = () =>
  `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

function readCookie(request, name) {
  const header = request.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...rest] = part.trim().split("=");
    if (k === name) return rest.join("=");
  }
  return "";
}

export async function isOwner(request) {
  const raw = readCookie(request, COOKIE);
  const [payload, signature] = raw.split(".");
  if (!payload || !signature) return false;
  const expected = sign(payload);
  if (signature.length !== expected.length) return false;
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return false;
  let data;
  try {
    data = JSON.parse(Buffer.from(payload, "base64url").toString());
  } catch {
    return false;
  }
  if (!data || typeof data.exp !== "number" || data.exp < Date.now()) return false;
  const auth = await getAuth();
  return data.v === auth.sessionVersion;
}
