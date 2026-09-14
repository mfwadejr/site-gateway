import crypto from "node:crypto";

// Minimal RFC 4648 base32 (no padding), and RFC 6238 TOTP on top of RFC 4226 HOTP.
// Implemented against Node's built-in crypto only — no third-party dependency.

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Encode(buffer) {
  let bits = "";
  for (const byte of buffer) bits += byte.toString(2).padStart(8, "0");
  let output = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) output += BASE32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  const remainder = bits.length % 5;
  if (remainder) output += BASE32_ALPHABET[parseInt(bits.slice(bits.length - remainder).padEnd(5, "0"), 2)];
  return output;
}

export function base32Decode(value) {
  const cleaned = String(value || "").toUpperCase().replace(/[^A-Z2-7]/g, "");
  let bits = "";
  for (const char of cleaned) {
    const index = BASE32_ALPHABET.indexOf(char);
    if (index < 0) continue;
    bits += index.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function generateTotpSecret() {
  return base32Encode(crypto.randomBytes(20)); // 160-bit key, standard for authenticator apps
}

function hotp(secretBuffer, counter, digits = 6) {
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const hmac = crypto.createHmac("sha1", secretBuffer).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary = ((hmac[offset] & 0x7f) << 24) | ((hmac[offset + 1] & 0xff) << 16) | ((hmac[offset + 2] & 0xff) << 8) | (hmac[offset + 3] & 0xff);
  return String(binary % 10 ** digits).padStart(digits, "0");
}

export function totpAt(base32Secret, forTime = Date.now(), step = 30, digits = 6) {
  const counter = Math.floor(forTime / 1000 / step);
  return hotp(base32Decode(base32Secret), counter, digits);
}

// Accepts a code from the current step or one step on either side, to tolerate normal clock drift.
export function verifyTotp(base32Secret, code, { step = 30, digits = 6, window = 1, forTime = Date.now() } = {}) {
  const candidate = String(code || "").trim().replace(/\s+/g, "");
  if (!/^\d{6,8}$/.test(candidate)) return false;
  const secretBuffer = base32Decode(base32Secret);
  const baseCounter = Math.floor(forTime / 1000 / step);
  for (let offset = -window; offset <= window; offset++) {
    const expected = hotp(secretBuffer, baseCounter + offset, digits);
    if (crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(candidate.padStart(digits, "0")))) return true;
  }
  return false;
}

export function otpauthUri({ secret, username, issuer = "Site Gateway" }) {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(username)}`;
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

export function generateRecoveryCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(5).toString("hex").toUpperCase(); // 10 hex chars
    codes.push(`${raw.slice(0, 5)}-${raw.slice(5, 10)}`);
  }
  return codes;
}
