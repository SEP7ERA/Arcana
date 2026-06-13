// util.js — byte / encoding helpers shared by every crypto module.
//
// These helpers are intentionally dependency-free and work unchanged in both
// the browser and in Node.js (v20+), because everything downstream relies only
// on standard Web platform APIs (Uint8Array, TextEncoder, btoa/atob).

/** UTF-8 string -> Uint8Array */
export function utf8ToBytes(str) {
  return new TextEncoder().encode(str);
}

/** Uint8Array -> UTF-8 string */
export function bytesToUtf8(bytes) {
  return new TextDecoder().decode(bytes);
}

/** Uint8Array -> base64 string */
export function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000; // avoid call-stack limits on big inputs
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/** base64 string -> Uint8Array */
export function base64ToBytes(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** Concatenate any number of Uint8Arrays into one. */
export function concatBytes(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

/**
 * Constant-time-ish equality for two byte arrays.
 * (Web Crypto verification already runs in constant time where it matters;
 * this is used for non-secret comparisons like fingerprints.)
 */
export function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** Uint8Array -> lowercase hex string */
export function bytesToHex(bytes) {
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return hex;
}
