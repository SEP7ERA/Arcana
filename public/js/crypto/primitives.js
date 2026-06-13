// primitives.js — thin, audited wrappers over the Web Crypto API.
//
// Design choices
// --------------
// * Curve: NIST P-256 (secp256r1) for both ECDH (key agreement) and ECDSA
//   (prekey signatures). The real Signal protocol uses Curve25519/Ed25519;
//   P-256 is used here because it is supported by `crypto.subtle` in *every*
//   modern browser and in Node.js with zero dependencies. The protocol
//   structure (X3DH + Double Ratchet) is identical regardless of the curve.
// * AEAD: AES-256-GCM. Provides confidentiality + integrity in one primitive.
// * KDF: HKDF-SHA-256 for key separation; HMAC-SHA-256 for the symmetric
//   chain ratchet.
//
// We never implement elliptic-curve math or cipher internals ourselves — that
// is delegated to the platform's vetted implementation. This file only wires
// the standard primitives together.

const subtle = globalThis.crypto.subtle;

const EC_PARAMS = { name: "ECDH", namedCurve: "P-256" };
const SIG_PARAMS = { name: "ECDSA", namedCurve: "P-256" };
const SIG_ALG = { name: "ECDSA", hash: "SHA-256" };

/** Cryptographically secure random bytes. */
export function randomBytes(length) {
  return globalThis.crypto.getRandomValues(new Uint8Array(length));
}

// ---------------------------------------------------------------------------
// Elliptic-curve keys
// ---------------------------------------------------------------------------

/** Generate an ECDH key pair (used for all Diffie–Hellman operations). */
export async function generateDHKeyPair() {
  return subtle.generateKey(EC_PARAMS, true, ["deriveBits"]);
}

/** Generate an ECDSA key pair (used to sign prekeys / identity assertions). */
export async function generateSigningKeyPair() {
  return subtle.generateKey(SIG_PARAMS, true, ["sign", "verify"]);
}

/** Export a public CryptoKey to raw (65-byte uncompressed point) bytes. */
export async function exportPublicKey(key) {
  return new Uint8Array(await subtle.exportKey("raw", key));
}

/** Import raw public-key bytes as an ECDH public key. */
export function importDHPublicKey(bytes) {
  return subtle.importKey("raw", bytes, EC_PARAMS, true, []);
}

/** Import raw public-key bytes as an ECDSA (verify-only) public key. */
export function importSigningPublicKey(bytes) {
  return subtle.importKey("raw", bytes, SIG_PARAMS, true, ["verify"]);
}

/**
 * Diffie–Hellman: combine our private key with their public key and return the
 * 32-byte shared secret (the X coordinate of the shared point).
 */
export async function dh(privateKey, publicKey) {
  const bits = await subtle.deriveBits(
    { name: "ECDH", public: publicKey },
    privateKey,
    256,
  );
  return new Uint8Array(bits);
}

// ---------------------------------------------------------------------------
// Signatures (Ed25519-style "signed prekey" assertion, via ECDSA P-256)
// ---------------------------------------------------------------------------

export async function sign(privateKey, data) {
  return new Uint8Array(await subtle.sign(SIG_ALG, privateKey, data));
}

export async function verify(publicKey, signature, data) {
  return subtle.verify(SIG_ALG, publicKey, signature, data);
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

/**
 * HKDF-SHA-256. `salt` and `info` default to empty.
 * Returns `length` bytes of derived key material.
 */
export async function hkdf(ikm, salt, info, length) {
  const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: salt ?? new Uint8Array(0),
      info: info ?? new Uint8Array(0),
    },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/** HMAC-SHA-256 over `data` with `keyBytes`. Returns the 32-byte tag. */
export async function hmac(keyBytes, data) {
  const key = await subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await subtle.sign("HMAC", key, data));
}

/** SHA-256 digest. */
export async function sha256(data) {
  return new Uint8Array(await subtle.digest("SHA-256", data));
}

// ---------------------------------------------------------------------------
// Authenticated encryption (AES-256-GCM)
// ---------------------------------------------------------------------------

/**
 * Encrypt with AES-256-GCM.
 * @param {Uint8Array} keyBytes  32-byte key
 * @param {Uint8Array} iv        12-byte nonce (must be unique per key)
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} aad       additional authenticated data (not encrypted)
 * @returns {Uint8Array} ciphertext || 16-byte auth tag
 */
export async function aesGcmEncrypt(keyBytes, iv, plaintext, aad) {
  const key = await subtle.importKey("raw", keyBytes, "AES-GCM", false, [
    "encrypt",
  ]);
  const ct = await subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad ?? new Uint8Array(0) },
    key,
    plaintext,
  );
  return new Uint8Array(ct);
}

/**
 * Decrypt AES-256-GCM. Throws if the auth tag fails (tampering / wrong key).
 */
export async function aesGcmDecrypt(keyBytes, iv, ciphertext, aad) {
  const key = await subtle.importKey("raw", keyBytes, "AES-GCM", false, [
    "decrypt",
  ]);
  const pt = await subtle.decrypt(
    { name: "AES-GCM", iv, additionalData: aad ?? new Uint8Array(0) },
    key,
    ciphertext,
  );
  return new Uint8Array(pt);
}
