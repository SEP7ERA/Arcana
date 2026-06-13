// doubleRatchet.js — the Double Ratchet algorithm (Perrin & Marlinspike).
//
// After X3DH produces an initial shared secret, the Double Ratchet manages all
// subsequent message keys. It combines two ratchets:
//
//   * Symmetric-key ratchet — every message advances a chain via HMAC, so each
//     message key is used exactly once and old keys can be deleted. This gives
//     *forward secrecy*: compromising the current state does not reveal past
//     messages.
//
//   * Diffie-Hellman ratchet — each time a new public ratchet key arrives, both
//     sides mix a fresh DH output into the root key. This gives *break-in
//     recovery* (a.k.a. future/post-compromise secrecy): once an attacker who
//     stole the state misses one round-trip, they are locked out again.
//
// Out-of-order and dropped messages are handled by caching "skipped" message
// keys keyed by (sender ratchet key, message number).

import {
  generateDHKeyPair,
  exportPublicKey,
  importDHPublicKey,
  dh,
  hkdf,
  hmac,
  aesGcmEncrypt,
  aesGcmDecrypt,
} from "./primitives.js";
import { concatBytes, bytesToBase64, base64ToBytes } from "./util.js";

const MAX_SKIP = 1000; // refuse to skip more than this many messages at once

const INFO_RK = new TextEncoder().encode("E2EEChat_DoubleRatchet_RootKey");
const INFO_MK = new TextEncoder().encode("E2EEChat_DoubleRatchet_MessageKey");

// --- Key derivation functions ----------------------------------------------

/** Root-key KDF: mixes a DH output into the root key, yielding (RK', CK). */
async function kdfRootKey(rootKey, dhOut) {
  const out = await hkdf(dhOut, rootKey, INFO_RK, 64);
  return { rootKey: out.subarray(0, 32), chainKey: out.subarray(32, 64) };
}

/** Chain-key KDF: advances a chain and emits one message key. */
async function kdfChainKey(chainKey) {
  const messageKey = await hmac(chainKey, new Uint8Array([0x01]));
  const nextChainKey = await hmac(chainKey, new Uint8Array([0x02]));
  return { chainKey: nextChainKey, messageKey };
}

/** Expand a message key into an AES-256 key + 96-bit GCM nonce. */
async function deriveMessageMaterial(messageKey) {
  const out = await hkdf(messageKey, new Uint8Array(32), INFO_MK, 44);
  return { aesKey: out.subarray(0, 32), iv: out.subarray(32, 44) };
}

// --- Header encoding (bound into the AEAD as associated data) ---------------

function encodeHeader(dhBytes, pn, n) {
  const buf = new Uint8Array(dhBytes.length + 8);
  buf.set(dhBytes, 0);
  const view = new DataView(buf.buffer);
  view.setUint32(dhBytes.length, pn >>> 0, false);
  view.setUint32(dhBytes.length + 4, n >>> 0, false);
  return buf;
}

export class DoubleRatchet {
  constructor() {
    this.DHs = null; // our current ratchet key pair
    this.DHsPub = null; // cached raw bytes of DHs.publicKey
    this.DHr = null; // their current ratchet public key (CryptoKey)
    this.DHrB64 = null; // cached base64 of DHr, for comparison
    this.rootKey = null;
    this.CKs = null; // sending chain key
    this.CKr = null; // receiving chain key
    this.Ns = 0; // messages sent in current sending chain
    this.Nr = 0; // messages received in current receiving chain
    this.PN = 0; // length of previous sending chain
    this.skipped = new Map(); // "dhB64|n" -> message key bytes
    this.AD = new Uint8Array(0); // associated data from X3DH
  }

  /**
   * Initialize the side that *sent* the first message (Alice).
   * @param sharedKey  X3DH shared secret
   * @param theirRatchetPub  CryptoKey — Bob's signed prekey (his first ratchet key)
   * @param associatedData   IK_A || IK_B
   */
  static async initSender(sharedKey, theirRatchetPub, associatedData) {
    const r = new DoubleRatchet();
    r.AD = associatedData;
    r.DHs = await generateDHKeyPair();
    r.DHsPub = await exportPublicKey(r.DHs.publicKey);
    r.DHr = theirRatchetPub;
    r.DHrB64 = bytesToBase64(await exportPublicKey(theirRatchetPub));
    const dhOut = await dh(r.DHs.privateKey, r.DHr);
    const { rootKey, chainKey } = await kdfRootKey(sharedKey, dhOut);
    r.rootKey = rootKey;
    r.CKs = chainKey;
    return r;
  }

  /**
   * Initialize the side that *received* the first message (Bob).
   * @param sharedKey      X3DH shared secret
   * @param ourRatchetPair our signed-prekey key pair (our first ratchet key)
   * @param associatedData IK_A || IK_B
   */
  static async initReceiver(sharedKey, ourRatchetPair, associatedData) {
    const r = new DoubleRatchet();
    r.AD = associatedData;
    r.DHs = ourRatchetPair;
    r.DHsPub = await exportPublicKey(ourRatchetPair.publicKey);
    r.rootKey = sharedKey;
    return r;
  }

  /** Encrypt one message. Returns { header, ciphertext } ready for the wire. */
  async encrypt(plaintext) {
    const { chainKey, messageKey } = await kdfChainKey(this.CKs);
    this.CKs = chainKey;

    const n = this.Ns;
    const pn = this.PN;
    this.Ns += 1;

    const headerBytes = encodeHeader(this.DHsPub, pn, n);
    const { aesKey, iv } = await deriveMessageMaterial(messageKey);
    const ciphertext = await aesGcmEncrypt(
      aesKey,
      iv,
      plaintext,
      concatBytes(this.AD, headerBytes),
    );

    return {
      header: { dh: bytesToBase64(this.DHsPub), pn, n },
      ciphertext: bytesToBase64(ciphertext),
    };
  }

  /** Decrypt one message given its wire header + base64 ciphertext. */
  async decrypt(header, ciphertextB64) {
    const ciphertext = base64ToBytes(ciphertextB64);
    const dhBytes = base64ToBytes(header.dh);
    const headerBytes = encodeHeader(dhBytes, header.pn, header.n);
    const aad = concatBytes(this.AD, headerBytes);

    // 1. Was this a message we previously skipped (out of order / dropped)?
    const skippedKey = `${header.dh}|${header.n}`;
    if (this.skipped.has(skippedKey)) {
      const messageKey = this.skipped.get(skippedKey);
      this.skipped.delete(skippedKey);
      return this._decryptWith(messageKey, ciphertext, aad);
    }

    // 2. New ratchet key from the peer -> perform a DH ratchet step.
    if (header.dh !== this.DHrB64) {
      await this._skipMessageKeys(header.pn);
      await this._dhRatchet(dhBytes, header.dh);
    }

    // 3. Advance the receiving chain to the message number, caching any gaps.
    await this._skipMessageKeys(header.n);

    const { chainKey, messageKey } = await kdfChainKey(this.CKr);
    this.CKr = chainKey;
    this.Nr += 1;
    return this._decryptWith(messageKey, ciphertext, aad);
  }

  async _decryptWith(messageKey, ciphertext, aad) {
    const { aesKey, iv } = await deriveMessageMaterial(messageKey);
    // Throws if the GCM tag fails — i.e. tampering or the wrong key.
    return aesGcmDecrypt(aesKey, iv, ciphertext, aad);
  }

  /** Cache message keys for messages numbered [Nr, until) in the current chain. */
  async _skipMessageKeys(until) {
    if (this.Nr + MAX_SKIP < until) {
      throw new Error("Too many skipped messages — possible attack or data loss.");
    }
    if (this.CKr == null) return;
    while (this.Nr < until) {
      const { chainKey, messageKey } = await kdfChainKey(this.CKr);
      this.CKr = chainKey;
      this.skipped.set(`${this.DHrB64}|${this.Nr}`, messageKey);
      this.Nr += 1;
    }
  }

  /** Perform a Diffie-Hellman ratchet step on receiving a new ratchet key. */
  async _dhRatchet(newDhBytes, newDhB64) {
    this.PN = this.Ns;
    this.Ns = 0;
    this.Nr = 0;
    this.DHr = await importDHPublicKey(newDhBytes);
    this.DHrB64 = newDhB64;

    // Derive the new receiving chain from the old sending key + new peer key.
    let dhOut = await dh(this.DHs.privateKey, this.DHr);
    let kdf = await kdfRootKey(this.rootKey, dhOut);
    this.rootKey = kdf.rootKey;
    this.CKr = kdf.chainKey;

    // Generate our own new ratchet key and derive the new sending chain.
    this.DHs = await generateDHKeyPair();
    this.DHsPub = await exportPublicKey(this.DHs.publicKey);
    dhOut = await dh(this.DHs.privateKey, this.DHr);
    kdf = await kdfRootKey(this.rootKey, dhOut);
    this.rootKey = kdf.rootKey;
    this.CKs = kdf.chainKey;
  }
}
