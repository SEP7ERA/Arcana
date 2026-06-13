// identity.js — a user's long-lived key material and the public "prekey
// bundle" they publish to the server so others can start a session offline.
//
// A bundle mirrors Signal's registration data:
//   * Identity key    (IK)  — long-term ECDH key, the cryptographic identity.
//   * Signing key     (SK)  — long-term ECDSA key that signs the prekey.
//   * Signed prekey   (SPK) — medium-term ECDH key, signed by SK.
//   * One-time prekeys (OPK)— single-use ECDH keys for extra forward secrecy.
//
// The server only ever sees the *public* halves. Private keys never leave the
// client.

import {
  generateDHKeyPair,
  generateSigningKeyPair,
  exportPublicKey,
  importSigningPublicKey,
  importDHPublicKey,
  sign,
  verify,
  sha256,
} from "./primitives.js";
import { bytesToBase64, base64ToBytes, concatBytes, bytesToHex } from "./util.js";

export class Identity {
  constructor() {
    this.identityKey = null; // ECDH key pair {publicKey, privateKey}
    this.signingKey = null; // ECDSA key pair
    this.signedPreKey = null; // { id, keyPair, signature: Uint8Array }
    this.oneTimePreKeys = new Map(); // id -> ECDH key pair
    this._opkCounter = 0;
  }

  /** Create a brand-new identity with `opkCount` one-time prekeys. */
  static async create(opkCount = 10) {
    const id = new Identity();
    id.identityKey = await generateDHKeyPair();
    id.signingKey = await generateSigningKeyPair();
    await id.rotateSignedPreKey();
    await id.replenishOneTimePreKeys(opkCount);
    return id;
  }

  /** Generate a fresh signed prekey and sign it with the long-term signing key. */
  async rotateSignedPreKey() {
    const keyPair = await generateDHKeyPair();
    const pub = await exportPublicKey(keyPair.publicKey);
    const signature = await sign(this.signingKey.privateKey, pub);
    this.signedPreKey = { id: 1, keyPair, signature };
  }

  /** Top up the pool of one-time prekeys. */
  async replenishOneTimePreKeys(count) {
    const added = [];
    for (let i = 0; i < count; i++) {
      const id = ++this._opkCounter;
      const keyPair = await generateDHKeyPair();
      this.oneTimePreKeys.set(id, keyPair);
      added.push(id);
    }
    return added;
  }

  /** Consume (and remove) the one-time prekey a peer used to reach us. */
  takeOneTimePreKey(id) {
    if (id == null) return null;
    const kp = this.oneTimePreKeys.get(id);
    this.oneTimePreKeys.delete(id);
    return kp ?? null;
  }

  /**
   * Build the public bundle to publish to the server. Includes all currently
   * available one-time prekeys; the server hands them out one at a time.
   */
  async publishBundle() {
    const oneTimePreKeys = [];
    for (const [id, kp] of this.oneTimePreKeys) {
      oneTimePreKeys.push({
        id,
        publicKey: bytesToBase64(await exportPublicKey(kp.publicKey)),
      });
    }
    return {
      identityKey: bytesToBase64(await exportPublicKey(this.identityKey.publicKey)),
      signingKey: bytesToBase64(await exportPublicKey(this.signingKey.publicKey)),
      signedPreKey: {
        id: this.signedPreKey.id,
        publicKey: bytesToBase64(
          await exportPublicKey(this.signedPreKey.keyPair.publicKey),
        ),
        signature: bytesToBase64(this.signedPreKey.signature),
      },
      oneTimePreKeys,
    };
  }

  /** 8-byte hex fingerprint of this identity (for the local UI). */
  async fingerprint() {
    return fingerprintFor(
      await exportPublicKey(this.identityKey.publicKey),
      await exportPublicKey(this.signingKey.publicKey),
    );
  }
}

/**
 * Verify a peer's bundle: the signed prekey must carry a valid signature from
 * the peer's advertised signing key. This is what stops the server from
 * silently swapping in its own prekey (a man-in-the-middle attempt).
 */
export async function verifyBundle(bundle) {
  const signingPub = await importSigningPublicKey(
    base64ToBytes(bundle.signingKey),
  );
  const spkPub = base64ToBytes(bundle.signedPreKey.publicKey);
  const sig = base64ToBytes(bundle.signedPreKey.signature);
  return verify(signingPub, sig, spkPub);
}

/**
 * Compute a stable fingerprint from an identity key + signing key.
 * Used both for the local identity badge and for the per-conversation
 * "safety number" (out-of-band identity verification).
 */
export async function fingerprintFor(identityKeyBytes, signingKeyBytes) {
  const digest = await sha256(concatBytes(identityKeyBytes, signingKeyBytes));
  return bytesToHex(digest.subarray(0, 8));
}

/**
 * A symmetric "safety number" two users can compare out-of-band to confirm
 * there is no man-in-the-middle. Both sides derive the same value regardless
 * of who computes it because the inputs are sorted.
 */
export async function safetyNumber(bundleA, bundleB) {
  const a = await fingerprintFor(
    base64ToBytes(bundleA.identityKey),
    base64ToBytes(bundleA.signingKey),
  );
  const b = await fingerprintFor(
    base64ToBytes(bundleB.identityKey),
    base64ToBytes(bundleB.signingKey),
  );
  const [first, second] = [a, b].sort();
  // Group into readable 5-char blocks.
  return (first + second).match(/.{1,5}/g).join(" ");
}
