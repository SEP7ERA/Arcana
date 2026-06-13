// x3dh.js — Extended Triple Diffie-Hellman key agreement.
//
// X3DH lets Alice derive a shared secret with Bob *while Bob is offline*, using
// only the public prekey bundle Bob previously uploaded to the server. It
// provides mutual authentication (each side mixes in the other's long-term
// identity key) and a measure of forward secrecy (the ephemeral + one-time
// keys). The resulting secret seeds the Double Ratchet.
//
// Four Diffie-Hellman operations are combined:
//   DH1 = DH(IK_A, SPK_B)   binds Alice's identity to Bob's signed prekey
//   DH2 = DH(EK_A, IK_B)    binds Bob's identity to Alice's ephemeral
//   DH3 = DH(EK_A, SPK_B)   ephemeral <-> signed prekey
//   DH4 = DH(EK_A, OPK_B)   ephemeral <-> one-time prekey (optional)
//   SK  = HKDF(F || DH1 || DH2 || DH3 || DH4)
//
// The order is chosen so Alice and Bob compute the same four shared secrets
// from opposite sides of each pairing.

import {
  generateDHKeyPair,
  exportPublicKey,
  importDHPublicKey,
  dh,
  hkdf,
} from "./primitives.js";
import { concatBytes, base64ToBytes } from "./util.js";
import { verifyBundle } from "./identity.js";

// 32 leading 0xFF bytes, per the X3DH spec, to domain-separate the KDF input.
const KDF_F = new Uint8Array(32).fill(0xff);
const KDF_SALT = new Uint8Array(32); // all-zero salt
const KDF_INFO = new TextEncoder().encode("E2EEChat_X3DH_P256_AESGCM");

async function deriveSecret(dh1, dh2, dh3, dh4) {
  const ikm = dh4
    ? concatBytes(KDF_F, dh1, dh2, dh3, dh4)
    : concatBytes(KDF_F, dh1, dh2, dh3);
  return hkdf(ikm, KDF_SALT, KDF_INFO, 32);
}

/**
 * Alice's side: start a session toward Bob from his published bundle.
 *
 * @param {Identity} identity   Alice's own identity (private keys).
 * @param {object}   bundle      Bob's public prekey bundle (from the server).
 * @returns initial-message header + the X3DH shared secret and the public
 *          signed-prekey Bob will use as his first ratchet key.
 */
export async function initiateX3DH(identity, bundle) {
  if (!(await verifyBundle(bundle))) {
    throw new Error("Bob's prekey bundle has an invalid signature — aborting.");
  }

  const ikB = await importDHPublicKey(base64ToBytes(bundle.identityKey));
  const spkB = await importDHPublicKey(base64ToBytes(bundle.signedPreKey.publicKey));
  const opkEntry = bundle.oneTimePreKeys && bundle.oneTimePreKeys[0];
  const opkB = opkEntry
    ? await importDHPublicKey(base64ToBytes(opkEntry.publicKey))
    : null;

  // Ephemeral key, used once for this handshake.
  const ephemeral = await generateDHKeyPair();

  const dh1 = await dh(identity.identityKey.privateKey, spkB);
  const dh2 = await dh(ephemeral.privateKey, ikB);
  const dh3 = await dh(ephemeral.privateKey, spkB);
  const dh4 = opkB ? await dh(ephemeral.privateKey, opkB) : null;

  const sharedKey = await deriveSecret(dh1, dh2, dh3, dh4);

  const ikAPub = await exportPublicKey(identity.identityKey.publicKey);
  const ikBPub = await exportPublicKey(ikB);
  const ekAPub = await exportPublicKey(ephemeral.publicKey);

  return {
    sharedKey,
    // Associated data binds both identities into every ratchet message.
    associatedData: concatBytes(ikAPub, ikBPub),
    // Sent in the clear inside the first message so Bob can reconstruct SK.
    initialHeader: {
      identityKeyBytes: ikAPub,
      ephemeralKey: ekAPub,
      oneTimePreKeyId: opkEntry ? opkEntry.id : null,
    },
    // Bob's signed prekey doubles as the first DH ratchet public key.
    receiverRatchetKey: spkB,
  };
}

/**
 * Bob's side: reconstruct the X3DH shared secret from Alice's first message.
 *
 * @param {Identity} identity        Bob's own identity (private keys).
 * @param {object}   header          { identityKeyBytes, ephemeralKey, oneTimePreKeyId }
 * @returns { sharedKey, associatedData, ratchetKeyPair }
 */
export async function respondX3DH(identity, header) {
  const ikA = await importDHPublicKey(header.identityKeyBytes);
  const ekA = await importDHPublicKey(header.ephemeralKey);

  const spkPair = identity.signedPreKey.keyPair;
  const opkPair = identity.takeOneTimePreKey(header.oneTimePreKeyId);

  const dh1 = await dh(spkPair.privateKey, ikA);
  const dh2 = await dh(identity.identityKey.privateKey, ekA);
  const dh3 = await dh(spkPair.privateKey, ekA);
  const dh4 = opkPair ? await dh(opkPair.privateKey, ekA) : null;

  const sharedKey = await deriveSecret(dh1, dh2, dh3, dh4);

  const ikAPub = header.identityKeyBytes;
  const ikBPub = await exportPublicKey(identity.identityKey.publicKey);

  return {
    sharedKey,
    associatedData: concatBytes(ikAPub, ikBPub),
    // Bob's signed prekey pair is his initial DH ratchet key pair.
    ratchetKeyPair: spkPair,
  };
}
