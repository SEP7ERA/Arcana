// session.js — high-level per-conversation session.
//
// Wraps X3DH (initial key agreement) and the Double Ratchet (ongoing message
// keys) behind a small API:
//
//   const s = await Session.initiate(myIdentity, peerBundle);  // I start it
//   const envelope = await s.encrypt("hello");                 // -> send to peer
//
//   const s = await Session.respond(myIdentity, envelope);     // peer started it
//   const text = await s.decrypt(envelope);
//
// An "envelope" is the only thing that travels over the network. It is opaque
// ciphertext plus routing/ratchet headers; the relay server cannot read it.

import { initiateX3DH, respondX3DH } from "./x3dh.js";
import { DoubleRatchet } from "./doubleRatchet.js";
import { utf8ToBytes, bytesToUtf8, bytesToBase64, base64ToBytes } from "./util.js";

export class Session {
  constructor(identity) {
    this.identity = identity;
    this.ratchet = null;
    this.isInitiator = false;
    this.hasReceived = false;
    // The X3DH prekey header, attached to outgoing messages until the peer
    // replies (so they can establish the session even if messages arrive out
    // of order or the first one is dropped).
    this._pendingX3DH = null;
  }

  /** Start a session toward a peer using their published prekey bundle (Alice). */
  static async initiate(identity, peerBundle) {
    const session = new Session(identity);
    session.isInitiator = true;

    const result = await initiateX3DH(identity, peerBundle);
    session.ratchet = await DoubleRatchet.initSender(
      result.sharedKey,
      result.receiverRatchetKey,
      result.associatedData,
    );
    session._pendingX3DH = {
      identityKey: bytesToBase64(result.initialHeader.identityKeyBytes),
      ephemeralKey: bytesToBase64(result.initialHeader.ephemeralKey),
      oneTimePreKeyId: result.initialHeader.oneTimePreKeyId,
    };
    return session;
  }

  /** Establish a session from an incoming initial (prekey) envelope (Bob). */
  static async respond(identity, envelope) {
    if (!envelope.x3dh) {
      throw new Error("Cannot establish session: envelope has no X3DH header.");
    }
    const session = new Session(identity);
    const header = {
      identityKeyBytes: base64ToBytes(envelope.x3dh.identityKey),
      ephemeralKey: base64ToBytes(envelope.x3dh.ephemeralKey),
      oneTimePreKeyId: envelope.x3dh.oneTimePreKeyId,
    };
    const result = await respondX3DH(identity, header);
    session.ratchet = await DoubleRatchet.initReceiver(
      result.sharedKey,
      result.ratchetKeyPair,
      result.associatedData,
    );
    return session;
  }

  /** Encrypt a UTF-8 string into a wire envelope. */
  async encrypt(text) {
    const { header, ciphertext } = await this.ratchet.encrypt(utf8ToBytes(text));
    const envelope = { header, ciphertext };
    // Keep advertising the X3DH header until we've heard back from the peer.
    if (this.isInitiator && !this.hasReceived) {
      envelope.x3dh = this._pendingX3DH;
    }
    return envelope;
  }

  /** Decrypt a wire envelope into the original UTF-8 string. */
  async decrypt(envelope) {
    const plaintext = await this.ratchet.decrypt(
      envelope.header,
      envelope.ciphertext,
    );
    this.hasReceived = true;
    return bytesToUtf8(plaintext);
  }
}
