// protocol.test.js — exercises the X3DH + Double Ratchet implementation.
//
// These tests run in Node.js (>=20) using the very same crypto modules the
// browser loads — there is no browser-only code in `public/js/crypto`. Run them
// with `npm test`.
//
// They assert the properties that matter for an E2EE messenger:
//   * correct two-way decryption after an offline X3DH handshake
//   * message keys are single-use (forward secrecy at the key level)
//   * the DH ratchet steps on each round trip (break-in recovery)
//   * out-of-order and dropped messages still decrypt
//   * tampering is detected (AEAD integrity)
//   * prekey signatures are verified (MITM resistance)
//   * a third party with different keys cannot decrypt
//   * safety numbers are symmetric

import { test } from "node:test";
import assert from "node:assert/strict";

import { Identity, safetyNumber, verifyBundle } from "../public/js/crypto/identity.js";
import { Session } from "../public/js/crypto/session.js";
import { base64ToBytes, bytesToBase64 } from "../public/js/crypto/util.js";

// Mimic the relay server handing out a bundle with a single one-time prekey.
async function bundleWithOneOPK(identity) {
  const bundle = await identity.publishBundle();
  bundle.oneTimePreKeys = bundle.oneTimePreKeys.slice(0, 1);
  return bundle;
}

// Run the X3DH handshake and return ready-to-use sessions for both parties.
// Alice initiates; Bob responds and decrypts the first message.
async function handshake() {
  const alice = await Identity.create();
  const bob = await Identity.create();
  const bobBundle = await bundleWithOneOPK(bob);

  const aliceSession = await Session.initiate(alice, bobBundle);
  const first = await aliceSession.encrypt("__handshake__");
  const bobSession = await Session.respond(bob, first);
  const opened = await bobSession.decrypt(first);
  assert.equal(opened, "__handshake__");

  return { alice, bob, aliceSession, bobSession };
}

test("X3DH establishes a shared session and Bob decrypts Alice", async () => {
  const { aliceSession, bobSession } = await handshake();
  const env = await aliceSession.encrypt("hello bob 👋");
  assert.equal(await bobSession.decrypt(env), "hello bob 👋");
});

test("conversation is bidirectional", async () => {
  const { aliceSession, bobSession } = await handshake();
  const toAlice = await bobSession.encrypt("hi alice");
  assert.equal(await aliceSession.decrypt(toAlice), "hi alice");
  const toBob = await aliceSession.encrypt("hey bob");
  assert.equal(await bobSession.decrypt(toBob), "hey bob");
});

test("a long alternating conversation stays in sync", async () => {
  const { aliceSession, bobSession } = await handshake();
  for (let i = 0; i < 20; i++) {
    const a = await aliceSession.encrypt(`alice #${i}`);
    assert.equal(await bobSession.decrypt(a), `alice #${i}`);
    const b = await bobSession.encrypt(`bob #${i}`);
    assert.equal(await aliceSession.decrypt(b), `bob #${i}`);
  }
});

test("identical plaintext produces different ciphertext (fresh key per message)", async () => {
  const { aliceSession } = await handshake();
  const c1 = await aliceSession.encrypt("same text");
  const c2 = await aliceSession.encrypt("same text");
  assert.notEqual(c1.ciphertext, c2.ciphertext);
});

test("message keys are single-use (forward secrecy)", async () => {
  const { aliceSession, bobSession } = await handshake();
  const env = await aliceSession.encrypt("read once");
  assert.equal(await bobSession.decrypt(env), "read once");
  // The chain has advanced and the key is gone — replay must fail.
  await assert.rejects(() => bobSession.decrypt(env));
});

test("DH ratchet steps on each round trip (break-in recovery)", async () => {
  const { aliceSession, bobSession } = await handshake();
  const before = bytesToBase64(aliceSession.ratchet.DHsPub);
  const reply = await bobSession.encrypt("a reply");
  await aliceSession.decrypt(reply);
  const after = bytesToBase64(aliceSession.ratchet.DHsPub);
  // Receiving a new ratchet key forced Alice to generate a fresh one.
  assert.notEqual(before, after);
});

test("out-of-order and skipped messages still decrypt", async () => {
  const { aliceSession, bobSession } = await handshake();
  const m0 = await aliceSession.encrypt("m0");
  const m1 = await aliceSession.encrypt("m1");
  const m2 = await aliceSession.encrypt("m2");
  // Deliver 2, then 0, then 1.
  assert.equal(await bobSession.decrypt(m2), "m2");
  assert.equal(await bobSession.decrypt(m0), "m0");
  assert.equal(await bobSession.decrypt(m1), "m1");
});

test("tampered ciphertext is rejected (AEAD integrity)", async () => {
  const { aliceSession, bobSession } = await handshake();
  const env = await aliceSession.encrypt("do not modify");
  const bytes = base64ToBytes(env.ciphertext);
  bytes[bytes.length - 1] ^= 0x01; // flip one bit of the auth tag
  const tampered = { ...env, ciphertext: bytesToBase64(bytes) };
  await assert.rejects(() => bobSession.decrypt(tampered));
});

test("a bundle with an invalid signature is rejected", async () => {
  const bob = await Identity.create();
  const bundle = await bob.publishBundle();
  const sig = base64ToBytes(bundle.signedPreKey.signature);
  sig[0] ^= 0x01;
  bundle.signedPreKey.signature = bytesToBase64(sig);

  assert.equal(await verifyBundle(bundle), false);

  const alice = await Identity.create();
  await assert.rejects(() => Session.initiate(alice, bundle));
});

test("a third party with different keys cannot decrypt", async () => {
  const alice = await Identity.create();
  const bob = await Identity.create();
  const eve = await Identity.create();

  const bobBundle = await bundleWithOneOPK(bob);
  const aliceSession = await Session.initiate(alice, bobBundle);
  const env = await aliceSession.encrypt("for bob's eyes only");

  // Eve intercepts the envelope and tries to open it with her own identity.
  await assert.rejects(async () => {
    const eveSession = await Session.respond(eve, env);
    await eveSession.decrypt(env);
  });
});

test("group fan-out: each member decrypts only their own copy", async () => {
  // Groups encrypt a message separately per member over pairwise sessions.
  const alice = await Identity.create();
  const bob = await Identity.create();
  const carol = await Identity.create();

  const aliceToBob = await Session.initiate(alice, await bundleWithOneOPK(bob));
  const aliceToCarol = await Session.initiate(alice, await bundleWithOneOPK(carol));

  const text = "hello team";
  const envBob = await aliceToBob.encrypt(text);
  envBob.group = "g1";
  const envCarol = await aliceToCarol.encrypt(text);
  envCarol.group = "g1";

  // Same plaintext, but an independent ciphertext per member.
  assert.notEqual(envBob.ciphertext, envCarol.ciphertext);

  const bobSession = await Session.respond(bob, envBob);
  assert.equal(await bobSession.decrypt(envBob), text);

  const carolSession = await Session.respond(carol, envCarol);
  assert.equal(await carolSession.decrypt(envCarol), text);

  // Bob cannot open the copy addressed to Carol.
  await assert.rejects(async () => {
    const s = await Session.respond(bob, envCarol);
    await s.decrypt(envCarol);
  });
});

test("safety numbers are symmetric and verifiable", async () => {
  const a = await Identity.create();
  const b = await Identity.create();
  const ba = await a.publishBundle();
  const bb = await b.publishBundle();

  const fromA = await safetyNumber(ba, bb);
  const fromB = await safetyNumber(bb, ba);
  assert.equal(fromA, fromB);
  assert.match(fromA, /^[0-9a-f ]+$/); // grouped hex blocks
});
