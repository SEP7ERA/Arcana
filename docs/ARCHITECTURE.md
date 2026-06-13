# Architecture

This document goes one level deeper than the README: the exact data that flows
over the wire, the per-conversation state machine, and the key-derivation
details.

## Components

```
┌──────────────────────┐         WebSocket          ┌──────────────────────┐
│   Browser  (Alice)   │  ───────────────────────▶  │   Browser   (Bob)    │
│                      │       via relay server     │                      │
│  app.js  (UI)        │                            │  app.js  (UI)        │
│  session.js          │   ┌────────────────────┐   │  session.js          │
│  x3dh.js             │   │     server.js      │   │  x3dh.js             │
│  doubleRatchet.js    │──▶│  • prekey directory │◀──│  doubleRatchet.js   │
│  identity.js         │   │  • opaque relay     │   │  identity.js         │
│  primitives.js       │   │  • offline queue    │   │  primitives.js       │
│  (Web Crypto)        │   └────────────────────┘   │  (Web Crypto)        │
└──────────────────────┘     sees only ciphertext   └──────────────────────┘
```

All cryptography lives in `public/js/crypto/`. The server (`server.js`) has no
crypto code at all — by construction it cannot read messages.

## Registration: the prekey bundle

On sign-in each client generates and publishes a **public** bundle:

```jsonc
{
  "identityKey":  "<base64 ECDH public key>",   // IK  — long-term identity
  "signingKey":   "<base64 ECDSA public key>",  // SK  — signs the prekey
  "signedPreKey": {
    "id": 1,
    "publicKey": "<base64 ECDH public key>",    // SPK — medium-term
    "signature": "<base64 ECDSA signature>"     // Sig(SK, SPK)
  },
  "oneTimePreKeys": [                            // OPKs — single-use
    { "id": 1, "publicKey": "<base64>" }, ...
  ]
}
```

Private keys are kept in memory on the client and are **never** transmitted.
The server hands out one OPK per session request and asks the owner to
replenish the pool when it runs low.

## The envelope (the only thing on the wire)

Every message is wrapped in an envelope the server treats as an opaque blob:

```jsonc
{
  // Present only until the recipient first replies, so they can run X3DH.
  "x3dh": {
    "identityKey":     "<base64 IK_A>",
    "ephemeralKey":    "<base64 EK_A>",
    "oneTimePreKeyId": 1
  },
  // Double Ratchet header (authenticated, not secret).
  "header": {
    "dh": "<base64 current ratchet public key>",
    "pn": 0,   // length of the previous sending chain
    "n":  3    // message number within the current chain
  },
  "ciphertext": "<base64 AES-256-GCM output>"
}
```

The header is bound into the AEAD as associated data, so it cannot be altered
without breaking decryption.

## Key derivation

```
X3DH:
  SK         = HKDF( 0xFF*32 ‖ DH1 ‖ DH2 ‖ DH3 ‖ DH4,  salt=0,  info="…X3DH…")

Double Ratchet root KDF (on each DH ratchet step):
  RK', CK    = HKDF( ikm = DH(DHs, DHr),  salt = RK,  info="…RootKey…")   // 64 bytes

Symmetric chain KDF (per message):
  mk         = HMAC-SHA256( CK, 0x01 )
  CK'        = HMAC-SHA256( CK, 0x02 )

Message material:
  AESKey ‖ IV = HKDF( ikm = mk,  salt = 0,  info="…MessageKey…")          // 32 + 12 bytes
```

`AD` (associated data) for every AEAD operation is `IK_A ‖ IK_B ‖ header`,
binding both identities and the ratchet header to each ciphertext.

## Session state machine

Each `Session` owns one `DoubleRatchet`. The two sides initialize differently:

- **Initiator (Alice):** generates a fresh ratchet key pair and derives the
  first **sending** chain from `DH(new key, Bob's signed prekey)`.
- **Responder (Bob):** uses his signed-prekey pair as the initial ratchet key;
  his first **receiving** chain is derived when Alice's first message arrives.

```
            ┌──────────────── send() ────────────────┐
            ▼                                          │
   ┌─────────────────┐   new ratchet key on receive   │
   │ symmetric ratchet│ ─────────────┐                 │
   │  (per message)   │              ▼                 │
   └─────────────────┘     ┌───────────────────┐       │
            ▲              │   DH ratchet step  │ ──────┘
            │              │ (new root key, new │
            └──────────────│  send + recv chain)│
                           └───────────────────┘
```

### Receiving algorithm (simplified)

```
1. If the message key was previously skipped → use it (out-of-order delivery).
2. Else if the header carries a new ratchet key → perform a DH ratchet step,
   caching any skipped keys from the old chain.
3. Advance the receiving chain to the message number (caching gaps).
4. Derive the message key, AES-GCM-decrypt (fails closed on tampering).
```

Skipped message keys are stored in a bounded map (`MAX_SKIP = 1000`) keyed by
`(ratchet public key, message number)`.

## Offline delivery

Because X3DH only needs Bob's *published* bundle, Alice can encrypt to Bob while
he is offline. The relay queues the envelope and delivers it when Bob
reconnects, at which point he runs X3DH and the Double Ratchet to decrypt — no
prior contact required.
