# Security model

> ⚠️ **This is an educational prototype, not audited software.** Do not use it
> to protect information that actually matters. For real applications use a
> reviewed library such as [libsignal](https://github.com/signalapp/libsignal).

## Goals

The system aims to provide the guarantees of a modern secure messenger between
two honest endpoints:

- **Confidentiality** — only the intended recipient can read a message.
- **Integrity & authenticity** — messages cannot be modified or forged in
  transit; AES-256-GCM fails closed on any tampering.
- **Forward secrecy** — compromising current key material does not expose past
  messages (each message key is used once and discarded).
- **Post-compromise / break-in recovery** — after a state compromise, security
  self-heals once an uncompromised DH ratchet step occurs.
- **Mutual authentication** — both long-term identity keys are mixed into the
  X3DH handshake; users can compare a **safety number** out of band to detect a
  man-in-the-middle.

## Threat model

### Defended against

| Adversary | Outcome |
| --- | --- |
| **Passive network eavesdropper** | Sees only ciphertext + metadata; cannot read messages. |
| **Malicious / compromised relay server** | Holds no private keys; cannot decrypt, and cannot forge a valid prekey signature to MITM without it being detectable via safety numbers. |
| **Message tampering / replay** | AEAD rejects modified ciphertext; single-use message keys make replay fail. |
| **Future key theft** | Forward secrecy protects already-sent messages. |

### Explicitly *not* defended against

| Limitation | Notes |
| --- | --- |
| **Endpoint compromise** | If a device is compromised *while* it holds live session state, current and future messages on that session can be read until a healing ratchet step. |
| **Metadata** | The server learns who talks to whom and when. There is no sealed-sender or traffic-analysis protection. |
| **Trust-on-first-use** | Identity binding relies on users comparing safety numbers. Without that out-of-band check, a server that swaps keys at first contact is not automatically detected. |
| **Denial of service** | No rate limiting, abuse controls, or auth on the relay. |
| **Key persistence** | Keys live in memory only; there is no secure at-rest storage. |

## Cryptographic choices

| Function | Algorithm | Notes |
| --- | --- | --- |
| Diffie–Hellman | ECDH P-256 | Curve choice driven by universal Web Crypto support; see README. |
| Signatures | ECDSA P-256 / SHA-256 | Authenticates signed prekeys. |
| KDF | HKDF-SHA-256 | Domain-separated with distinct `info` strings per use. |
| Chain ratchet | HMAC-SHA-256 | Distinct constants (`0x01`/`0x02`) for message vs. chain key. |
| AEAD | AES-256-GCM | 96-bit nonce derived per-message via HKDF; never reused under a key. |

All primitives come from the platform's audited Web Crypto implementation. No
elliptic-curve or cipher internals are implemented by hand in this project.

## Reporting

This is a learning project; there is no formal disclosure process. If you spot a
bug in the protocol implementation, please open an issue describing it.
