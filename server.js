// server.js — the relay + prekey directory.
//
// IMPORTANT: this server is deliberately "dumb". Its entire job is to
//   1. store and hand out *public* prekey bundles, and
//   2. forward opaque encrypted envelopes between clients.
//
// It holds no private keys and never sees plaintext. Every `envelope` it
// relays is ciphertext produced by the Double Ratchet on a client. Even a fully
// compromised server (or anyone who taps the wire) learns only metadata
// (who talks to whom and when), never message contents. This is the core
// property of end-to-end encryption.

import express from "express";
import { createServer } from "node:http";
import { WebSocketServer } from "ws";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const __dirname = dirname(fileURLToPath(import.meta.url));
const PORT = process.env.PORT || 3000;
const LOW_PREKEY_THRESHOLD = 3;

const app = express();
app.use(express.static(join(__dirname, "public")));
app.get("/health", (_req, res) => res.json({ status: "ok" }));

const httpServer = createServer(app);
const wss = new WebSocketServer({ server: httpServer });

/**
 * In-memory state. A real deployment would use a database, but the security
 * model does not depend on the storage — only *public* data lives here.
 *
 *   bundles:      username -> public prekey bundle  (persists across reconnects
 *                 so peers can start sessions while the owner is offline)
 *   online:       username -> live WebSocket
 *   offlineQueue: username -> [ { from, envelope } ]   (ciphertext awaiting pickup)
 */
const bundles = new Map();
const online = new Map();
const offlineQueue = new Map();

function send(ws, payload) {
  if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(payload));
}

function broadcastPresence(username, isOnline) {
  const msg = { type: "presence", username, online: isOnline };
  for (const ws of online.values()) send(ws, msg);
}

function onlineUsernames(except) {
  return [...online.keys()].filter((u) => u !== except);
}

/** Return a copy of a bundle with at most one (consumed) one-time prekey. */
function takeBundleFor(targetName) {
  const bundle = bundles.get(targetName);
  if (!bundle) return null;

  const oneTimePreKeys = [];
  if (bundle.oneTimePreKeys && bundle.oneTimePreKeys.length > 0) {
    oneTimePreKeys.push(bundle.oneTimePreKeys.shift()); // single-use: remove it
  }
  // Ask the owner (if online) to top up when running low.
  const ownerWs = online.get(targetName);
  if (ownerWs && (bundle.oneTimePreKeys?.length ?? 0) < LOW_PREKEY_THRESHOLD) {
    send(ownerWs, { type: "low-prekeys" });
  }
  return {
    identityKey: bundle.identityKey,
    signingKey: bundle.signingKey,
    signedPreKey: bundle.signedPreKey,
    oneTimePreKeys,
  };
}

wss.on("connection", (ws) => {
  ws.username = null;
  ws.isAlive = true;
  ws.on("pong", () => (ws.isAlive = true));

  ws.on("message", (raw) => {
    let msg;
    try {
      msg = JSON.parse(raw.toString());
    } catch {
      return send(ws, { type: "error", message: "Malformed JSON." });
    }

    switch (msg.type) {
      case "register": {
        const { username, bundle } = msg;
        if (!username || !bundle) {
          return send(ws, { type: "error", message: "Missing username or bundle." });
        }
        if (online.has(username) && online.get(username) !== ws) {
          return send(ws, { type: "error", message: "That name is already online." });
        }
        ws.username = username;
        bundles.set(username, bundle); // (re)publish public keys
        online.set(username, ws);

        send(ws, { type: "registered", username });
        send(ws, { type: "users", users: onlineUsernames(username) });
        broadcastPresence(username, true);

        // Deliver anything that arrived while this user was offline.
        const queued = offlineQueue.get(username);
        if (queued && queued.length) {
          for (const item of queued) {
            send(ws, { type: "message", from: item.from, envelope: item.envelope });
          }
          offlineQueue.delete(username);
        }
        break;
      }

      case "get-bundle": {
        const bundle = takeBundleFor(msg.username);
        if (!bundle) {
          return send(ws, {
            type: "error",
            context: "get-bundle",
            message: `No registered keys for "${msg.username}".`,
          });
        }
        send(ws, { type: "bundle", username: msg.username, bundle });
        break;
      }

      case "replenish": {
        // Client topping up its pool of one-time prekeys.
        const bundle = bundles.get(ws.username);
        if (bundle && Array.isArray(msg.oneTimePreKeys)) {
          bundle.oneTimePreKeys.push(...msg.oneTimePreKeys);
        }
        break;
      }

      case "list-users": {
        send(ws, { type: "users", users: onlineUsernames(ws.username) });
        break;
      }

      case "message": {
        const { to, envelope } = msg;
        if (!to || !envelope) {
          return send(ws, { type: "error", message: "Missing recipient or envelope." });
        }
        const targetWs = online.get(to);
        if (targetWs) {
          // Pure relay: forward the opaque envelope untouched.
          send(targetWs, { type: "message", from: ws.username, envelope });
        } else {
          // Recipient offline: queue the ciphertext for later delivery.
          if (!offlineQueue.has(to)) offlineQueue.set(to, []);
          offlineQueue.get(to).push({ from: ws.username, envelope });
          send(ws, { type: "queued", to });
        }
        break;
      }

      default:
        send(ws, { type: "error", message: `Unknown message type: ${msg.type}` });
    }
  });

  ws.on("close", () => {
    if (ws.username && online.get(ws.username) === ws) {
      online.delete(ws.username); // keep the bundle for offline delivery
      broadcastPresence(ws.username, false);
    }
  });
});

// Drop dead connections so presence stays accurate.
const heartbeat = setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }
    ws.isAlive = false;
    ws.ping();
  }
}, 30000);
wss.on("close", () => clearInterval(heartbeat));

httpServer.listen(PORT, () => {
  console.log(`\n  🔒 E2EE chat relay running at http://localhost:${PORT}`);
  console.log(`     Open it in two browser tabs to start an encrypted chat.\n`);
});
