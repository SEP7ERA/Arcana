// app.js — UI + session orchestration.
//
// Responsibilities:
//   * generate this browser's identity + prekey bundle and register it
//   * maintain one Session (X3DH + Double Ratchet) per conversation
//   * encrypt outgoing / decrypt incoming messages
//   * render everything (using textContent only — never innerHTML for user data)

import { Identity, safetyNumber } from "./crypto/identity.js";
import { Session } from "./crypto/session.js";
import { ChatConnection } from "./net.js";

// ---- State ----------------------------------------------------------------
const state = {
  conn: null,
  identity: null,
  username: null,
  myBundle: null,
  sessions: new Map(), // peer -> Session
  peerBundles: new Map(), // peer -> bundle (for safety numbers)
  conversations: new Map(), // peer -> [ { dir, text, cipher, ts } ]
  online: new Set(),
  unread: new Map(), // peer -> count
  activePeer: null,
};

// ---- DOM ------------------------------------------------------------------
const $ = (id) => document.getElementById(id);
const els = {
  login: $("login"),
  loginForm: $("login-form"),
  usernameInput: $("username-input"),
  loginStatus: $("login-status"),
  app: $("app"),
  meUsername: $("me-username"),
  meFingerprint: $("me-fingerprint"),
  userList: $("user-list"),
  peerName: $("peer-name"),
  peerStatus: $("peer-status"),
  safetyBtn: $("safety-btn"),
  safetyPanel: $("safety-panel"),
  safetyNumber: $("safety-number"),
  messages: $("messages"),
  composer: $("composer"),
  messageInput: $("message-input"),
};

// ---- Login ----------------------------------------------------------------
els.loginForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = els.usernameInput.value.trim();
  if (!username) return;

  const button = els.loginForm.querySelector("button");
  button.disabled = true;
  setStatus("Generating identity & prekeys…");

  try {
    state.username = username;
    state.identity = await Identity.create(10);
    state.myBundle = await state.identity.publishBundle();

    setStatus("Connecting to relay…");
    state.conn = new ChatConnection(wsUrl());
    wireConnection(state.conn);
    await state.conn.connect();

    state.conn.send({
      type: "register",
      username,
      bundle: state.myBundle,
    });
  } catch (err) {
    console.error(err);
    setStatus("Error: " + err.message);
    button.disabled = false;
  }
});

function wsUrl() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return `${proto}//${location.host}`;
}

function setStatus(text) {
  els.loginStatus.textContent = text;
}

// ---- Connection events ----------------------------------------------------
function wireConnection(conn) {
  conn.on("registered", async () => {
    els.login.classList.add("hidden");
    els.app.classList.remove("hidden");
    els.meUsername.textContent = state.username;
    els.meFingerprint.textContent = await state.identity.fingerprint();
  });

  conn.on("users", (msg) => {
    state.online = new Set(msg.users);
    renderUserList();
  });

  conn.on("presence", (msg) => {
    if (msg.online) state.online.add(msg.username);
    else state.online.delete(msg.username);
    renderUserList();
    if (msg.username === state.activePeer) renderPeerHeader();
  });

  conn.on("message", (msg) => handleIncoming(msg.from, msg.envelope));

  conn.on("queued", (msg) => {
    addSystemMessage(msg.to, "Recipient offline — message queued for delivery.");
  });

  conn.on("low-prekeys", () => replenishPreKeys());

  conn.on("error", (msg) => {
    console.warn("Server error:", msg.message);
  });

  conn.on("close", () => {
    addSystemMessage(state.activePeer, "Disconnected from relay.");
  });
}

async function replenishPreKeys() {
  const ids = await state.identity.replenishOneTimePreKeys(10);
  state.myBundle = await state.identity.publishBundle();
  // Send only the newly added prekeys to the server.
  const added = state.myBundle.oneTimePreKeys.filter((k) => ids.includes(k.id));
  state.conn.send({ type: "replenish", oneTimePreKeys: added });
}

// ---- Sessions -------------------------------------------------------------
async function getOrCreateSession(peer) {
  if (state.sessions.has(peer)) return state.sessions.get(peer);

  const bundle = await state.conn.getBundle(peer);
  state.peerBundles.set(peer, bundle);
  const session = await Session.initiate(state.identity, bundle);
  state.sessions.set(peer, session);
  return session;
}

async function handleIncoming(from, envelope) {
  try {
    let session = state.sessions.get(from);
    if (!session) {
      if (!envelope.x3dh) {
        console.warn(`No session and no X3DH header from ${from}; cannot decrypt.`);
        return;
      }
      session = await Session.respond(state.identity, envelope);
      state.sessions.set(from, session);
      // Fetch their bundle in the background so a safety number is available.
      fetchPeerBundle(from);
    }

    const text = await session.decrypt(envelope);
    pushMessage(from, { dir: "in", text, cipher: envelope.ciphertext });

    if (from === state.activePeer) {
      renderConversation();
    } else {
      state.unread.set(from, (state.unread.get(from) ?? 0) + 1);
      renderUserList();
    }
  } catch (err) {
    console.error(`Failed to decrypt message from ${from}:`, err);
    addSystemMessage(from, "⚠️ A message failed to decrypt (it may be corrupt).");
  }
}

async function fetchPeerBundle(peer) {
  if (state.peerBundles.has(peer)) return;
  try {
    const bundle = await state.conn.getBundle(peer);
    state.peerBundles.set(peer, bundle);
    if (peer === state.activePeer) renderSafetyNumber();
  } catch {
    /* best effort */
  }
}

// ---- Sending --------------------------------------------------------------
els.composer.addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = els.messageInput.value.trim();
  if (!text || !state.activePeer) return;
  els.messageInput.value = "";

  const peer = state.activePeer;
  try {
    const session = await getOrCreateSession(peer);
    const envelope = await session.encrypt(text);
    state.conn.send({ type: "message", to: peer, envelope });
    pushMessage(peer, { dir: "out", text, cipher: envelope.ciphertext });
    renderConversation();
  } catch (err) {
    console.error(err);
    addSystemMessage(peer, "⚠️ Could not send: " + err.message);
  }
});

// ---- Conversations / rendering -------------------------------------------
function pushMessage(peer, message) {
  message.ts = Date.now();
  if (!state.conversations.has(peer)) state.conversations.set(peer, []);
  state.conversations.get(peer).push(message);
}

function addSystemMessage(peer, text) {
  if (!peer) return;
  pushMessage(peer, { dir: "system", text });
  if (peer === state.activePeer) renderConversation();
}

function selectPeer(peer) {
  state.activePeer = peer;
  state.unread.delete(peer);
  els.composer.classList.remove("hidden");
  els.safetyBtn.classList.remove("hidden");
  els.safetyPanel.classList.add("hidden");
  renderUserList();
  renderPeerHeader();
  renderConversation();
  renderSafetyNumber();
  if (!state.peerBundles.has(peer)) fetchPeerBundle(peer);
}

function renderUserList() {
  const peers = new Set([
    ...state.online,
    ...state.conversations.keys(),
  ]);
  peers.delete(state.username);

  els.userList.replaceChildren();

  if (peers.size === 0) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No one else is online yet.";
    els.userList.appendChild(li);
    return;
  }

  for (const peer of [...peers].sort()) {
    const li = document.createElement("li");
    if (peer === state.activePeer) li.classList.add("active");

    const dot = document.createElement("span");
    dot.className = "dot" + (state.online.has(peer) ? " online" : "");
    li.appendChild(dot);

    const name = document.createElement("span");
    name.textContent = peer;
    li.appendChild(name);

    const unread = state.unread.get(peer);
    if (unread) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = String(unread);
      li.appendChild(badge);
    }

    li.addEventListener("click", () => selectPeer(peer));
    els.userList.appendChild(li);
  }
}

function renderPeerHeader() {
  els.peerName.textContent = state.activePeer ?? "Select a contact";
  els.peerStatus.textContent = state.activePeer
    ? state.online.has(state.activePeer)
      ? "🔒 end-to-end encrypted · online"
      : "🔒 end-to-end encrypted · offline"
    : "";
}

function renderConversation() {
  els.messages.replaceChildren();
  const convo = state.conversations.get(state.activePeer) ?? [];

  if (convo.length === 0) {
    const div = document.createElement("div");
    div.className = "empty-state";
    const p = document.createElement("p");
    p.textContent = "No messages yet. Say hello — it's encrypted end to end.";
    div.appendChild(p);
    els.messages.appendChild(div);
    return;
  }

  for (const m of convo) {
    if (m.dir === "system") {
      const s = document.createElement("div");
      s.className = "system-msg";
      s.textContent = m.text;
      els.messages.appendChild(s);
      continue;
    }

    const bubble = document.createElement("div");
    bubble.className = `msg ${m.dir}`;
    bubble.title = "Click to reveal the ciphertext the server saw";

    const body = document.createElement("div");
    body.textContent = m.text;
    bubble.appendChild(body);

    const meta = document.createElement("span");
    meta.className = "meta";
    meta.textContent = new Date(m.ts).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
    });
    bubble.appendChild(meta);

    if (m.cipher) {
      const cipher = document.createElement("div");
      cipher.className = "cipher";
      cipher.textContent = "ciphertext: " + m.cipher;
      bubble.appendChild(cipher);
      bubble.addEventListener("click", () =>
        bubble.classList.toggle("show-cipher"),
      );
    }

    els.messages.appendChild(bubble);
  }
  els.messages.scrollTop = els.messages.scrollHeight;
}

// ---- Safety number --------------------------------------------------------
els.safetyBtn.addEventListener("click", () => {
  els.safetyPanel.classList.toggle("hidden");
  renderSafetyNumber();
});

async function renderSafetyNumber() {
  const peer = state.activePeer;
  const bundle = state.peerBundles.get(peer);
  if (!bundle) {
    els.safetyNumber.textContent = "fetching keys…";
    return;
  }
  els.safetyNumber.textContent = await safetyNumber(state.myBundle, bundle);
}

renderUserList();
