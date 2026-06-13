// app.js — UI + session orchestration.
//
// Responsibilities:
//   * generate this browser's identity + prekey bundle and register it
//   * maintain one Session (X3DH + Double Ratchet) per *peer*
//   * encrypt outgoing / decrypt incoming messages
//   * 1:1 chats and group chats (groups fan a message out as N pairwise-
//     encrypted envelopes — see sendToGroup)
//   * render everything (using textContent only — never innerHTML for user data)

import { Identity, safetyNumber } from "./crypto/identity.js";
import { Session } from "./crypto/session.js";
import { ChatConnection } from "./net.js";

// A conversation key namespaces peers vs groups so they never collide.
const peerKey = (username) => `peer:${username}`;
const groupKey = (id) => `group:${id}`;
const activeKey = () =>
  state.active
    ? state.active.type === "group"
      ? groupKey(state.active.id)
      : peerKey(state.active.id)
    : null;

// ---- State ----------------------------------------------------------------
const state = {
  conn: null,
  identity: null,
  username: null,
  myBundle: null,
  sessions: new Map(), // peer -> Session
  peerBundles: new Map(), // peer -> bundle (for safety numbers)
  groups: new Map(), // groupId -> { id, name, members }
  conversations: new Map(), // convKey -> [ { dir, text, sender?, cipher, ts } ]
  online: new Set(),
  unread: new Map(), // convKey -> count
  active: null, // { type: 'peer'|'group', id }
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
  groupList: $("group-list"),
  newGroupBtn: $("new-group-btn"),
  peerName: $("peer-name"),
  peerStatus: $("peer-status"),
  safetyBtn: $("safety-btn"),
  safetyPanel: $("safety-panel"),
  safetyNumber: $("safety-number"),
  messages: $("messages"),
  composer: $("composer"),
  messageInput: $("message-input"),
  // group modal
  groupModal: $("group-modal"),
  groupForm: $("group-form"),
  groupNameInput: $("group-name-input"),
  groupMembers: $("group-members"),
  groupCancel: $("group-cancel"),
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

    state.conn.send({ type: "register", username, bundle: state.myBundle });
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
    renderSidebar();
  });

  conn.on("presence", (msg) => {
    if (msg.online) state.online.add(msg.username);
    else state.online.delete(msg.username);
    renderSidebar();
    if (state.active?.type === "peer" && state.active.id === msg.username) {
      renderHeader();
    }
  });

  conn.on("group", (msg) => {
    state.groups.set(msg.group.id, msg.group);
    renderSidebar();
    // If we created it, jump straight into it.
    if (msg.group.createdBy === state.username && !isActiveGroup(msg.group.id)) {
      selectChat({ type: "group", id: msg.group.id });
    }
  });

  conn.on("message", (msg) => handleIncoming(msg.from, msg.envelope));
  conn.on("queued", (msg) =>
    addSystemMessage(peerKey(msg.to), "Recipient offline — message queued."),
  );
  conn.on("low-prekeys", () => replenishPreKeys());
  conn.on("error", (msg) => console.warn("Server error:", msg.message));
  conn.on("close", () =>
    addSystemMessage(activeKey(), "Disconnected from relay."),
  );
}

async function replenishPreKeys() {
  const ids = await state.identity.replenishOneTimePreKeys(10);
  state.myBundle = await state.identity.publishBundle();
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
      fetchPeerBundle(from); // for safety numbers, in the background
    }

    // The message decrypts only under our session with `from`, so attribution
    // to `from` is cryptographically sound regardless of what the relay claims.
    const text = await session.decrypt(envelope);

    if (envelope.group) {
      routeIncoming(groupKey(envelope.group), {
        dir: "in",
        text,
        sender: from,
        cipher: envelope.ciphertext,
      });
    } else {
      routeIncoming(peerKey(from), { dir: "in", text, cipher: envelope.ciphertext });
    }
  } catch (err) {
    console.error(`Failed to decrypt message from ${from}:`, err);
  }
}

function routeIncoming(convKey, message) {
  pushMessage(convKey, message);
  if (activeKey() === convKey) {
    renderConversation();
  } else {
    state.unread.set(convKey, (state.unread.get(convKey) ?? 0) + 1);
    renderSidebar();
  }
}

async function fetchPeerBundle(peer) {
  if (state.peerBundles.has(peer)) return;
  try {
    const bundle = await state.conn.getBundle(peer);
    state.peerBundles.set(peer, bundle);
    if (state.active?.type === "peer" && state.active.id === peer) {
      renderSafetyNumber();
    }
  } catch {
    /* best effort */
  }
}

// ---- Sending --------------------------------------------------------------
els.composer.addEventListener("submit", async (e) => {
  e.preventDefault();
  const text = els.messageInput.value.trim();
  if (!text || !state.active) return;
  els.messageInput.value = "";

  try {
    if (state.active.type === "group") {
      await sendToGroup(state.groups.get(state.active.id), text);
    } else {
      await sendToPeer(state.active.id, text);
    }
  } catch (err) {
    console.error(err);
    addSystemMessage(activeKey(), "⚠️ Could not send: " + err.message);
  }
});

async function sendToPeer(peer, text) {
  const session = await getOrCreateSession(peer);
  const envelope = await session.encrypt(text);
  state.conn.send({ type: "message", to: peer, envelope });
  pushMessage(peerKey(peer), { dir: "out", text, cipher: envelope.ciphertext });
  renderConversation();
}

// Group fan-out: encrypt the message separately for each member using that
// member's own Double Ratchet session, then send N individual envelopes. Every
// copy keeps full forward secrecy; the server still only relays ciphertext.
async function sendToGroup(group, text) {
  if (!group) return;
  let firstCipher = null;
  for (const member of group.members) {
    if (member === state.username) continue;
    try {
      const session = await getOrCreateSession(member);
      const envelope = await session.encrypt(text);
      envelope.group = group.id;
      state.conn.send({ type: "message", to: member, envelope });
      if (!firstCipher) firstCipher = envelope.ciphertext;
    } catch (err) {
      console.error(`Group send to ${member} failed:`, err);
    }
  }
  pushMessage(groupKey(group.id), {
    dir: "out",
    text,
    sender: state.username,
    cipher: firstCipher,
  });
  renderConversation();
}

// ---- Conversations / messages ---------------------------------------------
function pushMessage(convKey, message) {
  if (!convKey) return;
  message.ts = Date.now();
  if (!state.conversations.has(convKey)) state.conversations.set(convKey, []);
  state.conversations.get(convKey).push(message);
}

function addSystemMessage(convKey, text) {
  if (!convKey) return;
  pushMessage(convKey, { dir: "system", text });
  if (activeKey() === convKey) renderConversation();
}

// ---- Selection ------------------------------------------------------------
function isActiveGroup(id) {
  return state.active?.type === "group" && state.active.id === id;
}

function selectChat(chat) {
  state.active = chat;
  state.unread.delete(activeKey());
  els.composer.classList.remove("hidden");
  els.safetyPanel.classList.add("hidden");
  // Safety numbers only make sense for 1:1 chats.
  els.safetyBtn.classList.toggle("hidden", chat.type !== "peer");

  renderSidebar();
  renderHeader();
  renderConversation();

  if (chat.type === "peer") {
    renderSafetyNumber();
    if (!state.peerBundles.has(chat.id)) fetchPeerBundle(chat.id);
  }
}

// ---- Rendering: sidebar ---------------------------------------------------
function knownPeers() {
  const peers = new Set(state.online);
  for (const key of state.conversations.keys()) {
    if (key.startsWith("peer:")) peers.add(key.slice(5));
  }
  for (const group of state.groups.values()) {
    for (const m of group.members) peers.add(m);
  }
  peers.delete(state.username);
  return [...peers].sort();
}

function renderSidebar() {
  renderUserList();
  renderGroupList();
}

function renderUserList() {
  els.userList.replaceChildren();
  const peers = knownPeers();

  if (peers.length === 0) {
    const li = document.createElement("li");
    li.className = "muted";
    li.textContent = "No one else here yet.";
    els.userList.appendChild(li);
    return;
  }

  for (const peer of peers) {
    const li = document.createElement("li");
    if (state.active?.type === "peer" && state.active.id === peer) {
      li.classList.add("active");
    }

    const dot = document.createElement("span");
    dot.className = "dot" + (state.online.has(peer) ? " online" : "");
    li.appendChild(dot);

    const name = document.createElement("span");
    name.textContent = peer;
    li.appendChild(name);

    appendUnread(li, peerKey(peer));
    li.addEventListener("click", () => selectChat({ type: "peer", id: peer }));
    els.userList.appendChild(li);
  }
}

function renderGroupList() {
  els.groupList.replaceChildren();
  for (const group of state.groups.values()) {
    const li = document.createElement("li");
    if (isActiveGroup(group.id)) li.classList.add("active");

    const icon = document.createElement("span");
    icon.className = "group-icon";
    icon.textContent = "#";
    li.appendChild(icon);

    const name = document.createElement("span");
    name.textContent = group.name;
    li.appendChild(name);

    appendUnread(li, groupKey(group.id));
    li.addEventListener("click", () => selectChat({ type: "group", id: group.id }));
    els.groupList.appendChild(li);
  }
}

function appendUnread(li, convKey) {
  const count = state.unread.get(convKey);
  if (count) {
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = String(count);
    li.appendChild(badge);
  }
}

// ---- Rendering: header + messages -----------------------------------------
function renderHeader() {
  if (!state.active) {
    els.peerName.textContent = "Select a contact";
    els.peerStatus.textContent = "";
    return;
  }
  if (state.active.type === "group") {
    const group = state.groups.get(state.active.id);
    els.peerName.textContent = "# " + group.name;
    els.peerStatus.textContent = `🔒 end-to-end encrypted · ${group.members.length} members`;
  } else {
    const peer = state.active.id;
    els.peerName.textContent = peer;
    els.peerStatus.textContent =
      "🔒 end-to-end encrypted · " +
      (state.online.has(peer) ? "online" : "offline");
  }
}

function renderConversation() {
  els.messages.replaceChildren();
  const convo = state.conversations.get(activeKey()) ?? [];
  const isGroup = state.active?.type === "group";

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

    // In groups, label who sent each incoming message.
    if (isGroup && m.dir === "in" && m.sender) {
      const who = document.createElement("div");
      who.className = "sender";
      who.textContent = m.sender;
      bubble.appendChild(who);
    }

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
  if (state.active?.type !== "peer") return;
  const bundle = state.peerBundles.get(state.active.id);
  if (!bundle) {
    els.safetyNumber.textContent = "fetching keys…";
    return;
  }
  els.safetyNumber.textContent = await safetyNumber(state.myBundle, bundle);
}

// ---- Group creation modal -------------------------------------------------
els.newGroupBtn.addEventListener("click", openGroupModal);
els.groupCancel.addEventListener("click", () =>
  els.groupModal.classList.add("hidden"),
);

function openGroupModal() {
  els.groupNameInput.value = "";
  els.groupMembers.replaceChildren();

  const candidates = knownPeers();
  if (candidates.length === 0) {
    const note = document.createElement("p");
    note.className = "modal-note";
    note.textContent = "No other users are available yet. Have someone else sign in first.";
    els.groupMembers.appendChild(note);
  }
  for (const peer of candidates) {
    const label = document.createElement("label");
    label.className = "member-option";
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.value = peer;
    label.appendChild(cb);
    label.appendChild(document.createTextNode(" " + peer));
    els.groupMembers.appendChild(label);
  }
  els.groupModal.classList.remove("hidden");
}

els.groupForm.addEventListener("submit", (e) => {
  e.preventDefault();
  const name = els.groupNameInput.value.trim() || "Group";
  const members = [...els.groupMembers.querySelectorAll("input:checked")].map(
    (cb) => cb.value,
  );
  if (members.length === 0) return;
  state.conn.send({ type: "create-group", name, members });
  els.groupModal.classList.add("hidden");
});

renderSidebar();
