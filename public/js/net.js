// net.js — thin WebSocket client with a small event API and a
// request/response helper for fetching prekey bundles.

export class ChatConnection {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.handlers = new Map();
    this._bundleWaiters = new Map(); // username -> { resolve, reject }
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.ws = new WebSocket(this.url);
      this.ws.addEventListener("open", () => resolve());
      this.ws.addEventListener("error", () =>
        reject(new Error("WebSocket connection failed.")),
      );
      this.ws.addEventListener("close", () => this._emit("close"));
      this.ws.addEventListener("message", (event) => this._onMessage(event));
    });
  }

  _onMessage(event) {
    let msg;
    try {
      msg = JSON.parse(event.data);
    } catch {
      return;
    }

    // Resolve any pending getBundle() promise.
    if (msg.type === "bundle") {
      const waiter = this._bundleWaiters.get(msg.username);
      if (waiter) {
        this._bundleWaiters.delete(msg.username);
        waiter.resolve(msg.bundle);
      }
    }
    if (msg.type === "error" && msg.context === "get-bundle") {
      // Reject the most recent bundle request (best effort).
      for (const [name, waiter] of this._bundleWaiters) {
        this._bundleWaiters.delete(name);
        waiter.reject(new Error(msg.message));
        break;
      }
    }

    this._emit(msg.type, msg);
  }

  on(type, fn) {
    if (!this.handlers.has(type)) this.handlers.set(type, []);
    this.handlers.get(type).push(fn);
  }

  _emit(type, msg) {
    for (const fn of this.handlers.get(type) ?? []) fn(msg);
  }

  send(obj) {
    this.ws.send(JSON.stringify(obj));
  }

  /** Fetch a peer's prekey bundle, consuming one of their one-time prekeys. */
  getBundle(username) {
    // De-duplicate concurrent requests for the same user so two callers share
    // one round trip (and consume only one one-time prekey).
    const existing = this._bundleWaiters.get(username);
    if (existing) return existing.promise;

    let resolve, reject;
    const promise = new Promise((res, rej) => {
      resolve = res;
      reject = rej;
    });
    this._bundleWaiters.set(username, { resolve, reject, promise });
    this.send({ type: "get-bundle", username });
    setTimeout(() => {
      if (this._bundleWaiters.has(username)) {
        this._bundleWaiters.delete(username);
        reject(new Error(`Timed out fetching bundle for ${username}.`));
      }
    }, 8000);
    return promise;
  }
}
