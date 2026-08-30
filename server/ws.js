import { WebSocketServer, WebSocket } from 'ws';

/**
 * Broadcast hub.
 *
 * Every client gets a snapshot on connect so the map is populated immediately
 * rather than staying blank until the next attack. Slow clients are dropped
 * rather than buffered - a stalled browser must not become backpressure on the
 * pollers.
 */
export class Hub {
  constructor(server, { onConnect, onMessage }) {
    this.wss = new WebSocketServer({ server, path: '/ws' });
    this.onConnect = onConnect;

    this.wss.on('connection', (ws, req) => {
      ws.isAlive = true;
      ws.on('pong', () => { ws.isAlive = true; });
      ws.on('error', () => ws.terminate());
      const ip = req.socket.remoteAddress;
      console.log(`[ws] client connected (${ip}), ${this.wss.clients.size} total`);
      ws.on('close', () => console.log(`[ws] client disconnected, ${this.wss.clients.size} total`));
      // Clients talk back only to choose a stats window. Anything malformed is
      // ignored rather than allowed to throw inside the socket handler.
      ws.on('message', (data) => {
        if (!onMessage) return;
        try {
          const msg = JSON.parse(String(data).slice(0, 4096));
          for (const out of onMessage(msg, ws) ?? []) this.#send(ws, out);
        } catch { /* not our protocol */ }
      });
      for (const msg of this.onConnect(ws)) this.#send(ws, msg);
    });

    this.heartbeat = setInterval(() => {
      for (const ws of this.wss.clients) {
        if (!ws.isAlive) { ws.terminate(); continue; }
        ws.isAlive = false;
        ws.ping();
      }
    }, 30_000);
  }

  #send(ws, msg) {
    if (ws.readyState !== WebSocket.OPEN) return;
    // A client that cannot keep up gets cut loose instead of growing a queue.
    if (ws.bufferedAmount > 1_000_000) { ws.terminate(); return; }
    ws.send(JSON.stringify(msg));
  }

  broadcast(msg) {
    if (!this.wss.clients.size) return;
    const payload = JSON.stringify(msg);
    for (const ws of this.wss.clients) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      if (ws.bufferedAmount > 1_000_000) { ws.terminate(); continue; }
      ws.send(payload);
    }
  }

  /**
   * Send a per-client message. `build` is called once per distinct value of
   * `keyOf(ws)` and the payload reused, so N clients watching the same stats
   * window cost one serialisation rather than N.
   */
  each(keyOf, build) {
    if (!this.wss.clients.size) return;
    const payloads = new Map();
    for (const ws of this.wss.clients) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      if (ws.bufferedAmount > 1_000_000) { ws.terminate(); continue; }
      const key = keyOf(ws);
      let payload = payloads.get(key);
      if (payload === undefined) payloads.set(key, (payload = JSON.stringify(build(key))));
      ws.send(payload);
    }
  }

  get clientCount() {
    return this.wss.clients.size;
  }

  close() {
    clearInterval(this.heartbeat);
    this.wss.close();
  }
}
