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
  constructor(server, { onConnect }) {
    this.wss = new WebSocketServer({ server, path: '/ws' });
    this.onConnect = onConnect;

    this.wss.on('connection', (ws, req) => {
      ws.isAlive = true;
      ws.on('pong', () => { ws.isAlive = true; });
      ws.on('error', () => ws.terminate());
      const ip = req.socket.remoteAddress;
      console.log(`[ws] client connected (${ip}), ${this.wss.clients.size} total`);
      ws.on('close', () => console.log(`[ws] client disconnected, ${this.wss.clients.size} total`));
      for (const msg of this.onConnect()) this.#send(ws, msg);
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

  get clientCount() {
    return this.wss.clients.size;
  }

  close() {
    clearInterval(this.heartbeat);
    this.wss.close();
  }
}
