// @ts-nocheck
import type { BuiltinHandler, FunctionMetadata, ModuleMetadata, Value } from "@wiredwp/robinpath";
import { randomBytes, createHash } from "node:crypto";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { EventEmitter } from "node:events";
import type { Socket } from "node:net";

// ── RFC 6455 WebSocket opcodes ──────────────────────────────────────────────
const OP_CONTINUATION = 0x0;
const OP_TEXT = 0x1;
const OP_BINARY = 0x2;
const OP_CLOSE = 0x8;
const OP_PING = 0x9;
const OP_PONG = 0xa;

const READY_STATE = { CONNECTING: 0, OPEN: 1, CLOSING: 2, CLOSED: 3 } as const;

// ── Minimal RFC 6455 WebSocket client ───────────────────────────────────────
class RawWebSocket extends EventEmitter {
  readyState: number = READY_STATE.CONNECTING;
  private socket: Socket | null = null;
  private buffer: Buffer = Buffer.alloc(0);
  private fragments: Buffer[] = [];
  private fragmentOpcode: number = 0;

  constructor(url: string, options?: { headers?: Record<string, string> }) {
    super();
    this._connect(url, options?.headers ?? {});
  }

  // ── Connection via HTTP(S) upgrade ──────────────────────────────────────
  private _connect(url: string, extraHeaders: Record<string, string>) {
    const parsed = new URL(url);
    const isSecure = parsed.protocol === "wss:" || parsed.protocol === "https:";
    const port = parsed.port ? Number(parsed.port) : isSecure ? 443 : 80;
    const path = (parsed.pathname || "/") + (parsed.search || "");

    const key = randomBytes(16).toString("base64");

    const headers: Record<string, string> = {
      Host: parsed.host,
      Upgrade: "websocket",
      Connection: "Upgrade",
      "Sec-WebSocket-Key": key,
      "Sec-WebSocket-Version": "13",
      ...extraHeaders,
    };

    const reqFn = isSecure ? httpsRequest : httpRequest;
    const req = reqFn({
      hostname: parsed.hostname,
      port,
      path,
      method: "GET",
      headers,
    });

    req.on("upgrade", (res, socket, head) => {
      // Validate accept key per RFC 6455 §4.2.2
      const expectedAccept = createHash("sha1")
        .update(key + "258EAFA5-E914-47DA-95CA-5AB5DC525DA0")
        .digest("base64");
      const actualAccept = res.headers["sec-websocket-accept"];
      if (actualAccept !== expectedAccept) {
        socket.destroy();
        this.readyState = READY_STATE.CLOSED;
        this.emit("error", new Error("Invalid Sec-WebSocket-Accept header"));
        return;
      }

      this.socket = socket;
      this.readyState = READY_STATE.OPEN;

      // Process any data that arrived with the upgrade response
      if (head && head.length > 0) {
        this.buffer = Buffer.concat([this.buffer, head]);
        this._drain();
      }

      socket.on("data", (chunk: Buffer) => {
        this.buffer = Buffer.concat([this.buffer, chunk]);
        this._drain();
      });

      socket.on("close", () => {
        this.readyState = READY_STATE.CLOSED;
        this.emit("close");
      });

      socket.on("error", (err) => {
        this.readyState = READY_STATE.CLOSED;
        this.emit("error", err);
      });

      this.emit("open");
    });

    req.on("error", (err) => {
      this.readyState = READY_STATE.CLOSED;
      this.emit("error", err);
    });

    req.end();
  }

  // ── Frame parser (RFC 6455 §5.2) ───────────────────────────────────────
  private _drain() {
    while (true) {
      if (this.buffer.length < 2) return;

      const firstByte = this.buffer[0];
      const secondByte = this.buffer[1];

      const fin = (firstByte & 0x80) !== 0;
      const opcode = firstByte & 0x0f;
      const masked = (secondByte & 0x80) !== 0;
      let payloadLen = secondByte & 0x7f;
      let offset = 2;

      if (payloadLen === 126) {
        if (this.buffer.length < 4) return;
        payloadLen = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (this.buffer.length < 10) return;
        // Read as two 32-bit values (JavaScript safe integer range)
        const hi = this.buffer.readUInt32BE(2);
        const lo = this.buffer.readUInt32BE(6);
        payloadLen = hi * 0x100000000 + lo;
        offset = 10;
      }

      let maskKey: Buffer | null = null;
      if (masked) {
        if (this.buffer.length < offset + 4) return;
        maskKey = this.buffer.subarray(offset, offset + 4);
        offset += 4;
      }

      if (this.buffer.length < offset + payloadLen) return;

      let payload = this.buffer.subarray(offset, offset + payloadLen);
      // Advance the buffer past this frame
      this.buffer = Buffer.from(this.buffer.subarray(offset + payloadLen));

      // Unmask if needed (servers usually don't mask, but handle it)
      if (masked && maskKey) {
        payload = Buffer.from(payload);
        for (let i = 0; i < payload.length; i++) {
          payload[i] ^= maskKey[i & 3];
        }
      }

      this._handleFrame(fin, opcode, payload);
    }
  }

  private _handleFrame(fin: boolean, opcode: number, payload: Buffer) {
    // Handle control frames (can appear between fragmented data frames)
    if (opcode === OP_CLOSE) {
      this.readyState = READY_STATE.CLOSING;
      // Echo close frame back
      this._sendFrame(OP_CLOSE, payload.length >= 2 ? payload.subarray(0, 2) : Buffer.alloc(0));
      this.socket?.end();
      this.readyState = READY_STATE.CLOSED;
      this.emit("close");
      return;
    }

    if (opcode === OP_PING) {
      this._sendFrame(OP_PONG, payload);
      this.emit("ping", payload);
      return;
    }

    if (opcode === OP_PONG) {
      this.emit("pong", payload);
      return;
    }

    // Handle data frames with fragmentation
    if (opcode !== OP_CONTINUATION) {
      // Start of a new message (or single-frame message)
      this.fragmentOpcode = opcode;
      this.fragments = [payload];
    } else {
      // Continuation frame
      this.fragments.push(payload);
    }

    if (fin) {
      const fullPayload = this.fragments.length === 1
        ? this.fragments[0]
        : Buffer.concat(this.fragments);
      this.fragments = [];

      if (this.fragmentOpcode === OP_TEXT) {
        this.emit("message", fullPayload.toString("utf-8"));
      } else if (this.fragmentOpcode === OP_BINARY) {
        this.emit("message", fullPayload);
      }
    }
  }

  // ── Frame writer (client frames MUST be masked per RFC 6455 §5.3) ──────
  private _sendFrame(opcode: number, data: Buffer | string) {
    if (!this.socket || this.socket.destroyed) return;

    const payload = typeof data === "string" ? Buffer.from(data, "utf-8") : data;
    const len = payload.length;

    // Calculate header size: 2 base + extended length + 4 mask
    let headerSize = 2 + 4; // base + mask key
    let extBytes = 0;
    if (len >= 65536) {
      extBytes = 8;
    } else if (len >= 126) {
      extBytes = 2;
    }
    headerSize += extBytes;

    const frame = Buffer.alloc(headerSize + len);
    frame[0] = 0x80 | opcode; // FIN + opcode

    // Payload length + mask bit
    if (len < 126) {
      frame[1] = 0x80 | len;
    } else if (len < 65536) {
      frame[1] = 0x80 | 126;
      frame.writeUInt16BE(len, 2);
    } else {
      frame[1] = 0x80 | 127;
      frame.writeUInt32BE(Math.floor(len / 0x100000000), 2);
      frame.writeUInt32BE(len >>> 0, 6);
    }

    // Mask key
    const maskOffset = 2 + extBytes;
    const mask = randomBytes(4);
    mask.copy(frame, maskOffset);

    // Masked payload
    const dataOffset = maskOffset + 4;
    for (let i = 0; i < len; i++) {
      frame[dataOffset + i] = payload[i] ^ mask[i & 3];
    }

    this.socket.write(frame);
  }

  // ── Public API ─────────────────────────────────────────────────────────
  send(data: string | Buffer) {
    if (this.readyState !== READY_STATE.OPEN) {
      throw new Error("WebSocket is not open");
    }
    const opcode = typeof data === "string" ? OP_TEXT : OP_BINARY;
    this._sendFrame(opcode, data);
  }

  ping(data?: Buffer) {
    if (this.readyState !== READY_STATE.OPEN) return;
    this._sendFrame(OP_PING, data ?? Buffer.alloc(0));
  }

  close(code?: number, reason?: string) {
    if (this.readyState === READY_STATE.CLOSED || this.readyState === READY_STATE.CLOSING) return;
    this.readyState = READY_STATE.CLOSING;
    let payload = Buffer.alloc(0);
    if (code !== undefined) {
      const reasonBuf = reason ? Buffer.from(reason, "utf-8") : Buffer.alloc(0);
      payload = Buffer.alloc(2 + reasonBuf.length);
      payload.writeUInt16BE(code, 0);
      reasonBuf.copy(payload, 2);
    }
    this._sendFrame(OP_CLOSE, payload);
    // Give server time to respond, then force close
    setTimeout(() => {
      if (this.socket && !this.socket.destroyed) {
        this.socket.destroy();
      }
      this.readyState = READY_STATE.CLOSED;
    }, 3000);
  }
}

// ── Connection store ────────────────────────────────────────────────────────
const connections = new Map<string, { ws: RawWebSocket; messages: unknown[]; maxHistory: number }>();

// ── Handlers ────────────────────────────────────────────────────────────────

const connect: BuiltinHandler = async (args) => {
  const name = String(args[0] ?? "default");
  const url = String(args[1] ?? "");
  const opts = (typeof args[2] === "object" && args[2] !== null ? args[2] : {}) as Record<string, unknown>;
  if (!url) throw new Error("WebSocket URL is required");

  return new Promise<{ name: string; url: string; connected: boolean }>((resolve: any, reject: any) => {
    const headers = (typeof opts.headers === "object" && opts.headers !== null ? opts.headers : {}) as Record<string, string>;
    const ws = new RawWebSocket(url, { headers });
    const state = { ws, messages: [] as unknown[], maxHistory: Number(opts.maxHistory ?? 100) };

    ws.on("message", (data: any) => {
      const msg = typeof data === "string" ? data : data.toString();
      try { state.messages.push(JSON.parse(msg)); } catch { state.messages.push(msg); }
      if (state.messages.length > state.maxHistory) state.messages.shift();
    });

    ws.on("open", () => { connections.set(name, state); resolve({ name, url, connected: true }); });
    ws.on("error", (err: any) => reject(new Error(`WebSocket error: ${err.message}`)));

    const timeout = Number(opts.timeout ?? 10000);
    setTimeout(() => reject(new Error("WebSocket connection timeout")), timeout);
  });
};

const send: BuiltinHandler = (args) => {
  const name = String(args[0] ?? "default");
  const data = args[1];
  const conn = connections.get(name);
  if (!conn) throw new Error(`Connection "${name}" not found`);
  if (conn.ws.readyState !== READY_STATE.OPEN) throw new Error(`Connection "${name}" is not open`);
  const msg = typeof data === "string" ? data : JSON.stringify(data);
  conn.ws.send(msg);
  return true;
};

const receive: BuiltinHandler = async (args) => {
  const name = String(args[0] ?? "default");
  const timeoutMs = parseInt(String(args[1] ?? "10000"), 10);
  const conn = connections.get(name);
  if (!conn) throw new Error(`Connection "${name}" not found`);

  return new Promise<any>((resolve: any, reject: any) => {
    const handler = (data: any) => {
      clearTimeout(timer);
      const msg = typeof data === "string" ? data : data.toString();
      try { resolve(JSON.parse(msg)); } catch { resolve(msg); }
    };
    const timer = setTimeout(() => { conn.ws.removeListener("message", handler); reject(new Error("Receive timeout")); }, timeoutMs);
    conn.ws.once("message", handler);
  });
};

const messages: BuiltinHandler = (args) => {
  const name = String(args[0] ?? "default");
  const limit = parseInt(String(args[1] ?? "50"), 10);
  const conn = connections.get(name);
  if (!conn) throw new Error(`Connection "${name}" not found`);
  return conn.messages.slice(-limit);
};

const isConnected: BuiltinHandler = (args) => {
  const name = String(args[0] ?? "default");
  const conn = connections.get(name);
  return conn ? conn.ws.readyState === READY_STATE.OPEN : false;
};

const close: BuiltinHandler = (args) => {
  const name = String(args[0] ?? "default");
  const conn = connections.get(name);
  if (!conn) return false;
  conn.ws.close();
  connections.delete(name);
  return true;
};

const onMessage: BuiltinHandler = (args) => {
  const name = String(args[0] ?? "default");
  const handler = args[1];
  if (typeof handler !== "function") throw new Error("Handler must be a function");
  const conn = connections.get(name);
  if (!conn) throw new Error(`Connection "${name}" not found`);
  conn.ws.on("message", (data: any) => {
    const msg = typeof data === "string" ? data : data.toString();
    try { (handler as Function)(JSON.parse(msg)); } catch { (handler as Function)(msg); }
  });
  return true;
};

const ping: BuiltinHandler = (args) => {
  const name = String(args[0] ?? "default");
  const conn = connections.get(name);
  if (!conn || conn.ws.readyState !== READY_STATE.OPEN) return false;
  conn.ws.ping();
  return true;
};

export const SocketFunctions: Record<string, BuiltinHandler> = { connect, send, receive, messages, isConnected, close, onMessage, ping };

export const SocketFunctionMetadata = {
  connect: { description: "Connect to a WebSocket server", parameters: [{ name: "name", dataType: "string", description: "Connection name", formInputType: "text", required: true }, { name: "url", dataType: "string", description: "WebSocket URL (ws:// or wss://)", formInputType: "text", required: true }, { name: "options", dataType: "object", description: "{headers, timeout, maxHistory}", formInputType: "text", required: false }], returnType: "object", returnDescription: "{name, url, connected}", example: 'socket.connect "slack" "wss://wss.slack.com/link"' },
  send: { description: "Send a message through a WebSocket connection", parameters: [{ name: "name", dataType: "string", description: "Connection name", formInputType: "text", required: true }, { name: "data", dataType: "any", description: "Message (string or JSON)", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "True if sent", example: 'socket.send "slack" {"type": "message", "text": "Hello"}' },
  receive: { description: "Wait for and receive the next message", parameters: [{ name: "name", dataType: "string", description: "Connection name", formInputType: "text", required: true }, { name: "timeout", dataType: "number", description: "Timeout in ms (default 10000)", formInputType: "text", required: false }], returnType: "any", returnDescription: "Received message", example: 'socket.receive "slack" 5000' },
  messages: { description: "Get recent message history", parameters: [{ name: "name", dataType: "string", description: "Connection name", formInputType: "text", required: true }, { name: "limit", dataType: "number", description: "Max messages (default 50)", formInputType: "text", required: false }], returnType: "array", returnDescription: "Array of recent messages", example: 'socket.messages "slack" 10' },
  isConnected: { description: "Check if a WebSocket is connected", parameters: [{ name: "name", dataType: "string", description: "Connection name", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "True if open", example: 'socket.isConnected "slack"' },
  close: { description: "Close a WebSocket connection", parameters: [{ name: "name", dataType: "string", description: "Connection name", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "True if closed", example: 'socket.close "slack"' },
  onMessage: { description: "Register a handler for incoming messages", parameters: [{ name: "name", dataType: "string", description: "Connection name", formInputType: "text", required: true }, { name: "handler", dataType: "string", description: "Callback function", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "True", example: 'socket.onMessage "slack" $handler' },
  ping: { description: "Send a ping to keep the connection alive", parameters: [{ name: "name", dataType: "string", description: "Connection name", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "True if sent", example: 'socket.ping "slack"' },
};

export const SocketModuleMetadata = {
  description: "WebSocket client for real-time communication with message history, handlers, and connection management",
  methods: ["connect", "send", "receive", "messages", "isConnected", "close", "onMessage", "ping"],
};
