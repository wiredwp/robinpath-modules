// @ts-nocheck
import type { BuiltinHandler, FunctionMetadata, ModuleMetadata, Value } from "@wiredwp/robinpath";
import * as net from "node:net";
import * as tls from "node:tls";
import * as crypto from "node:crypto";

// ---------------------------------------------------------------------------
// MQTT v3.1.1 protocol constants
// ---------------------------------------------------------------------------
const enum PacketType {
  CONNECT = 1,
  CONNACK = 2,
  PUBLISH = 3,
  PUBACK = 4,
  SUBSCRIBE = 8,
  SUBACK = 9,
  UNSUBSCRIBE = 10,
  UNSUBACK = 11,
  PINGREQ = 12,
  PINGRESP = 13,
  DISCONNECT = 14,
}

const PROTOCOL_NAME = "MQTT";
const PROTOCOL_LEVEL = 4; // v3.1.1

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/** Encode remaining length as MQTT variable-length encoding. */
function encodeRemainingLength(length: number): Buffer {
  const bytes: number[] = [];
  do {
    let encodedByte = length % 128;
    length = Math.floor(length / 128);
    if (length > 0) encodedByte |= 0x80;
    bytes.push(encodedByte);
  } while (length > 0);
  return Buffer.from(bytes);
}

/** Decode remaining length from a buffer starting at offset. Returns [value, bytesConsumed]. */
function decodeRemainingLength(buf: Buffer, startOffset: number): [number, number] {
  let multiplier = 1;
  let value = 0;
  let offset = startOffset;
  let encodedByte: number;
  do {
    if (offset >= buf.length) throw new Error("Malformed remaining length");
    encodedByte = buf[offset++];
    value += (encodedByte & 0x7f) * multiplier;
    multiplier *= 128;
    if (multiplier > 128 * 128 * 128 * 128) throw new Error("Malformed remaining length");
  } while ((encodedByte & 0x80) !== 0);
  return [value, offset - startOffset];
}

/** Encode a UTF-8 string with 2-byte length prefix (MQTT style). */
function encodeUtf8String(str: string): Buffer {
  const strBuf = Buffer.from(str, "utf8");
  const lenBuf = Buffer.alloc(2);
  lenBuf.writeUInt16BE(strBuf.length, 0);
  return Buffer.concat([lenBuf, strBuf]);
}

/** Build a fixed header byte. */
function fixedHeaderByte(type: PacketType, flags = 0): number {
  return ((type & 0x0f) << 4) | (flags & 0x0f);
}

/** Build a complete MQTT packet from type+flags and payload. */
function buildPacket(type: PacketType, flags: number, payload: Buffer): Buffer {
  const header = Buffer.from([fixedHeaderByte(type, flags)]);
  const rl = encodeRemainingLength(payload.length);
  return Buffer.concat([header, rl, payload]);
}

// ---------------------------------------------------------------------------
// Packet builders
// ---------------------------------------------------------------------------

interface WillConfig {
  topic: string;
  payload: string;
  qos: 0 | 1 | 2;
  retain: boolean;
}

interface ConnectOptions {
  clientId?: string;
  cleanSession?: boolean;
  keepalive?: number;
  username?: string;
  password?: string;
  will?: WillConfig;
}

function buildConnectPacket(opts: ConnectOptions): Buffer {
  const clientId = opts.clientId ?? `robinpath_${crypto.randomBytes(8).toString("hex")}`;
  const keepalive = opts.keepalive ?? 60;
  const cleanSession = opts.cleanSession !== false;

  // Variable header
  const protocolName = encodeUtf8String(PROTOCOL_NAME);
  const protocolLevel = Buffer.from([PROTOCOL_LEVEL]);

  // Connect flags
  let connectFlags = 0;
  if (cleanSession) connectFlags |= 0x02;
  if (opts.will) {
    connectFlags |= 0x04; // will flag
    connectFlags |= (opts.will.qos & 0x03) << 3; // will QoS
    if (opts.will.retain) connectFlags |= 0x20; // will retain
  }
  if (opts.username) connectFlags |= 0x80;
  if (opts.password) connectFlags |= 0x40;

  const flagsBuf = Buffer.from([connectFlags]);
  const keepaliveBuf = Buffer.alloc(2);
  keepaliveBuf.writeUInt16BE(keepalive, 0);

  // Payload
  const parts: Buffer[] = [protocolName, protocolLevel, flagsBuf, keepaliveBuf, encodeUtf8String(clientId)];

  if (opts.will) {
    parts.push(encodeUtf8String(opts.will.topic));
    parts.push(encodeUtf8String(opts.will.payload));
  }
  if (opts.username) parts.push(encodeUtf8String(opts.username));
  if (opts.password) parts.push(encodeUtf8String(opts.password));

  const payload = Buffer.concat(parts);
  return buildPacket(PacketType.CONNECT, 0, payload);
}

function buildPublishPacket(topic: string, message: string, qos: number, retain: boolean, packetId?: number): Buffer {
  const topicBuf = encodeUtf8String(topic);
  const msgBuf = Buffer.from(message, "utf8");
  const parts: Buffer[] = [topicBuf];

  if (qos > 0 && packetId !== undefined) {
    const pidBuf = Buffer.alloc(2);
    pidBuf.writeUInt16BE(packetId, 0);
    parts.push(pidBuf);
  }

  parts.push(msgBuf);
  const payload = Buffer.concat(parts);

  let flags = 0;
  flags |= (qos & 0x03) << 1;
  if (retain) flags |= 0x01;

  return buildPacket(PacketType.PUBLISH, flags, payload);
}

function buildSubscribePacket(packetId: number, topic: string, qos: number): Buffer {
  const pidBuf = Buffer.alloc(2);
  pidBuf.writeUInt16BE(packetId, 0);
  const topicBuf = encodeUtf8String(topic);
  const qosBuf = Buffer.from([qos & 0x03]);
  const payload = Buffer.concat([pidBuf, topicBuf, qosBuf]);
  return buildPacket(PacketType.SUBSCRIBE, 0x02, payload); // flags must be 0x02 per spec
}

function buildUnsubscribePacket(packetId: number, topic: string): Buffer {
  const pidBuf = Buffer.alloc(2);
  pidBuf.writeUInt16BE(packetId, 0);
  const topicBuf = encodeUtf8String(topic);
  const payload = Buffer.concat([pidBuf, topicBuf]);
  return buildPacket(PacketType.UNSUBSCRIBE, 0x02, payload); // flags must be 0x02 per spec
}

function buildPingreqPacket(): Buffer {
  return Buffer.from([fixedHeaderByte(PacketType.PINGREQ, 0), 0x00]);
}

function buildDisconnectPacket(): Buffer {
  return Buffer.from([fixedHeaderByte(PacketType.DISCONNECT, 0), 0x00]);
}

// ---------------------------------------------------------------------------
// Internal client class wrapping a raw TCP/TLS socket
// ---------------------------------------------------------------------------

interface PendingOperation {
  resolve: (value: any) => void;
  reject: (err: Error) => void;
}

class MqttConnection {
  socket: net.Socket | tls.TLSSocket | null = null;
  connected = false;
  brokerUrl: string;
  options: ConnectOptions;
  willConfig: WillConfig | null = null;

  private _packetIdCounter = 0;
  private _pendingConnect: PendingOperation | null = null;
  private _pendingPublish: Map<number, PendingOperation> = new Map();
  private _pendingSubscribe: Map<number, { topic: string; op: PendingOperation }> = new Map();
  private _pendingUnsubscribe: Map<number, { topic: string; op: PendingOperation }> = new Map();
  private _keepaliveTimer: ReturnType<typeof setInterval> | null = null;
  private _recvBuf: Buffer = Buffer.alloc(0);

  onMessage: ((topic: string, message: Buffer) => void) | null = null;

  constructor(brokerUrl: string, options: ConnectOptions) {
    this.brokerUrl = brokerUrl;
    this.options = options;
    if (options.will) {
      this.willConfig = { ...options.will };
    }
  }

  private _nextPacketId(): number {
    this._packetIdCounter = (this._packetIdCounter % 65535) + 1;
    return this._packetIdCounter;
  }

  connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this._pendingConnect = { resolve, reject };

      const url = new URL(this.brokerUrl);
      const useTls = url.protocol === "mqtts:" || url.protocol === "tls:";
      const port = parseInt(url.port || (useTls ? "8883" : "1883"), 10);
      const host = url.hostname || "localhost";

      const connectOpts = this.options;
      if (connectOpts.will === undefined && this.willConfig) {
        connectOpts.will = this.willConfig;
      }

      const onConnect = () => {
        // Send CONNECT packet
        const pkt = buildConnectPacket(connectOpts);
        this.socket!.write(pkt);
      };

      if (useTls) {
        this.socket = tls.connect({ host, port, rejectUnauthorized: false }, onConnect);
      } else {
        this.socket = net.createConnection({ host, port }, onConnect);
      }

      this.socket.on("data", (data: Buffer) => this._onData(data));
      this.socket.on("error", (err: Error) => this._onError(err));
      this.socket.on("close", () => this._onClose());
    });
  }

  private _onData(data: Buffer): void {
    this._recvBuf = Buffer.concat([this._recvBuf, data]);
    this._parsePackets();
  }

  private _parsePackets(): void {
    while (this._recvBuf.length >= 2) {
      // Need at least 1 byte header + 1 byte remaining length
      let offset = 1;
      let rlResult: [number, number];
      try {
        rlResult = decodeRemainingLength(this._recvBuf, offset);
      } catch {
        break; // incomplete
      }
      const [remainingLength, rlBytes] = rlResult;
      offset += rlBytes;
      const totalLength = offset + remainingLength;

      if (this._recvBuf.length < totalLength) break; // incomplete packet

      const packetBuf = this._recvBuf.subarray(0, totalLength);
      this._recvBuf = this._recvBuf.subarray(totalLength);

      const headerByte = packetBuf[0];
      const packetType = (headerByte >> 4) & 0x0f;
      const flags = headerByte & 0x0f;
      const payloadStart = offset;
      const payload = packetBuf.subarray(payloadStart);

      this._handlePacket(packetType, flags, payload);
    }
  }

  private _handlePacket(type: number, flags: number, payload: Buffer): void {
    switch (type) {
      case PacketType.CONNACK:
        this._handleConnack(payload);
        break;
      case PacketType.PUBLISH:
        this._handlePublish(flags, payload);
        break;
      case PacketType.PUBACK:
        this._handlePuback(payload);
        break;
      case PacketType.SUBACK:
        this._handleSuback(payload);
        break;
      case PacketType.UNSUBACK:
        this._handleUnsuback(payload);
        break;
      case PacketType.PINGRESP:
        // Keepalive acknowledged, nothing to do
        break;
      default:
        // Ignore unknown packet types
        break;
    }
  }

  private _handleConnack(payload: Buffer): void {
    if (payload.length < 2) {
      this._pendingConnect?.reject(new Error("Malformed CONNACK"));
      return;
    }
    const returnCode = payload[1];
    if (returnCode === 0) {
      this.connected = true;
      this._startKeepalive();
      this._pendingConnect?.resolve(undefined);
    } else {
      const reasons: Record<number, string> = {
        1: "Unacceptable protocol version",
        2: "Identifier rejected",
        3: "Server unavailable",
        4: "Bad username or password",
        5: "Not authorized",
      };
      this._pendingConnect?.reject(new Error(`CONNACK error: ${reasons[returnCode] ?? `code ${returnCode}`}`));
    }
    this._pendingConnect = null;
  }

  private _handlePublish(flags: number, payload: Buffer): void {
    const qos = (flags >> 1) & 0x03;
    if (payload.length < 2) return;

    const topicLen = payload.readUInt16BE(0);
    const topic = payload.subarray(2, 2 + topicLen).toString("utf8");
    let offset = 2 + topicLen;

    let packetId: number | undefined;
    if (qos > 0) {
      packetId = payload.readUInt16BE(offset);
      offset += 2;
    }

    const message = payload.subarray(offset);

    // Dispatch to handler
    if (this.onMessage) {
      this.onMessage(topic, message);
    }

    // Send PUBACK for QoS 1
    if (qos === 1 && packetId !== undefined) {
      const puback = Buffer.alloc(4);
      puback[0] = fixedHeaderByte(PacketType.PUBACK, 0);
      puback[1] = 2;
      puback.writeUInt16BE(packetId, 2);
      this.socket?.write(puback);
    }
  }

  private _handlePuback(payload: Buffer): void {
    if (payload.length < 2) return;
    const packetId = payload.readUInt16BE(0);
    const pending = this._pendingPublish.get(packetId);
    if (pending) {
      this._pendingPublish.delete(packetId);
      pending.resolve(undefined);
    }
  }

  private _handleSuback(payload: Buffer): void {
    if (payload.length < 3) return;
    const packetId = payload.readUInt16BE(0);
    const grantedQos = payload[2];
    const pending = this._pendingSubscribe.get(packetId);
    if (pending) {
      this._pendingSubscribe.delete(packetId);
      if (grantedQos === 0x80) {
        pending.op.reject(new Error(`Subscription to "${pending.topic}" rejected by broker`));
      } else {
        pending.op.resolve({ topic: pending.topic, grantedQos });
      }
    }
  }

  private _handleUnsuback(payload: Buffer): void {
    if (payload.length < 2) return;
    const packetId = payload.readUInt16BE(0);
    const pending = this._pendingUnsubscribe.get(packetId);
    if (pending) {
      this._pendingUnsubscribe.delete(packetId);
      pending.op.resolve({ topic: pending.topic });
    }
  }

  private _startKeepalive(): void {
    const interval = ((this.options.keepalive ?? 60) * 1000) / 2; // send at half the keepalive interval
    this._keepaliveTimer = setInterval(() => {
      if (this.connected && this.socket) {
        this.socket.write(buildPingreqPacket());
      }
    }, interval);
  }

  private _stopKeepalive(): void {
    if (this._keepaliveTimer) {
      clearInterval(this._keepaliveTimer);
      this._keepaliveTimer = null;
    }
  }

  private _onError(err: Error): void {
    if (this._pendingConnect) {
      this._pendingConnect.reject(err);
      this._pendingConnect = null;
    }
    // Reject all pending operations
    for (const [, p] of this._pendingPublish) p.reject(err);
    this._pendingPublish.clear();
    for (const [, p] of this._pendingSubscribe) p.op.reject(err);
    this._pendingSubscribe.clear();
    for (const [, p] of this._pendingUnsubscribe) p.op.reject(err);
    this._pendingUnsubscribe.clear();
  }

  private _onClose(): void {
    this.connected = false;
    this._stopKeepalive();
  }

  publishMsg(topic: string, message: string, qos: number, retain: boolean): Promise<void> {
    const packetId = qos > 0 ? this._nextPacketId() : undefined;
    const pkt = buildPublishPacket(topic, message, qos, retain, packetId);
    this.socket!.write(pkt);

    if (qos === 0) return Promise.resolve();

    return new Promise((resolve, reject) => {
      this._pendingPublish.set(packetId!, { resolve, reject });
    });
  }

  subscribeTopic(topic: string, qos: number): Promise<{ topic: string; grantedQos: number }> {
    const packetId = this._nextPacketId();
    const pkt = buildSubscribePacket(packetId, topic, qos);
    this.socket!.write(pkt);

    return new Promise((resolve, reject) => {
      this._pendingSubscribe.set(packetId, { topic, op: { resolve, reject } });
    });
  }

  unsubscribeTopic(topic: string): Promise<{ topic: string }> {
    const packetId = this._nextPacketId();
    const pkt = buildUnsubscribePacket(packetId, topic);
    this.socket!.write(pkt);

    return new Promise((resolve, reject) => {
      this._pendingUnsubscribe.set(packetId, { topic, op: { resolve, reject } });
    });
  }

  disconnectClean(): Promise<void> {
    return new Promise((resolve) => {
      this._stopKeepalive();
      if (this.socket) {
        this.socket.write(buildDisconnectPacket());
        this.socket.end(() => {
          this.connected = false;
          this.socket = null;
          resolve();
        });
      } else {
        this.connected = false;
        resolve();
      }
    });
  }

  reconnectClient(): void {
    this._stopKeepalive();
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
    this.connected = false;
    // Re-connect asynchronously — fire and forget; user can check isConnected
    this.connect().catch(() => {});
  }
}

// ---------------------------------------------------------------------------
// Module-level state (mirrors original)
// ---------------------------------------------------------------------------

const clients: Map<string, MqttConnection> = new Map();
const messageHandlers: Map<string, Map<string, (topic: string, message: Buffer) => void>> = new Map();
const lastMessages: Map<string, Map<string, string>> = new Map();
const subscribedTopics: Map<string, Set<string>> = new Map();
const defaultQos: Map<string, number> = new Map();

function getClient(id: string): MqttConnection {
  const client = clients.get(id);
  if (!client) {
    throw new Error(`MQTT client "${id}" not found. Call connect() first.`);
  }
  return client;
}

// ---------------------------------------------------------------------------
// Handlers (same signatures as original)
// ---------------------------------------------------------------------------

const connect: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const brokerUrl = String(args[1] ?? "mqtt://localhost:1883");
  const options = (args[2] ?? {}) as Record<string, any>;

  if (clients.has(id)) {
    throw new Error(`MQTT client "${id}" already exists. Disconnect first or use a different id.`);
  }

  const connectOpts: ConnectOptions = {
    clientId: options.clientId ?? options.clientid ?? undefined,
    cleanSession: options.clean !== undefined ? Boolean(options.clean) : true,
    keepalive: options.keepalive !== undefined ? Number(options.keepalive) : 60,
    username: options.username ?? undefined,
    password: options.password ?? undefined,
    will: options.will ?? undefined,
  };

  const conn = new MqttConnection(brokerUrl, connectOpts);

  clients.set(id, conn);
  messageHandlers.set(id, new Map());
  lastMessages.set(id, new Map());
  subscribedTopics.set(id, new Set());
  defaultQos.set(id, 0);

  conn.onMessage = (topic: string, message: Buffer) => {
    const msgs = lastMessages.get(id);
    if (msgs) {
      msgs.set(topic, message.toString());
    }

    const handlers = messageHandlers.get(id);
    if (handlers) {
      for (const handler of handlers.values()) {
        handler(topic, message);
      }
    }
  };

  // Initiate connection (async). We don't await here to match original behavior.
  conn.connect().catch(() => {});

  return { id, brokerUrl, status: "connecting" };
};

const publish: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const topic = String(args[1]);
  const message = String(args[2]);
  const opts = (args[3] ?? {}) as Record<string, any>;

  if (!topic) throw new Error("Topic is required.");
  const client = getClient(id);

  const qos = opts.qos ?? defaultQos.get(id) ?? 0;
  const retain = Boolean(opts.retain ?? false);

  return client.publishMsg(topic, message, qos, retain).then(() => ({
    id,
    topic,
    message,
    qos,
  }));
};

const subscribe: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const topic = String(args[1]);
  const opts = (args[2] ?? {}) as Record<string, any>;

  if (!topic) throw new Error("Topic is required.");
  const client = getClient(id);

  const qos = opts.qos ?? defaultQos.get(id) ?? 0;

  return client.subscribeTopic(topic, qos).then((result) => {
    const topics = subscribedTopics.get(id);
    if (topics) topics.add(topic);
    return { id, topic, granted: [{ topic, qos: result.grantedQos }] };
  });
};

const unsubscribe: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const topic = String(args[1]);

  if (!topic) throw new Error("Topic is required.");
  const client = getClient(id);

  return client.unsubscribeTopic(topic).then(() => {
    const topics = subscribedTopics.get(id);
    if (topics) topics.delete(topic);
    return { id, topic, status: "unsubscribed" };
  });
};

const on: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const handlerId = String(args[1] ?? `handler_${Date.now()}`);
  const callback = args[2] as ((topic: string, message: Buffer) => void) | undefined;

  if (!callback || typeof callback !== "function") {
    throw new Error("A callback function is required.");
  }

  getClient(id);

  const handlers = messageHandlers.get(id);
  if (handlers) {
    handlers.set(handlerId, callback);
  }

  return { id, handlerId, status: "registered" };
};

const disconnect: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const client = getClient(id);

  return client.disconnectClean().then(() => {
    clients.delete(id);
    messageHandlers.delete(id);
    lastMessages.delete(id);
    subscribedTopics.delete(id);
    defaultQos.delete(id);
    return { id, status: "disconnected" };
  });
};

const isConnected: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const client = clients.get(id);
  return { id, connected: client ? client.connected : false };
};

const reconnect: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const client = getClient(id);
  client.reconnectClient();
  return { id, status: "reconnecting" };
};

const topics: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  getClient(id);
  const t = subscribedTopics.get(id);
  return { id, topics: t ? Array.from(t) : [] };
};

const lastMessage: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const topic = String(args[1]);

  if (!topic) throw new Error("Topic is required.");
  getClient(id);

  const msgs = lastMessages.get(id);
  const msg = msgs ? msgs.get(topic) ?? null : null;

  return { id, topic, message: msg };
};

const qos: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const level = Number(args[1] ?? 0);

  if (level < 0 || level > 2) {
    throw new Error("QoS level must be 0, 1, or 2.");
  }

  getClient(id);
  defaultQos.set(id, level);

  return { id, qos: level };
};

const will: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const topic = String(args[1]);
  const payload = String(args[2] ?? "");
  const willQos = Number(args[3] ?? 0) as 0 | 1 | 2;
  const retain = Boolean(args[4] ?? false);

  if (!topic) throw new Error("Topic is required for last will.");

  const client = getClient(id);
  client.willConfig = { topic, payload, qos: willQos, retain };
  client.options.will = { topic, payload, qos: willQos, retain };

  return { id, will: { topic, payload, qos: willQos, retain } };
};

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export const MqttFunctions: Record<string, BuiltinHandler> = {
  connect,
  publish,
  subscribe,
  unsubscribe,
  on,
  disconnect,
  isConnected,
  reconnect,
  topics,
  lastMessage,
  qos,
  will,
};

export const MqttFunctionMetadata = {
	connect: {
		description: 'Connect to an MQTT broker',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'brokerUrl', dataType: 'string', formInputType: 'text', description: 'Broker URL (e.g. mqtt://localhost:1883)', required: false },
			{ name: 'options', dataType: 'object', formInputType: 'json', description: 'MQTT connection options', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	publish: {
		description: 'Publish a message to an MQTT topic',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'topic', dataType: 'string', formInputType: 'text', description: 'Topic to publish to', required: true },
			{ name: 'message', dataType: 'string', formInputType: 'text', description: 'Message payload', required: true },
			{ name: 'options', dataType: 'object', formInputType: 'json', description: 'Publish options (qos, retain, etc.)', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	subscribe: {
		description: 'Subscribe to an MQTT topic',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'topic', dataType: 'string', formInputType: 'text', description: 'Topic to subscribe to', required: true },
			{ name: 'options', dataType: 'object', formInputType: 'json', description: 'Subscribe options (qos, etc.)', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	unsubscribe: {
		description: 'Unsubscribe from an MQTT topic',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'topic', dataType: 'string', formInputType: 'text', description: 'Topic to unsubscribe from', required: true },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	on: {
		description: 'Register a message handler for incoming MQTT messages',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'handlerId', dataType: 'string', formInputType: 'text', description: 'Unique handler identifier', required: false },
			{ name: 'callback', dataType: 'string', formInputType: 'text', description: 'Handler function receiving (topic, message)', required: true },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	disconnect: {
		description: 'Disconnect from an MQTT broker and clean up resources',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	isConnected: {
		description: 'Check if an MQTT client is currently connected',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	reconnect: {
		description: 'Reconnect an existing MQTT client to its broker',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	topics: {
		description: 'List all topics the client is currently subscribed to',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	lastMessage: {
		description: 'Get the last received message on a specific topic',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'topic', dataType: 'string', formInputType: 'text', description: 'Topic to get last message for', required: true },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	qos: {
		description: 'Set the default Quality of Service level for the client',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'level', dataType: 'number', formInputType: 'number', description: 'QoS level: 0 (at most once), 1 (at least once), 2 (exactly once)', required: true },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	will: {
		description: 'Set the last will and testament message for the client',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'topic', dataType: 'string', formInputType: 'text', description: 'Will topic', required: true },
			{ name: 'payload', dataType: 'string', formInputType: 'text', description: 'Will message payload', required: false },
			{ name: 'qos', dataType: 'number', formInputType: 'number', description: 'Will QoS level (0, 1, or 2)', required: false },
			{ name: 'retain', dataType: 'boolean', formInputType: 'checkbox', description: 'Whether to retain the will message', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
};

export const MqttModuleMetadata = {
	description: 'MQTT client module for connecting to MQTT brokers, publishing messages, subscribing to topics, and handling incoming messages. Supports multiple concurrent client connections, QoS levels, last will messages, and message history tracking.',
	methods: ['connect', 'publish', 'subscribe', 'unsubscribe', 'on', 'disconnect', 'isConnected', 'reconnect', 'topics', 'lastMessage', 'qos', 'will'],
};
