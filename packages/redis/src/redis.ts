// @ts-nocheck
import type { BuiltinHandler, FunctionMetadata, ModuleMetadata } from "@wiredwp/robinpath";
import * as net from "node:net";
import * as tls from "node:tls";

// ---------------------------------------------------------------------------
// RESP v2 protocol implementation over raw TCP / TLS
// ---------------------------------------------------------------------------

interface RedisConnection {
  socket: net.Socket;
  buffer: Buffer;
  pending: Array<{ resolve: (v: any) => void; reject: (e: Error) => void }>;
  prefix: string;
}

const connections = new Map<string, RedisConnection>();

// ---- RESP encoder ----------------------------------------------------------

function encodeCommand(args: string[]): string {
  let out = `*${args.length}\r\n`;
  for (const a of args) {
    const buf = Buffer.from(a, "utf8");
    out += `$${buf.length}\r\n${a}\r\n`;
  }
  return out;
}

// ---- RESP decoder ----------------------------------------------------------

interface ParseResult {
  value: any;
  consumed: number;
}

function findCRLF(buf: Buffer, start: number): number {
  for (let i = start; i < buf.length - 1; i++) {
    if (buf[i] === 0x0d && buf[i + 1] === 0x0a) return i;
  }
  return -1;
}

function parseResp(buf: Buffer, offset: number): ParseResult | null {
  if (offset >= buf.length) return null;
  const type = buf[offset];

  // Simple String  +OK\r\n
  if (type === 0x2b) {
    const end = findCRLF(buf, offset);
    if (end === -1) return null;
    return { value: buf.subarray(offset + 1, end).toString("utf8"), consumed: end + 2 - offset };
  }

  // Error  -ERR msg\r\n
  if (type === 0x2d) {
    const end = findCRLF(buf, offset);
    if (end === -1) return null;
    return { value: new Error(buf.subarray(offset + 1, end).toString("utf8")), consumed: end + 2 - offset };
  }

  // Integer  :1000\r\n
  if (type === 0x3a) {
    const end = findCRLF(buf, offset);
    if (end === -1) return null;
    return { value: parseInt(buf.subarray(offset + 1, end).toString("utf8"), 10), consumed: end + 2 - offset };
  }

  // Bulk String  $6\r\nhello!\r\n  or  $-1\r\n (null)
  if (type === 0x24) {
    const end = findCRLF(buf, offset);
    if (end === -1) return null;
    const len = parseInt(buf.subarray(offset + 1, end).toString("utf8"), 10);
    if (len === -1) return { value: null, consumed: end + 2 - offset };
    const dataStart = end + 2;
    const dataEnd = dataStart + len;
    if (buf.length < dataEnd + 2) return null; // incomplete
    return { value: buf.subarray(dataStart, dataEnd).toString("utf8"), consumed: dataEnd + 2 - offset };
  }

  // Array  *2\r\n...
  if (type === 0x2a) {
    const end = findCRLF(buf, offset);
    if (end === -1) return null;
    const count = parseInt(buf.subarray(offset + 1, end).toString("utf8"), 10);
    if (count === -1) return { value: null, consumed: end + 2 - offset };
    let pos = end + 2 - offset; // relative consumed so far
    const items: any[] = [];
    for (let i = 0; i < count; i++) {
      const r = parseResp(buf, offset + pos);
      if (r === null) return null; // incomplete
      items.push(r.value);
      pos += r.consumed;
    }
    return { value: items, consumed: pos };
  }

  // Unknown type – skip to next CRLF
  const end = findCRLF(buf, offset);
  if (end === -1) return null;
  return { value: buf.subarray(offset + 1, end).toString("utf8"), consumed: end + 2 - offset };
}

// ---- Connection helpers ----------------------------------------------------

function setupDataHandler(conn: RedisConnection) {
  conn.socket.on("data", (chunk: Buffer) => {
    conn.buffer = Buffer.concat([conn.buffer, chunk]);
    drainBuffer(conn);
  });
  conn.socket.on("error", (err) => {
    while (conn.pending.length) conn.pending.shift()!.reject(err);
  });
  conn.socket.on("close", () => {
    const e = new Error("Redis connection closed");
    while (conn.pending.length) conn.pending.shift()!.reject(e);
  });
}

function drainBuffer(conn: RedisConnection) {
  while (conn.pending.length && conn.buffer.length > 0) {
    const result = parseResp(conn.buffer, 0);
    if (result === null) break; // need more data
    conn.buffer = conn.buffer.subarray(result.consumed);
    const { resolve, reject } = conn.pending.shift()!;
    if (result.value instanceof Error) reject(result.value);
    else resolve(result.value);
  }
}

function sendCommand(conn: RedisConnection, args: string[]): Promise<any> {
  return new Promise((resolve, reject) => {
    conn.pending.push({ resolve, reject });
    conn.socket.write(encodeCommand(args));
  });
}

function getConn(name: string): RedisConnection {
  const conn = connections.get(name);
  if (!conn) throw new Error(`Redis connection "${name}" not found. Call redis.connect first.`);
  return conn;
}

function prefixKey(conn: RedisConnection, key: string): string {
  return conn.prefix ? conn.prefix + key : key;
}

async function rawCmd(connName: string, args: string[]): Promise<any> {
  const conn = getConn(connName);
  return sendCommand(conn, args);
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

const connect: BuiltinHandler = async (args) => {
  const opts = (typeof args[0] === "object" && args[0] !== null ? args[0] : {}) as Record<string, unknown>;
  const name = String(opts.name ?? "default");
  const host = String(opts.host ?? "localhost");
  const port = Number(opts.port ?? 6379);
  const password = opts.password ? String(opts.password) : undefined;
  const db = Number(opts.db ?? 0);
  const prefix = opts.prefix ? String(opts.prefix) : "";
  const useTls = Boolean(opts.tls ?? false);

  // Create socket
  const socket: net.Socket = await new Promise((resolve, reject) => {
    let sock: net.Socket;
    if (useTls) {
      sock = tls.connect({ host, port, rejectUnauthorized: opts.rejectUnauthorized !== false }, () => resolve(sock));
    } else {
      sock = net.createConnection({ host, port }, () => resolve(sock));
    }
    sock.once("error", reject);
  });

  const conn: RedisConnection = { socket, buffer: Buffer.alloc(0), pending: [], prefix };
  setupDataHandler(conn);

  // AUTH if password provided
  if (password) {
    const authReply = await sendCommand(conn, ["AUTH", password]);
    if (authReply instanceof Error) throw authReply;
  }

  // SELECT database
  if (db !== 0) {
    const selReply = await sendCommand(conn, ["SELECT", String(db)]);
    if (selReply instanceof Error) throw selReply;
  }

  connections.set(name, conn);
  return { name, connected: true };
};

const get: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  const v = await sendCommand(conn, ["GET", prefixKey(conn, String(args[0] ?? ""))]);
  if (v === null) return null;
  try { return JSON.parse(v); } catch { return v; }
};

const set: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[3] ?? "default"));
  const key = prefixKey(conn, String(args[0] ?? ""));
  const val = typeof args[1] === "string" ? args[1] : JSON.stringify(args[1]);
  const ttl = args[2] ? Number(args[2]) : undefined;
  if (ttl) await sendCommand(conn, ["SET", key, val, "EX", String(ttl)]);
  else await sendCommand(conn, ["SET", key, val]);
  return true;
};

const del: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  const keys = Array.isArray(args[0]) ? args[0].map(String) : [String(args[0] ?? "")];
  return await sendCommand(conn, ["DEL", ...keys.map((k) => prefixKey(conn, k))]);
};

const exists: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  return (await sendCommand(conn, ["EXISTS", prefixKey(conn, String(args[0] ?? ""))])) === 1;
};

const keys: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  return await sendCommand(conn, ["KEYS", prefixKey(conn, String(args[0] ?? "*"))]);
};

const ttl: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  return await sendCommand(conn, ["TTL", prefixKey(conn, String(args[0] ?? ""))]);
};

const expire: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[2] ?? "default"));
  return (await sendCommand(conn, ["EXPIRE", prefixKey(conn, String(args[0] ?? "")), String(Number(args[1] ?? 0))])) === 1;
};

const incr: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  return await sendCommand(conn, ["INCRBY", prefixKey(conn, String(args[0] ?? "")), String(Number(args[1] ?? 1))]);
};

const decr: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  return await sendCommand(conn, ["DECRBY", prefixKey(conn, String(args[0] ?? "")), String(Number(args[1] ?? 1))]);
};

const hget: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[2] ?? "default"));
  const v = await sendCommand(conn, ["HGET", prefixKey(conn, String(args[0] ?? "")), String(args[1] ?? "")]);
  if (v === null) return null;
  try { return JSON.parse(v); } catch { return v; }
};

const hset: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[2] ?? "default"));
  const data = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const flat: string[] = [];
  for (const [k, v] of Object.entries(data)) flat.push(k, typeof v === "string" ? v : JSON.stringify(v));
  await sendCommand(conn, ["HSET", prefixKey(conn, String(args[0] ?? "")), ...flat]);
  return true;
};

const hgetall: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  const arr = await sendCommand(conn, ["HGETALL", prefixKey(conn, String(args[0] ?? ""))]);
  if (!Array.isArray(arr)) return {};
  const obj: Record<string, string> = {};
  for (let i = 0; i < arr.length; i += 2) obj[arr[i]] = arr[i + 1];
  return obj;
};

const hdel: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[2] ?? "default"));
  const fields = Array.isArray(args[1]) ? args[1].map(String) : [String(args[1] ?? "")];
  return await sendCommand(conn, ["HDEL", prefixKey(conn, String(args[0] ?? "")), ...fields]);
};

const lpush: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[2] ?? "default"));
  const vals = Array.isArray(args[1]) ? args[1].map(String) : [String(args[1] ?? "")];
  return await sendCommand(conn, ["LPUSH", prefixKey(conn, String(args[0] ?? "")), ...vals]);
};

const rpush: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[2] ?? "default"));
  const vals = Array.isArray(args[1]) ? args[1].map(String) : [String(args[1] ?? "")];
  return await sendCommand(conn, ["RPUSH", prefixKey(conn, String(args[0] ?? "")), ...vals]);
};

const lpop: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  return await sendCommand(conn, ["LPOP", prefixKey(conn, String(args[0] ?? ""))]);
};

const rpop: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  return await sendCommand(conn, ["RPOP", prefixKey(conn, String(args[0] ?? ""))]);
};

const lrange: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[3] ?? "default"));
  return await sendCommand(conn, ["LRANGE", prefixKey(conn, String(args[0] ?? "")), String(Number(args[1] ?? 0)), String(Number(args[2] ?? -1))]);
};

const llen: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  return await sendCommand(conn, ["LLEN", prefixKey(conn, String(args[0] ?? ""))]);
};

const sadd: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[2] ?? "default"));
  const members = Array.isArray(args[1]) ? args[1].map(String) : [String(args[1] ?? "")];
  return await sendCommand(conn, ["SADD", prefixKey(conn, String(args[0] ?? "")), ...members]);
};

const smembers: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[1] ?? "default"));
  return await sendCommand(conn, ["SMEMBERS", prefixKey(conn, String(args[0] ?? ""))]);
};

const sismember: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[2] ?? "default"));
  return (await sendCommand(conn, ["SISMEMBER", prefixKey(conn, String(args[0] ?? "")), String(args[1] ?? "")])) === 1;
};

const srem: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[2] ?? "default"));
  const members = Array.isArray(args[1]) ? args[1].map(String) : [String(args[1] ?? "")];
  return await sendCommand(conn, ["SREM", prefixKey(conn, String(args[0] ?? "")), ...members]);
};

const publish: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[2] ?? "default"));
  return await sendCommand(conn, ["PUBLISH", String(args[0] ?? ""), String(args[1] ?? "")]);
};

const flushdb: BuiltinHandler = async (args) => {
  const conn = getConn(String(args[0] ?? "default"));
  await sendCommand(conn, ["FLUSHDB"]);
  return true;
};

const close: BuiltinHandler = async (args) => {
  const name = String(args[0] ?? "default");
  const c = connections.get(name);
  if (c) {
    c.socket.destroy();
    connections.delete(name);
  }
  return true;
};

const closeAll: BuiltinHandler = async () => {
  for (const [n, c] of connections) {
    c.socket.destroy();
    connections.delete(n);
  }
  return true;
};

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

export const RedisFunctions: Record<string, BuiltinHandler> = { connect, get, set, del, exists, keys, ttl, expire, incr, decr, hget, hset, hgetall, hdel, lpush, rpush, lpop, rpop, lrange, llen, sadd, smembers, sismember, srem, publish, flushdb, close, closeAll };

export const RedisFunctionMetadata = {
  connect: { description: "Connect to Redis", parameters: [{ name: "options", dataType: "object", description: "{host, port, password, db, prefix, name, tls}", formInputType: "text", required: true }], returnType: "object", returnDescription: "{name, connected}", example: 'redis.connect {"host": "localhost"}' },
  get: { description: "Get value by key", parameters: [{ name: "key", dataType: "string", description: "Key", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "any", returnDescription: "Value or null", example: 'redis.get "user:1"' },
  set: { description: "Set key-value", parameters: [{ name: "key", dataType: "string", description: "Key", formInputType: "text", required: true }, { name: "value", dataType: "any", description: "Value", formInputType: "text", required: true }, { name: "ttl", dataType: "number", description: "TTL in seconds", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "true", example: 'redis.set "user:1" {"name": "Alice"} 3600' },
  del: { description: "Delete key(s)", parameters: [{ name: "keys", dataType: "string", description: "Key or array of keys", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "Keys deleted", example: 'redis.del "user:1"' },
  exists: { description: "Check key exists", parameters: [{ name: "key", dataType: "string", description: "Key", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "true if exists", example: 'redis.exists "user:1"' },
  keys: { description: "Find keys by pattern", parameters: [{ name: "pattern", dataType: "string", description: "Glob pattern", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Matching keys", example: 'redis.keys "user:*"' },
  ttl: { description: "Get key TTL", parameters: [{ name: "key", dataType: "string", description: "Key", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "TTL in seconds", example: 'redis.ttl "session:abc"' },
  expire: { description: "Set key expiration", parameters: [{ name: "key", dataType: "string", description: "Key", formInputType: "text", required: true }, { name: "seconds", dataType: "number", description: "TTL", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "true if set", example: 'redis.expire "session:abc" 3600' },
  incr: { description: "Increment value", parameters: [{ name: "key", dataType: "string", description: "Key", formInputType: "text", required: true }, { name: "amount", dataType: "number", description: "Amount (default 1)", formInputType: "text", required: false }], returnType: "number", returnDescription: "New value", example: 'redis.incr "counter"' },
  decr: { description: "Decrement value", parameters: [{ name: "key", dataType: "string", description: "Key", formInputType: "text", required: true }, { name: "amount", dataType: "number", description: "Amount (default 1)", formInputType: "text", required: false }], returnType: "number", returnDescription: "New value", example: 'redis.decr "counter"' },
  hget: { description: "Get hash field", parameters: [{ name: "key", dataType: "string", description: "Hash key", formInputType: "text", required: true }, { name: "field", dataType: "string", description: "Field", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "any", returnDescription: "Value", example: 'redis.hget "user:1" "name"' },
  hset: { description: "Set hash fields", parameters: [{ name: "key", dataType: "string", description: "Hash key", formInputType: "text", required: true }, { name: "fields", dataType: "object", description: "Field-value pairs", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "true", example: 'redis.hset "user:1" {"name": "Alice", "age": 30}' },
  hgetall: { description: "Get all hash fields", parameters: [{ name: "key", dataType: "string", description: "Hash key", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "All fields", example: 'redis.hgetall "user:1"' },
  hdel: { description: "Delete hash fields", parameters: [{ name: "key", dataType: "string", description: "Hash key", formInputType: "text", required: true }, { name: "fields", dataType: "string", description: "Field(s)", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "Fields removed", example: 'redis.hdel "user:1" "age"' },
  lpush: { description: "Push to list head", parameters: [{ name: "key", dataType: "string", description: "List key", formInputType: "text", required: true }, { name: "values", dataType: "any", description: "Value(s)", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "List length", example: 'redis.lpush "queue" "task1"' },
  rpush: { description: "Push to list tail", parameters: [{ name: "key", dataType: "string", description: "List key", formInputType: "text", required: true }, { name: "values", dataType: "any", description: "Value(s)", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "List length", example: 'redis.rpush "queue" "task1"' },
  lpop: { description: "Pop from list head", parameters: [{ name: "key", dataType: "string", description: "List key", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "string", returnDescription: "Value or null", example: 'redis.lpop "queue"' },
  rpop: { description: "Pop from list tail", parameters: [{ name: "key", dataType: "string", description: "List key", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "string", returnDescription: "Value or null", example: 'redis.rpop "queue"' },
  lrange: { description: "Get list range", parameters: [{ name: "key", dataType: "string", description: "List key", formInputType: "text", required: true }, { name: "start", dataType: "number", description: "Start index", formInputType: "text", required: false }, { name: "stop", dataType: "number", description: "Stop index", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Values", example: 'redis.lrange "queue" 0 -1' },
  llen: { description: "Get list length", parameters: [{ name: "key", dataType: "string", description: "List key", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "Length", example: 'redis.llen "queue"' },
  sadd: { description: "Add to set", parameters: [{ name: "key", dataType: "string", description: "Set key", formInputType: "text", required: true }, { name: "members", dataType: "any", description: "Member(s)", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "Members added", example: 'redis.sadd "tags" ["js", "ts"]' },
  smembers: { description: "Get set members", parameters: [{ name: "key", dataType: "string", description: "Set key", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Members", example: 'redis.smembers "tags"' },
  sismember: { description: "Check set membership", parameters: [{ name: "key", dataType: "string", description: "Set key", formInputType: "text", required: true }, { name: "member", dataType: "string", description: "Member", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "true if member", example: 'redis.sismember "tags" "js"' },
  srem: { description: "Remove from set", parameters: [{ name: "key", dataType: "string", description: "Set key", formInputType: "text", required: true }, { name: "members", dataType: "any", description: "Member(s)", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "Members removed", example: 'redis.srem "tags" "old"' },
  publish: { description: "Publish message to channel", parameters: [{ name: "channel", dataType: "string", description: "Channel", formInputType: "text", required: true }, { name: "message", dataType: "string", description: "Message", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "Subscribers received", example: 'redis.publish "events" "user.created"' },
  flushdb: { description: "Flush current database", parameters: [{ name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "true", example: 'redis.flushdb' },
  close: { description: "Close connection", parameters: [{ name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "true", example: 'redis.close' },
  closeAll: { description: "Close all connections", parameters: [], returnType: "boolean", returnDescription: "true", example: 'redis.closeAll' },
};

export const RedisModuleMetadata = {
  description: "Redis client with strings, hashes, lists, sets, pub/sub, TTL, and connection management",
  methods: ["connect", "get", "set", "del", "exists", "keys", "ttl", "expire", "incr", "decr", "hget", "hset", "hgetall", "hdel", "lpush", "rpush", "lpop", "rpop", "lrange", "llen", "sadd", "smembers", "sismember", "srem", "publish", "flushdb", "close", "closeAll"],
};
