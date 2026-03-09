import type { BuiltinHandler } from "@wiredwp/robinpath";
import * as net from "node:net";
import * as tls from "node:tls";
import * as crypto from "node:crypto";

// ─── ObjectId ───────────────────────────────────────────────────────────────────

let oidCounter = crypto.randomInt(0, 0xffffff);
const oidRandom = crypto.randomBytes(5);

function generateObjectId(): string {
  const buf = Buffer.alloc(12);
  buf.writeUInt32BE(Math.floor(Date.now() / 1000), 0);
  oidRandom.copy(buf, 4);
  buf.writeUIntBE(oidCounter++ & 0xffffff, 9, 3);
  return buf.toString("hex");
}

function isValidObjectId(s: string): boolean {
  return /^[0-9a-fA-F]{24}$/.test(s);
}

// ─── BSON Encoder ───────────────────────────────────────────────────────────────

const BSON_DOUBLE = 0x01;
const BSON_STRING = 0x02;
const BSON_DOCUMENT = 0x03;
const BSON_ARRAY = 0x04;
const BSON_BINARY = 0x05;
const BSON_OBJECTID = 0x07;
const BSON_BOOLEAN = 0x08;
const BSON_DATE = 0x09;
const BSON_NULL = 0x0a;
const BSON_REGEX = 0x0b;
const BSON_INT32 = 0x10;
const BSON_TIMESTAMP = 0x11;
const BSON_INT64 = 0x12;

function encodeBson(obj: Record<string, unknown>): Buffer {
  const parts: Buffer[] = [];
  for (const key of Object.keys(obj)) {
    parts.push(encodeBsonElement(key, obj[key]));
  }
  const body = Buffer.concat(parts);
  const doc = Buffer.alloc(5 + body.length);
  doc.writeInt32LE(5 + body.length, 0);
  body.copy(doc, 4);
  doc[4 + body.length] = 0x00; // null terminator
  return doc;
}

function encodeBsonElement(key: string, value: unknown): Buffer {
  const keyBuf = Buffer.from(key + "\0", "utf8");

  if (value === null || value === undefined) {
    const buf = Buffer.alloc(1 + keyBuf.length);
    buf[0] = BSON_NULL;
    keyBuf.copy(buf, 1);
    return buf;
  }

  if (typeof value === "boolean") {
    const buf = Buffer.alloc(1 + keyBuf.length + 1);
    buf[0] = BSON_BOOLEAN;
    keyBuf.copy(buf, 1);
    buf[1 + keyBuf.length] = value ? 1 : 0;
    return buf;
  }

  if (typeof value === "number") {
    if (Number.isInteger(value) && value >= -2147483648 && value <= 2147483647) {
      const buf = Buffer.alloc(1 + keyBuf.length + 4);
      buf[0] = BSON_INT32;
      keyBuf.copy(buf, 1);
      buf.writeInt32LE(value, 1 + keyBuf.length);
      return buf;
    }
    const buf = Buffer.alloc(1 + keyBuf.length + 8);
    buf[0] = BSON_DOUBLE;
    keyBuf.copy(buf, 1);
    buf.writeDoubleLE(value, 1 + keyBuf.length);
    return buf;
  }

  if (typeof value === "bigint") {
    const buf = Buffer.alloc(1 + keyBuf.length + 8);
    buf[0] = BSON_INT64;
    keyBuf.copy(buf, 1);
    buf.writeBigInt64LE(value, 1 + keyBuf.length);
    return buf;
  }

  if (typeof value === "string") {
    // Check if it looks like an ObjectId in _id context
    if (key === "_id" && isValidObjectId(value)) {
      const oidBuf = Buffer.from(value, "hex");
      const buf = Buffer.alloc(1 + keyBuf.length + 12);
      buf[0] = BSON_OBJECTID;
      keyBuf.copy(buf, 1);
      oidBuf.copy(buf, 1 + keyBuf.length);
      return buf;
    }
    const strBuf = Buffer.from(value, "utf8");
    const buf = Buffer.alloc(1 + keyBuf.length + 4 + strBuf.length + 1);
    buf[0] = BSON_STRING;
    keyBuf.copy(buf, 1);
    buf.writeInt32LE(strBuf.length + 1, 1 + keyBuf.length);
    strBuf.copy(buf, 1 + keyBuf.length + 4);
    buf[1 + keyBuf.length + 4 + strBuf.length] = 0x00;
    return buf;
  }

  if (value instanceof Date) {
    const buf = Buffer.alloc(1 + keyBuf.length + 8);
    buf[0] = BSON_DATE;
    keyBuf.copy(buf, 1);
    buf.writeBigInt64LE(BigInt(value.getTime()), 1 + keyBuf.length);
    return buf;
  }

  if (value instanceof RegExp) {
    const pattern = Buffer.from(value.source + "\0", "utf8");
    let flags = "";
    if (value.global) flags += "g";
    if (value.ignoreCase) flags += "i";
    if (value.multiline) flags += "m";
    const flagsBuf = Buffer.from(flags + "\0", "utf8");
    const buf = Buffer.alloc(1 + keyBuf.length + pattern.length + flagsBuf.length);
    buf[0] = BSON_REGEX;
    keyBuf.copy(buf, 1);
    pattern.copy(buf, 1 + keyBuf.length);
    flagsBuf.copy(buf, 1 + keyBuf.length + pattern.length);
    return buf;
  }

  if (Buffer.isBuffer(value) || value instanceof Uint8Array) {
    const data = Buffer.isBuffer(value) ? value : Buffer.from(value);
    const buf = Buffer.alloc(1 + keyBuf.length + 4 + 1 + data.length);
    buf[0] = BSON_BINARY;
    keyBuf.copy(buf, 1);
    buf.writeInt32LE(data.length, 1 + keyBuf.length);
    buf[1 + keyBuf.length + 4] = 0x00; // subtype generic
    data.copy(buf, 1 + keyBuf.length + 5);
    return buf;
  }

  if (Array.isArray(value)) {
    const arrObj: Record<string, unknown> = {};
    for (let i = 0; i < value.length; i++) arrObj[String(i)] = value[i];
    const arrBson = encodeBson(arrObj);
    const buf = Buffer.alloc(1 + keyBuf.length + arrBson.length);
    buf[0] = BSON_ARRAY;
    keyBuf.copy(buf, 1);
    arrBson.copy(buf, 1 + keyBuf.length);
    return buf;
  }

  if (typeof value === "object") {
    // Handle special BSON-like objects
    const v = value as Record<string, unknown>;

    // { $oid: "..." }
    if (v.$oid && typeof v.$oid === "string") {
      const oidBuf = Buffer.from(v.$oid as string, "hex");
      const buf = Buffer.alloc(1 + keyBuf.length + 12);
      buf[0] = BSON_OBJECTID;
      keyBuf.copy(buf, 1);
      oidBuf.copy(buf, 1 + keyBuf.length);
      return buf;
    }

    // { $date: number }
    if (v.$date !== undefined) {
      const ts = typeof v.$date === "number" ? v.$date : new Date(v.$date as string).getTime();
      const buf = Buffer.alloc(1 + keyBuf.length + 8);
      buf[0] = BSON_DATE;
      keyBuf.copy(buf, 1);
      buf.writeBigInt64LE(BigInt(ts as number), 1 + keyBuf.length);
      return buf;
    }

    // { $timestamp: { t, i } }
    if (v.$timestamp && typeof v.$timestamp === "object") {
      const ts = v.$timestamp as { t: number; i: number };
      const buf = Buffer.alloc(1 + keyBuf.length + 8);
      buf[0] = BSON_TIMESTAMP;
      keyBuf.copy(buf, 1);
      buf.writeUInt32LE(ts.i || 0, 1 + keyBuf.length);
      buf.writeUInt32LE(ts.t || 0, 1 + keyBuf.length + 4);
      return buf;
    }

    // { $numberLong: "..." }
    if (v.$numberLong !== undefined) {
      const buf = Buffer.alloc(1 + keyBuf.length + 8);
      buf[0] = BSON_INT64;
      keyBuf.copy(buf, 1);
      buf.writeBigInt64LE(BigInt(v.$numberLong as string), 1 + keyBuf.length);
      return buf;
    }

    // Regular sub-document
    const subDoc = encodeBson(v as Record<string, unknown>);
    const buf = Buffer.alloc(1 + keyBuf.length + subDoc.length);
    buf[0] = BSON_DOCUMENT;
    keyBuf.copy(buf, 1);
    subDoc.copy(buf, 1 + keyBuf.length);
    return buf;
  }

  // Fallback: stringify
  const strVal = String(value);
  const strBuf = Buffer.from(strVal, "utf8");
  const buf = Buffer.alloc(1 + keyBuf.length + 4 + strBuf.length + 1);
  buf[0] = BSON_STRING;
  keyBuf.copy(buf, 1);
  buf.writeInt32LE(strBuf.length + 1, 1 + keyBuf.length);
  strBuf.copy(buf, 1 + keyBuf.length + 4);
  buf[1 + keyBuf.length + 4 + strBuf.length] = 0x00;
  return buf;
}

// ─── BSON Decoder ───────────────────────────────────────────────────────────────

function decodeBson(buf: Buffer, offset = 0): Record<string, unknown> {
  const docLen = buf.readInt32LE(offset);
  const end = offset + docLen - 1; // -1 for trailing null
  const result: Record<string, unknown> = {};
  let pos = offset + 4;

  while (pos < end) {
    const type = buf[pos++];
    if (type === 0) break;

    // Read cstring key
    const keyStart = pos;
    while (buf[pos] !== 0) pos++;
    const key = buf.toString("utf8", keyStart, pos);
    pos++; // skip null

    switch (type) {
      case BSON_DOUBLE:
        result[key] = buf.readDoubleLE(pos);
        pos += 8;
        break;

      case BSON_STRING: {
        const strLen = buf.readInt32LE(pos);
        pos += 4;
        result[key] = buf.toString("utf8", pos, pos + strLen - 1);
        pos += strLen;
        break;
      }

      case BSON_DOCUMENT: {
        const subDocLen = buf.readInt32LE(pos);
        result[key] = decodeBson(buf, pos);
        pos += subDocLen;
        break;
      }

      case BSON_ARRAY: {
        const arrDocLen = buf.readInt32LE(pos);
        const arrObj = decodeBson(buf, pos);
        // Convert indexed object to array
        const arr: unknown[] = [];
        for (let i = 0; String(i) in arrObj; i++) arr.push(arrObj[String(i)]);
        result[key] = arr;
        pos += arrDocLen;
        break;
      }

      case BSON_BINARY: {
        const binLen = buf.readInt32LE(pos);
        pos += 4;
        const _subtype = buf[pos++];
        result[key] = buf.subarray(pos, pos + binLen);
        pos += binLen;
        break;
      }

      case BSON_OBJECTID: {
        result[key] = buf.subarray(pos, pos + 12).toString("hex");
        pos += 12;
        break;
      }

      case BSON_BOOLEAN:
        result[key] = buf[pos++] === 1;
        break;

      case BSON_DATE: {
        const ms = buf.readBigInt64LE(pos);
        result[key] = new Date(Number(ms));
        pos += 8;
        break;
      }

      case BSON_NULL:
        result[key] = null;
        break;

      case BSON_REGEX: {
        const patStart = pos;
        while (buf[pos] !== 0) pos++;
        const pattern = buf.toString("utf8", patStart, pos);
        pos++;
        const flagStart = pos;
        while (buf[pos] !== 0) pos++;
        const flags = buf.toString("utf8", flagStart, pos);
        pos++;
        result[key] = new RegExp(pattern, flags);
        break;
      }

      case BSON_INT32:
        result[key] = buf.readInt32LE(pos);
        pos += 4;
        break;

      case BSON_TIMESTAMP: {
        const inc = buf.readUInt32LE(pos);
        const ts = buf.readUInt32LE(pos + 4);
        result[key] = { $timestamp: { t: ts, i: inc } };
        pos += 8;
        break;
      }

      case BSON_INT64: {
        const val = buf.readBigInt64LE(pos);
        // Convert to number if safe, otherwise keep as string
        const num = Number(val);
        result[key] = Number.isSafeInteger(num) ? num : val.toString();
        pos += 8;
        break;
      }

      default:
        throw new Error(`Unsupported BSON type: 0x${type.toString(16)} at position ${pos} for key "${key}"`);
    }
  }

  return result;
}

// ─── Wire Protocol ──────────────────────────────────────────────────────────────

let requestIdCounter = 1;

function buildOpMsg(body: Record<string, unknown>): Buffer {
  const bsonBody = encodeBson(body);

  // OP_MSG: flagBits(4) + kind(1) + bsonBody
  const sectionLen = 1 + bsonBody.length;
  const msgLen = 16 + 4 + sectionLen; // header(16) + flagBits(4) + section

  const buf = Buffer.alloc(msgLen);
  let offset = 0;

  // Header
  buf.writeInt32LE(msgLen, offset); offset += 4;          // messageLength
  buf.writeInt32LE(requestIdCounter++, offset); offset += 4; // requestID
  buf.writeInt32LE(0, offset); offset += 4;                  // responseTo
  buf.writeInt32LE(2013, offset); offset += 4;               // opCode = OP_MSG

  // flagBits
  buf.writeUInt32LE(0, offset); offset += 4;

  // Section Kind 0 (body)
  buf[offset++] = 0x00;
  bsonBody.copy(buf, offset);

  return buf;
}

function parseOpMsgReply(data: Buffer): Record<string, unknown> {
  // Header: 16 bytes
  // const msgLen = data.readInt32LE(0);
  // const reqId = data.readInt32LE(4);
  // const respTo = data.readInt32LE(8);
  // const opCode = data.readInt32LE(12);

  // flagBits: 4 bytes
  // const flags = data.readUInt32LE(16);

  // Section kind 0
  const kind = data[20];
  if (kind !== 0x00) throw new Error(`Unexpected OP_MSG section kind: ${kind}`);

  return decodeBson(data, 21);
}

// ─── Connection Management ──────────────────────────────────────────────────────

interface MongoConnection {
  socket: net.Socket | tls.TLSSocket;
  database: string;
  pendingData: Buffer;
  pendingResolve: ((data: Buffer) => void) | null;
}

const connections = new Map<string, MongoConnection>();

function parseUri(uri: string): {
  host: string;
  port: number;
  database: string;
  username?: string;
  password?: string;
  useTls: boolean;
  options: Record<string, string>;
} {
  const useTls = uri.startsWith("mongodb+srv://") || uri.includes("tls=true") || uri.includes("ssl=true");
  const cleaned = uri.replace(/^mongodb(\+srv)?:\/\//, "");

  let auth: string | undefined;
  let rest: string;
  const atIdx = cleaned.lastIndexOf("@");
  if (atIdx !== -1) {
    auth = cleaned.substring(0, atIdx);
    rest = cleaned.substring(atIdx + 1);
  } else {
    rest = cleaned;
  }

  // Parse options after ?
  const options: Record<string, string> = {};
  const qIdx = rest.indexOf("?");
  if (qIdx !== -1) {
    const qs = rest.substring(qIdx + 1);
    rest = rest.substring(0, qIdx);
    for (const pair of qs.split("&")) {
      const [k, v] = pair.split("=");
      if (k && v) options[decodeURIComponent(k)] = decodeURIComponent(v);
    }
  }

  // Parse host:port/database
  const slashIdx = rest.indexOf("/");
  let hostPort: string;
  let database = "test";
  if (slashIdx !== -1) {
    hostPort = rest.substring(0, slashIdx);
    const dbPart = rest.substring(slashIdx + 1);
    if (dbPart) database = dbPart;
  } else {
    hostPort = rest;
  }

  if (options.authSource) {
    // authSource doesn't override database
  }

  const colonIdx = hostPort.indexOf(":");
  let host = "localhost";
  let port = 27017;
  if (colonIdx !== -1) {
    host = hostPort.substring(0, colonIdx);
    port = parseInt(hostPort.substring(colonIdx + 1), 10) || 27017;
  } else if (hostPort) {
    host = hostPort;
  }

  let username: string | undefined;
  let password: string | undefined;
  if (auth) {
    const colonIdx2 = auth.indexOf(":");
    if (colonIdx2 !== -1) {
      username = decodeURIComponent(auth.substring(0, colonIdx2));
      password = decodeURIComponent(auth.substring(colonIdx2 + 1));
    } else {
      username = decodeURIComponent(auth);
    }
  }

  return { host, port, database, username, password, useTls, options };
}

function createSocket(host: string, port: number, useTls: boolean): Promise<net.Socket | tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    if (useTls) {
      const socket = tls.connect({ host, port, rejectUnauthorized: false }, () => {
        resolve(socket);
      });
      socket.once("error", reject);
    } else {
      const socket = net.createConnection({ host, port }, () => {
        resolve(socket);
      });
      socket.once("error", reject);
    }
  });
}

function setupSocket(conn: MongoConnection): void {
  conn.socket.on("data", (chunk: Buffer) => {
    conn.pendingData = Buffer.concat([conn.pendingData, chunk]);
    tryResolve(conn);
  });
}

function tryResolve(conn: MongoConnection): void {
  if (!conn.pendingResolve) return;
  if (conn.pendingData.length < 4) return;
  const msgLen = conn.pendingData.readInt32LE(0);
  if (conn.pendingData.length >= msgLen) {
    const msg = conn.pendingData.subarray(0, msgLen);
    conn.pendingData = conn.pendingData.subarray(msgLen);
    const resolve = conn.pendingResolve;
    conn.pendingResolve = null;
    resolve(Buffer.from(msg));
  }
}

function readReply(conn: MongoConnection): Promise<Buffer> {
  return new Promise((resolve) => {
    conn.pendingResolve = resolve;
    tryResolve(conn); // may already have data
  });
}

async function runCommand(conn: MongoConnection, cmd: Record<string, unknown>): Promise<Record<string, unknown>> {
  // Attach $db
  const cmdWithDb = { ...cmd, $db: conn.database };
  const msg = buildOpMsg(cmdWithDb);
  conn.socket.write(msg);
  const replyBuf = await readReply(conn);
  const reply = parseOpMsgReply(replyBuf);

  if (reply.ok !== 1 && reply.ok !== true) {
    const errmsg = reply.errmsg || reply.writeErrors || "Command failed";
    throw new Error(`MongoDB error: ${typeof errmsg === "string" ? errmsg : JSON.stringify(errmsg)}`);
  }

  return reply;
}

// ─── SCRAM-SHA-256 Authentication ───────────────────────────────────────────────

function xorBuffers(a: Buffer, b: Buffer): Buffer {
  const result = Buffer.alloc(a.length);
  for (let i = 0; i < a.length; i++) result[i] = a[i] ^ b[i];
  return result;
}

function hi(password: string, salt: Buffer, iterations: number): Buffer {
  // PBKDF2 with HMAC-SHA-256
  return crypto.pbkdf2Sync(password, salt, iterations, 32, "sha256");
}

async function authenticateScramSha256(
  conn: MongoConnection,
  username: string,
  password: string,
  authSource: string
): Promise<void> {
  const origDb = conn.database;
  conn.database = authSource;

  try {
    const nonce = crypto.randomBytes(24).toString("base64");
    const clientFirstBare = `n=${username.replace(/=/g, "=3D").replace(/,/g, "=2C")},r=${nonce}`;
    const clientFirstMsg = `n,,${clientFirstBare}`;

    // Step 1: saslStart
    const startReply = await runCommand(conn, {
      saslStart: 1,
      mechanism: "SCRAM-SHA-256",
      payload: Buffer.from(clientFirstMsg, "utf8"),
      autoAuthorize: 1,
    });

    const conversationId = startReply.conversationId;
    const serverFirstMsg = (startReply.payload as Buffer).toString("utf8");

    // Parse server-first-message: r=<nonce>,s=<salt>,i=<iterations>
    const serverParts: Record<string, string> = {};
    for (const part of serverFirstMsg.split(",")) {
      const eqIdx = part.indexOf("=");
      serverParts[part.substring(0, eqIdx)] = part.substring(eqIdx + 1);
    }

    const serverNonce = serverParts.r;
    const salt = Buffer.from(serverParts.s, "base64");
    const iterations = parseInt(serverParts.i, 10);

    if (!serverNonce.startsWith(nonce)) {
      throw new Error("SCRAM-SHA-256: Server nonce doesn't start with client nonce");
    }

    // SASLprep the password (simplified — just normalize)
    const preparedPassword = password;

    const saltedPassword = hi(preparedPassword, salt, iterations);
    const clientKey = crypto.createHmac("sha256", saltedPassword).update("Client Key").digest();
    const storedKey = crypto.createHash("sha256").update(clientKey).digest();

    const channelBinding = `c=${Buffer.from("n,,").toString("base64")}`;
    const clientFinalWithoutProof = `${channelBinding},r=${serverNonce}`;
    const authMessage = `${clientFirstBare},${serverFirstMsg},${clientFinalWithoutProof}`;

    const clientSignature = crypto.createHmac("sha256", storedKey).update(authMessage).digest();
    const clientProof = xorBuffers(clientKey, clientSignature);

    const clientFinalMsg = `${clientFinalWithoutProof},p=${clientProof.toString("base64")}`;

    // Step 2: saslContinue
    const continueReply = await runCommand(conn, {
      saslContinue: 1,
      conversationId,
      payload: Buffer.from(clientFinalMsg, "utf8"),
    });

    // Verify server signature
    const serverKey = crypto.createHmac("sha256", saltedPassword).update("Server Key").digest();
    const serverSignature = crypto.createHmac("sha256", serverKey).update(authMessage).digest();

    const serverFinalMsg = (continueReply.payload as Buffer).toString("utf8");
    const serverFinalParts: Record<string, string> = {};
    for (const part of serverFinalMsg.split(",")) {
      const eqIdx = part.indexOf("=");
      serverFinalParts[part.substring(0, eqIdx)] = part.substring(eqIdx + 1);
    }

    if (serverFinalParts.v !== serverSignature.toString("base64")) {
      throw new Error("SCRAM-SHA-256: Server signature verification failed");
    }

    // Step 3: If not done, one more saslContinue
    if (!continueReply.done) {
      await runCommand(conn, {
        saslContinue: 1,
        conversationId,
        payload: Buffer.alloc(0),
      });
    }
  } finally {
    conn.database = origDb;
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

function getConn(name: string): MongoConnection {
  const entry = connections.get(name);
  if (!entry) throw new Error(`MongoDB connection "${name}" not found. Call mongo.connect first.`);
  return entry;
}

/** Convert JS dates in filter/doc objects recursively so they BSON-encode properly */
function normalizeDoc(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj !== "object") return obj;
  if (obj instanceof Date || obj instanceof RegExp || Buffer.isBuffer(obj)) return obj;
  if (Array.isArray(obj)) return obj.map(normalizeDoc);
  const result: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    result[k] = normalizeDoc(v);
  }
  return result;
}

// Process cursor (firstBatch/nextBatch) from find/aggregate replies
function extractDocs(reply: Record<string, unknown>): unknown[] {
  const cursor = reply.cursor as Record<string, unknown> | undefined;
  if (!cursor) return [];
  const batch = (cursor.firstBatch || cursor.nextBatch) as unknown[];
  return batch || [];
}

// ─── Handlers ───────────────────────────────────────────────────────────────────

const connect: BuiltinHandler = async (args) => {
  const opts = (typeof args[0] === "object" && args[0] !== null ? args[0] : {}) as Record<string, unknown>;
  const name = String(opts.name ?? "default");
  const uri = String(opts.uri ?? opts.url ?? "mongodb://localhost:27017");
  const databaseOverride = opts.database ? String(opts.database) : undefined;

  const parsed = parseUri(uri);
  const database = databaseOverride ?? parsed.database;

  const socket = await createSocket(parsed.host, parsed.port, parsed.useTls);
  const conn: MongoConnection = {
    socket,
    database,
    pendingData: Buffer.alloc(0),
    pendingResolve: null,
  };
  setupSocket(conn);

  // Handshake: hello / ismaster
  await runCommand(conn, {
    hello: 1,
    client: {
      application: { name: "robinpath-mongo" },
      driver: { name: "robinpath-wire", version: "1.0.0" },
      os: { type: process.platform },
    },
  });

  // Authenticate if credentials provided
  if (parsed.username && parsed.password) {
    const authSource = parsed.options.authSource || parsed.database || "admin";
    await authenticateScramSha256(conn, parsed.username, parsed.password, authSource);
  }

  connections.set(name, conn);
  return { name, connected: true, database };
};

const find: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const filter = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const opts = (typeof args[2] === "object" && args[2] !== null ? args[2] : {}) as Record<string, unknown>;
  const name = String(args[3] ?? "default");
  const conn = getConn(name);

  const cmd: Record<string, unknown> = {
    find: collection,
    filter: normalizeDoc(filter),
  };
  if (opts.sort) cmd.sort = opts.sort;
  if (opts.limit) cmd.limit = Number(opts.limit);
  if (opts.skip) cmd.skip = Number(opts.skip);
  if (opts.projection) cmd.projection = opts.projection;

  const reply = await runCommand(conn, cmd);
  return extractDocs(reply);
};

const findOne: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const filter = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const name = String(args[2] ?? "default");
  const conn = getConn(name);

  const reply = await runCommand(conn, {
    find: collection,
    filter: normalizeDoc(filter),
    limit: 1,
    singleBatch: true,
  });

  const docs = extractDocs(reply);
  return docs.length > 0 ? docs[0] : null;
};

const insertOne: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const doc = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const name = String(args[2] ?? "default");
  const conn = getConn(name);

  // Generate _id if not present
  if (!doc._id) doc._id = generateObjectId();

  const reply = await runCommand(conn, {
    insert: collection,
    documents: [normalizeDoc(doc)],
  });

  return {
    insertedId: String(doc._id),
    acknowledged: reply.ok === 1 || reply.ok === true,
  };
};

const insertManyDocs: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const docs = (Array.isArray(args[1]) ? args[1] : []) as Record<string, unknown>[];
  const name = String(args[2] ?? "default");
  const conn = getConn(name);

  // Generate _id for each doc
  for (const doc of docs) {
    if (!doc._id) doc._id = generateObjectId();
  }

  const reply = await runCommand(conn, {
    insert: collection,
    documents: docs.map((d) => normalizeDoc(d)),
  });

  return {
    insertedCount: (reply.n as number) || docs.length,
    insertedIds: docs.map((d) => String(d._id)),
  };
};

const updateOne: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const filter = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const update = (typeof args[2] === "object" && args[2] !== null ? args[2] : {}) as Record<string, unknown>;
  const name = String(args[3] ?? "default");
  const conn = getConn(name);

  const op = update.$set || update.$unset || update.$inc ? update : { $set: update };

  const reply = await runCommand(conn, {
    update: collection,
    updates: [{ q: normalizeDoc(filter), u: normalizeDoc(op), multi: false }],
  });

  return {
    matchedCount: (reply.n as number) || 0,
    modifiedCount: (reply.nModified as number) ?? ((reply.n as number) || 0),
  };
};

const updateMany: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const filter = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const update = (typeof args[2] === "object" && args[2] !== null ? args[2] : {}) as Record<string, unknown>;
  const name = String(args[3] ?? "default");
  const conn = getConn(name);

  const op = update.$set || update.$unset || update.$inc ? update : { $set: update };

  const reply = await runCommand(conn, {
    update: collection,
    updates: [{ q: normalizeDoc(filter), u: normalizeDoc(op), multi: true }],
  });

  return {
    matchedCount: (reply.n as number) || 0,
    modifiedCount: (reply.nModified as number) ?? ((reply.n as number) || 0),
  };
};

const deleteOne: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const filter = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const name = String(args[2] ?? "default");
  const conn = getConn(name);

  const reply = await runCommand(conn, {
    delete: collection,
    deletes: [{ q: normalizeDoc(filter), limit: 1 }],
  });

  return { deletedCount: (reply.n as number) || 0 };
};

const deleteManyDocs: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const filter = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const name = String(args[2] ?? "default");
  const conn = getConn(name);

  const reply = await runCommand(conn, {
    delete: collection,
    deletes: [{ q: normalizeDoc(filter), limit: 0 }],
  });

  return { deletedCount: (reply.n as number) || 0 };
};

const aggregate: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const pipeline = (Array.isArray(args[1]) ? args[1] : []) as Record<string, unknown>[];
  const name = String(args[2] ?? "default");
  const conn = getConn(name);

  const reply = await runCommand(conn, {
    aggregate: collection,
    pipeline: pipeline.map((s) => normalizeDoc(s)),
    cursor: {},
  });

  return extractDocs(reply);
};

const countDocs: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const filter = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const name = String(args[2] ?? "default");
  const conn = getConn(name);

  const reply = await runCommand(conn, {
    count: collection,
    query: normalizeDoc(filter),
  });

  return (reply.n as number) || 0;
};

const distinct: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const field = String(args[1] ?? "");
  const filter = (typeof args[2] === "object" && args[2] !== null ? args[2] : {}) as Record<string, unknown>;
  const name = String(args[3] ?? "default");
  const conn = getConn(name);

  const reply = await runCommand(conn, {
    distinct: collection,
    key: field,
    query: normalizeDoc(filter),
  });

  return (reply.values as unknown[]) || [];
};

const collections: BuiltinHandler = async (args) => {
  const name = String(args[0] ?? "default");
  const conn = getConn(name);

  const reply = await runCommand(conn, {
    listCollections: 1,
    nameOnly: true,
  });

  const docs = extractDocs(reply);
  return docs.map((d: any) => d.name);
};

const createIndex: BuiltinHandler = async (args) => {
  const collection = String(args[0] ?? "");
  const keys = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, 1 | -1>;
  const opts = (typeof args[2] === "object" && args[2] !== null ? args[2] : {}) as Record<string, unknown>;
  const name = String(args[3] ?? "default");
  const conn = getConn(name);

  // Generate default index name from keys
  const indexName = opts.name
    ? String(opts.name)
    : Object.entries(keys)
        .map(([k, v]) => `${k}_${v}`)
        .join("_");

  const indexSpec: Record<string, unknown> = {
    key: keys,
    name: indexName,
    ...opts,
  };

  const reply = await runCommand(conn, {
    createIndexes: collection,
    indexes: [indexSpec],
  });

  return indexName;
};

const objectId: BuiltinHandler = (args) => {
  if (args[0]) {
    const id = String(args[0]);
    if (!isValidObjectId(id)) throw new Error(`Invalid ObjectId: ${id}`);
    return id;
  }
  return generateObjectId();
};

const close: BuiltinHandler = async (args) => {
  const name = String(args[0] ?? "default");
  const entry = connections.get(name);
  if (entry) {
    entry.socket.destroy();
    connections.delete(name);
  }
  return true;
};

const closeAll: BuiltinHandler = async () => {
  for (const [name, entry] of connections) {
    entry.socket.destroy();
    connections.delete(name);
  }
  return true;
};

// ─── Exports ────────────────────────────────────────────────────────────────────

export const MongoFunctions: Record<string, BuiltinHandler> = { connect, find, findOne, insertOne, insertMany: insertManyDocs, updateOne, updateMany, deleteOne, deleteMany: deleteManyDocs, aggregate, count: countDocs, distinct, collections, createIndex, objectId, close, closeAll };

export const MongoFunctionMetadata = {
  connect: { description: "Connect to MongoDB", parameters: [{ name: "options", dataType: "object", description: "{uri, database, name}", formInputType: "text", required: true }], returnType: "object", returnDescription: "{name, connected, database}", example: 'mongo.connect {"uri": "mongodb://localhost:27017", "database": "mydb"}' },
  find: { description: "Find documents", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "filter", dataType: "object", description: "Query filter", formInputType: "text", required: false }, { name: "options", dataType: "object", description: "{sort, limit, skip, projection}", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Documents", example: 'mongo.find "users" {"age": {"$gt": 18}} {"limit": 10}' },
  findOne: { description: "Find one document", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "filter", dataType: "object", description: "Query filter", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "Document or null", example: 'mongo.findOne "users" {"email": "alice@example.com"}' },
  insertOne: { description: "Insert one document", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "document", dataType: "object", description: "Document", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{insertedId, acknowledged}", example: 'mongo.insertOne "users" {"name": "Alice", "age": 30}' },
  insertMany: { description: "Insert multiple documents", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "documents", dataType: "array", description: "Documents", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{insertedCount, insertedIds}", example: 'mongo.insertMany "users" [{"name": "Alice"}, {"name": "Bob"}]' },
  updateOne: { description: "Update one document", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "filter", dataType: "object", description: "Query filter", formInputType: "text", required: true }, { name: "update", dataType: "object", description: "Update ops or fields", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{matchedCount, modifiedCount}", example: 'mongo.updateOne "users" {"_id": "..."} {"name": "Bob"}' },
  updateMany: { description: "Update many documents", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "filter", dataType: "object", description: "Query filter", formInputType: "text", required: true }, { name: "update", dataType: "object", description: "Update ops", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{matchedCount, modifiedCount}", example: 'mongo.updateMany "users" {"active": false} {"$set": {"archived": true}}' },
  deleteOne: { description: "Delete one document", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "filter", dataType: "object", description: "Query filter", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{deletedCount}", example: 'mongo.deleteOne "users" {"_id": "..."}' },
  deleteMany: { description: "Delete many documents", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "filter", dataType: "object", description: "Query filter", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{deletedCount}", example: 'mongo.deleteMany "users" {"archived": true}' },
  aggregate: { description: "Run aggregation pipeline", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "pipeline", dataType: "array", description: "Pipeline stages", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Results", example: 'mongo.aggregate "orders" [{"$group": {"_id": "$status", "count": {"$sum": 1}}}]' },
  count: { description: "Count documents", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "filter", dataType: "object", description: "Query filter", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "Count", example: 'mongo.count "users" {"active": true}' },
  distinct: { description: "Get distinct values", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "field", dataType: "string", description: "Field name", formInputType: "text", required: true }, { name: "filter", dataType: "object", description: "Query filter", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Distinct values", example: 'mongo.distinct "users" "country"' },
  collections: { description: "List collections", parameters: [{ name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Collection names", example: 'mongo.collections' },
  createIndex: { description: "Create index", parameters: [{ name: "collection", dataType: "string", description: "Collection", formInputType: "text", required: true }, { name: "keys", dataType: "object", description: "Index keys {field: 1|-1}", formInputType: "text", required: true }, { name: "options", dataType: "object", description: "{unique, sparse, ...}", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "string", returnDescription: "Index name", example: 'mongo.createIndex "users" {"email": 1} {"unique": true}' },
  objectId: { description: "Generate or parse ObjectId", parameters: [{ name: "id", dataType: "string", description: "Existing ID string or omit for new", formInputType: "text", required: false }], returnType: "string", returnDescription: "ObjectId string", example: 'mongo.objectId' },
  close: { description: "Close connection", parameters: [{ name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "true", example: 'mongo.close' },
  closeAll: { description: "Close all connections", parameters: [], returnType: "boolean", returnDescription: "true", example: 'mongo.closeAll' },
};

export const MongoModuleMetadata = {
  description: "MongoDB client with find, insert, update, delete, aggregation pipeline, indexing, and connection management",
  methods: ["connect", "find", "findOne", "insertOne", "insertMany", "updateOne", "updateMany", "deleteOne", "deleteMany", "aggregate", "count", "distinct", "collections", "createIndex", "objectId", "close", "closeAll"],
};
