// @ts-nocheck
import type { BuiltinHandler, FunctionMetadata, ModuleMetadata, Value } from "@wiredwp/robinpath";
import * as net from "node:net";
import * as tls from "node:tls";
import * as crypto from "node:crypto";

// ─── PostgreSQL Wire Protocol v3 Implementation ─────────────────────────────

interface PgConnection {
  socket: net.Socket | tls.TLSSocket;
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
  ssl: boolean;
  ready: boolean;
  buffer: Buffer;
  fieldDescriptions: FieldDescription[];
}

interface FieldDescription {
  name: string;
  tableOID: number;
  columnIndex: number;
  typeOID: number;
  typeSize: number;
  typeMod: number;
  format: number;
}

interface QueryResult {
  rows: Record<string, unknown>[];
  rowCount: number;
  command: string;
}

interface PgError extends Error {
  severity?: string;
  code?: string;
  detail?: string;
  hint?: string;
  position?: string;
}

// ─── Buffer Helpers ──────────────────────────────────────────────────────────

function writeInt32BE(buf: Buffer, value: number, offset: number): void {
  buf[offset] = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

function writeInt16BE(buf: Buffer, value: number, offset: number): void {
  buf[offset] = (value >>> 8) & 0xff;
  buf[offset + 1] = value & 0xff;
}

function readInt32BE(buf: Buffer, offset: number): number {
  return ((buf[offset]! << 24) | (buf[offset + 1]! << 16) | (buf[offset + 2]! << 8) | buf[offset + 3]!) >>> 0;
}

function readInt16BE(buf: Buffer, offset: number): number {
  return (buf[offset]! << 8) | buf[offset + 1]!;
}

function readCString(buf: Buffer, offset: number): { value: string; end: number } {
  let end = offset;
  while (end < buf.length && buf[end] !== 0) end++;
  return { value: buf.subarray(offset, end).toString("utf8"), end: end + 1 };
}

// ─── Message Building ────────────────────────────────────────────────────────

function buildStartupMessage(user: string, database: string): Buffer {
  const params = `user\0${user}\0database\0${database}\0\0`;
  const paramsBuf = Buffer.from(params, "utf8");
  const len = 4 + 4 + paramsBuf.length; // length + protocol version + params
  const buf = Buffer.alloc(len);
  writeInt32BE(buf, len, 0);
  // Protocol version 3.0
  writeInt16BE(buf, 3, 4);
  writeInt16BE(buf, 0, 6);
  paramsBuf.copy(buf, 8);
  return buf;
}

function buildSSLRequest(): Buffer {
  const buf = Buffer.alloc(8);
  writeInt32BE(buf, 8, 0);
  // SSL request code: 80877103
  writeInt32BE(buf, 80877103, 4);
  return buf;
}

function buildPasswordMessage(password: string): Buffer {
  const pwBuf = Buffer.from(password + "\0", "utf8");
  const len = 4 + pwBuf.length;
  const buf = Buffer.alloc(1 + len);
  buf[0] = 0x70; // 'p'
  writeInt32BE(buf, len, 1);
  pwBuf.copy(buf, 5);
  return buf;
}

function buildMD5PasswordMessage(user: string, password: string, salt: Buffer): Buffer {
  // md5(md5(password + user) + salt)
  const inner = crypto.createHash("md5").update(password + user).digest("hex");
  const outer = "md5" + crypto.createHash("md5").update(inner + salt.toString("binary"), "binary").digest("hex");
  return buildPasswordMessage(outer);
}

function buildQueryMessage(sql: string): Buffer {
  const sqlBuf = Buffer.from(sql + "\0", "utf8");
  const len = 4 + sqlBuf.length;
  const buf = Buffer.alloc(1 + len);
  buf[0] = 0x51; // 'Q'
  writeInt32BE(buf, len, 1);
  sqlBuf.copy(buf, 5);
  return buf;
}

function buildTerminateMessage(): Buffer {
  const buf = Buffer.alloc(5);
  buf[0] = 0x58; // 'X'
  writeInt32BE(buf, 4, 1);
  return buf;
}

// ─── Field Type Parsing (OID → JS value) ────────────────────────────────────

const OID_BOOL = 16;
const OID_INT2 = 21;
const OID_INT4 = 23;
const OID_INT8 = 20;
const OID_FLOAT4 = 700;
const OID_FLOAT8 = 701;
const OID_NUMERIC = 1700;
const OID_TEXT = 25;
const OID_VARCHAR = 1043;
const OID_CHAR = 18;
const OID_BPCHAR = 1042;
const OID_NAME = 19;
const OID_JSON = 114;
const OID_JSONB = 3802;
const OID_TIMESTAMP = 1114;
const OID_TIMESTAMPTZ = 1184;
const OID_DATE = 1082;
const OID_OID = 26;

function parseFieldValue(value: string | null, typeOID: number): unknown {
  if (value === null) return null;

  switch (typeOID) {
    case OID_BOOL:
      return value === "t" || value === "true" || value === "TRUE";
    case OID_INT2:
    case OID_INT4:
    case OID_OID:
      return parseInt(value, 10);
    case OID_INT8: {
      const n = BigInt(value);
      // Return number if safe, otherwise string to avoid precision loss
      if (n >= Number.MIN_SAFE_INTEGER && n <= Number.MAX_SAFE_INTEGER) return Number(n);
      return value;
    }
    case OID_FLOAT4:
    case OID_FLOAT8:
    case OID_NUMERIC:
      return parseFloat(value);
    case OID_JSON:
    case OID_JSONB:
      try { return JSON.parse(value); } catch { return value; }
    case OID_TIMESTAMP:
    case OID_TIMESTAMPTZ:
    case OID_DATE:
      return value; // Return as ISO string
    default:
      return value;
  }
}

// ─── Error Parsing ───────────────────────────────────────────────────────────

function parseErrorResponse(buf: Buffer, offset: number, end: number): PgError {
  const fields: Record<string, string> = {};
  let pos = offset;
  while (pos < end) {
    const fieldType = buf[pos]!;
    pos++;
    if (fieldType === 0) break;
    const str = readCString(buf, pos);
    pos = str.end;
    const code = String.fromCharCode(fieldType);
    fields[code] = str.value;
  }
  const err = new Error(fields["M"] || "Unknown PostgreSQL error") as PgError;
  err.severity = fields["S"] || fields["V"];
  err.code = fields["C"];
  err.detail = fields["D"];
  err.hint = fields["H"];
  err.position = fields["P"];
  return err;
}

// ─── Connection Management ───────────────────────────────────────────────────

const connections = new Map<string, PgConnection>();

function getConn(name: string): PgConnection {
  const conn = connections.get(name);
  if (!conn) throw new Error(`PostgreSQL connection "${name}" not found. Call postgres.connect first.`);
  return conn;
}

function waitForData(socket: net.Socket | tls.TLSSocket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const onData = (data: Buffer) => {
      socket.removeListener("error", onError);
      resolve(data);
    };
    const onError = (err: Error) => {
      socket.removeListener("data", onData);
      reject(err);
    };
    socket.once("data", onData);
    socket.once("error", onError);
  });
}

/**
 * Reads complete PG messages from the socket. Accumulates partial data
 * and returns all collected buffers once we have at least one complete message.
 */
async function readMessages(conn: PgConnection): Promise<Buffer> {
  // If we already have enough data for at least one full message, return it
  while (true) {
    if (conn.buffer.length >= 5) {
      const msgLen = readInt32BE(conn.buffer, 1) + 1; // type byte + length
      if (conn.buffer.length >= msgLen) {
        return conn.buffer;
      }
    }
    const data = await waitForData(conn.socket);
    conn.buffer = Buffer.concat([conn.buffer, data]);
  }
}

/**
 * Consume one message from the connection buffer.
 * Returns { type, payload } or null if not enough data.
 */
function consumeMessage(conn: PgConnection): { type: number; payload: Buffer } | null {
  if (conn.buffer.length < 5) return null;
  const type = conn.buffer[0]!;
  const len = readInt32BE(conn.buffer, 1);
  const totalLen = 1 + len;
  if (conn.buffer.length < totalLen) return null;
  const payload = conn.buffer.subarray(5, totalLen);
  conn.buffer = conn.buffer.subarray(totalLen);
  return { type, payload };
}

/**
 * Ensure we can consume at least one message, reading from socket if needed.
 */
async function ensureMessage(conn: PgConnection): Promise<{ type: number; payload: Buffer }> {
  while (true) {
    const msg = consumeMessage(conn);
    if (msg) return msg;
    const data = await waitForData(conn.socket);
    conn.buffer = Buffer.concat([conn.buffer, data]);
  }
}

// ─── Authentication ──────────────────────────────────────────────────────────

async function authenticate(conn: PgConnection): Promise<void> {
  // Send startup message
  conn.socket.write(buildStartupMessage(conn.user, conn.database));

  while (true) {
    const msg = await ensureMessage(conn);
    const type = msg.type;

    // 'R' = Authentication
    if (type === 0x52) {
      const authType = readInt32BE(msg.payload, 0);
      if (authType === 0) {
        // AuthenticationOk
        continue;
      } else if (authType === 5) {
        // AuthenticationMD5Password
        const salt = msg.payload.subarray(4, 8);
        conn.socket.write(buildMD5PasswordMessage(conn.user, conn.password, salt));
        continue;
      } else if (authType === 3) {
        // AuthenticationCleartextPassword
        conn.socket.write(buildPasswordMessage(conn.password));
        continue;
      } else if (authType === 10) {
        // AuthenticationSASL (SCRAM-SHA-256)
        await handleSCRAMAuth(conn, msg.payload);
        continue;
      } else {
        throw new Error(`Unsupported authentication type: ${authType}`);
      }
    }

    // 'E' = ErrorResponse
    if (type === 0x45) {
      throw parseErrorResponse(msg.payload, 0, msg.payload.length);
    }

    // 'K' = BackendKeyData - ignore
    if (type === 0x4b) continue;

    // 'S' = ParameterStatus - ignore
    if (type === 0x53) continue;

    // 'Z' = ReadyForQuery
    if (type === 0x5a) {
      conn.ready = true;
      return;
    }

    // 'N' = NoticeResponse - ignore
    if (type === 0x4e) continue;
  }
}

// ─── SCRAM-SHA-256 Authentication ────────────────────────────────────────────

async function handleSCRAMAuth(conn: PgConnection, payload: Buffer): Promise<void> {
  // payload contains mechanism list (null-terminated strings followed by empty string)
  // We need SCRAM-SHA-256
  let pos = 4; // skip authType already read
  let hasSCRAM = false;
  while (pos < payload.length) {
    const str = readCString(payload, pos);
    pos = str.end;
    if (str.value === "SCRAM-SHA-256") hasSCRAM = true;
    if (str.value === "") break;
  }
  if (!hasSCRAM) throw new Error("Server requires SCRAM authentication but SCRAM-SHA-256 not offered");

  // Generate client nonce
  const clientNonce = crypto.randomBytes(18).toString("base64");
  const clientFirstBare = `n=*,r=${clientNonce}`;
  const clientFirstMessage = `n,,${clientFirstBare}`;

  // Send SASLInitialResponse
  const mechanism = Buffer.from("SCRAM-SHA-256\0", "utf8");
  const clientFirstBuf = Buffer.from(clientFirstMessage, "utf8");
  const saslLen = 4 + mechanism.length + 4 + clientFirstBuf.length;
  const saslBuf = Buffer.alloc(1 + saslLen);
  saslBuf[0] = 0x70; // 'p'
  writeInt32BE(saslBuf, saslLen, 1);
  mechanism.copy(saslBuf, 5);
  writeInt32BE(saslBuf, clientFirstBuf.length, 5 + mechanism.length);
  clientFirstBuf.copy(saslBuf, 5 + mechanism.length + 4);
  conn.socket.write(saslBuf);

  // Read AuthenticationSASLContinue (type 11)
  const msg2 = await ensureMessage(conn);
  if (msg2.type !== 0x52) throw new Error("Expected Authentication message during SCRAM");
  const authType2 = readInt32BE(msg2.payload, 0);
  if (authType2 !== 11) throw new Error(`Expected AuthenticationSASLContinue (11), got ${authType2}`);

  const serverFirstMessage = msg2.payload.subarray(4).toString("utf8");
  const serverFields: Record<string, string> = {};
  for (const part of serverFirstMessage.split(",")) {
    const eq = part.indexOf("=");
    if (eq > 0) serverFields[part.substring(0, eq)] = part.substring(eq + 1);
  }

  const serverNonce = serverFields["r"]!;
  const salt = Buffer.from(serverFields["s"]!, "base64");
  const iterations = parseInt(serverFields["i"]!, 10);

  if (!serverNonce.startsWith(clientNonce)) {
    throw new Error("Server nonce does not start with client nonce");
  }

  // Derive keys
  const saltedPassword = crypto.pbkdf2Sync(conn.password, salt, iterations, 32, "sha256");
  const clientKey = crypto.createHmac("sha256", saltedPassword).update("Client Key").digest();
  const storedKey = crypto.createHash("sha256").update(clientKey).digest();

  const clientFinalNoProof = `c=biws,r=${serverNonce}`;
  const authMessage = `${clientFirstBare},${serverFirstMessage},${clientFinalNoProof}`;

  const clientSignature = crypto.createHmac("sha256", storedKey).update(authMessage).digest();
  const proof = Buffer.alloc(clientKey.length);
  for (let i = 0; i < clientKey.length; i++) {
    proof[i] = clientKey[i]! ^ clientSignature[i]!;
  }

  const serverKey = crypto.createHmac("sha256", saltedPassword).update("Server Key").digest();
  const expectedServerSignature = crypto.createHmac("sha256", serverKey).update(authMessage).digest();

  const clientFinalMessage = `${clientFinalNoProof},p=${proof.toString("base64")}`;

  // Send SASLResponse
  const clientFinalBuf = Buffer.from(clientFinalMessage, "utf8");
  const respLen = 4 + clientFinalBuf.length;
  const respBuf = Buffer.alloc(1 + respLen);
  respBuf[0] = 0x70; // 'p'
  writeInt32BE(respBuf, respLen, 1);
  clientFinalBuf.copy(respBuf, 5);
  conn.socket.write(respBuf);

  // Read AuthenticationSASLFinal (type 12)
  const msg3 = await ensureMessage(conn);
  if (msg3.type !== 0x52) throw new Error("Expected Authentication message during SCRAM final");
  const authType3 = readInt32BE(msg3.payload, 0);
  if (authType3 !== 12) throw new Error(`Expected AuthenticationSASLFinal (12), got ${authType3}`);

  const serverFinalMessage = msg3.payload.subarray(4).toString("utf8");
  const serverFinalFields: Record<string, string> = {};
  for (const part of serverFinalMessage.split(",")) {
    const eq = part.indexOf("=");
    if (eq > 0) serverFinalFields[part.substring(0, eq)] = part.substring(eq + 1);
  }

  if (serverFinalFields["v"]) {
    const serverSignature = Buffer.from(serverFinalFields["v"], "base64");
    if (!serverSignature.equals(expectedServerSignature)) {
      throw new Error("Server signature mismatch during SCRAM authentication");
    }
  }

  // After SCRAM, expect AuthenticationOk (type 0)
  const msg4 = await ensureMessage(conn);
  if (msg4.type === 0x52) {
    const authType4 = readInt32BE(msg4.payload, 0);
    if (authType4 !== 0) throw new Error(`Expected AuthenticationOk after SCRAM, got ${authType4}`);
  }
}

// ─── SSL Upgrade ─────────────────────────────────────────────────────────────

async function upgradeToSSL(rawSocket: net.Socket, host: string): Promise<tls.TLSSocket> {
  rawSocket.write(buildSSLRequest());
  const response = await waitForData(rawSocket);
  if (response[0] === 0x53) {
    // 'S' = server supports SSL
    return new Promise((resolve, reject) => {
      const tlsSocket = tls.connect({
        socket: rawSocket,
        servername: host,
        rejectUnauthorized: false,
      }, () => {
        resolve(tlsSocket);
      });
      tlsSocket.once("error", reject);
    });
  }
  throw new Error("Server does not support SSL");
}

// ─── Connect ─────────────────────────────────────────────────────────────────

async function createConnection(opts: {
  host: string;
  port: number;
  user: string;
  password: string;
  database: string;
  ssl: boolean;
}): Promise<PgConnection> {
  return new Promise((resolve, reject) => {
    const rawSocket = net.createConnection({ host: opts.host, port: opts.port }, async () => {
      try {
        let socket: net.Socket | tls.TLSSocket = rawSocket;
        if (opts.ssl) {
          socket = await upgradeToSSL(rawSocket, opts.host);
        }
        const conn: PgConnection = {
          socket,
          host: opts.host,
          port: opts.port,
          user: opts.user,
          password: opts.password,
          database: opts.database,
          ssl: opts.ssl,
          ready: false,
          buffer: Buffer.alloc(0),
          fieldDescriptions: [],
        };
        await authenticate(conn);
        resolve(conn);
      } catch (err) {
        rawSocket.destroy();
        reject(err);
      }
    });
    rawSocket.once("error", reject);
  });
}

// ─── Simple Query Protocol ───────────────────────────────────────────────────

async function executeQuery(conn: PgConnection, sql: string): Promise<QueryResult> {
  conn.socket.write(buildQueryMessage(sql));

  const rows: Record<string, unknown>[] = [];
  let fields: FieldDescription[] = [];
  let command = "";
  let rowCount = 0;

  while (true) {
    const msg = await ensureMessage(conn);
    const type = msg.type;

    // 'T' = RowDescription
    if (type === 0x54) {
      const numFields = readInt16BE(msg.payload, 0);
      fields = [];
      let pos = 2;
      for (let i = 0; i < numFields; i++) {
        const nameStr = readCString(msg.payload, pos);
        pos = nameStr.end;
        const tableOID = readInt32BE(msg.payload, pos); pos += 4;
        const columnIndex = readInt16BE(msg.payload, pos); pos += 2;
        const typeOID = readInt32BE(msg.payload, pos); pos += 4;
        const typeSize = readInt16BE(msg.payload, pos); pos += 2;
        const typeMod = readInt32BE(msg.payload, pos); pos += 4;
        const format = readInt16BE(msg.payload, pos); pos += 2;
        fields.push({ name: nameStr.value, tableOID, columnIndex, typeOID, typeSize, typeMod, format });
      }
      continue;
    }

    // 'D' = DataRow
    if (type === 0x44) {
      const numColumns = readInt16BE(msg.payload, 0);
      const row: Record<string, unknown> = {};
      let pos = 2;
      for (let i = 0; i < numColumns; i++) {
        const colLen = readInt32BE(msg.payload, pos) | 0; // signed
        pos += 4;
        if (colLen === -1) {
          // NULL
          row[fields[i]?.name ?? `col${i}`] = null;
        } else {
          const valStr = msg.payload.subarray(pos, pos + colLen).toString("utf8");
          pos += colLen;
          const field = fields[i];
          row[field?.name ?? `col${i}`] = field ? parseFieldValue(valStr, field.typeOID) : valStr;
        }
      }
      rows.push(row);
      continue;
    }

    // 'C' = CommandComplete
    if (type === 0x43) {
      const cmdStr = readCString(msg.payload, 0).value;
      command = cmdStr;
      // Parse row count from command tag (e.g. "INSERT 0 1", "UPDATE 5", "DELETE 3", "SELECT 10")
      const parts = cmdStr.split(" ");
      const lastPart = parts[parts.length - 1];
      if (lastPart && /^\d+$/.test(lastPart)) {
        rowCount = parseInt(lastPart, 10);
      }
      continue;
    }

    // 'Z' = ReadyForQuery
    if (type === 0x5a) {
      conn.ready = true;
      return { rows, rowCount, command };
    }

    // 'E' = ErrorResponse
    if (type === 0x45) {
      // After error, still need to read until ReadyForQuery
      const err = parseErrorResponse(msg.payload, 0, msg.payload.length);
      // Drain until ReadyForQuery
      while (true) {
        const next = await ensureMessage(conn);
        if (next.type === 0x5a) {
          conn.ready = true;
          break;
        }
      }
      throw err;
    }

    // 'N' = NoticeResponse - ignore
    if (type === 0x4e) continue;

    // 'I' = EmptyQueryResponse
    if (type === 0x49) continue;
  }
}

// ─── Parameterized Query (via simple query with escaped params) ──────────────

function escapeParam(value: unknown): string {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Cannot use non-finite number as parameter");
    return String(value);
  }
  if (typeof value === "boolean") return value ? "TRUE" : "FALSE";
  if (typeof value === "object") {
    return `'${escapeString(JSON.stringify(value))}'`;
  }
  return `'${escapeString(String(value))}'`;
}

function escapeString(str: string): string {
  return str.replace(/'/g, "''").replace(/\\/g, "\\\\");
}

function interpolateParams(sql: string, params: unknown[]): string {
  if (!params || params.length === 0) return sql;
  let idx = 0;
  return sql.replace(/\$(\d+)/g, (_, numStr) => {
    const num = parseInt(numStr, 10) - 1;
    if (num < 0 || num >= params.length) return `$${numStr}`;
    return escapeParam(params[num]);
  });
}

// ─── Connection Pool (simple: one connection per name) ───────────────────────

interface PoolEntry {
  connections: PgConnection[];
  opts: { host: string; port: number; user: string; password: string; database: string; ssl: boolean };
  max: number;
  available: PgConnection[];
  waiters: ((conn: PgConnection) => void)[];
}

const pools = new Map<string, PoolEntry>();

async function acquireConnection(name: string): Promise<PgConnection> {
  const pool = pools.get(name);
  if (!pool) throw new Error(`PostgreSQL connection "${name}" not found. Call postgres.connect first.`);

  // Return available connection
  if (pool.available.length > 0) {
    return pool.available.pop()!;
  }

  // Create new if under max
  if (pool.connections.length < pool.max) {
    const conn = await createConnection(pool.opts);
    pool.connections.push(conn);
    return conn;
  }

  // Wait for one to be released
  return new Promise<PgConnection>((resolve) => {
    pool.waiters.push(resolve);
  });
}

function releaseConnection(name: string, conn: PgConnection): void {
  const pool = pools.get(name);
  if (!pool) return;
  if (pool.waiters.length > 0) {
    const waiter = pool.waiters.shift()!;
    waiter(conn);
  } else {
    pool.available.push(conn);
  }
}

async function poolQuery(name: string, sql: string, params?: unknown[]): Promise<QueryResult> {
  const interpolatedSQL = interpolateParams(sql, params ?? []);
  const conn = await acquireConnection(name);
  try {
    const result = await executeQuery(conn, interpolatedSQL);
    return result;
  } finally {
    releaseConnection(name, conn);
  }
}

// ─── Handlers ────────────────────────────────────────────────────────────────

const connect: BuiltinHandler = async (args) => {
  const opts = (typeof args[0] === "object" && args[0] !== null ? args[0] : {}) as Record<string, unknown>;
  const name = String(opts.name ?? "default");
  const host = String(opts.host ?? "localhost");
  const port = Number(opts.port ?? 5432);
  const user = String(opts.user ?? "postgres");
  const password = opts.password ? String(opts.password) : "";
  const database = opts.database ? String(opts.database) : user;
  const max = Number(opts.max ?? 10);
  const ssl = opts.ssl === true;

  const connOpts = { host, port, user, password, database, ssl };

  // Create initial connection to verify connectivity
  const conn = await createConnection(connOpts);

  const pool: PoolEntry = {
    connections: [conn],
    opts: connOpts,
    max,
    available: [conn],
    waiters: [],
  };

  pools.set(name, pool);
  return { name, connected: true };
};

const query: BuiltinHandler = async (args) => {
  const sql = String(args[0] ?? "");
  const params = Array.isArray(args[1]) ? args[1] : [];
  const name = String(args[2] ?? "default");
  const result = await poolQuery(name, sql, params);
  return result.rows;
};

const queryOne: BuiltinHandler = async (args) => {
  const sql = String(args[0] ?? "");
  const params = Array.isArray(args[1]) ? args[1] : [];
  const name = String(args[2] ?? "default");
  const result = await poolQuery(name, sql, params);
  return result.rows[0] ?? null;
};

const insert: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const data = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const name = String(args[2] ?? "default");
  const keys = Object.keys(data);
  const placeholders = keys.map((_, i) => `$${i + 1}`).join(", ");
  const sql = `INSERT INTO ${table} (${keys.join(", ")}) VALUES (${placeholders}) RETURNING *`;
  const result = await poolQuery(name, sql, Object.values(data));
  return result.rows[0];
};

const insertMany: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const rows = (Array.isArray(args[1]) ? args[1] : []) as Record<string, unknown>[];
  const name = String(args[2] ?? "default");
  if (rows.length === 0) return [];
  const keys = Object.keys(rows[0]!);
  const values: unknown[] = [];
  const placeholderRows = rows.map((row: any, ri: any) => {
    const ph = keys.map((k: any, ki: any) => { values.push(row[k]); return `$${ri * keys.length + ki + 1}`; });
    return `(${ph.join(", ")})`;
  });
  const sql = `INSERT INTO ${table} (${keys.join(", ")}) VALUES ${placeholderRows.join(", ")} RETURNING *`;
  const result = await poolQuery(name, sql, values);
  return result.rows;
};

const update: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const data = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const where = String(args[2] ?? "1=0");
  const whereParams = Array.isArray(args[3]) ? args[3] : [];
  const name = String(args[4] ?? "default");
  const keys = Object.keys(data);
  const vals = Object.values(data);
  const sets = keys.map((k, i) => `${k} = $${i + 1}`).join(", ");
  const adjustedWhere = where.replace(/\$(\d+)/g, (_, n) => `$${Number(n) + keys.length}`);
  const sql = `UPDATE ${table} SET ${sets} WHERE ${adjustedWhere} RETURNING *`;
  const result = await poolQuery(name, sql, [...vals, ...whereParams]);
  return { affectedRows: result.rowCount, rows: result.rows };
};

const remove: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const where = String(args[1] ?? "1=0");
  const params = Array.isArray(args[2]) ? args[2] : [];
  const name = String(args[3] ?? "default");
  const sql = `DELETE FROM ${table} WHERE ${where} RETURNING *`;
  const result = await poolQuery(name, sql, params);
  return { affectedRows: result.rowCount, rows: result.rows };
};

const transaction: BuiltinHandler = async (args) => {
  const queries = (Array.isArray(args[0]) ? args[0] : []) as { sql: string; params?: unknown[] }[];
  const name = String(args[1] ?? "default");
  const conn = await acquireConnection(name);
  try {
    await executeQuery(conn, "BEGIN");
    const results: unknown[] = [];
    for (const q of queries) {
      const interpolated = interpolateParams(q.sql, q.params ?? []);
      const res = await executeQuery(conn, interpolated);
      results.push(res.rows);
    }
    await executeQuery(conn, "COMMIT");
    return { success: true, results };
  } catch (err) {
    try { await executeQuery(conn, "ROLLBACK"); } catch { /* ignore rollback errors */ }
    throw err;
  } finally {
    releaseConnection(name, conn);
  }
};

const tables: BuiltinHandler = async (args) => {
  const schema = String(args[0] ?? "public");
  const name = String(args[1] ?? "default");
  const result = await poolQuery(name, "SELECT table_name FROM information_schema.tables WHERE table_schema = $1 ORDER BY table_name", [schema]);
  return result.rows.map((r: Record<string, string>) => r.table_name);
};

const describe: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const name = String(args[1] ?? "default");
  const result = await poolQuery(name, "SELECT column_name, data_type, is_nullable, column_default FROM information_schema.columns WHERE table_name = $1 ORDER BY ordinal_position", [table]);
  return result.rows;
};

const count: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const where = args[1] ? `WHERE ${String(args[1])}` : "";
  const params = Array.isArray(args[2]) ? args[2] : [];
  const name = String(args[3] ?? "default");
  const result = await poolQuery(name, `SELECT COUNT(*)::int as count FROM ${table} ${where}`, params);
  return result.rows[0]?.count ?? 0;
};

const listen: BuiltinHandler = async (args) => {
  const channel = String(args[0] ?? "");
  const name = String(args[1] ?? "default");
  // LISTEN requires a dedicated connection (not returned to pool)
  const pool = pools.get(name);
  if (!pool) throw new Error(`PostgreSQL connection "${name}" not found. Call postgres.connect first.`);
  const conn = await createConnection(pool.opts);
  await executeQuery(conn, `LISTEN ${channel}`);
  // Keep connection alive for notifications (don't release to pool)
  return { channel, listening: true };
};

const close: BuiltinHandler = async (args) => {
  const name = String(args[0] ?? "default");
  const pool = pools.get(name);
  if (pool) {
    for (const conn of pool.connections) {
      try {
        conn.socket.write(buildTerminateMessage());
        conn.socket.destroy();
      } catch { /* ignore */ }
    }
    for (const conn of pool.available) {
      try {
        conn.socket.write(buildTerminateMessage());
        conn.socket.destroy();
      } catch { /* ignore */ }
    }
    pools.delete(name);
  }
  return true;
};

const closeAll: BuiltinHandler = async () => {
  for (const [name] of pools) {
    const pool = pools.get(name);
    if (pool) {
      for (const conn of pool.connections) {
        try {
          conn.socket.write(buildTerminateMessage());
          conn.socket.destroy();
        } catch { /* ignore */ }
      }
    }
    pools.delete(name);
  }
  return true;
};

// ─── Exports ─────────────────────────────────────────────────────────────────

export const PostgresFunctions: Record<string, BuiltinHandler> = { connect, query, queryOne, insert, insertMany, update, remove, transaction, tables, describe, count, listen, close, closeAll };

export const PostgresFunctionMetadata = {
  connect: { description: "Connect to PostgreSQL", parameters: [{ name: "options", dataType: "object", description: "{host, port, user, password, database, name, max, ssl}", formInputType: "text", required: true }], returnType: "object", returnDescription: "{name, connected}", example: 'postgres.connect {"host": "localhost", "user": "postgres", "database": "mydb"}' },
  query: { description: "Execute SQL query", parameters: [{ name: "sql", dataType: "string", description: "SQL with $1 params", formInputType: "text", required: true }, { name: "params", dataType: "array", description: "Parameters", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Result rows", example: 'postgres.query "SELECT * FROM users WHERE id = $1" [1]' },
  queryOne: { description: "Execute query returning single row", parameters: [{ name: "sql", dataType: "string", description: "SQL", formInputType: "text", required: true }, { name: "params", dataType: "array", description: "Parameters", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "Single row or null", example: 'postgres.queryOne "SELECT * FROM users WHERE id = $1" [1]' },
  insert: { description: "Insert row with RETURNING", parameters: [{ name: "table", dataType: "string", description: "Table", formInputType: "text", required: true }, { name: "data", dataType: "object", description: "Column values", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "Inserted row", example: 'postgres.insert "users" {"name": "Alice"}' },
  insertMany: { description: "Insert multiple rows", parameters: [{ name: "table", dataType: "string", description: "Table", formInputType: "text", required: true }, { name: "rows", dataType: "array", description: "Row objects", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Inserted rows", example: 'postgres.insertMany "users" [{"name": "Alice"}, {"name": "Bob"}]' },
  update: { description: "Update rows with RETURNING", parameters: [{ name: "table", dataType: "string", description: "Table", formInputType: "text", required: true }, { name: "data", dataType: "object", description: "Columns to update", formInputType: "text", required: true }, { name: "where", dataType: "string", description: "WHERE clause", formInputType: "text", required: true }, { name: "params", dataType: "array", description: "WHERE params", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{affectedRows, rows}", example: 'postgres.update "users" {"name": "Bob"} "id = $1" [1]' },
  remove: { description: "Delete rows with RETURNING", parameters: [{ name: "table", dataType: "string", description: "Table", formInputType: "text", required: true }, { name: "where", dataType: "string", description: "WHERE clause", formInputType: "text", required: true }, { name: "params", dataType: "array", description: "WHERE params", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{affectedRows, rows}", example: 'postgres.remove "users" "id = $1" [1]' },
  transaction: { description: "Execute in transaction", parameters: [{ name: "queries", dataType: "array", description: "Array of {sql, params}", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{success, results}", example: 'postgres.transaction [{"sql": "INSERT INTO users (name) VALUES ($1)", "params": ["Alice"]}]' },
  tables: { description: "List tables in schema", parameters: [{ name: "schema", dataType: "string", description: "Schema (default public)", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Table names", example: 'postgres.tables "public"' },
  describe: { description: "Describe table columns", parameters: [{ name: "table", dataType: "string", description: "Table", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Column definitions", example: 'postgres.describe "users"' },
  count: { description: "Count rows", parameters: [{ name: "table", dataType: "string", description: "Table", formInputType: "text", required: true }, { name: "where", dataType: "string", description: "WHERE clause", formInputType: "text", required: false }, { name: "params", dataType: "array", description: "WHERE params", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "Count", example: 'postgres.count "users"' },
  listen: { description: "Listen for NOTIFY events", parameters: [{ name: "channel", dataType: "string", description: "Channel name", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{channel, listening}", example: 'postgres.listen "events"' },
  close: { description: "Close connection pool", parameters: [{ name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "true", example: 'postgres.close' },
  closeAll: { description: "Close all pools", parameters: [], returnType: "boolean", returnDescription: "true", example: 'postgres.closeAll' },
};

export const PostgresModuleMetadata = {
  description: "PostgreSQL client with connection pooling, parameterized queries, transactions, RETURNING, and LISTEN/NOTIFY",
  methods: ["connect", "query", "queryOne", "insert", "insertMany", "update", "remove", "transaction", "tables", "describe", "count", "listen", "close", "closeAll"],
};
