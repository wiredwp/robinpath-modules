// @ts-nocheck
import type { BuiltinHandler, FunctionMetadata, ModuleMetadata, Value } from "@wiredwp/robinpath";
import * as net from "node:net";
import * as tls from "node:tls";
import * as crypto from "node:crypto";

// ─── MySQL Wire Protocol Constants ───────────────────────────────────────────

const COM_QUERY = 0x03;
const COM_QUIT = 0x01;

const CLIENT_LONG_PASSWORD = 0x00000001;
const CLIENT_FOUND_ROWS = 0x00000002;
const CLIENT_LONG_FLAG = 0x00000004;
const CLIENT_CONNECT_WITH_DB = 0x00000008;
const CLIENT_PROTOCOL_41 = 0x00000200;
const CLIENT_TRANSACTIONS = 0x00002000;
const CLIENT_SECURE_CONNECTION = 0x00008000;
const CLIENT_PLUGIN_AUTH = 0x00080000;
const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000;
const CLIENT_DEPRECATE_EOF = 0x01000000;
const CLIENT_SSL = 0x00000800;

const CHARSET_UTF8MB4 = 45; // utf8mb4_general_ci

const OK_PACKET = 0x00;
const ERR_PACKET = 0xff;
const EOF_PACKET = 0xfe;
const LOCAL_INFILE_PACKET = 0xfb;

// ─── Buffer helpers ──────────────────────────────────────────────────────────

function readLenencInt(buf: Buffer, offset: number): { value: number; newOffset: number } {
  const first = buf[offset]!;
  if (first < 0xfb) return { value: first, newOffset: offset + 1 };
  if (first === 0xfb) return { value: -1, newOffset: offset + 1 }; // NULL
  if (first === 0xfc) return { value: buf.readUInt16LE(offset + 1), newOffset: offset + 3 };
  if (first === 0xfd) return { value: buf.readUIntLE(offset + 1, 3), newOffset: offset + 4 };
  // 0xfe
  // JS can't precisely handle 8-byte ints, but for row counts this is fine
  const lo = buf.readUInt32LE(offset + 1);
  const hi = buf.readUInt32LE(offset + 5);
  return { value: hi * 0x100000000 + lo, newOffset: offset + 9 };
}

function readLenencString(buf: Buffer, offset: number): { value: string | null; newOffset: number } {
  const { value: len, newOffset } = readLenencInt(buf, offset);
  if (len === -1) return { value: null, newOffset };
  return { value: buf.toString("utf8", newOffset, newOffset + len), newOffset: newOffset + len };
}

function readNullTermString(buf: Buffer, offset: number): { value: string; newOffset: number } {
  const end = buf.indexOf(0x00, offset);
  return { value: buf.toString("utf8", offset, end), newOffset: end + 1 };
}

function writeLenencInt(value: number): Buffer {
  if (value < 0xfb) {
    const b = Buffer.alloc(1);
    b[0] = value;
    return b;
  }
  if (value <= 0xffff) {
    const b = Buffer.alloc(3);
    b[0] = 0xfc;
    b.writeUInt16LE(value, 1);
    return b;
  }
  if (value <= 0xffffff) {
    const b = Buffer.alloc(4);
    b[0] = 0xfd;
    b.writeUIntLE(value, 1, 3);
    return b;
  }
  const b = Buffer.alloc(9);
  b[0] = 0xfe;
  b.writeUInt32LE(value >>> 0, 1);
  b.writeUInt32LE(Math.floor(value / 0x100000000), 5);
  return b;
}

function writeLenencString(str: string): Buffer {
  const strBuf = Buffer.from(str, "utf8");
  return Buffer.concat([writeLenencInt(strBuf.length), strBuf]);
}

// ─── Packet framing ─────────────────────────────────────────────────────────

function buildPacket(sequenceId: number, payload: Buffer): Buffer {
  const header = Buffer.alloc(4);
  header.writeUIntLE(payload.length, 0, 3);
  header[3] = sequenceId & 0xff;
  return Buffer.concat([header, payload]);
}

// ─── Authentication ──────────────────────────────────────────────────────────

function mysqlNativePasswordAuth(password: string, scramble: Buffer): Buffer {
  if (!password) return Buffer.alloc(0);
  // SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))
  const sha1pass = crypto.createHash("sha1").update(password).digest();
  const sha1sha1pass = crypto.createHash("sha1").update(sha1pass).digest();
  const combined = crypto.createHash("sha1").update(Buffer.concat([scramble, sha1sha1pass])).digest();
  const result = Buffer.alloc(20);
  for (let i = 0; i < 20; i++) {
    result[i] = sha1pass[i]! ^ combined[i]!;
  }
  return result;
}

// ─── Connection class ────────────────────────────────────────────────────────

interface MysqlConnectionOpts {
  host: string;
  port: number;
  user: string;
  password?: string;
  database?: string;
  charset?: number;
  ssl?: boolean;
}

interface ServerGreeting {
  protocolVersion: number;
  serverVersion: string;
  connectionId: number;
  authPluginData: Buffer;
  capabilityFlags: number;
  characterSet: number;
  statusFlags: number;
  authPluginName: string;
}

interface ColumnDef {
  catalog: string;
  schema: string;
  tableAlias: string;
  table: string;
  columnAlias: string;
  column: string;
  characterSet: number;
  maxColumnSize: number;
  columnType: number;
  flags: number;
  decimals: number;
}

interface OkResult {
  type: "ok";
  affectedRows: number;
  insertId: number;
  statusFlags: number;
  warnings: number;
  info: string;
}

class MysqlConnection {
  private socket: net.Socket | tls.TLSSocket;
  private buffer: Buffer = Buffer.alloc(0);
  private sequenceId = 0;
  private opts: MysqlConnectionOpts;
  private greeting: ServerGreeting | null = null;
  private serverCapabilities = 0;
  private useDeprecateEof = false;

  // packet reading promise chain
  private pendingResolve: ((pkt: Buffer) => void) | null = null;
  private pendingReject: ((err: Error) => void) | null = null;
  private packetQueue: Buffer[] = [];
  private socketError: Error | null = null;

  constructor(opts: MysqlConnectionOpts) {
    this.opts = opts;
    this.socket = new net.Socket();
  }

  async connect(): Promise<void> {
    await this._tcpConnect();
    this._setupDataHandler();

    // Read server greeting
    const greetingPkt = await this._readPacket();
    this.greeting = this._parseGreeting(greetingPkt);
    this.serverCapabilities = this.greeting.capabilityFlags;

    // Build capability flags
    let clientFlags =
      CLIENT_LONG_PASSWORD |
      CLIENT_FOUND_ROWS |
      CLIENT_LONG_FLAG |
      CLIENT_PROTOCOL_41 |
      CLIENT_TRANSACTIONS |
      CLIENT_SECURE_CONNECTION |
      CLIENT_PLUGIN_AUTH |
      CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;

    if (this.opts.database) clientFlags |= CLIENT_CONNECT_WITH_DB;
    if (this.serverCapabilities & CLIENT_DEPRECATE_EOF) {
      clientFlags |= CLIENT_DEPRECATE_EOF;
      this.useDeprecateEof = true;
    }

    // SSL upgrade if requested
    if (this.opts.ssl && (this.serverCapabilities & CLIENT_SSL)) {
      clientFlags |= CLIENT_SSL;
      const sslRequestPayload = Buffer.alloc(32);
      sslRequestPayload.writeUInt32LE(clientFlags, 0);
      sslRequestPayload.writeUInt32LE(0x01000000, 4); // max packet size 16MB
      sslRequestPayload[8] = this.opts.charset ?? CHARSET_UTF8MB4;
      // 23 bytes of filler (already zeros)
      this.sequenceId++;
      this._writePacket(sslRequestPayload);
      await this._upgradeToTls();
    }

    // Auth response
    const scramble = this.greeting.authPluginData;
    const authResponse = mysqlNativePasswordAuth(this.opts.password ?? "", scramble);
    const authPlugin = "mysql_native_password";

    const user = Buffer.from(this.opts.user, "utf8");
    const db = this.opts.database ? Buffer.from(this.opts.database, "utf8") : null;
    const authPluginBuf = Buffer.from(authPlugin + "\0", "utf8");

    // Calculate payload size
    let payloadSize = 4 + 4 + 1 + 23 + user.length + 1 + 1 + authResponse.length;
    if (db) payloadSize += db.length + 1;
    payloadSize += authPluginBuf.length;

    const payload = Buffer.alloc(payloadSize);
    let off = 0;

    // Capability flags (4 bytes)
    payload.writeUInt32LE(clientFlags, off); off += 4;
    // Max packet size (4 bytes)
    payload.writeUInt32LE(0x01000000, off); off += 4;
    // Character set (1 byte)
    payload[off] = this.opts.charset ?? CHARSET_UTF8MB4; off += 1;
    // 23 bytes filler
    off += 23;
    // Username null-terminated
    user.copy(payload, off); off += user.length;
    payload[off] = 0; off += 1;
    // Auth response length-encoded
    payload[off] = authResponse.length; off += 1;
    authResponse.copy(payload, off); off += authResponse.length;
    // Database null-terminated (if present)
    if (db) {
      db.copy(payload, off); off += db.length;
      payload[off] = 0; off += 1;
    }
    // Auth plugin name
    authPluginBuf.copy(payload, off);

    this.sequenceId++;
    this._writePacket(payload);

    // Read auth result
    const authResult = await this._readPacket();
    if (authResult[0] === ERR_PACKET) {
      throw this._parseError(authResult);
    }
    // Could be auth switch request (0xfe) or OK (0x00)
    if (authResult[0] === 0xfe) {
      // Auth switch request
      const { authData, pluginName } = this._parseAuthSwitch(authResult);
      const switchAuth = mysqlNativePasswordAuth(this.opts.password ?? "", authData);
      this.sequenceId++;
      this._writePacket(switchAuth);
      const switchResult = await this._readPacket();
      if (switchResult[0] === ERR_PACKET) {
        throw this._parseError(switchResult);
      }
    }
    // Connected successfully
  }

  async executeQuery(sql: string, params?: unknown[]): Promise<{ rows?: Record<string, unknown>[]; ok?: OkResult }> {
    // Build the actual SQL by interpolating params (simple ? replacement)
    const finalSql = params && params.length > 0 ? this._interpolateParams(sql, params) : sql;

    // COM_QUERY packet
    const sqlBuf = Buffer.from(finalSql, "utf8");
    const payload = Buffer.alloc(1 + sqlBuf.length);
    payload[0] = COM_QUERY;
    sqlBuf.copy(payload, 1);

    this.sequenceId = 0;
    this._writePacket(payload);

    // Read first response packet
    const first = await this._readPacket();

    if (first[0] === OK_PACKET) {
      return { ok: this._parseOk(first) };
    }
    if (first[0] === ERR_PACKET) {
      throw this._parseError(first);
    }
    if (first[0] === LOCAL_INFILE_PACKET) {
      throw new Error("LOCAL INFILE not supported");
    }

    // It's a result set: first byte is column count (lenenc int)
    const { value: columnCount } = readLenencInt(first, 0);

    // Read column definitions
    const columns: ColumnDef[] = [];
    for (let i = 0; i < columnCount; i++) {
      const colPkt = await this._readPacket();
      columns.push(this._parseColumnDef(colPkt));
    }

    // EOF after column defs (unless CLIENT_DEPRECATE_EOF)
    if (!this.useDeprecateEof) {
      await this._readPacket(); // EOF
    }

    // Read rows
    const rows: Record<string, unknown>[] = [];
    while (true) {
      const rowPkt = await this._readPacket();

      // Check for EOF or OK (end of rows)
      if (this.useDeprecateEof) {
        if (rowPkt[0] === OK_PACKET && rowPkt.length >= 7) break;
        if (rowPkt[0] === ERR_PACKET) throw this._parseError(rowPkt);
      } else {
        if (rowPkt[0] === EOF_PACKET && rowPkt.length < 9) break;
        if (rowPkt[0] === ERR_PACKET) throw this._parseError(rowPkt);
      }

      // Parse text protocol row
      const row: Record<string, unknown> = {};
      let roff = 0;
      for (let i = 0; i < columnCount; i++) {
        const col = columns[i]!;
        const { value: rawVal, newOffset } = readLenencString(rowPkt, roff);
        roff = newOffset;
        row[col.columnAlias || col.column] = rawVal === null ? null : this._castValue(rawVal, col.columnType);
      }
      rows.push(row);
    }

    return { rows };
  }

  async quit(): Promise<void> {
    try {
      const payload = Buffer.alloc(1);
      payload[0] = COM_QUIT;
      this.sequenceId = 0;
      this._writePacket(payload);
    } catch (_) {
      // ignore
    }
    this.socket.destroy();
  }

  destroy(): void {
    this.socket.destroy();
  }

  // ─── Private helpers ─────────────────────────────────────────────────────

  private _tcpConnect(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket.connect(this.opts.port, this.opts.host, () => resolve());
      this.socket.once("error", (err) => reject(err));
    });
  }

  private _upgradeToTls(): Promise<void> {
    return new Promise((resolve, reject) => {
      const tlsSocket = tls.connect({
        socket: this.socket as net.Socket,
        rejectUnauthorized: false,
      }, () => {
        this.socket = tlsSocket;
        this._setupDataHandler();
        resolve();
      });
      tlsSocket.once("error", (err) => reject(err));
    });
  }

  private _setupDataHandler(): void {
    this.socket.on("data", (chunk: Buffer) => {
      this.buffer = Buffer.concat([this.buffer, chunk]);
      this._drainPackets();
    });
    this.socket.on("error", (err: Error) => {
      this.socketError = err;
      if (this.pendingReject) {
        const rej = this.pendingReject;
        this.pendingResolve = null;
        this.pendingReject = null;
        rej(err);
      }
    });
    this.socket.on("close", () => {
      if (this.pendingReject) {
        const rej = this.pendingReject;
        this.pendingResolve = null;
        this.pendingReject = null;
        rej(new Error("Connection closed unexpectedly"));
      }
    });
  }

  private _drainPackets(): void {
    while (this.buffer.length >= 4) {
      const pktLen = this.buffer.readUIntLE(0, 3);
      const seq = this.buffer[3]!;
      if (this.buffer.length < 4 + pktLen) break;
      const pktPayload = this.buffer.subarray(4, 4 + pktLen);
      this.buffer = this.buffer.subarray(4 + pktLen);
      this.sequenceId = (seq + 1) & 0xff;

      if (this.pendingResolve) {
        const res = this.pendingResolve;
        this.pendingResolve = null;
        this.pendingReject = null;
        res(Buffer.from(pktPayload));
      } else {
        this.packetQueue.push(Buffer.from(pktPayload));
      }
    }
  }

  private _readPacket(): Promise<Buffer> {
    if (this.packetQueue.length > 0) {
      return Promise.resolve(this.packetQueue.shift()!);
    }
    if (this.socketError) {
      return Promise.reject(this.socketError);
    }
    return new Promise((resolve, reject) => {
      this.pendingResolve = resolve;
      this.pendingReject = reject;
      // Try draining again in case data arrived between checks
      this._drainPackets();
    });
  }

  private _writePacket(payload: Buffer): void {
    const pkt = buildPacket(this.sequenceId, payload);
    this.socket.write(pkt);
  }

  private _parseGreeting(buf: Buffer): ServerGreeting {
    let off = 0;
    const protocolVersion = buf[off]!; off += 1;
    const { value: serverVersion, newOffset: off2 } = readNullTermString(buf, off);
    off = off2;
    const connectionId = buf.readUInt32LE(off); off += 4;
    const authPluginDataPart1 = buf.subarray(off, off + 8); off += 8;
    off += 1; // filler
    const capLow = buf.readUInt16LE(off); off += 2;
    const characterSet = buf[off]!; off += 1;
    const statusFlags = buf.readUInt16LE(off); off += 2;
    const capHigh = buf.readUInt16LE(off); off += 2;
    const capabilityFlags = capLow | (capHigh << 16);

    let authPluginDataLen = 0;
    if (capabilityFlags & CLIENT_PLUGIN_AUTH) {
      authPluginDataLen = buf[off]!;
    }
    off += 1;
    off += 10; // reserved

    let authPluginDataPart2 = Buffer.alloc(0);
    if (capabilityFlags & CLIENT_SECURE_CONNECTION) {
      const part2Len = Math.max(13, authPluginDataLen - 8);
      authPluginDataPart2 = buf.subarray(off, off + part2Len);
      off += part2Len;
      // Remove trailing null from part2 for scramble
      if (authPluginDataPart2[authPluginDataPart2.length - 1] === 0) {
        authPluginDataPart2 = authPluginDataPart2.subarray(0, authPluginDataPart2.length - 1);
      }
    }

    let authPluginName = "mysql_native_password";
    if (capabilityFlags & CLIENT_PLUGIN_AUTH) {
      const { value } = readNullTermString(buf, off);
      authPluginName = value;
    }

    const authPluginData = Buffer.concat([authPluginDataPart1, authPluginDataPart2]);

    return {
      protocolVersion,
      serverVersion,
      connectionId,
      authPluginData,
      capabilityFlags,
      characterSet,
      statusFlags,
      authPluginName,
    };
  }

  private _parseAuthSwitch(buf: Buffer): { pluginName: string; authData: Buffer } {
    let off = 1; // skip 0xfe
    const { value: pluginName, newOffset } = readNullTermString(buf, off);
    off = newOffset;
    const authData = buf.subarray(off, buf.length - (buf[buf.length - 1] === 0 ? 1 : 0));
    return { pluginName, authData };
  }

  private _parseOk(buf: Buffer): OkResult {
    let off = 1; // skip 0x00
    const { value: affectedRows, newOffset: off2 } = readLenencInt(buf, off);
    const { value: insertId, newOffset: off3 } = readLenencInt(buf, off2);
    const statusFlags = buf.readUInt16LE(off3);
    const warnings = buf.readUInt16LE(off3 + 2);
    const info = buf.toString("utf8", off3 + 4);
    return { type: "ok", affectedRows, insertId, statusFlags, warnings, info };
  }

  private _parseError(buf: Buffer): Error {
    let off = 1; // skip 0xff
    const errno = buf.readUInt16LE(off); off += 2;
    // If has SQL state marker
    let sqlState = "";
    if (buf[off] === 0x23) { // '#'
      off += 1;
      sqlState = buf.toString("utf8", off, off + 5); off += 5;
    }
    const message = buf.toString("utf8", off);
    const err = new Error(`MySQL Error ${errno} (${sqlState}): ${message}`);
    (err as any).errno = errno;
    (err as any).sqlState = sqlState;
    return err;
  }

  private _parseColumnDef(buf: Buffer): ColumnDef {
    let off = 0;
    const { value: catalog, newOffset: o1 } = readLenencString(buf, off); off = o1;
    const { value: schema, newOffset: o2 } = readLenencString(buf, off); off = o2;
    const { value: tableAlias, newOffset: o3 } = readLenencString(buf, off); off = o3;
    const { value: table, newOffset: o4 } = readLenencString(buf, off); off = o4;
    const { value: columnAlias, newOffset: o5 } = readLenencString(buf, off); off = o5;
    const { value: column, newOffset: o6 } = readLenencString(buf, off); off = o6;
    off += 1; // filler (0x0c)
    const characterSet = buf.readUInt16LE(off); off += 2;
    const maxColumnSize = buf.readUInt32LE(off); off += 4;
    const columnType = buf[off]!; off += 1;
    const flags = buf.readUInt16LE(off); off += 2;
    const decimals = buf[off]!;
    return {
      catalog: catalog ?? "",
      schema: schema ?? "",
      tableAlias: tableAlias ?? "",
      table: table ?? "",
      columnAlias: columnAlias ?? "",
      column: column ?? "",
      characterSet,
      maxColumnSize,
      columnType,
      flags,
      decimals,
    };
  }

  private _castValue(value: string, columnType: number): unknown {
    // MySQL column types relevant for casting
    // TINY=1, SHORT=2, LONG=3, FLOAT=4, DOUBLE=5, NULL=6, TIMESTAMP=7,
    // LONGLONG=8, INT24=9, DATE=10, TIME=11, DATETIME=12, YEAR=13,
    // NEWDATE=14, VARCHAR=15, BIT=16, NEWDECIMAL=246, ENUM=247,
    // TINY_BLOB=249, MEDIUM_BLOB=250, LONG_BLOB=251, BLOB=252, VAR_STRING=253, STRING=254

    // Integer types
    if ([1, 2, 3, 8, 9, 13, 16].includes(columnType)) {
      const n = Number(value);
      if (!Number.isNaN(n)) return n;
      return value;
    }
    // Float/double/decimal types
    if ([4, 5, 246].includes(columnType)) {
      const n = Number(value);
      if (!Number.isNaN(n)) return n;
      return value;
    }
    // Date/time types - return as strings
    if ([7, 10, 11, 12, 14].includes(columnType)) {
      return value;
    }
    // NULL type
    if (columnType === 6) return null;
    // Everything else (strings, blobs, enums, etc.)
    return value;
  }

  private _interpolateParams(sql: string, params: unknown[]): string {
    let idx = 0;
    return sql.replace(/\?/g, () => {
      if (idx >= params.length) return "?";
      const val = params[idx++];
      return this._escapeValue(val);
    });
  }

  private _escapeValue(val: unknown): string {
    if (val === null || val === undefined) return "NULL";
    if (typeof val === "number") {
      if (!Number.isFinite(val)) return "NULL";
      return String(val);
    }
    if (typeof val === "boolean") return val ? "1" : "0";
    if (val instanceof Date) {
      const iso = val.toISOString().replace("T", " ").replace("Z", "");
      return `'${iso}'`;
    }
    if (Buffer.isBuffer(val)) {
      return `X'${val.toString("hex")}'`;
    }
    const str = String(val);
    // Escape special characters
    const escaped = str
      .replace(/\\/g, "\\\\")
      .replace(/'/g, "\\'")
      .replace(/"/g, '\\"')
      .replace(/\0/g, "\\0")
      .replace(/\n/g, "\\n")
      .replace(/\r/g, "\\r")
      .replace(/\x1a/g, "\\Z");
    return `'${escaped}'`;
  }
}

// ─── Connection pool (simplified) ────────────────────────────────────────────

interface PoolOpts extends MysqlConnectionOpts {
  connectionLimit: number;
}

class MysqlPool {
  private opts: PoolOpts;
  private idle: MysqlConnection[] = [];
  private active = 0;
  private waiting: Array<{ resolve: (conn: MysqlConnection) => void; reject: (err: Error) => void }> = [];
  private closed = false;

  constructor(opts: PoolOpts) {
    this.opts = opts;
  }

  async getConnection(): Promise<MysqlConnection> {
    if (this.closed) throw new Error("Pool is closed");

    if (this.idle.length > 0) {
      this.active++;
      return this.idle.pop()!;
    }

    if (this.active < this.opts.connectionLimit) {
      this.active++;
      const conn = new MysqlConnection(this.opts);
      try {
        await conn.connect();
        return conn;
      } catch (err) {
        this.active--;
        throw err;
      }
    }

    // Wait for a connection to be released
    return new Promise((resolve, reject) => {
      this.waiting.push({ resolve, reject });
    });
  }

  release(conn: MysqlConnection): void {
    if (this.closed) {
      conn.destroy();
      this.active--;
      return;
    }

    if (this.waiting.length > 0) {
      const waiter = this.waiting.shift()!;
      waiter.resolve(conn);
      return;
    }

    this.active--;
    this.idle.push(conn);
  }

  async execute(sql: string, params?: unknown[]): Promise<{ rows?: Record<string, unknown>[]; ok?: OkResult }> {
    const conn = await this.getConnection();
    try {
      const result = await conn.executeQuery(sql, params);
      this.release(conn);
      return result;
    } catch (err) {
      // On error, destroy the connection rather than returning to pool
      conn.destroy();
      this.active--;
      // Service any waiters by creating new connections
      this._serviceWaiters();
      throw err;
    }
  }

  private async _serviceWaiters(): Promise<void> {
    while (this.waiting.length > 0 && this.active < this.opts.connectionLimit) {
      const waiter = this.waiting.shift()!;
      this.active++;
      try {
        const conn = new MysqlConnection(this.opts);
        await conn.connect();
        waiter.resolve(conn);
      } catch (err) {
        this.active--;
        waiter.reject(err as Error);
      }
    }
  }

  async end(): Promise<void> {
    this.closed = true;
    for (const waiter of this.waiting) {
      waiter.reject(new Error("Pool is closing"));
    }
    this.waiting = [];
    for (const conn of this.idle) {
      await conn.quit().catch(() => {});
    }
    this.idle = [];
  }
}

// ─── Module state ────────────────────────────────────────────────────────────

const pools = new Map<string, MysqlPool>();

function getPool(name: string): MysqlPool {
  const pool = pools.get(name);
  if (!pool) throw new Error(`MySQL connection "${name}" not found. Call mysql.connect first.`);
  return pool;
}

// ─── Handlers ────────────────────────────────────────────────────────────────

const connect: BuiltinHandler = async (args) => {
  const opts = (typeof args[0] === "object" && args[0] !== null ? args[0] : {}) as Record<string, unknown>;
  const name = String(opts.name ?? "default");
  const pool = new MysqlPool({
    host: String(opts.host ?? "localhost"),
    port: Number(opts.port ?? 3306),
    user: String(opts.user ?? "root"),
    password: opts.password ? String(opts.password) : undefined,
    database: opts.database ? String(opts.database) : undefined,
    connectionLimit: Number(opts.connectionLimit ?? 10),
    charset: opts.charset ? Number(opts.charset) : CHARSET_UTF8MB4,
    ssl: Boolean(opts.ssl ?? false),
  });
  pools.set(name, pool);
  // Verify connectivity by getting and releasing a connection
  const conn = await pool.getConnection();
  pool.release(conn);
  return { name, connected: true };
};

const query: BuiltinHandler = async (args) => {
  const sql = String(args[0] ?? "");
  const params = Array.isArray(args[1]) ? args[1] : [];
  const name = String(args[2] ?? "default");
  const result = await getPool(name).execute(sql, params);
  return result.rows ?? result.ok;
};

const insert: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const data = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const name = String(args[2] ?? "default");
  const keys = Object.keys(data);
  const placeholders = keys.map(() => "?").join(", ");
  const sql = `INSERT INTO ${table} (${keys.join(", ")}) VALUES (${placeholders})`;
  const result = await getPool(name).execute(sql, Object.values(data));
  return { insertId: result.ok?.insertId ?? 0, affectedRows: result.ok?.affectedRows ?? 0 };
};

const insertMany: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const rows = (Array.isArray(args[1]) ? args[1] : []) as Record<string, unknown>[];
  const name = String(args[2] ?? "default");
  if (rows.length === 0) return { affectedRows: 0 };
  const keys = Object.keys(rows[0]!);
  const placeholders = rows.map(() => `(${keys.map(() => "?").join(", ")})`).join(", ");
  const values = rows.flatMap((r: any) => keys.map((k: any) => r[k]));
  const sql = `INSERT INTO ${table} (${keys.join(", ")}) VALUES ${placeholders}`;
  const result = await getPool(name).execute(sql, values);
  return { affectedRows: result.ok?.affectedRows ?? 0 };
};

const update: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const data = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const where = String(args[2] ?? "1=0");
  const params = Array.isArray(args[3]) ? args[3] : [];
  const name = String(args[4] ?? "default");
  const sets = Object.keys(data).map((k: any) => `${k} = ?`).join(", ");
  const sql = `UPDATE ${table} SET ${sets} WHERE ${where}`;
  const result = await getPool(name).execute(sql, [...Object.values(data), ...params]);
  return { affectedRows: result.ok?.affectedRows ?? 0 };
};

const remove: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const where = String(args[1] ?? "1=0");
  const params = Array.isArray(args[2]) ? args[2] : [];
  const name = String(args[3] ?? "default");
  const sql = `DELETE FROM ${table} WHERE ${where}`;
  const result = await getPool(name).execute(sql, params);
  return { affectedRows: result.ok?.affectedRows ?? 0 };
};

const transaction: BuiltinHandler = async (args) => {
  const queries = (Array.isArray(args[0]) ? args[0] : []) as { sql: string; params?: unknown[] }[];
  const name = String(args[1] ?? "default");
  const pool = getPool(name);
  const conn = await pool.getConnection();
  try {
    await conn.executeQuery("BEGIN");
    const results: unknown[] = [];
    for (const q of queries) {
      const r = await conn.executeQuery(q.sql, q.params ?? []);
      results.push(r.rows ?? r.ok);
    }
    await conn.executeQuery("COMMIT");
    pool.release(conn);
    return { success: true, results };
  } catch (err) {
    try { await conn.executeQuery("ROLLBACK"); } catch (_) {}
    conn.destroy();
    throw err;
  }
};

const tables: BuiltinHandler = async (args) => {
  const name = String(args[0] ?? "default");
  const result = await getPool(name).execute("SHOW TABLES");
  return (result.rows ?? []).map((r: any) => Object.values(r)[0]);
};

const describe: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const name = String(args[1] ?? "default");
  const result = await getPool(name).execute(`DESCRIBE ${table}`);
  return result.rows ?? [];
};

const count: BuiltinHandler = async (args) => {
  const table = String(args[0] ?? "");
  const where = args[1] ? `WHERE ${String(args[1])}` : "";
  const params = Array.isArray(args[2]) ? args[2] : [];
  const name = String(args[3] ?? "default");
  const result = await getPool(name).execute(`SELECT COUNT(*) as count FROM ${table} ${where}`, params);
  return (result.rows ?? [])[0]?.count ?? 0;
};

const close: BuiltinHandler = async (args) => {
  const name = String(args[0] ?? "default");
  const pool = pools.get(name);
  if (pool) { await pool.end(); pools.delete(name); }
  return true;
};

const closeAll: BuiltinHandler = async () => {
  for (const [name, pool] of pools) { await pool.end(); pools.delete(name); }
  return true;
};

// ─── Exports ─────────────────────────────────────────────────────────────────

export const MysqlFunctions: Record<string, BuiltinHandler> = { connect, query, insert, insertMany, update, remove, transaction, tables, describe, count, close, closeAll };

export const MysqlFunctionMetadata = {
  connect: { description: "Connect to MySQL database", parameters: [{ name: "options", dataType: "object", description: "{host, port, user, password, database, name, connectionLimit}", formInputType: "text", required: true }], returnType: "object", returnDescription: "{name, connected}", example: 'mysql.connect {"host": "localhost", "user": "root", "database": "mydb"}' },
  query: { description: "Execute SQL query", parameters: [{ name: "sql", dataType: "string", description: "SQL query", formInputType: "text", required: true }, { name: "params", dataType: "array", description: "Query parameters", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Query results", example: 'mysql.query "SELECT * FROM users WHERE id = ?" [1]' },
  insert: { description: "Insert a row", parameters: [{ name: "table", dataType: "string", description: "Table name", formInputType: "text", required: true }, { name: "data", dataType: "object", description: "Column values", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{insertId, affectedRows}", example: 'mysql.insert "users" {"name": "Alice", "email": "alice@example.com"}' },
  insertMany: { description: "Insert multiple rows", parameters: [{ name: "table", dataType: "string", description: "Table name", formInputType: "text", required: true }, { name: "rows", dataType: "array", description: "Array of row objects", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{affectedRows}", example: 'mysql.insertMany "users" [{"name": "Alice"}, {"name": "Bob"}]' },
  update: { description: "Update rows", parameters: [{ name: "table", dataType: "string", description: "Table name", formInputType: "text", required: true }, { name: "data", dataType: "object", description: "Columns to update", formInputType: "text", required: true }, { name: "where", dataType: "string", description: "WHERE clause", formInputType: "text", required: true }, { name: "params", dataType: "array", description: "WHERE params", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{affectedRows}", example: 'mysql.update "users" {"name": "Bob"} "id = ?" [1]' },
  remove: { description: "Delete rows", parameters: [{ name: "table", dataType: "string", description: "Table name", formInputType: "text", required: true }, { name: "where", dataType: "string", description: "WHERE clause", formInputType: "text", required: true }, { name: "params", dataType: "array", description: "WHERE params", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{affectedRows}", example: 'mysql.remove "users" "id = ?" [1]' },
  transaction: { description: "Execute queries in transaction", parameters: [{ name: "queries", dataType: "array", description: "Array of {sql, params}", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "object", returnDescription: "{success, results}", example: 'mysql.transaction [{"sql": "INSERT INTO users (name) VALUES (?)", "params": ["Alice"]}]' },
  tables: { description: "List all tables", parameters: [{ name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Table names", example: 'mysql.tables' },
  describe: { description: "Describe table structure", parameters: [{ name: "table", dataType: "string", description: "Table name", formInputType: "text", required: true }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "array", returnDescription: "Column definitions", example: 'mysql.describe "users"' },
  count: { description: "Count rows", parameters: [{ name: "table", dataType: "string", description: "Table name", formInputType: "text", required: true }, { name: "where", dataType: "string", description: "WHERE clause", formInputType: "text", required: false }, { name: "params", dataType: "array", description: "WHERE params", formInputType: "text", required: false }, { name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "number", returnDescription: "Row count", example: 'mysql.count "users" "active = ?" [true]' },
  close: { description: "Close connection pool", parameters: [{ name: "connection", dataType: "string", description: "Connection name", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "true", example: 'mysql.close' },
  closeAll: { description: "Close all connection pools", parameters: [], returnType: "boolean", returnDescription: "true", example: 'mysql.closeAll' },
};

export const MysqlModuleMetadata = {
  description: "MySQL/MariaDB client with connection pooling, parameterized queries, transactions, and CRUD operations",
  methods: ["connect", "query", "insert", "insertMany", "update", "remove", "transaction", "tables", "describe", "count", "close", "closeAll"],
};
