// @ts-nocheck
import type { BuiltinHandler, FunctionMetadata, ModuleMetadata } from "@wiredwp/robinpath";
import * as net from "node:net";
import * as tls from "node:tls";

// =============================================================================
// ASN.1 BER Encoding/Decoding
// =============================================================================

const ASN1_TAG = {
  BOOLEAN: 0x01,
  INTEGER: 0x02,
  OCTET_STRING: 0x04,
  NULL: 0x05,
  ENUMERATED: 0x0a,
  SEQUENCE: 0x30,
  SET: 0x31,
} as const;

// LDAP-specific context tags
const LDAP_OP = {
  BindRequest: 0x60,       // [APPLICATION 0] SEQUENCE
  BindResponse: 0x61,      // [APPLICATION 1] SEQUENCE
  UnbindRequest: 0x42,     // [APPLICATION 2]
  SearchRequest: 0x63,     // [APPLICATION 3] SEQUENCE
  SearchResultEntry: 0x64, // [APPLICATION 4] SEQUENCE
  SearchResultDone: 0x65,  // [APPLICATION 5] SEQUENCE
  ModifyRequest: 0x66,     // [APPLICATION 6] SEQUENCE
  ModifyResponse: 0x67,    // [APPLICATION 7] SEQUENCE
  AddRequest: 0x68,        // [APPLICATION 8] SEQUENCE
  AddResponse: 0x69,       // [APPLICATION 9] SEQUENCE
  DeleteRequest: 0x4a,     // [APPLICATION 10]
  DeleteResponse: 0x6b,    // [APPLICATION 11] SEQUENCE
  ModifyDNRequest: 0x6c,   // [APPLICATION 12] SEQUENCE
  ModifyDNResponse: 0x6d,  // [APPLICATION 13] SEQUENCE
  CompareRequest: 0x6e,    // [APPLICATION 14] SEQUENCE
  CompareResponse: 0x6f,   // [APPLICATION 15] SEQUENCE
} as const;

/** Encode ASN.1 length in BER format (short or long form). */
function encodeLength(length: number): Buffer {
  if (length < 0x80) {
    return Buffer.from([length]);
  }
  const bytes: number[] = [];
  let tmp = length;
  while (tmp > 0) {
    bytes.unshift(tmp & 0xff);
    tmp >>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

/** Encode a complete TLV (Tag-Length-Value). */
function encodeTLV(tag: number, value: Buffer): Buffer {
  const len = encodeLength(value.length);
  return Buffer.concat([Buffer.from([tag]), len, value]);
}

/** Encode an ASN.1 INTEGER. */
function encodeInteger(value: number): Buffer {
  const bytes: number[] = [];
  if (value === 0) {
    bytes.push(0);
  } else {
    let tmp = value;
    while (tmp > 0) {
      bytes.unshift(tmp & 0xff);
      tmp >>= 8;
    }
    // Add leading zero if high bit is set (to keep it positive)
    if (bytes[0] & 0x80) bytes.unshift(0);
  }
  return encodeTLV(ASN1_TAG.INTEGER, Buffer.from(bytes));
}

/** Encode an ASN.1 OCTET STRING from a JS string. */
function encodeOctetString(value: string): Buffer {
  return encodeTLV(ASN1_TAG.OCTET_STRING, Buffer.from(value, "utf8"));
}

/** Encode an ASN.1 BOOLEAN. */
function encodeBoolean(value: boolean): Buffer {
  return encodeTLV(ASN1_TAG.BOOLEAN, Buffer.from([value ? 0xff : 0x00]));
}

/** Encode an ASN.1 ENUMERATED. */
function encodeEnumerated(value: number): Buffer {
  const bytes: number[] = [];
  if (value === 0) {
    bytes.push(0);
  } else {
    let tmp = value;
    while (tmp > 0) {
      bytes.unshift(tmp & 0xff);
      tmp >>= 8;
    }
    if (bytes[0] & 0x80) bytes.unshift(0);
  }
  return encodeTLV(ASN1_TAG.ENUMERATED, Buffer.from(bytes));
}

/** Encode an ASN.1 SEQUENCE wrapping content buffers. */
function encodeSequence(items: Buffer[]): Buffer {
  return encodeTLV(ASN1_TAG.SEQUENCE, Buffer.concat(items));
}

/** Encode an ASN.1 SET wrapping content buffers. */
function encodeSet(items: Buffer[]): Buffer {
  return encodeTLV(ASN1_TAG.SET, Buffer.concat(items));
}

/** Encode a context-specific constructed tag (e.g., APPLICATION tags for LDAP ops). */
function encodeContextConstructed(tag: number, items: Buffer[]): Buffer {
  return encodeTLV(tag, Buffer.concat(items));
}

/** Encode a context-specific primitive tag. */
function encodeContextPrimitive(classTag: number, value: Buffer): Buffer {
  return encodeTLV(classTag, value);
}

// --- BER Decoder ---

interface BERElement {
  tag: number;
  value: Buffer;
  children?: BERElement[];
}

/** Decode BER length. Returns [length, bytesConsumed]. */
function decodeLength(buf: Buffer, offset: number): [number, number] {
  const first = buf[offset];
  if (first < 0x80) {
    return [first, 1];
  }
  const numBytes = first & 0x7f;
  if (numBytes === 0) throw new Error("Indefinite length not supported");
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | buf[offset + 1 + i];
  }
  return [length, 1 + numBytes];
}

/** Decode a single BER TLV element. Returns [element, bytesConsumed]. */
function decodeBER(buf: Buffer, offset: number = 0): [BERElement, number] {
  const tag = buf[offset];
  const [length, lenBytes] = decodeLength(buf, offset + 1);
  const valueStart = offset + 1 + lenBytes;
  const value = buf.subarray(valueStart, valueStart + length);

  const isConstructed = (tag & 0x20) !== 0;
  const element: BERElement = { tag, value };

  if (isConstructed) {
    element.children = [];
    let childOffset = 0;
    while (childOffset < value.length) {
      const [child, consumed] = decodeBER(value, childOffset);
      element.children.push(child);
      childOffset += consumed;
    }
  }

  return [element, 1 + lenBytes + length];
}

/** Parse an integer from BER value bytes. */
function berToInt(buf: Buffer): number {
  let val = 0;
  for (let i = 0; i < buf.length; i++) {
    val = (val << 8) | buf[i];
  }
  return val;
}

/** Parse a string from BER OCTET STRING value. */
function berToString(buf: Buffer): string {
  return buf.toString("utf8");
}

// =============================================================================
// LDAP Message Construction
// =============================================================================

let messageIdCounter = 0;

function nextMessageId(): number {
  messageIdCounter = (messageIdCounter + 1) & 0x7fffffff;
  return messageIdCounter;
}

/** Wrap an LDAP operation body in an LDAPMessage SEQUENCE envelope. */
function buildLDAPMessage(messageId: number, operationBody: Buffer, controls?: Buffer): Buffer {
  const items = [encodeInteger(messageId), operationBody];
  if (controls) items.push(controls);
  return encodeSequence(items);
}

/** Build a BindRequest (simple authentication). */
function buildBindRequest(messageId: number, dn: string, password: string): Buffer {
  const version = encodeInteger(3);
  const name = encodeOctetString(dn);
  // Simple auth: context tag [0] primitive for password
  const authChoice = encodeContextPrimitive(0x80, Buffer.from(password, "utf8"));
  const body = encodeContextConstructed(LDAP_OP.BindRequest, [version, name, authChoice]);
  return buildLDAPMessage(messageId, body);
}

/** Build an UnbindRequest. */
function buildUnbindRequest(messageId: number): Buffer {
  const body = encodeTLV(LDAP_OP.UnbindRequest, Buffer.alloc(0));
  return buildLDAPMessage(messageId, body);
}

// Search scope mapping
const SCOPE_MAP: Record<string, number> = {
  base: 0,
  one: 1,
  sub: 2,
  subordinate: 3,
};

// Search deref mapping
const DEREF_MAP: Record<string, number> = {
  never: 0,
  searching: 1,
  finding: 2,
  always: 3,
};

/** Encode an LDAP search filter string into BER. */
function encodeFilter(filter: string): Buffer {
  filter = filter.trim();

  // Compound filters: (&(...)(...)...) or (|(...)(...)...)
  if (filter.startsWith("(") && filter.endsWith(")")) {
    const inner = filter.slice(1, -1);

    if (inner.startsWith("&")) {
      const subs = parseFilterList(inner.slice(1));
      return encodeTLV(0xa0, Buffer.concat(subs.map(encodeFilter)));
    }
    if (inner.startsWith("|")) {
      const subs = parseFilterList(inner.slice(1));
      return encodeTLV(0xa1, Buffer.concat(subs.map(encodeFilter)));
    }
    if (inner.startsWith("!")) {
      const sub = inner.slice(1).trim();
      return encodeTLV(0xa2, encodeFilter(sub));
    }

    // Simple filter inside parens
    return encodeSimpleFilter(inner);
  }

  return encodeSimpleFilter(filter);
}

/** Parse a list of parenthesized filter expressions. */
function parseFilterList(s: string): string[] {
  const filters: string[] = [];
  let depth = 0;
  let start = -1;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "(") {
      if (depth === 0) start = i;
      depth++;
    } else if (s[i] === ")") {
      depth--;
      if (depth === 0 && start >= 0) {
        filters.push(s.slice(start, i + 1));
        start = -1;
      }
    }
  }
  return filters;
}

/** Encode a simple LDAP filter (attr=value, attr>=value, attr<=value, attr=*). */
function encodeSimpleFilter(filter: string): Buffer {
  // Presence: attr=*
  const presMatch = filter.match(/^([^=<>~]+)=\*$/);
  if (presMatch) {
    return encodeTLV(0x87, Buffer.from(presMatch[1], "utf8"));
  }

  // Substring: attr=*val*, attr=val*, attr=*val
  if (filter.includes("=") && filter.includes("*")) {
    const eqIdx = filter.indexOf("=");
    const attr = filter.slice(0, eqIdx);
    const valPart = filter.slice(eqIdx + 1);
    return encodeSubstringFilter(attr, valPart);
  }

  // Approx match: attr~=value
  const approxMatch = filter.match(/^([^=<>~]+)~=(.*)$/);
  if (approxMatch) {
    return encodeTLV(0xa8, Buffer.concat([
      encodeOctetString(approxMatch[1]),
      encodeOctetString(approxMatch[2]),
    ]));
  }

  // GreaterOrEqual: attr>=value
  const geMatch = filter.match(/^([^=<>~]+)>=(.*)$/);
  if (geMatch) {
    return encodeTLV(0xa5, Buffer.concat([
      encodeOctetString(geMatch[1]),
      encodeOctetString(geMatch[2]),
    ]));
  }

  // LessOrEqual: attr<=value
  const leMatch = filter.match(/^([^=<>~]+)<=(.*)$/);
  if (leMatch) {
    return encodeTLV(0xa6, Buffer.concat([
      encodeOctetString(leMatch[1]),
      encodeOctetString(leMatch[2]),
    ]));
  }

  // EqualityMatch: attr=value
  const eqMatch = filter.match(/^([^=<>~]+)=(.*)$/);
  if (eqMatch) {
    return encodeTLV(0xa3, Buffer.concat([
      encodeOctetString(eqMatch[1]),
      encodeOctetString(eqMatch[2]),
    ]));
  }

  // Fallback: present filter on objectClass
  return encodeTLV(0x87, Buffer.from("objectClass", "utf8"));
}

/** Encode a substring filter: initial*any*...*any*final */
function encodeSubstringFilter(attr: string, valPart: string): Buffer {
  const parts = valPart.split("*");
  const subBufs: Buffer[] = [];

  for (let i = 0; i < parts.length; i++) {
    if (parts[i] === "") continue;
    if (i === 0) {
      // initial
      subBufs.push(encodeTLV(0x80, Buffer.from(parts[i], "utf8")));
    } else if (i === parts.length - 1) {
      // final
      subBufs.push(encodeTLV(0x82, Buffer.from(parts[i], "utf8")));
    } else {
      // any
      subBufs.push(encodeTLV(0x81, Buffer.from(parts[i], "utf8")));
    }
  }

  return encodeTLV(0xa4, Buffer.concat([
    encodeOctetString(attr),
    encodeSequence(subBufs),
  ]));
}

/** Build a SearchRequest. */
function buildSearchRequest(
  messageId: number,
  baseDN: string,
  options: {
    scope?: string | number;
    derefAliases?: string | number;
    sizeLimit?: number;
    timeLimit?: number;
    typesOnly?: boolean;
    filter?: string;
    attributes?: string[];
  } = {}
): Buffer {
  const scope = typeof options.scope === "number"
    ? options.scope
    : SCOPE_MAP[String(options.scope ?? "sub")] ?? 2;
  const deref = typeof options.derefAliases === "number"
    ? options.derefAliases
    : DEREF_MAP[String(options.derefAliases ?? "never")] ?? 0;
  const sizeLimit = options.sizeLimit ?? 0;
  const timeLimit = options.timeLimit ?? 0;
  const typesOnly = options.typesOnly ?? false;
  const filterStr = options.filter ?? "(objectClass=*)";
  const attrs = options.attributes ?? [];

  const items: Buffer[] = [
    encodeOctetString(baseDN),
    encodeEnumerated(scope),
    encodeEnumerated(deref),
    encodeInteger(sizeLimit),
    encodeInteger(timeLimit),
    encodeBoolean(typesOnly),
    encodeFilter(filterStr),
    encodeSequence(attrs.map((a) => encodeOctetString(a))),
  ];

  const body = encodeContextConstructed(LDAP_OP.SearchRequest, items);
  return buildLDAPMessage(messageId, body);
}

/** Build a ModifyRequest. */
function buildModifyRequest(
  messageId: number,
  dn: string,
  changes: Array<{ operation: string; modification: Record<string, unknown> }>
): Buffer {
  const opMap: Record<string, number> = { add: 0, delete: 1, replace: 2 };

  const changeItems = changes.map((c) => {
    const op = opMap[c.operation] ?? 2;
    const attrName = Object.keys(c.modification)[0];
    const attrValues = Object.values(c.modification)[0] as string[];
    const valBufs = (attrValues ?? []).map((v) => encodeOctetString(String(v)));
    const partialAttr = encodeSequence([
      encodeOctetString(attrName),
      encodeSet(valBufs),
    ]);
    return encodeSequence([encodeEnumerated(op), partialAttr]);
  });

  const body = encodeContextConstructed(LDAP_OP.ModifyRequest, [
    encodeOctetString(dn),
    encodeSequence(changeItems),
  ]);
  return buildLDAPMessage(messageId, body);
}

/** Build an AddRequest. */
function buildAddRequest(
  messageId: number,
  dn: string,
  entry: Record<string, unknown>
): Buffer {
  const attrList = Object.entries(entry).map(([key, val]) => {
    const values = Array.isArray(val) ? val : [val];
    return encodeSequence([
      encodeOctetString(key),
      encodeSet(values.map((v) => encodeOctetString(String(v)))),
    ]);
  });

  const body = encodeContextConstructed(LDAP_OP.AddRequest, [
    encodeOctetString(dn),
    encodeSequence(attrList),
  ]);
  return buildLDAPMessage(messageId, body);
}

/** Build a DeleteRequest. */
function buildDeleteRequest(messageId: number, dn: string): Buffer {
  const body = encodeTLV(LDAP_OP.DeleteRequest, Buffer.from(dn, "utf8"));
  return buildLDAPMessage(messageId, body);
}

/** Build a CompareRequest. */
function buildCompareRequest(messageId: number, dn: string, attribute: string, value: string): Buffer {
  const ava = encodeSequence([
    encodeOctetString(attribute),
    encodeOctetString(value),
  ]);
  const body = encodeContextConstructed(LDAP_OP.CompareRequest, [
    encodeOctetString(dn),
    ava,
  ]);
  return buildLDAPMessage(messageId, body);
}

/** Build a ModifyDNRequest. */
function buildModifyDNRequest(messageId: number, dn: string, newRDN: string, deleteOldRDN: boolean, newSuperior?: string): Buffer {
  const items: Buffer[] = [
    encodeOctetString(dn),
    encodeOctetString(newRDN),
    encodeBoolean(deleteOldRDN),
  ];
  if (newSuperior !== undefined) {
    items.push(encodeContextPrimitive(0x80, Buffer.from(newSuperior, "utf8")));
  }
  const body = encodeContextConstructed(LDAP_OP.ModifyDNRequest, items);
  return buildLDAPMessage(messageId, body);
}

// =============================================================================
// LDAP Response Parsing
// =============================================================================

interface LDAPResponse {
  messageId: number;
  protocolOp: number;
  body: BERElement;
}

/** Parse an LDAP result (status code, matchedDN, diagnosticMessage). */
function parseLDAPResult(el: BERElement): { status: number; matchedDN: string; diagnosticMessage: string } {
  const children = el.children ?? [];
  return {
    status: children[0] ? berToInt(children[0].value) : -1,
    matchedDN: children[1] ? berToString(children[1].value) : "",
    diagnosticMessage: children[2] ? berToString(children[2].value) : "",
  };
}

/** Parse a SearchResultEntry. */
function parseSearchResultEntry(el: BERElement): { dn: string; attributes: Array<{ type: string; values: string[] }> } {
  const children = el.children ?? [];
  const dn = children[0] ? berToString(children[0].value) : "";
  const attrListEl = children[1];
  const attributes: Array<{ type: string; values: string[] }> = [];

  if (attrListEl?.children) {
    for (const attrEl of attrListEl.children) {
      const attrChildren = attrEl.children ?? [];
      const type = attrChildren[0] ? berToString(attrChildren[0].value) : "";
      const values: string[] = [];
      if (attrChildren[1]?.children) {
        for (const valEl of attrChildren[1].children) {
          values.push(berToString(valEl.value));
        }
      }
      attributes.push({ type, values });
    }
  }

  return { dn, attributes };
}

// =============================================================================
// Connection Management
// =============================================================================

interface LDAPConnection {
  socket: net.Socket | tls.TLSSocket;
  url: string;
  host: string;
  port: number;
  useTLS: boolean;
  connected: boolean;
  pendingCallbacks: Map<number, {
    resolve: (messages: LDAPResponse[]) => void;
    reject: (err: Error) => void;
    messages: LDAPResponse[];
    expectMultiple?: boolean;
  }>;
  recvBuffer: Buffer;
}

const connections: Map<string, LDAPConnection> = new Map();

function getConnection(id: string): LDAPConnection {
  const conn = connections.get(id);
  if (!conn) {
    throw new Error(`LDAP client "${id}" not found. Call connect() first.`);
  }
  return conn;
}

/** Parse URL into host, port, and TLS flag. */
function parseURL(url: string): { host: string; port: number; useTLS: boolean } {
  let useTLS = false;
  let defaultPort = 389;
  let cleanUrl = url;

  if (url.startsWith("ldaps://")) {
    useTLS = true;
    defaultPort = 636;
    cleanUrl = url.slice(8);
  } else if (url.startsWith("ldap://")) {
    cleanUrl = url.slice(7);
  }

  // Remove trailing slash
  cleanUrl = cleanUrl.replace(/\/$/, "");

  const colonIdx = cleanUrl.indexOf(":");
  if (colonIdx >= 0) {
    return {
      host: cleanUrl.slice(0, colonIdx),
      port: parseInt(cleanUrl.slice(colonIdx + 1), 10) || defaultPort,
      useTLS,
    };
  }

  return { host: cleanUrl || "localhost", port: defaultPort, useTLS };
}

/** Try to read one complete LDAP message from the buffer.
 *  Returns [parsed, bytesConsumed] or null if buffer incomplete. */
function tryReadMessage(buf: Buffer): [LDAPResponse, number] | null {
  if (buf.length < 2) return null;

  // Read tag
  if (buf[0] !== ASN1_TAG.SEQUENCE) return null;

  let offset = 1;
  const first = buf[offset];
  let totalLen: number;
  let lenBytes: number;

  if (first < 0x80) {
    totalLen = first;
    lenBytes = 1;
  } else {
    const numLenBytes = first & 0x7f;
    if (buf.length < offset + 1 + numLenBytes) return null;
    totalLen = 0;
    for (let i = 0; i < numLenBytes; i++) {
      totalLen = (totalLen << 8) | buf[offset + 1 + i];
    }
    lenBytes = 1 + numLenBytes;
  }

  const totalPacketLen = 1 + lenBytes + totalLen;
  if (buf.length < totalPacketLen) return null;

  const packet = buf.subarray(0, totalPacketLen);
  const [el] = decodeBER(packet, 0);
  const children = el.children ?? [];

  const messageId = children[0] ? berToInt(children[0].value) : 0;
  const protocolOpEl = children[1];

  return [{
    messageId,
    protocolOp: protocolOpEl?.tag ?? 0,
    body: protocolOpEl ?? { tag: 0, value: Buffer.alloc(0) },
  }, totalPacketLen];
}

/** Process incoming data on the connection. */
function onData(conn: LDAPConnection, data: Buffer): void {
  conn.recvBuffer = Buffer.concat([conn.recvBuffer, data]);

  while (true) {
    const result = tryReadMessage(conn.recvBuffer);
    if (!result) break;

    const [msg, consumed] = result;
    conn.recvBuffer = conn.recvBuffer.subarray(consumed);

    const pending = conn.pendingCallbacks.get(msg.messageId);
    if (pending) {
      pending.messages.push(msg);

      // For search operations, we keep collecting until we get SearchResultDone
      if (pending.expectMultiple) {
        if (msg.protocolOp === LDAP_OP.SearchResultDone) {
          conn.pendingCallbacks.delete(msg.messageId);
          pending.resolve(pending.messages);
        }
        // SearchResultEntry or SearchResultReference: keep collecting
      } else {
        conn.pendingCallbacks.delete(msg.messageId);
        pending.resolve(pending.messages);
      }
    }
  }
}

/** Send a message and wait for the response. */
function sendAndReceive(
  conn: LDAPConnection,
  msgId: number,
  data: Buffer,
  expectMultiple: boolean = false
): Promise<LDAPResponse[]> {
  return new Promise((resolve, reject) => {
    conn.pendingCallbacks.set(msgId, {
      resolve,
      reject,
      messages: [],
      expectMultiple,
    });

    conn.socket.write(data, (err) => {
      if (err) {
        conn.pendingCallbacks.delete(msgId);
        reject(err);
      }
    });
  });
}

/** Create a TCP or TLS connection. */
function createSocket(host: string, port: number, useTLS: boolean, options: any = {}): Promise<net.Socket | tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    if (useTLS) {
      const tlsOptions: tls.ConnectionOptions = {
        host,
        port,
        rejectUnauthorized: options.rejectUnauthorized ?? true,
        ...options.tlsOptions,
      };
      const sock = tls.connect(tlsOptions, () => {
        resolve(sock);
      });
      sock.once("error", reject);
    } else {
      const sock = net.createConnection({ host, port }, () => {
        resolve(sock);
      });
      sock.once("error", reject);
    }
  });
}

// =============================================================================
// LDAP Handler Functions
// =============================================================================

const connect: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const url = String(args[1] ?? "ldap://localhost:389");
  const options = (args[2] ?? {}) as Record<string, any>;

  if (connections.has(id)) {
    throw new Error(`LDAP client "${id}" already exists. Close it first or use a different id.`);
  }

  const { host, port, useTLS } = parseURL(url);
  const socket = await createSocket(host, port, useTLS, options);

  const conn: LDAPConnection = {
    socket,
    url,
    host,
    port,
    useTLS,
    connected: true,
    pendingCallbacks: new Map(),
    recvBuffer: Buffer.alloc(0),
  };

  socket.on("data", (data: Buffer) => onData(conn, data));
  socket.on("close", () => {
    conn.connected = false;
  });
  socket.on("error", (err: Error) => {
    conn.connected = false;
    // Reject all pending operations
    for (const [, pending] of conn.pendingCallbacks) {
      pending.reject(err);
    }
    conn.pendingCallbacks.clear();
  });

  connections.set(id, conn);

  return { id, url, status: "created" };
};

const search: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const baseDN = String(args[1]);
  const options = (args[2] ?? {}) as Record<string, any>;

  if (!baseDN) throw new Error("Base DN is required.");
  const conn = getConnection(id);

  const msgId = nextMessageId();
  const msg = buildSearchRequest(msgId, baseDN, options);

  const responses = await sendAndReceive(conn, msgId, msg, true);

  const entries: Record<string, unknown>[] = [];
  let resultStatus = 0;

  for (const resp of responses) {
    if (resp.protocolOp === LDAP_OP.SearchResultEntry) {
      const entry = parseSearchResultEntry(resp.body);
      entries.push({
        dn: entry.dn,
        attributes: entry.attributes,
      });
    } else if (resp.protocolOp === LDAP_OP.SearchResultDone) {
      const result = parseLDAPResult(resp.body);
      resultStatus = result.status;
      if (result.status !== 0) {
        throw new Error(`LDAP search failed: ${result.diagnosticMessage} (status ${result.status})`);
      }
    }
  }

  return {
    id,
    baseDN,
    status: resultStatus,
    entries,
    count: entries.length,
  };
};

const bind: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const dn = String(args[1]);
  const password = String(args[2]);

  if (!dn) throw new Error("DN is required for bind.");
  if (!password) throw new Error("Password is required for bind.");

  const conn = getConnection(id);
  const msgId = nextMessageId();
  const msg = buildBindRequest(msgId, dn, password);

  const responses = await sendAndReceive(conn, msgId, msg);
  const resp = responses[0];

  if (resp && resp.protocolOp === LDAP_OP.BindResponse) {
    const result = parseLDAPResult(resp.body);
    if (result.status !== 0) {
      throw new Error(`LDAP bind failed: ${result.diagnosticMessage} (status ${result.status})`);
    }
  }

  return { id, dn, status: "bound" };
};

const unbind: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const conn = getConnection(id);

  const msgId = nextMessageId();
  const msg = buildUnbindRequest(msgId);

  // UnbindRequest has no response; just send and close
  conn.socket.write(msg);

  return new Promise<any>((resolve) => {
    conn.socket.end(() => {
      conn.connected = false;
      connections.delete(id);
      resolve({ id, status: "unbound" });
    });
  });
};

const add: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const dn = String(args[1]);
  const entry = args[2] as Record<string, unknown>;

  if (!dn) throw new Error("DN is required.");
  if (!entry || typeof entry !== "object") throw new Error("Entry object is required.");

  const conn = getConnection(id);
  const msgId = nextMessageId();
  const msg = buildAddRequest(msgId, dn, entry);

  const responses = await sendAndReceive(conn, msgId, msg);
  const resp = responses[0];

  if (resp && resp.protocolOp === LDAP_OP.AddResponse) {
    const result = parseLDAPResult(resp.body);
    if (result.status !== 0) {
      throw new Error(`LDAP add failed: ${result.diagnosticMessage} (status ${result.status})`);
    }
  }

  return { id, dn, status: "added" };
};

const modify: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const dn = String(args[1]);
  const changes = args[2] as Array<{ operation: string; modification: Record<string, unknown> }>;

  if (!dn) throw new Error("DN is required.");
  if (!changes || !Array.isArray(changes)) throw new Error("Changes array is required.");

  const conn = getConnection(id);
  const msgId = nextMessageId();
  const msg = buildModifyRequest(msgId, dn, changes);

  const responses = await sendAndReceive(conn, msgId, msg);
  const resp = responses[0];

  if (resp && resp.protocolOp === LDAP_OP.ModifyResponse) {
    const result = parseLDAPResult(resp.body);
    if (result.status !== 0) {
      throw new Error(`LDAP modify failed: ${result.diagnosticMessage} (status ${result.status})`);
    }
  }

  return { id, dn, status: "modified", changeCount: changes.length };
};

const del: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const dn = String(args[1]);

  if (!dn) throw new Error("DN is required.");
  const conn = getConnection(id);

  const msgId = nextMessageId();
  const msg = buildDeleteRequest(msgId, dn);

  const responses = await sendAndReceive(conn, msgId, msg);
  const resp = responses[0];

  if (resp && resp.protocolOp === LDAP_OP.DeleteResponse) {
    const result = parseLDAPResult(resp.body);
    if (result.status !== 0) {
      throw new Error(`LDAP delete failed: ${result.diagnosticMessage} (status ${result.status})`);
    }
  }

  return { id, dn, status: "deleted" };
};

const compare: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const dn = String(args[1]);
  const attribute = String(args[2]);
  const value = String(args[3]);

  if (!dn) throw new Error("DN is required.");
  if (!attribute) throw new Error("Attribute name is required.");
  if (!value) throw new Error("Value is required.");

  const conn = getConnection(id);
  const msgId = nextMessageId();
  const msg = buildCompareRequest(msgId, dn, attribute, value);

  const responses = await sendAndReceive(conn, msgId, msg);
  const resp = responses[0];

  let matched = false;
  if (resp && resp.protocolOp === LDAP_OP.CompareResponse) {
    const result = parseLDAPResult(resp.body);
    // Status 6 = compareTrue, 5 = compareFalse
    matched = result.status === 6;
    if (result.status !== 6 && result.status !== 5) {
      throw new Error(`LDAP compare failed: ${result.diagnosticMessage} (status ${result.status})`);
    }
  }

  return { id, dn, attribute, matched };
};

const modifyDN: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const dn = String(args[1]);
  const newDN = String(args[2]);

  if (!dn) throw new Error("Current DN is required.");
  if (!newDN) throw new Error("New DN is required.");

  const conn = getConnection(id);

  // Parse the newDN to extract newRDN and optional newSuperior
  // If newDN contains a comma, the first component is the new RDN
  // and we try to determine newSuperior from context
  const commaIdx = newDN.indexOf(",");
  let newRDN: string;
  let newSuperior: string | undefined;

  if (commaIdx >= 0) {
    newRDN = newDN.slice(0, commaIdx);
    newSuperior = newDN.slice(commaIdx + 1);
  } else {
    newRDN = newDN;
  }

  const msgId = nextMessageId();
  const msg = buildModifyDNRequest(msgId, dn, newRDN, true, newSuperior);

  const responses = await sendAndReceive(conn, msgId, msg);
  const resp = responses[0];

  if (resp && resp.protocolOp === LDAP_OP.ModifyDNResponse) {
    const result = parseLDAPResult(resp.body);
    if (result.status !== 0) {
      throw new Error(`LDAP modifyDN failed: ${result.diagnosticMessage} (status ${result.status})`);
    }
  }

  return { id, oldDN: dn, newDN, status: "renamed" };
};

const findUser: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const baseDN = String(args[1]);
  const username = String(args[2]);
  const usernameAttribute = String(args[3] ?? "uid");

  if (!baseDN) throw new Error("Base DN is required.");
  if (!username) throw new Error("Username is required.");

  const conn = getConnection(id);
  const msgId = nextMessageId();
  const msg = buildSearchRequest(msgId, baseDN, {
    filter: `(${usernameAttribute}=${username})`,
    scope: "sub",
  });

  const responses = await sendAndReceive(conn, msgId, msg, true);

  const entries: Record<string, unknown>[] = [];
  for (const resp of responses) {
    if (resp.protocolOp === LDAP_OP.SearchResultEntry) {
      const entry = parseSearchResultEntry(resp.body);
      entries.push({
        dn: entry.dn,
        attributes: entry.attributes,
      });
    } else if (resp.protocolOp === LDAP_OP.SearchResultDone) {
      const result = parseLDAPResult(resp.body);
      if (result.status !== 0) {
        throw new Error(`LDAP search failed: ${result.diagnosticMessage} (status ${result.status})`);
      }
    }
  }

  return {
    id,
    username,
    found: entries.length > 0,
    user: entries[0] ?? null,
  };
};

const authenticate: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const baseDN = String(args[1]);
  const username = String(args[2]);
  const password = String(args[3]);
  const usernameAttribute = String(args[4] ?? "uid");

  if (!baseDN) throw new Error("Base DN is required.");
  if (!username) throw new Error("Username is required.");
  if (!password) throw new Error("Password is required.");

  const conn = getConnection(id);

  // Step 1: Search for the user's DN
  const searchMsgId = nextMessageId();
  const searchMsg = buildSearchRequest(searchMsgId, baseDN, {
    filter: `(${usernameAttribute}=${username})`,
    scope: "sub",
  });

  const searchResponses = await sendAndReceive(conn, searchMsgId, searchMsg, true);

  let userDN: string | null = null;
  for (const resp of searchResponses) {
    if (resp.protocolOp === LDAP_OP.SearchResultEntry) {
      const entry = parseSearchResultEntry(resp.body);
      userDN = entry.dn;
    }
  }

  if (!userDN) {
    return { id, username, authenticated: false, reason: "User not found" };
  }

  // Step 2: Open a new connection and try to bind as the user
  const { host, port, useTLS } = parseURL(conn.url);
  try {
    const authSocket = await createSocket(host, port, useTLS);
    const authConn: LDAPConnection = {
      socket: authSocket,
      url: conn.url,
      host,
      port,
      useTLS,
      connected: true,
      pendingCallbacks: new Map(),
      recvBuffer: Buffer.alloc(0),
    };

    authSocket.on("data", (data: Buffer) => onData(authConn, data));
    authSocket.on("close", () => { authConn.connected = false; });
    authSocket.on("error", () => { authConn.connected = false; });

    const bindMsgId = nextMessageId();
    const bindMsg = buildBindRequest(bindMsgId, userDN, password);

    const bindResponses = await sendAndReceive(authConn, bindMsgId, bindMsg);
    const bindResp = bindResponses[0];

    let authenticated = false;
    if (bindResp && bindResp.protocolOp === LDAP_OP.BindResponse) {
      const result = parseLDAPResult(bindResp.body);
      authenticated = result.status === 0;
    }

    // Clean up auth connection
    const unbindMsgId = nextMessageId();
    authSocket.write(buildUnbindRequest(unbindMsgId));
    authSocket.end();

    if (authenticated) {
      return { id, username, authenticated: true, dn: userDN };
    } else {
      return { id, username, authenticated: false, reason: "Invalid credentials" };
    }
  } catch {
    return { id, username, authenticated: false, reason: "Invalid credentials" };
  }
};

const groups: BuiltinHandler = async (args: Value[]): Promise<unknown> => {
  const id = String(args[0] ?? "default");
  const baseDN = String(args[1]);
  const userDN = String(args[2]);
  const groupAttribute = String(args[3] ?? "member");

  if (!baseDN) throw new Error("Base DN is required.");
  if (!userDN) throw new Error("User DN is required.");

  const conn = getConnection(id);
  const msgId = nextMessageId();
  const msg = buildSearchRequest(msgId, baseDN, {
    filter: `(&(objectClass=groupOfNames)(${groupAttribute}=${userDN}))`,
    scope: "sub",
    attributes: ["cn", "dn"],
  });

  const responses = await sendAndReceive(conn, msgId, msg, true);

  const groupList: Record<string, unknown>[] = [];
  for (const resp of responses) {
    if (resp.protocolOp === LDAP_OP.SearchResultEntry) {
      const entry = parseSearchResultEntry(resp.body);
      const cnAttr = entry.attributes.find((a) => a.type === "cn");
      groupList.push({
        dn: entry.dn,
        cn: cnAttr?.values[0] ?? null,
      });
    } else if (resp.protocolOp === LDAP_OP.SearchResultDone) {
      const result = parseLDAPResult(resp.body);
      if (result.status !== 0) {
        throw new Error(`LDAP search failed: ${result.diagnosticMessage} (status ${result.status})`);
      }
    }
  }

  return { id, userDN, groups: groupList, count: groupList.length };
};

const close: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const conn = getConnection(id);

  conn.socket.destroy();
  conn.connected = false;
  connections.delete(id);

  return { id, status: "closed" };
};

const isConnected: BuiltinHandler = (args: Value[]): unknown => {
  const id = String(args[0] ?? "default");
  const conn = connections.get(id);
  return { id, connected: conn ? conn.connected : false };
};

// =============================================================================
// Exports
// =============================================================================

export const LdapFunctions: Record<string, BuiltinHandler> = {
  connect,
  search,
  bind,
  unbind,
  add,
  modify,
  del,
  compare,
  modifyDN,
  findUser,
  authenticate,
  groups,
  close,
  isConnected,
};

export const LdapFunctionMetadata = {
	connect: {
		description: 'Create and connect an LDAP client to a server',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'url', dataType: 'string', formInputType: 'text', description: 'LDAP server URL (e.g. ldap://localhost:389)', required: false },
			{ name: 'options', dataType: 'object', formInputType: 'json', description: 'Additional connection options', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	search: {
		description: 'Search for entries in the LDAP directory',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'baseDN', dataType: 'string', formInputType: 'text', description: 'Base DN to search from', required: true },
			{ name: 'options', dataType: 'object', formInputType: 'json', description: 'Search options (filter, scope, attributes, etc.)', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	bind: {
		description: 'Authenticate (bind) to the LDAP server with a DN and password',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'dn', dataType: 'string', formInputType: 'text', description: 'Distinguished name to bind as', required: true },
			{ name: 'password', dataType: 'string', formInputType: 'text', description: 'Password for authentication', required: true },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	unbind: {
		description: 'Unbind and disconnect from the LDAP server',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	add: {
		description: 'Add a new entry to the LDAP directory',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'dn', dataType: 'string', formInputType: 'text', description: 'Distinguished name for the new entry', required: true },
			{ name: 'entry', dataType: 'object', formInputType: 'json', description: 'Entry attributes as key-value pairs', required: true },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	modify: {
		description: "Modify an existing LDAP entry's attributes",
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'dn', dataType: 'string', formInputType: 'text', description: 'DN of the entry to modify', required: true },
			{ name: 'changes', dataType: 'array', formInputType: 'json', description: 'Array of changes with operation (add/delete/replace) and modification', required: true },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	del: {
		description: 'Delete an entry from the LDAP directory',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'dn', dataType: 'string', formInputType: 'text', description: 'DN of the entry to delete', required: true },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	compare: {
		description: 'Compare an attribute value against an LDAP entry',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'dn', dataType: 'string', formInputType: 'text', description: 'DN of the entry to compare', required: true },
			{ name: 'attribute', dataType: 'string', formInputType: 'text', description: 'Attribute name to compare', required: true },
			{ name: 'value', dataType: 'string', formInputType: 'text', description: 'Value to compare against', required: true },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	modifyDN: {
		description: 'Rename an LDAP entry by changing its DN',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'dn', dataType: 'string', formInputType: 'text', description: 'Current DN of the entry', required: true },
			{ name: 'newDN', dataType: 'string', formInputType: 'text', description: 'New DN for the entry', required: true },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	findUser: {
		description: 'Convenience function to search for a user by username',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'baseDN', dataType: 'string', formInputType: 'text', description: 'Base DN to search from', required: true },
			{ name: 'username', dataType: 'string', formInputType: 'text', description: 'Username to search for', required: true },
			{ name: 'usernameAttribute', dataType: 'string', formInputType: 'text', description: 'LDAP attribute for username (default: uid)', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	authenticate: {
		description: 'Authenticate a user by searching for their DN and then binding with their password',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'baseDN', dataType: 'string', formInputType: 'text', description: 'Base DN to search from', required: true },
			{ name: 'username', dataType: 'string', formInputType: 'text', description: 'Username to authenticate', required: true },
			{ name: 'password', dataType: 'string', formInputType: 'text', description: 'User password', required: true },
			{ name: 'usernameAttribute', dataType: 'string', formInputType: 'text', description: 'LDAP attribute for username (default: uid)', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	groups: {
		description: 'Get all groups that a user belongs to',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
			{ name: 'baseDN', dataType: 'string', formInputType: 'text', description: 'Base DN to search groups from', required: true },
			{ name: 'userDN', dataType: 'string', formInputType: 'text', description: 'DN of the user to find groups for', required: true },
			{ name: 'groupAttribute', dataType: 'string', formInputType: 'text', description: 'Group membership attribute (default: member)', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	close: {
		description: 'Forcefully close the LDAP client connection and clean up resources',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
	isConnected: {
		description: 'Check if the LDAP client is currently connected',
		parameters: [
			{ name: 'id', dataType: 'string', formInputType: 'text', description: 'Client identifier', required: false },
		],
		returnType: 'object',
		returnDescription: 'API response.',
	},
};

export const LdapModuleMetadata = {
	description:
		'LDAP client module for interacting with LDAP directories. Supports connecting, binding, searching, adding, modifying, and deleting entries. Includes convenience functions for user authentication, user lookup, and group membership queries.',
	methods: ['connect', 'search', 'bind', 'unbind', 'add', 'modify', 'del', 'compare', 'modifyDN', 'findUser', 'authenticate', 'groups', 'close', 'isConnected'],
};
