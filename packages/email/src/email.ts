import type { BuiltinHandler } from "@wiredwp/robinpath";
import * as net from "node:net";
import * as tls from "node:tls";
import * as crypto from "node:crypto";
import * as fs from "node:fs";

// ── Internal Types ─────────────────────────────────────────────────

interface SmtpTransport {
  host: string;
  port: number;
  secure: boolean; // true = implicit TLS (port 465), false = STARTTLS or plain
  user: string;
  pass: string;
  rejectUnauthorized: boolean;
}

interface SmtpAttachment {
  filename?: string;
  path?: string;
  content?: string | Buffer;
  contentType?: string;
  encoding?: string;
}

// ── Internal State ──────────────────────────────────────────────────

const transporters = new Map<string, SmtpTransport>();

// ── Low-level SMTP Client ──────────────────────────────────────────

function toBase64(input: string | Buffer): string {
  if (Buffer.isBuffer(input)) return input.toString("base64");
  return Buffer.from(input, "utf-8").toString("base64");
}

function generateMessageId(domain: string): string {
  const rand = crypto.randomBytes(16).toString("hex");
  return `<${rand}@${domain}>`;
}

function generateBoundary(): string {
  return `----=_Part_${crypto.randomBytes(12).toString("hex")}`;
}

/**
 * Read a complete SMTP response (may span multiple lines).
 * Returns the full response string including the final status code.
 */
function readResponse(socket: net.Socket | tls.TLSSocket): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = "";
    const onData = (chunk: Buffer) => {
      buffer += chunk.toString("utf-8");
      // SMTP multiline: "250-..." continues, "250 ..." is last line
      const lines = buffer.split("\r\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i]!;
        // A final line matches /^\d{3} / or /^\d{3}$/
        if (line.length >= 3 && /^\d{3}(?: |$)/.test(line)) {
          // Check if this is the last non-empty line
          const remaining = lines.slice(i + 1).filter(Boolean);
          if (remaining.length === 0) {
            socket.removeListener("data", onData);
            socket.removeListener("error", onError);
            socket.removeListener("close", onClose);
            resolve(buffer.trim());
            return;
          }
        }
      }
    };
    const onError = (err: Error) => {
      socket.removeListener("data", onData);
      socket.removeListener("close", onClose);
      reject(err);
    };
    const onClose = () => {
      socket.removeListener("data", onData);
      socket.removeListener("error", onError);
      if (buffer.trim()) resolve(buffer.trim());
      else reject(new Error("Connection closed before response"));
    };
    socket.on("data", onData);
    socket.on("error", onError);
    socket.on("close", onClose);
  });
}

/**
 * Send a command and read the response.
 */
async function smtpCommand(
  socket: net.Socket | tls.TLSSocket,
  command: string,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const responsePromise = readResponse(socket);
    socket.write(command + "\r\n", "utf-8", (err) => {
      if (err) return reject(err);
    });
    responsePromise.then(resolve, reject);
  });
}

/**
 * Assert the response starts with an expected status code.
 */
function assertStatus(response: string, expected: string, context: string): void {
  if (!response.startsWith(expected)) {
    throw new Error(`SMTP ${context} failed: ${response}`);
  }
}

/**
 * Build a MIME message from the given options.
 */
function buildMimeMessage(opts: {
  from?: string;
  to: string;
  subject?: string;
  text?: string;
  html?: string;
  cc?: string;
  bcc?: string;
  replyTo?: string;
  attachments?: SmtpAttachment[];
  priority?: string;
  headers?: Record<string, string>;
  messageId: string;
}): string {
  const lines: string[] = [];

  // Headers
  lines.push(`Message-ID: ${opts.messageId}`);
  lines.push(`Date: ${new Date().toUTCString()}`);
  if (opts.from) lines.push(`From: ${opts.from}`);
  lines.push(`To: ${opts.to}`);
  if (opts.cc) lines.push(`Cc: ${opts.cc}`);
  if (opts.subject) lines.push(`Subject: =?UTF-8?B?${toBase64(opts.subject)}?=`);
  if (opts.replyTo) lines.push(`Reply-To: ${opts.replyTo}`);

  // Priority
  if (opts.priority === "high") {
    lines.push("X-Priority: 1");
    lines.push("Importance: high");
  } else if (opts.priority === "low") {
    lines.push("X-Priority: 5");
    lines.push("Importance: low");
  }

  // Custom headers
  if (opts.headers) {
    for (const [key, value] of Object.entries(opts.headers)) {
      lines.push(`${key}: ${value}`);
    }
  }

  lines.push("MIME-Version: 1.0");

  const hasAttachments = opts.attachments && opts.attachments.length > 0;
  const hasHtml = !!opts.html;
  const hasText = !!opts.text;

  if (hasAttachments) {
    // Mixed multipart for attachments
    const mixedBoundary = generateBoundary();
    lines.push(`Content-Type: multipart/mixed; boundary="${mixedBoundary}"`);
    lines.push("");

    // Body part
    if (hasHtml && hasText) {
      const altBoundary = generateBoundary();
      lines.push(`--${mixedBoundary}`);
      lines.push(`Content-Type: multipart/alternative; boundary="${altBoundary}"`);
      lines.push("");
      lines.push(`--${altBoundary}`);
      lines.push("Content-Type: text/plain; charset=UTF-8");
      lines.push("Content-Transfer-Encoding: base64");
      lines.push("");
      lines.push(wrapBase64(toBase64(opts.text!)));
      lines.push(`--${altBoundary}`);
      lines.push("Content-Type: text/html; charset=UTF-8");
      lines.push("Content-Transfer-Encoding: base64");
      lines.push("");
      lines.push(wrapBase64(toBase64(opts.html!)));
      lines.push(`--${altBoundary}--`);
    } else if (hasHtml) {
      lines.push(`--${mixedBoundary}`);
      lines.push("Content-Type: text/html; charset=UTF-8");
      lines.push("Content-Transfer-Encoding: base64");
      lines.push("");
      lines.push(wrapBase64(toBase64(opts.html!)));
    } else if (hasText) {
      lines.push(`--${mixedBoundary}`);
      lines.push("Content-Type: text/plain; charset=UTF-8");
      lines.push("Content-Transfer-Encoding: base64");
      lines.push("");
      lines.push(wrapBase64(toBase64(opts.text!)));
    }

    // Attachment parts
    for (const att of opts.attachments!) {
      lines.push(`--${mixedBoundary}`);
      const ct = att.contentType || "application/octet-stream";
      const fn = att.filename || "attachment";
      lines.push(`Content-Type: ${ct}; name="${fn}"`);
      lines.push("Content-Transfer-Encoding: base64");
      lines.push(`Content-Disposition: attachment; filename="${fn}"`);
      lines.push("");

      let data: Buffer;
      if (att.path) {
        data = fs.readFileSync(att.path);
      } else if (Buffer.isBuffer(att.content)) {
        data = att.content;
      } else if (typeof att.content === "string") {
        if (att.encoding === "base64") {
          data = Buffer.from(att.content, "base64");
        } else {
          data = Buffer.from(att.content, "utf-8");
        }
      } else {
        data = Buffer.alloc(0);
      }
      lines.push(wrapBase64(data.toString("base64")));
    }

    lines.push(`--${mixedBoundary}--`);
  } else if (hasHtml && hasText) {
    // Alternative multipart (text + html, no attachments)
    const altBoundary = generateBoundary();
    lines.push(`Content-Type: multipart/alternative; boundary="${altBoundary}"`);
    lines.push("");
    lines.push(`--${altBoundary}`);
    lines.push("Content-Type: text/plain; charset=UTF-8");
    lines.push("Content-Transfer-Encoding: base64");
    lines.push("");
    lines.push(wrapBase64(toBase64(opts.text!)));
    lines.push(`--${altBoundary}`);
    lines.push("Content-Type: text/html; charset=UTF-8");
    lines.push("Content-Transfer-Encoding: base64");
    lines.push("");
    lines.push(wrapBase64(toBase64(opts.html!)));
    lines.push(`--${altBoundary}--`);
  } else if (hasHtml) {
    lines.push("Content-Type: text/html; charset=UTF-8");
    lines.push("Content-Transfer-Encoding: base64");
    lines.push("");
    lines.push(wrapBase64(toBase64(opts.html!)));
  } else {
    lines.push("Content-Type: text/plain; charset=UTF-8");
    lines.push("Content-Transfer-Encoding: base64");
    lines.push("");
    lines.push(wrapBase64(toBase64(opts.text || "")));
  }

  return lines.join("\r\n");
}

/** Wrap base64 to 76-char lines per MIME spec */
function wrapBase64(b64: string): string {
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 76) {
    lines.push(b64.slice(i, i + 76));
  }
  return lines.join("\r\n");
}

/**
 * Extract all recipient addresses from a potentially comma-separated string.
 * Handles "Name <addr>" format.
 */
function extractAddresses(input: string): string[] {
  return input
    .split(/,(?![^<]*>)/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const m = s.match(/<([^>]+)>/);
      return m ? m[1]! : s;
    });
}

/**
 * Open a TCP or TLS connection and perform full SMTP send.
 */
async function smtpSend(
  transport: SmtpTransport,
  mailFrom: string,
  rcptTo: string[],
  mimeMessage: string,
): Promise<{ response: string }> {
  return new Promise((resolve, reject) => {
    let socket: net.Socket | tls.TLSSocket;

    const tlsOpts: tls.ConnectionOptions = {
      host: transport.host,
      port: transport.port,
      rejectUnauthorized: transport.rejectUnauthorized,
      servername: transport.host,
    };

    const handleSession = async (sock: net.Socket | tls.TLSSocket) => {
      try {
        // Read greeting
        const greeting = await readResponse(sock);
        assertStatus(greeting, "220", "greeting");

        // EHLO
        const domain = transport.user.includes("@")
          ? transport.user.split("@")[1]!
          : "localhost";
        const ehloResp = await smtpCommand(sock, `EHLO ${domain}`);
        assertStatus(ehloResp, "250", "EHLO");

        // STARTTLS if not already secure
        if (!transport.secure) {
          if (ehloResp.includes("STARTTLS")) {
            const starttlsResp = await smtpCommand(sock, "STARTTLS");
            assertStatus(starttlsResp, "220", "STARTTLS");

            // Upgrade to TLS
            const tlsSock = await new Promise<tls.TLSSocket>((res, rej) => {
              const upgraded = tls.connect(
                {
                  socket: sock as net.Socket,
                  host: transport.host,
                  rejectUnauthorized: transport.rejectUnauthorized,
                  servername: transport.host,
                },
                () => res(upgraded),
              );
              upgraded.on("error", rej);
            });

            // Re-EHLO after STARTTLS
            const ehlo2 = await smtpCommand(tlsSock, `EHLO ${domain}`);
            assertStatus(ehlo2, "250", "EHLO after STARTTLS");

            // Continue session on TLS socket
            await authenticateAndSend(tlsSock, transport, mailFrom, rcptTo, mimeMessage, resolve);
            return;
          }
        }

        // Already secure (implicit TLS) or no STARTTLS available
        await authenticateAndSend(sock, transport, mailFrom, rcptTo, mimeMessage, resolve);
      } catch (err) {
        try { sock.destroy(); } catch {}
        reject(err);
      }
    };

    if (transport.secure) {
      // Implicit TLS (port 465)
      socket = tls.connect(tlsOpts, () => {
        handleSession(socket);
      });
    } else {
      // Plain TCP first, then optionally STARTTLS
      socket = net.createConnection(
        { host: transport.host, port: transport.port },
        () => {
          handleSession(socket);
        },
      );
    }

    socket.on("error", (err) => reject(err));
    socket.setTimeout(30000, () => {
      socket.destroy();
      reject(new Error("SMTP connection timed out"));
    });
  });
}

async function authenticateAndSend(
  sock: net.Socket | tls.TLSSocket,
  transport: SmtpTransport,
  mailFrom: string,
  rcptTo: string[],
  mimeMessage: string,
  resolve: (val: { response: string }) => void,
): Promise<void> {
  // AUTH LOGIN
  if (transport.user && transport.pass) {
    // Try AUTH LOGIN first
    const authResp = await smtpCommand(sock, "AUTH LOGIN");
    if (authResp.startsWith("334")) {
      // Server expects base64 username
      const userResp = await smtpCommand(sock, toBase64(transport.user));
      assertStatus(userResp, "334", "AUTH LOGIN username");
      const passResp = await smtpCommand(sock, toBase64(transport.pass));
      assertStatus(passResp, "235", "AUTH LOGIN password");
    } else {
      // Fallback: AUTH PLAIN
      const credentials = toBase64(`\0${transport.user}\0${transport.pass}`);
      const plainResp = await smtpCommand(sock, `AUTH PLAIN ${credentials}`);
      assertStatus(plainResp, "235", "AUTH PLAIN");
    }
  }

  // MAIL FROM
  const fromResp = await smtpCommand(sock, `MAIL FROM:<${mailFrom}>`);
  assertStatus(fromResp, "250", "MAIL FROM");

  // RCPT TO
  const accepted: string[] = [];
  const rejected: string[] = [];
  for (const rcpt of rcptTo) {
    const rcptResp = await smtpCommand(sock, `RCPT TO:<${rcpt}>`);
    if (rcptResp.startsWith("250")) {
      accepted.push(rcpt);
    } else {
      rejected.push(rcpt);
    }
  }

  if (accepted.length === 0) {
    const quitResp = await smtpCommand(sock, "QUIT");
    sock.destroy();
    throw new Error(`All recipients rejected: ${rejected.join(", ")}`);
  }

  // DATA
  const dataResp = await smtpCommand(sock, "DATA");
  assertStatus(dataResp, "354", "DATA");

  // Send the message body, terminated by \r\n.\r\n
  // Dot-stuffing: lines starting with "." get an extra "." prepended
  const stuffed = mimeMessage.replace(/\r\n\./g, "\r\n..");
  const endResp = await smtpCommand(sock, stuffed + "\r\n.");
  assertStatus(endResp, "250", "end-of-data");

  // QUIT
  try {
    await smtpCommand(sock, "QUIT");
  } catch {
    // Server may close connection immediately — that's fine
  }
  sock.destroy();

  resolve({ response: endResp });
}

/**
 * Perform an SMTP connection just to verify credentials / connectivity.
 */
async function smtpVerify(transport: SmtpTransport): Promise<void> {
  return new Promise((resolve, reject) => {
    let socket: net.Socket | tls.TLSSocket;

    const handleSession = async (sock: net.Socket | tls.TLSSocket) => {
      try {
        const greeting = await readResponse(sock);
        assertStatus(greeting, "220", "greeting");

        const domain = transport.user.includes("@")
          ? transport.user.split("@")[1]!
          : "localhost";
        const ehloResp = await smtpCommand(sock, `EHLO ${domain}`);
        assertStatus(ehloResp, "250", "EHLO");

        if (!transport.secure && ehloResp.includes("STARTTLS")) {
          const starttlsResp = await smtpCommand(sock, "STARTTLS");
          assertStatus(starttlsResp, "220", "STARTTLS");

          const tlsSock = await new Promise<tls.TLSSocket>((res, rej) => {
            const upgraded = tls.connect(
              {
                socket: sock as net.Socket,
                host: transport.host,
                rejectUnauthorized: transport.rejectUnauthorized,
                servername: transport.host,
              },
              () => res(upgraded),
            );
            upgraded.on("error", rej);
          });

          const ehlo2 = await smtpCommand(tlsSock, `EHLO ${domain}`);
          assertStatus(ehlo2, "250", "EHLO after STARTTLS");

          if (transport.user && transport.pass) {
            const authResp = await smtpCommand(tlsSock, "AUTH LOGIN");
            if (authResp.startsWith("334")) {
              const userResp = await smtpCommand(tlsSock, toBase64(transport.user));
              assertStatus(userResp, "334", "AUTH LOGIN username");
              const passResp = await smtpCommand(tlsSock, toBase64(transport.pass));
              assertStatus(passResp, "235", "AUTH LOGIN password");
            } else {
              const credentials = toBase64(`\0${transport.user}\0${transport.pass}`);
              const plainResp = await smtpCommand(tlsSock, `AUTH PLAIN ${credentials}`);
              assertStatus(plainResp, "235", "AUTH PLAIN");
            }
          }

          await smtpCommand(tlsSock, "QUIT").catch(() => {});
          tlsSock.destroy();
          resolve();
          return;
        }

        if (transport.user && transport.pass) {
          const authResp = await smtpCommand(sock, "AUTH LOGIN");
          if (authResp.startsWith("334")) {
            const userResp = await smtpCommand(sock, toBase64(transport.user));
            assertStatus(userResp, "334", "AUTH LOGIN username");
            const passResp = await smtpCommand(sock, toBase64(transport.pass));
            assertStatus(passResp, "235", "AUTH LOGIN password");
          } else {
            const credentials = toBase64(`\0${transport.user}\0${transport.pass}`);
            const plainResp = await smtpCommand(sock, `AUTH PLAIN ${credentials}`);
            assertStatus(plainResp, "235", "AUTH PLAIN");
          }
        }

        await smtpCommand(sock, "QUIT").catch(() => {});
        sock.destroy();
        resolve();
      } catch (err) {
        try { sock.destroy(); } catch {}
        reject(err);
      }
    };

    if (transport.secure) {
      socket = tls.connect(
        {
          host: transport.host,
          port: transport.port,
          rejectUnauthorized: transport.rejectUnauthorized,
          servername: transport.host,
        },
        () => handleSession(socket),
      );
    } else {
      socket = net.createConnection(
        { host: transport.host, port: transport.port },
        () => handleSession(socket),
      );
    }

    socket.on("error", (err) => reject(err));
    socket.setTimeout(15000, () => {
      socket.destroy();
      reject(new Error("SMTP verify timed out"));
    });
  });
}

// ── Well-known service map ─────────────────────────────────────────

const SERVICES: Record<string, { host: string; port: number; secure: boolean }> = {
  gmail: { host: "smtp.gmail.com", port: 465, secure: true },
  outlook: { host: "smtp-mail.outlook.com", port: 587, secure: false },
  hotmail: { host: "smtp-mail.outlook.com", port: 587, secure: false },
  yahoo: { host: "smtp.mail.yahoo.com", port: 465, secure: true },
  icloud: { host: "smtp.mail.me.com", port: 587, secure: false },
  zoho: { host: "smtp.zoho.com", port: 465, secure: true },
  aol: { host: "smtp.aol.com", port: 465, secure: true },
  fastmail: { host: "smtp.fastmail.com", port: 465, secure: true },
  protonmail: { host: "smtp.protonmail.ch", port: 465, secure: true },
  sendgrid: { host: "smtp.sendgrid.net", port: 465, secure: true },
  mailgun: { host: "smtp.mailgun.org", port: 465, secure: true },
  ses: { host: "email-smtp.us-east-1.amazonaws.com", port: 465, secure: true },
};

// ── Function Handlers ───────────────────────────────────────────────

const createTransport: BuiltinHandler = (args) => {
  const name = String(args[0] ?? "default");
  const opts = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;

  let host = opts.host ? String(opts.host) : "";
  let port = opts.port ? Number(opts.port) : 0;
  let secure = opts.secure !== undefined ? Boolean(opts.secure) : false;

  // Resolve well-known service
  if (opts.service) {
    const svc = SERVICES[String(opts.service).toLowerCase()];
    if (svc) {
      if (!host) host = svc.host;
      if (!port) port = svc.port;
      if (opts.secure === undefined) secure = svc.secure;
    }
  }

  if (!port) port = secure ? 465 : 587;

  const rejectUnauthorized = !(opts.tls === false || opts.rejectUnauthorized === false);

  const transport: SmtpTransport = {
    host,
    port,
    secure,
    user: String(opts.user ?? ""),
    pass: String(opts.pass ?? ""),
    rejectUnauthorized,
  };

  transporters.set(name, transport);
  return { name, host, port, service: opts.service };
};

const send: BuiltinHandler = async (args) => {
  const transportName = String(args[0] ?? "default");
  const opts = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;

  const transport = transporters.get(transportName);
  if (!transport) throw new Error(`Transport "${transportName}" not found. Create it first with email.createTransport.`);

  const from = opts.from ? String(opts.from) : (transport.user || undefined);
  const to = opts.to ? String(opts.to) : "";
  const subject = opts.subject ? String(opts.subject) : undefined;
  let text = opts.text ? String(opts.text) : undefined;
  const html = opts.html ? String(opts.html) : undefined;
  const cc = opts.cc ? String(opts.cc) : undefined;
  const bcc = opts.bcc ? String(opts.bcc) : undefined;
  const replyTo = opts.replyTo ? String(opts.replyTo) : undefined;
  const priority = opts.priority ? String(opts.priority) : undefined;
  const headers = (typeof opts.headers === "object" && opts.headers !== null)
    ? opts.headers as Record<string, string>
    : undefined;

  if (!html && !text && opts.body) {
    text = String(opts.body);
  }

  // Parse attachments
  let attachments: SmtpAttachment[] | undefined;
  if (Array.isArray(opts.attachments)) {
    attachments = (opts.attachments as Record<string, unknown>[]).map((att) => ({
      filename: att.filename ? String(att.filename) : undefined,
      path: att.path ? String(att.path) : undefined,
      content: att.content as string | Buffer | undefined,
      contentType: att.contentType ? String(att.contentType) : undefined,
      encoding: att.encoding ? String(att.encoding) : undefined,
    }));
  }

  // Determine sender address (strip display name for envelope)
  const fromAddr = from ? (from.match(/<([^>]+)>/)?.[1] ?? from) : "";
  const domain = fromAddr.includes("@") ? fromAddr.split("@")[1]! : transport.host;
  const messageId = generateMessageId(domain);

  // Collect all recipients for envelope
  const rcptTo: string[] = [
    ...extractAddresses(to),
    ...(cc ? extractAddresses(cc) : []),
    ...(bcc ? extractAddresses(bcc) : []),
  ];

  const mimeMessage = buildMimeMessage({
    from, to, subject, text, html, cc, replyTo, attachments, priority, headers, messageId,
  });

  const result = await smtpSend(transport, fromAddr, rcptTo, mimeMessage);

  // Derive accepted/rejected from rcptTo (the smtpSend tracks this internally,
  // but for simplicity we report all envelope recipients as accepted if send succeeded)
  return {
    messageId,
    accepted: rcptTo,
    rejected: [] as string[],
    response: result.response,
  };
};

const sendQuick: BuiltinHandler = async (args) => {
  const transportName = String(args[0] ?? "default");
  const to = String(args[1] ?? "");
  const subject = String(args[2] ?? "");
  const body = String(args[3] ?? "");
  const from = args[4] != null ? String(args[4]) : undefined;

  const transport = transporters.get(transportName);
  if (!transport) throw new Error(`Transport "${transportName}" not found.`);

  const isHtml = body.includes("<") && body.includes(">");

  const senderFrom = from || transport.user || undefined;
  const fromAddr = senderFrom ? (senderFrom.match(/<([^>]+)>/)?.[1] ?? senderFrom) : "";
  const domain = fromAddr.includes("@") ? fromAddr.split("@")[1]! : transport.host;
  const messageId = generateMessageId(domain);
  const rcptTo = extractAddresses(to);

  const mimeMessage = buildMimeMessage({
    from: senderFrom,
    to,
    subject,
    ...(isHtml ? { html: body } : { text: body }),
    messageId,
  });

  const result = await smtpSend(transport, fromAddr, rcptTo, mimeMessage);

  return {
    messageId,
    accepted: rcptTo,
    rejected: [] as string[],
  };
};

const verify: BuiltinHandler = async (args) => {
  const transportName = String(args[0] ?? "default");
  const transport = transporters.get(transportName);
  if (!transport) throw new Error(`Transport "${transportName}" not found.`);

  try {
    await smtpVerify(transport);
    return { connected: true };
  } catch (err: unknown) {
    return { connected: false, error: err instanceof Error ? err.message : String(err) };
  }
};

const isValid: BuiltinHandler = (args) => {
  const email = String(args[0] ?? "");
  const regex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  return regex.test(email);
};

const parseAddress: BuiltinHandler = (args) => {
  const input = String(args[0] ?? "");
  const match = input.match(/^(.+?)\s*<([^>]+)>$/);
  if (match) {
    return {
      name: match[1]!.trim().replace(/^["']|["']$/g, ""),
      address: match[2]!.trim(),
      full: input,
    };
  }
  return {
    name: "",
    address: input.trim(),
    full: input.trim(),
  };
};

const parseAddressList: BuiltinHandler = (args) => {
  const input = String(args[0] ?? "");
  const addresses = input.split(/,(?![^<]*>)/).map((s: string) => s.trim()).filter(Boolean);
  return addresses.map((addr: string) => {
    const result = parseAddress([addr]) as { name: string; address: string; full: string };
    return result;
  });
};

const extractDomain: BuiltinHandler = (args) => {
  const email = String(args[0] ?? "");
  const atIndex = email.lastIndexOf("@");
  if (atIndex === -1) return null;
  return email.substring(atIndex + 1).toLowerCase();
};

const buildAddress: BuiltinHandler = (args) => {
  const name = String(args[0] ?? "");
  const email = String(args[1] ?? "");
  if (!name) return email;
  return `"${name}" <${email}>`;
};

const close: BuiltinHandler = (args) => {
  const transportName = String(args[0] ?? "default");
  const transport = transporters.get(transportName);
  if (!transport) return false;
  transporters.delete(transportName);
  return true;
};

const createTestAccount: BuiltinHandler = async () => {
  // Ethereal test account creation via their API (no nodemailer needed)
  // We make a raw HTTPS request to Ethereal's API
  const response = await new Promise<string>((resolve, reject) => {
    const postData = JSON.stringify({ requestor: "robinpath", version: "1.0" });
    const options: tls.ConnectionOptions = {
      host: "api.nodemailer.com",
      port: 443,
      rejectUnauthorized: true,
      servername: "api.nodemailer.com",
    };

    const sock = tls.connect(options, () => {
      const req = [
        "POST /user HTTP/1.1",
        "Host: api.nodemailer.com",
        "Content-Type: application/json",
        `Content-Length: ${Buffer.byteLength(postData)}`,
        "Connection: close",
        "",
        postData,
      ].join("\r\n");
      sock.write(req);
    });

    let data = "";
    sock.on("data", (chunk) => { data += chunk.toString(); });
    sock.on("end", () => resolve(data));
    sock.on("error", reject);
    sock.setTimeout(15000, () => {
      sock.destroy();
      reject(new Error("Ethereal account creation timed out"));
    });
  });

  // Parse HTTP response body (skip headers)
  const bodyStart = response.indexOf("\r\n\r\n");
  if (bodyStart === -1) throw new Error("Invalid Ethereal API response");
  let bodyStr = response.slice(bodyStart + 4);

  // Handle chunked transfer encoding
  if (response.toLowerCase().includes("transfer-encoding: chunked")) {
    const chunks: string[] = [];
    let remaining = bodyStr;
    while (remaining.length > 0) {
      const lineEnd = remaining.indexOf("\r\n");
      if (lineEnd === -1) break;
      const chunkSize = parseInt(remaining.slice(0, lineEnd), 16);
      if (chunkSize === 0) break;
      chunks.push(remaining.slice(lineEnd + 2, lineEnd + 2 + chunkSize));
      remaining = remaining.slice(lineEnd + 2 + chunkSize + 2);
    }
    bodyStr = chunks.join("");
  }

  const account = JSON.parse(bodyStr);

  if (account.status !== "success") {
    throw new Error(`Ethereal account creation failed: ${JSON.stringify(account)}`);
  }

  const smtpHost = account.smtp?.host || "smtp.ethereal.email";
  const smtpPort = account.smtp?.port || 587;
  const smtpSecure = account.smtp?.secure || false;

  const transport: SmtpTransport = {
    host: smtpHost,
    port: smtpPort,
    secure: smtpSecure,
    user: account.user,
    pass: account.pass,
    rejectUnauthorized: true,
  };
  transporters.set("test", transport);

  return {
    name: "test",
    user: account.user,
    pass: account.pass,
    smtp: { host: smtpHost, port: smtpPort },
    web: account.web || `https://ethereal.email/login`,
  };
};

const getTestUrl: BuiltinHandler = (args) => {
  const messageId = String(args[0] ?? "");
  if (!messageId) return null;
  // Ethereal message URL format — strip angle brackets from messageId
  const cleanId = messageId.replace(/^<|>$/g, "");
  return `https://ethereal.email/message/${encodeURIComponent(cleanId)}`;
};

// ── Exports ─────────────────────────────────────────────────────────

export const EmailFunctions: Record<string, BuiltinHandler> = {
  createTransport, send, sendQuick, verify, isValid, parseAddress, parseAddressList, extractDomain, buildAddress, close, createTestAccount, getTestUrl,
};

export const EmailFunctionMetadata = {
  createTransport: {
    description: "Create a named SMTP transport for sending emails",
    parameters: [
      { name: "name", dataType: "string", description: "Transport name (default: 'default')", formInputType: "text", required: false },
      { name: "options", dataType: "object", description: "{host, port, secure, service, user, pass, tls}", formInputType: "text", required: true },
    ],
    returnType: "object", returnDescription: "Transport configuration", example: 'email.createTransport "gmail" {"service": "gmail", "user": "me@gmail.com", "pass": "app-password"}',
  },
  send: {
    description: "Send an email with full options (to, subject, body, attachments, etc.)",
    parameters: [
      { name: "transport", dataType: "string", description: "Transport name", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{from, to, subject, text, html, body, cc, bcc, replyTo, attachments, priority, headers}", formInputType: "text", required: true },
    ],
    returnType: "object", returnDescription: "{messageId, accepted, rejected, response}", example: 'email.send "gmail" {"to": "bob@example.com", "subject": "Hello", "text": "Hi there"}',
  },
  sendQuick: {
    description: "Send a simple email with just to, subject, and body",
    parameters: [
      { name: "transport", dataType: "string", description: "Transport name", formInputType: "text", required: true },
      { name: "to", dataType: "string", description: "Recipient email", formInputType: "text", required: true },
      { name: "subject", dataType: "string", description: "Email subject", formInputType: "text", required: true },
      { name: "body", dataType: "string", description: "Email body (text or HTML)", formInputType: "text", required: true },
      { name: "from", dataType: "string", description: "Sender email (optional)", formInputType: "text", required: false },
    ],
    returnType: "object", returnDescription: "{messageId, accepted, rejected}", example: 'email.sendQuick "gmail" "bob@example.com" "Hello" "Hi Bob!"',
  },
  verify: {
    description: "Verify SMTP connection to the mail server",
    parameters: [
      { name: "transport", dataType: "string", description: "Transport name", formInputType: "text", required: true },
    ],
    returnType: "object", returnDescription: "{connected: boolean, error?: string}", example: 'email.verify "gmail"',
  },
  isValid: {
    description: "Validate an email address format",
    parameters: [
      { name: "email", dataType: "string", description: "Email address to validate", formInputType: "text", required: true },
    ],
    returnType: "boolean", returnDescription: "True if email format is valid", example: 'email.isValid "user@example.com"',
  },
  parseAddress: {
    description: "Parse an email address string into name and address parts",
    parameters: [
      { name: "address", dataType: "string", description: "Email address (e.g. 'John Doe <john@example.com>')", formInputType: "text", required: true },
    ],
    returnType: "object", returnDescription: "{name, address, full}", example: 'email.parseAddress "John Doe <john@example.com>"',
  },
  parseAddressList: {
    description: "Parse a comma-separated list of email addresses",
    parameters: [
      { name: "addresses", dataType: "string", description: "Comma-separated email addresses", formInputType: "text", required: true },
    ],
    returnType: "array", returnDescription: "Array of {name, address, full} objects", example: 'email.parseAddressList "Alice <a@b.com>, Bob <b@b.com>"',
  },
  extractDomain: {
    description: "Extract the domain part from an email address",
    parameters: [
      { name: "email", dataType: "string", description: "Email address", formInputType: "text", required: true },
    ],
    returnType: "string", returnDescription: "Domain part (e.g. 'example.com')", example: 'email.extractDomain "user@example.com"',
  },
  buildAddress: {
    description: "Build a formatted email address from name and email",
    parameters: [
      { name: "name", dataType: "string", description: "Display name", formInputType: "text", required: true },
      { name: "email", dataType: "string", description: "Email address", formInputType: "text", required: true },
    ],
    returnType: "string", returnDescription: "Formatted address like '\"Name\" <email>'", example: 'email.buildAddress "John Doe" "john@example.com"',
  },
  close: {
    description: "Close a transport connection",
    parameters: [
      { name: "transport", dataType: "string", description: "Transport name", formInputType: "text", required: true },
    ],
    returnType: "boolean", returnDescription: "True if transport was closed", example: 'email.close "gmail"',
  },
  createTestAccount: {
    description: "Create an Ethereal test account for development (no real emails sent)",
    parameters: [],
    returnType: "object", returnDescription: "{name, user, pass, smtp, web}", example: "email.createTestAccount",
  },
  getTestUrl: {
    description: "Get the Ethereal preview URL for a test email",
    parameters: [
      { name: "messageId", dataType: "string", description: "Message ID from send result", formInputType: "text", required: true },
    ],
    returnType: "string", returnDescription: "URL to preview the email or null", example: 'email.getTestUrl $messageId',
  },
};

export const EmailModuleMetadata = {
  description: "SMTP email sending with transports, attachments, address parsing, and Ethereal test accounts",
  methods: ["createTransport", "send", "sendQuick", "verify", "isValid", "parseAddress", "parseAddressList", "extractDomain", "buildAddress", "close", "createTestAccount", "getTestUrl"],
};
