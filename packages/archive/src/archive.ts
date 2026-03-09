// @ts-nocheck
import type { BuiltinHandler, FunctionMetadata, ModuleMetadata, Value } from "@wiredwp/robinpath";
import {
  existsSync,
  mkdirSync,
  statSync,
  readFileSync,
  writeFileSync,
  readdirSync,
} from "node:fs";
import { join, basename, dirname, relative, normalize, sep } from "node:path";
import { deflateRawSync, inflateRawSync, gzipSync, gunzipSync, crc32 } from "node:zlib";

// ---------------------------------------------------------------------------
// ZIP format helpers (binary-level implementation)
// ---------------------------------------------------------------------------

function dosDateTime(date: Date): { time: number; date: number } {
  const t =
    ((date.getHours() & 0x1f) << 11) |
    ((date.getMinutes() & 0x3f) << 5) |
    ((date.getSeconds() >> 1) & 0x1f);
  const d =
    (((date.getFullYear() - 1980) & 0x7f) << 9) |
    (((date.getMonth() + 1) & 0x0f) << 4) |
    (date.getDate() & 0x1f);
  return { time: t, date: d };
}

function computeCrc32(buf: Buffer): number {
  // node:zlib crc32 is available since Node 20+; use it if present, otherwise fallback
  if (typeof crc32 === "function") {
    return crc32(buf) >>> 0;
  }
  // manual CRC-32 fallback
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = (c >>> 8) ^ crc32Table[(c ^ buf[i]) & 0xff];
  }
  return (c ^ 0xffffffff) >>> 0;
}

// Precomputed CRC-32 table (IEEE 802.3 polynomial)
const crc32Table: number[] = (() => {
  const table: number[] = new Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c >>> 0;
  }
  return table;
})();

interface ZipEntry {
  name: string; // path inside zip (forward slashes)
  data: Buffer; // uncompressed data
  isDirectory: boolean;
}

/** Collect all files under a directory recursively. */
function collectFiles(dirPath: string, prefix: string): ZipEntry[] {
  const entries: ZipEntry[] = [];
  const items = readdirSync(dirPath, { withFileTypes: true });
  for (const item of items) {
    const fullPath = join(dirPath, item.name);
    const entryName = prefix ? prefix + "/" + item.name : item.name;
    if (item.isDirectory()) {
      entries.push({ name: entryName + "/", data: Buffer.alloc(0), isDirectory: true });
      entries.push(...collectFiles(fullPath, entryName));
    } else {
      entries.push({ name: entryName, data: readFileSync(fullPath), isDirectory: false });
    }
  }
  return entries;
}

/** Build a ZIP buffer from an array of ZipEntry. */
function buildZipBuffer(entries: ZipEntry[], level: number = 9): Buffer {
  const localHeaders: Buffer[] = [];
  const centralEntries: Buffer[] = [];
  let offset = 0;
  const now = new Date();
  const { time: dosTime, date: dosDate } = dosDateTime(now);

  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.name, "utf-8");
    const uncompressedData = entry.data;
    const crc = entry.isDirectory ? 0 : computeCrc32(uncompressedData);
    const uncompressedSize = uncompressedData.length;

    let compressedData: Buffer;
    let method: number;

    if (entry.isDirectory || uncompressedSize === 0) {
      compressedData = Buffer.alloc(0);
      method = 0; // stored
    } else {
      compressedData = deflateRawSync(uncompressedData, { level });
      // If deflated is larger, store instead
      if (compressedData.length >= uncompressedSize) {
        compressedData = uncompressedData;
        method = 0;
      } else {
        method = 8; // deflated
      }
    }

    const compressedSize = compressedData.length;

    // Local file header (30 bytes + name + data)
    const local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(0x04034b50, 0); // signature
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6); // flags
    local.writeUInt16LE(method, 8); // compression
    local.writeUInt16LE(dosTime, 10);
    local.writeUInt16LE(dosDate, 12);
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compressedSize, 18);
    local.writeUInt32LE(uncompressedSize, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28); // extra field length
    nameBytes.copy(local, 30);

    localHeaders.push(local);
    localHeaders.push(compressedData);

    // Central directory entry (46 bytes + name)
    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(0x02014b50, 0); // signature
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(0, 8); // flags
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(dosTime, 12);
    central.writeUInt16LE(dosDate, 14);
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compressedSize, 20);
    central.writeUInt32LE(uncompressedSize, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(0, 30); // extra field length
    central.writeUInt16LE(0, 32); // comment length
    central.writeUInt16LE(0, 34); // disk number
    central.writeUInt16LE(0, 36); // internal attrs
    central.writeUInt32LE(entry.isDirectory ? 0x10 : 0, 38); // external attrs
    central.writeUInt32LE(offset, 42); // local header offset
    nameBytes.copy(central, 46);

    centralEntries.push(central);
    offset += local.length + compressedData.length;
  }

  const centralDirOffset = offset;
  let centralDirSize = 0;
  for (const c of centralEntries) centralDirSize += c.length;

  // End of Central Directory Record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // signature
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // disk with central dir
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirSize, 12);
  eocd.writeUInt32LE(centralDirOffset, 16);
  eocd.writeUInt16LE(0, 20); // comment length

  return Buffer.concat([...localHeaders, ...centralEntries, eocd]);
}

interface ParsedZipEntry {
  name: string;
  compressedSize: number;
  uncompressedSize: number;
  method: number;
  crc: number;
  dataOffset: number; // offset into the zip buffer where compressed data starts
  isDirectory: boolean;
}

/** Parse central directory from a ZIP buffer. */
function parseZipEntries(buf: Buffer): ParsedZipEntry[] {
  // Find End of Central Directory Record (scan backwards)
  let eocdOffset = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }
  if (eocdOffset === -1) throw new Error("Invalid ZIP: EOCD not found");

  const centralDirOffset = buf.readUInt32LE(eocdOffset + 16);
  const entryCount = buf.readUInt16LE(eocdOffset + 10);

  const entries: ParsedZipEntry[] = [];
  let pos = centralDirOffset;

  for (let i = 0; i < entryCount; i++) {
    if (buf.readUInt32LE(pos) !== 0x02014b50) throw new Error("Invalid ZIP central directory entry");
    const method = buf.readUInt16LE(pos + 10);
    const crc = buf.readUInt32LE(pos + 16);
    const compressedSize = buf.readUInt32LE(pos + 20);
    const uncompressedSize = buf.readUInt32LE(pos + 24);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const localHeaderOffset = buf.readUInt32LE(pos + 42);
    const name = buf.subarray(pos + 46, pos + 46 + nameLen).toString("utf-8");

    // Compute data offset from local file header
    const localNameLen = buf.readUInt16LE(localHeaderOffset + 26);
    const localExtraLen = buf.readUInt16LE(localHeaderOffset + 28);
    const dataOffset = localHeaderOffset + 30 + localNameLen + localExtraLen;

    entries.push({
      name,
      compressedSize,
      uncompressedSize,
      method,
      crc,
      dataOffset,
      isDirectory: name.endsWith("/"),
    });

    pos += 46 + nameLen + extraLen + commentLen;
  }

  return entries;
}

/** Decompress a single entry from a ZIP buffer. */
function decompressEntry(buf: Buffer, entry: ParsedZipEntry): Buffer {
  const raw = buf.subarray(entry.dataOffset, entry.dataOffset + entry.compressedSize);
  if (entry.method === 0) return Buffer.from(raw); // stored
  if (entry.method === 8) return inflateRawSync(raw); // deflated
  throw new Error(`Unsupported compression method: ${entry.method}`);
}

// ---------------------------------------------------------------------------
// TAR format helpers (512-byte block-level implementation)
// ---------------------------------------------------------------------------

function tarHeader(name: string, size: number, typeFlag: string, mode: number = 0o644): Buffer {
  const header = Buffer.alloc(512);
  // name (100 bytes)
  const nameBytes = Buffer.from(name, "utf-8");
  nameBytes.copy(header, 0, 0, Math.min(nameBytes.length, 100));
  // mode (8 bytes octal, null-terminated)
  header.write(mode.toString(8).padStart(7, "0") + "\0", 100, 8, "utf-8");
  // uid (8 bytes)
  header.write("0000000\0", 108, 8, "utf-8");
  // gid (8 bytes)
  header.write("0000000\0", 116, 8, "utf-8");
  // size (12 bytes octal, null-terminated)
  header.write(size.toString(8).padStart(11, "0") + "\0", 124, 12, "utf-8");
  // mtime (12 bytes octal)
  const mtime = Math.floor(Date.now() / 1000);
  header.write(mtime.toString(8).padStart(11, "0") + "\0", 136, 12, "utf-8");
  // checksum placeholder (8 spaces)
  header.write("        ", 148, 8, "utf-8");
  // type flag (1 byte)
  header.write(typeFlag, 156, 1, "utf-8");
  // magic "ustar\0" (6 bytes) + version "00" (2 bytes)
  header.write("ustar\0", 257, 6, "utf-8");
  header.write("00", 263, 2, "utf-8");

  // Compute checksum: sum of all unsigned bytes treating checksum field as spaces
  let cksum = 0;
  for (let i = 0; i < 512; i++) cksum += header[i];
  header.write(cksum.toString(8).padStart(6, "0") + "\0 ", 148, 8, "utf-8");

  return header;
}

function collectTarEntries(dirPath: string, prefix: string): Buffer[] {
  const blocks: Buffer[] = [];
  const items = readdirSync(dirPath, { withFileTypes: true });
  for (const item of items) {
    const fullPath = join(dirPath, item.name);
    const entryName = prefix ? prefix + "/" + item.name : item.name;
    if (item.isDirectory()) {
      blocks.push(tarHeader(entryName + "/", 0, "5", 0o755));
      blocks.push(...collectTarEntries(fullPath, entryName));
    } else {
      const data = readFileSync(fullPath);
      blocks.push(tarHeader(entryName, data.length, "0", 0o644));
      blocks.push(data);
      // Pad to 512-byte boundary
      const remainder = data.length % 512;
      if (remainder > 0) blocks.push(Buffer.alloc(512 - remainder));
    }
  }
  return blocks;
}

function buildTarBuffer(sources: { name: string; fullPath: string }[]): Buffer {
  const blocks: Buffer[] = [];
  for (const src of sources) {
    const stat = statSync(src.fullPath);
    if (stat.isDirectory()) {
      blocks.push(tarHeader(src.name + "/", 0, "5", 0o755));
      blocks.push(...collectTarEntries(src.fullPath, src.name));
    } else {
      const data = readFileSync(src.fullPath);
      blocks.push(tarHeader(src.name, data.length, "0", 0o644));
      blocks.push(data);
      const remainder = data.length % 512;
      if (remainder > 0) blocks.push(Buffer.alloc(512 - remainder));
    }
  }
  // Two 512-byte zero blocks mark end of archive
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

function extractTarBuffer(tarBuf: Buffer, outputDir: string): void {
  let pos = 0;
  while (pos + 512 <= tarBuf.length) {
    const header = tarBuf.subarray(pos, pos + 512);
    // Check for end-of-archive (all zeros)
    let allZero = true;
    for (let i = 0; i < 512; i++) {
      if (header[i] !== 0) { allZero = false; break; }
    }
    if (allZero) break;

    // Parse name (bytes 0-99, null-terminated)
    let nameEnd = 0;
    while (nameEnd < 100 && header[nameEnd] !== 0) nameEnd++;
    const name = header.subarray(0, nameEnd).toString("utf-8");

    // Parse size (bytes 124-135, octal, null-terminated)
    const sizeStr = header.subarray(124, 136).toString("utf-8").replace(/\0/g, "").trim();
    const size = parseInt(sizeStr, 8) || 0;

    // Type flag (byte 156)
    const typeFlag = String.fromCharCode(header[156]);

    const outPath = join(outputDir, name.replace(/\//g, sep));

    if (typeFlag === "5" || name.endsWith("/")) {
      // Directory
      mkdirSync(outPath, { recursive: true });
    } else {
      // Regular file
      const dir = dirname(outPath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      const data = tarBuf.subarray(pos + 512, pos + 512 + size);
      writeFileSync(outPath, data);
    }

    // Advance past header + data (padded to 512)
    const dataBlocks = Math.ceil(size / 512);
    pos += 512 + dataBlocks * 512;
  }
}

// ---------------------------------------------------------------------------
// BuiltinHandler implementations
// ---------------------------------------------------------------------------

const createZip: BuiltinHandler = async (args) => {
  const outputPath = String(args[0] ?? "archive.zip");
  const sources = Array.isArray(args[1]) ? args[1].map(String) : [String(args[1] ?? "")];
  const opts = (typeof args[2] === "object" && args[2] !== null ? args[2] : {}) as Record<string, unknown>;
  const level = Number(opts.level ?? 9);

  const entries: ZipEntry[] = [];
  let fileCount = 0;

  for (const src of sources) {
    if (!existsSync(src)) continue;
    if (statSync(src).isDirectory()) {
      const dirName = basename(src);
      entries.push({ name: dirName + "/", data: Buffer.alloc(0), isDirectory: true });
      entries.push(...collectFiles(src, dirName));
    } else {
      entries.push({ name: basename(src), data: readFileSync(src), isDirectory: false });
      fileCount++;
    }
  }

  // Count non-directory entries
  fileCount = entries.filter((e) => !e.isDirectory).length;

  const zipBuffer = buildZipBuffer(entries, level);
  writeFileSync(outputPath, zipBuffer);

  return { path: outputPath, size: zipBuffer.length, files: fileCount };
};

const extractZip: BuiltinHandler = (args) => {
  const zipPath = String(args[0] ?? "");
  const outputDir = String(args[1] ?? "./extracted");
  if (!existsSync(outputDir)) mkdirSync(outputDir, { recursive: true });

  const buf = readFileSync(zipPath);
  const parsed = parseZipEntries(buf);

  for (const entry of parsed) {
    const outPath = join(outputDir, entry.name.replace(/\//g, sep));
    if (entry.isDirectory) {
      mkdirSync(outPath, { recursive: true });
    } else {
      const dir = dirname(outPath);
      if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
      writeFileSync(outPath, decompressEntry(buf, entry));
    }
  }

  const entries = parsed.map((e) => ({
    name: e.name,
    size: e.uncompressedSize,
    isDirectory: e.isDirectory,
  }));

  return { path: outputDir, files: entries.length, entries };
};

const listZip: BuiltinHandler = (args) => {
  const zipPath = String(args[0] ?? "");
  const buf = readFileSync(zipPath);
  const parsed = parseZipEntries(buf);
  return parsed.map((e) => ({
    name: e.name,
    size: e.uncompressedSize,
    compressedSize: e.compressedSize,
    isDirectory: e.isDirectory,
  }));
};

const readFromZip: BuiltinHandler = (args) => {
  const zipPath = String(args[0] ?? "");
  const entryName = String(args[1] ?? "");
  const buf = readFileSync(zipPath);
  const parsed = parseZipEntries(buf);
  const entry = parsed.find((e) => e.name === entryName);
  if (!entry) return null;
  return decompressEntry(buf, entry).toString("utf-8");
};

const createTarGz: BuiltinHandler = async (args) => {
  const outputPath = String(args[0] ?? "archive.tar.gz");
  const sourceDir = String(args[1] ?? "");
  const opts = (typeof args[2] === "object" && args[2] !== null ? args[2] : {}) as Record<string, unknown>;
  const level = Number(opts.level ?? 9);

  if (!existsSync(sourceDir)) {
    throw new Error(`Source not found: ${sourceDir}`);
  }

  const sources = [{ name: basename(sourceDir), fullPath: sourceDir }];
  const tarBuf = buildTarBuffer(sources);
  const gzBuf = gzipSync(tarBuf, { level });
  writeFileSync(outputPath, gzBuf);

  return { path: outputPath };
};

const extractTarGz: BuiltinHandler = async (args) => {
  const tarPath = String(args[0] ?? "");
  const outputDir = String(args[1] ?? "./extracted");
  if (!existsSync(outputDir)) mkdirSync(outputDir, { recursive: true });

  const gzBuf = readFileSync(tarPath);
  const tarBuf = gunzipSync(gzBuf);
  extractTarBuffer(tarBuf, outputDir);

  return { path: outputDir };
};

const addToZip: BuiltinHandler = (args) => {
  const zipPath = String(args[0] ?? "");
  const filePath = String(args[1] ?? "");
  const entryName = String(args[2] ?? basename(filePath));

  // Read existing entries if zip exists
  let existingEntries: ZipEntry[] = [];
  if (existsSync(zipPath)) {
    const buf = readFileSync(zipPath);
    const parsed = parseZipEntries(buf);
    existingEntries = parsed.map((e) => ({
      name: e.name,
      data: e.isDirectory ? Buffer.alloc(0) : decompressEntry(buf, e),
      isDirectory: e.isDirectory,
    }));
  }

  // Add new entries
  if (existsSync(filePath) && statSync(filePath).isDirectory()) {
    existingEntries.push({ name: entryName + "/", data: Buffer.alloc(0), isDirectory: true });
    existingEntries.push(...collectFiles(filePath, entryName));
  } else if (existsSync(filePath)) {
    existingEntries.push({ name: entryName, data: readFileSync(filePath), isDirectory: false });
  }

  const zipBuffer = buildZipBuffer(existingEntries);
  writeFileSync(zipPath, zipBuffer);

  return { path: zipPath, added: entryName };
};

const removeFromZip: BuiltinHandler = (args) => {
  const zipPath = String(args[0] ?? "");
  const entryName = String(args[1] ?? "");

  const buf = readFileSync(zipPath);
  const parsed = parseZipEntries(buf);

  const remaining: ZipEntry[] = parsed
    .filter((e) => e.name !== entryName)
    .map((e) => ({
      name: e.name,
      data: e.isDirectory ? Buffer.alloc(0) : decompressEntry(buf, e),
      isDirectory: e.isDirectory,
    }));

  const zipBuffer = buildZipBuffer(remaining);
  writeFileSync(zipPath, zipBuffer);

  return true;
};

export const ArchiveFunctions: Record<string, BuiltinHandler> = { createZip, extractZip, listZip, readFromZip, createTarGz, extractTarGz, addToZip, removeFromZip };

export const ArchiveFunctionMetadata = {
  createZip: { description: "Create a .zip archive from files and directories", parameters: [{ name: "output", dataType: "string", description: "Output .zip path", formInputType: "text", required: true }, { name: "sources", dataType: "array", description: "Files/dirs to archive", formInputType: "text", required: true }, { name: "options", dataType: "object", description: "{level: 1-9}", formInputType: "text", required: false }], returnType: "object", returnDescription: "{path, size, files}", example: 'archive.createZip "./backup.zip" ["./src", "./package.json"]' },
  extractZip: { description: "Extract a .zip archive", parameters: [{ name: "zipPath", dataType: "string", description: ".zip file path", formInputType: "text", required: true }, { name: "outputDir", dataType: "string", description: "Extraction directory", formInputType: "text", required: true }], returnType: "object", returnDescription: "{path, files, entries}", example: 'archive.extractZip "./backup.zip" "./restored"' },
  listZip: { description: "List entries in a .zip file", parameters: [{ name: "zipPath", dataType: "string", description: ".zip file path", formInputType: "text", required: true }], returnType: "array", returnDescription: "Array of entry info", example: 'archive.listZip "./backup.zip"' },
  readFromZip: { description: "Read a file from inside a .zip without extracting", parameters: [{ name: "zipPath", dataType: "string", description: ".zip file path", formInputType: "text", required: true }, { name: "entry", dataType: "string", description: "Entry name", formInputType: "text", required: true }], returnType: "string", returnDescription: "File contents as string", example: 'archive.readFromZip "./backup.zip" "config.json"' },
  createTarGz: { description: "Create a .tar.gz archive", parameters: [{ name: "output", dataType: "string", description: "Output path", formInputType: "text", required: true }, { name: "source", dataType: "string", description: "Source dir/file", formInputType: "text", required: true }], returnType: "object", returnDescription: "{path}", example: 'archive.createTarGz "./backup.tar.gz" "./src"' },
  extractTarGz: { description: "Extract a .tar.gz archive", parameters: [{ name: "tarPath", dataType: "string", description: ".tar.gz path", formInputType: "text", required: true }, { name: "outputDir", dataType: "string", description: "Extraction directory", formInputType: "text", required: true }], returnType: "object", returnDescription: "{path}", example: 'archive.extractTarGz "./backup.tar.gz" "./restored"' },
  addToZip: { description: "Add a file or directory to an existing .zip", parameters: [{ name: "zipPath", dataType: "string", description: ".zip file path", formInputType: "text", required: true }, { name: "filePath", dataType: "string", description: "File to add", formInputType: "text", required: true }, { name: "entryName", dataType: "string", description: "Name inside zip", formInputType: "text", required: false }], returnType: "object", returnDescription: "{path, added}", example: 'archive.addToZip "./backup.zip" "./newfile.txt"' },
  removeFromZip: { description: "Remove an entry from a .zip", parameters: [{ name: "zipPath", dataType: "string", description: ".zip file path", formInputType: "text", required: true }, { name: "entry", dataType: "string", description: "Entry name to remove", formInputType: "text", required: true }], returnType: "boolean", returnDescription: "True", example: 'archive.removeFromZip "./backup.zip" "old.txt"' },
};

export const ArchiveModuleMetadata = {
  description: "Create, extract, and manipulate .zip and .tar.gz archives",
  methods: ["createZip", "extractZip", "listZip", "readFromZip", "createTarGz", "extractTarGz", "addToZip", "removeFromZip"],
};
