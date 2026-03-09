import type { BuiltinHandler, FunctionMetadata, ModuleMetadata } from "@wiredwp/robinpath";
import * as fs from "node:fs";
import * as path from "node:path";
import { deflateRawSync, inflateRawSync } from "node:zlib";

// ── CRC-32 ──────────────────────────────────────────────────────────

const crcTable: number[] = (() => {
  const table: number[] = new Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    }
    table[n] = c;
  }
  return table;
})();

function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    crc = crcTable[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

// ── XML Helpers ─────────────────────────────────────────────────────

function escapeXml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

/** Minimal XML tag-content extractor (non-greedy). Returns all matches. */
function xmlFindAll(xml: string, tag: string): string[] {
  const results: string[] = [];
  // Self-closing tags return ""
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?\\/?>|<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)<\\/${tag}>`, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    results.push(m[1] ?? "");
  }
  return results;
}

function xmlAttr(tag: string, attr: string): string | undefined {
  const re = new RegExp(`${attr}="([^"]*)"`, "i");
  const m = re.exec(tag);
  return m ? m[1] : undefined;
}

function xmlFindTags(xml: string, tag: string): string[] {
  const results: string[] = [];
  const re = new RegExp(`<${tag}\\b[^>]*\\/?>|<${tag}\\b[^>]*>[\\s\\S]*?<\\/${tag}>`, "g");
  let m: RegExpExecArray | null;
  while ((m = re.exec(xml)) !== null) {
    results.push(m[0]);
  }
  return results;
}

// ── Cell Reference Helpers ──────────────────────────────────────────

function colLetterToIndex(col: string): number {
  let idx = 0;
  for (let i = 0; i < col.length; i++) {
    idx = idx * 26 + (col.charCodeAt(i) - 64);
  }
  return idx; // 1-based
}

function indexToColLetter(idx: number): string {
  let s = "";
  while (idx > 0) {
    idx--;
    s = String.fromCharCode(65 + (idx % 26)) + s;
    idx = Math.floor(idx / 26);
  }
  return s;
}

function parseCellRef(ref: string): { col: number; row: number } {
  const m = /^([A-Z]+)(\d+)$/i.exec(ref);
  if (!m) throw new Error(`Invalid cell reference: ${ref}`);
  return { col: colLetterToIndex(m[1].toUpperCase()), row: parseInt(m[2], 10) };
}

// ── XLSX Date Helpers ───────────────────────────────────────────────

const EXCEL_EPOCH = new Date(1899, 11, 30).getTime(); // Dec 30, 1899

function dateToExcelSerial(d: Date): number {
  const ms = d.getTime() - EXCEL_EPOCH;
  return ms / 86400000;
}

function excelSerialToDate(serial: number): Date {
  return new Date(EXCEL_EPOCH + serial * 86400000);
}

function isDateValue(v: unknown): v is Date {
  return v instanceof Date;
}

// ── ZIP Reader ──────────────────────────────────────────────────────

interface ZipEntry {
  name: string;
  compressedData: Buffer;
  compressionMethod: number;
  uncompressedSize: number;
  compressedSize: number;
  crc: number;
}

function readZip(buf: Buffer): Map<string, Buffer> {
  const files = new Map<string, Buffer>();

  // Find End of Central Directory record
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

  let offset = centralDirOffset;
  for (let i = 0; i < entryCount; i++) {
    if (buf.readUInt32LE(offset) !== 0x02014b50) throw new Error("Invalid central directory header");

    const compressionMethod = buf.readUInt16LE(offset + 10);
    const compressedSize = buf.readUInt32LE(offset + 20);
    const uncompressedSize = buf.readUInt32LE(offset + 24);
    const nameLen = buf.readUInt16LE(offset + 28);
    const extraLen = buf.readUInt16LE(offset + 30);
    const commentLen = buf.readUInt16LE(offset + 32);
    const localHeaderOffset = buf.readUInt32LE(offset + 42);

    const name = buf.toString("utf8", offset + 46, offset + 46 + nameLen);
    offset += 46 + nameLen + extraLen + commentLen;

    // Read local file header to get actual data offset
    const localNameLen = buf.readUInt16LE(localHeaderOffset + 26);
    const localExtraLen = buf.readUInt16LE(localHeaderOffset + 28);
    const dataOffset = localHeaderOffset + 30 + localNameLen + localExtraLen;

    const compressedData = buf.subarray(dataOffset, dataOffset + compressedSize);

    let data: Buffer;
    if (compressionMethod === 0) {
      data = compressedData;
    } else if (compressionMethod === 8) {
      data = inflateRawSync(compressedData);
    } else {
      continue; // skip unsupported
    }

    files.set(name, data);
  }

  return files;
}

// ── ZIP Writer ──────────────────────────────────────────────────────

interface ZipFileEntry {
  name: string;
  data: Buffer;
}

function buildZip(entries: ZipFileEntry[]): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let localOffset = 0;

  for (const entry of entries) {
    const nameBuffer = Buffer.from(entry.name, "utf8");
    const uncompressedCrc = crc32(entry.data);
    const compressed = deflateRawSync(entry.data);

    // Use compressed only if it's actually smaller
    const useDeflate = compressed.length < entry.data.length;
    const storedData = useDeflate ? compressed : entry.data;
    const method = useDeflate ? 8 : 0;

    // Local file header (30 bytes + name + data)
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0); // signature
    localHeader.writeUInt16LE(20, 4);          // version needed
    localHeader.writeUInt16LE(0, 6);           // flags
    localHeader.writeUInt16LE(method, 8);      // compression
    localHeader.writeUInt16LE(0, 10);          // mod time
    localHeader.writeUInt16LE(0, 12);          // mod date
    localHeader.writeUInt32LE(uncompressedCrc, 14);
    localHeader.writeUInt32LE(storedData.length, 18);
    localHeader.writeUInt32LE(entry.data.length, 22);
    localHeader.writeUInt16LE(nameBuffer.length, 26);
    localHeader.writeUInt16LE(0, 28);          // extra field length

    localParts.push(localHeader, nameBuffer, storedData);

    // Central directory header (46 bytes + name)
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0); // signature
    centralHeader.writeUInt16LE(20, 4);          // version made by
    centralHeader.writeUInt16LE(20, 6);          // version needed
    centralHeader.writeUInt16LE(0, 8);           // flags
    centralHeader.writeUInt16LE(method, 10);     // compression
    centralHeader.writeUInt16LE(0, 12);          // mod time
    centralHeader.writeUInt16LE(0, 14);          // mod date
    centralHeader.writeUInt32LE(uncompressedCrc, 16);
    centralHeader.writeUInt32LE(storedData.length, 20);
    centralHeader.writeUInt32LE(entry.data.length, 24);
    centralHeader.writeUInt16LE(nameBuffer.length, 28);
    centralHeader.writeUInt16LE(0, 30);          // extra field length
    centralHeader.writeUInt16LE(0, 32);          // comment length
    centralHeader.writeUInt16LE(0, 34);          // disk number start
    centralHeader.writeUInt16LE(0, 36);          // internal attrs
    centralHeader.writeUInt32LE(0, 38);          // external attrs
    centralHeader.writeUInt32LE(localOffset, 42); // local header offset

    centralParts.push(centralHeader, nameBuffer);

    localOffset += 30 + nameBuffer.length + storedData.length;
  }

  const centralDirSize = centralParts.reduce((a, b) => a + b.length, 0);

  // End of Central Directory Record (22 bytes)
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);                     // disk number
  eocd.writeUInt16LE(0, 6);                     // disk with central dir
  eocd.writeUInt16LE(entries.length, 8);         // entries on this disk
  eocd.writeUInt16LE(entries.length, 10);        // total entries
  eocd.writeUInt32LE(centralDirSize, 12);
  eocd.writeUInt32LE(localOffset, 16);           // central dir offset
  eocd.writeUInt16LE(0, 20);                     // comment length

  return Buffer.concat([...localParts, ...centralParts, eocd]);
}

// ── XLSX XML Generation ─────────────────────────────────────────────

interface SheetData {
  name: string;
  rows: Record<string, unknown>[];
  headers: string[];
  colWidth: number;
  boldHeaders: boolean;
  headerColor?: string;
  autoFilter: boolean;
}

interface CellInfo {
  row: number;
  col: number;
  value: unknown;
}

function buildContentTypes(sheetCount: number): string {
  let sheets = "";
  for (let i = 1; i <= sheetCount; i++) {
    sheets += `<Override PartName="/xl/worksheets/sheet${i}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>`;
  }
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>
<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
${sheets}
</Types>`;
}

function buildRels(): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`;
}

function buildWorkbook(sheets: { name: string }[]): string {
  const sheetTags = sheets.map((s, i) =>
    `<sheet name="${escapeXml(s.name)}" sheetId="${i + 1}" r:id="rId${i + 1}"/>`
  ).join("");
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<sheets>${sheetTags}</sheets>
</workbook>`;
}

function buildWorkbookRels(sheetCount: number): string {
  const rels: string[] = [];
  for (let i = 1; i <= sheetCount; i++) {
    rels.push(`<Relationship Id="rId${i}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet${i}.xml"/>`);
  }
  rels.push(`<Relationship Id="rId${sheetCount + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>`);
  rels.push(`<Relationship Id="rId${sheetCount + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>`);
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
${rels.join("\n")}
</Relationships>`;
}

function buildStyles(hasHeaderColor: boolean, headerColorArgb?: string): string {
  // Style index 0: default, Style index 1: bold header, Style index 2: date format
  const fillSection = hasHeaderColor && headerColorArgb
    ? `<fills count="3">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
<fill><patternFill patternType="solid"><fgColor rgb="${headerColorArgb}"/></patternFill></fill>
</fills>`
    : `<fills count="2">
<fill><patternFill patternType="none"/></fill>
<fill><patternFill patternType="gray125"/></fill>
</fills>`;

  const boldFillId = hasHeaderColor ? 2 : 0;

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
<numFmts count="1">
<numFmt numFmtId="164" formatCode="yyyy-mm-dd"/>
</numFmts>
<fonts count="2">
<font><sz val="11"/><name val="Calibri"/></font>
<font><b/><sz val="11"/><name val="Calibri"/></font>
</fonts>
${fillSection}
<borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="3">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="${boldFillId}" borderId="0" xfId="0" applyFont="1"${hasHeaderColor ? ' applyFill="1"' : ""}/>
<xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1"/>
</cellXfs>
</styleSheet>`;
}

function buildSharedStrings(strings: string[]): string {
  const items = strings.map(s => `<si><t>${escapeXml(s)}</t></si>`).join("");
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="${strings.length}" uniqueCount="${strings.length}">
${items}
</sst>`;
}

function buildSheet(sheet: SheetData, sharedStringMap: Map<string, number>): string {
  const { rows, headers, colWidth, boldHeaders, autoFilter } = sheet;
  const colCount = headers.length;

  // Column definitions
  let colsDef = "";
  if (colWidth > 0) {
    const cols = headers.map((_, i) =>
      `<col min="${i + 1}" max="${i + 1}" width="${colWidth}" customWidth="1"/>`
    ).join("");
    colsDef = `<cols>${cols}</cols>`;
  }

  // Build rows
  const rowXmls: string[] = [];

  // Header row
  if (headers.length > 0) {
    const cells = headers.map((h, ci) => {
      const ref = `${indexToColLetter(ci + 1)}1`;
      const sIdx = sharedStringMap.get(h);
      const styleAttr = boldHeaders ? ` s="1"` : "";
      return `<c r="${ref}" t="s"${styleAttr}><v>${sIdx}</v></c>`;
    }).join("");
    rowXmls.push(`<row r="1">${cells}</row>`);
  }

  // Data rows
  for (let ri = 0; ri < rows.length; ri++) {
    const row = rows[ri];
    const rowNum = ri + 2; // 1-based, after header
    const cells: string[] = [];

    for (let ci = 0; ci < headers.length; ci++) {
      const key = headers[ci];
      const val = row[key];
      if (val === undefined || val === null) continue;

      const ref = `${indexToColLetter(ci + 1)}${rowNum}`;

      if (typeof val === "number") {
        cells.push(`<c r="${ref}"><v>${val}</v></c>`);
      } else if (typeof val === "boolean") {
        cells.push(`<c r="${ref}" t="b"><v>${val ? 1 : 0}</v></c>`);
      } else if (isDateValue(val)) {
        const serial = dateToExcelSerial(val);
        cells.push(`<c r="${ref}" s="2"><v>${serial}</v></c>`);
      } else {
        const str = String(val);
        let sIdx = sharedStringMap.get(str);
        if (sIdx === undefined) {
          sIdx = sharedStringMap.size;
          sharedStringMap.set(str, sIdx);
        }
        cells.push(`<c r="${ref}" t="s"><v>${sIdx}</v></c>`);
      }
    }

    if (cells.length > 0) {
      rowXmls.push(`<row r="${rowNum}">${cells.join("")}</row>`);
    }
  }

  const lastCol = indexToColLetter(colCount);
  const lastRow = rows.length + 1;
  const dimension = `A1:${lastCol}${lastRow}`;
  const autoFilterXml = autoFilter && headers.length > 0
    ? `<autoFilter ref="A1:${lastCol}1"/>`
    : "";

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
<dimension ref="${dimension}"/>
<sheetViews><sheetView tabSelected="1" workbookViewId="0"/></sheetViews>
<sheetFormatPr defaultRowHeight="15"/>
${colsDef}
<sheetData>${rowXmls.join("")}</sheetData>
${autoFilterXml}
</worksheet>`;
}

function writeXlsx(filePath: string, sheets: SheetData[]): void {
  const sharedStringMap = new Map<string, number>();

  // First pass: collect all shared strings (headers + string values)
  for (const sheet of sheets) {
    for (const h of sheet.headers) {
      if (!sharedStringMap.has(h)) sharedStringMap.set(h, sharedStringMap.size);
    }
    for (const row of sheet.rows) {
      for (const key of sheet.headers) {
        const val = row[key];
        if (val !== undefined && val !== null && typeof val === "string") {
          if (!sharedStringMap.has(val)) sharedStringMap.set(val, sharedStringMap.size);
        }
      }
    }
  }

  const hasHeaderColor = sheets.some(s => !!s.headerColor);
  const headerColorArgb = sheets.find(s => !!s.headerColor)?.headerColor;

  const sharedStringsArray = Array.from(sharedStringMap.entries())
    .sort((a, b) => a[1] - b[1])
    .map(e => e[0]);

  const zipEntries: ZipFileEntry[] = [];

  zipEntries.push({ name: "[Content_Types].xml", data: Buffer.from(buildContentTypes(sheets.length), "utf8") });
  zipEntries.push({ name: "_rels/.rels", data: Buffer.from(buildRels(), "utf8") });
  zipEntries.push({ name: "xl/workbook.xml", data: Buffer.from(buildWorkbook(sheets), "utf8") });
  zipEntries.push({ name: "xl/_rels/workbook.xml.rels", data: Buffer.from(buildWorkbookRels(sheets.length), "utf8") });
  zipEntries.push({ name: "xl/styles.xml", data: Buffer.from(buildStyles(hasHeaderColor, headerColorArgb), "utf8") });

  for (let i = 0; i < sheets.length; i++) {
    zipEntries.push({
      name: `xl/worksheets/sheet${i + 1}.xml`,
      data: Buffer.from(buildSheet(sheets[i], sharedStringMap), "utf8"),
    });
  }

  zipEntries.push({ name: "xl/sharedStrings.xml", data: Buffer.from(buildSharedStrings(sharedStringsArray), "utf8") });

  const zipBuffer = buildZip(zipEntries);
  const dir = path.dirname(filePath);
  if (dir && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(filePath, zipBuffer);
}

// ── XLSX Reader ─────────────────────────────────────────────────────

interface ParsedSheet {
  name: string;
  cells: Map<string, { value: unknown; formula?: string; type: string }>;
  maxRow: number;
  maxCol: number;
}

interface ParsedWorkbook {
  sheets: ParsedSheet[];
  sheetNames: string[];
}

function parseSharedStrings(xml: string): string[] {
  const strings: string[] = [];
  const siMatches = xmlFindTags(xml, "si");
  for (const si of siMatches) {
    // Handle <t> directly inside <si>
    const tMatch = /<t[^>]*>([\s\S]*?)<\/t>/g;
    const parts: string[] = [];
    let m: RegExpExecArray | null;
    while ((m = tMatch.exec(si)) !== null) {
      parts.push(m[1]);
    }
    strings.push(parts.join(""));
  }
  return strings;
}

function parseSheetXml(xml: string, sharedStrings: string[]): Map<string, { value: unknown; formula?: string; type: string }> {
  const cells = new Map<string, { value: unknown; formula?: string; type: string }>();

  const cTags = xmlFindTags(xml, "c");
  for (const cTag of cTags) {
    const refMatch = /r="([A-Z]+\d+)"/i.exec(cTag);
    if (!refMatch) continue;
    const ref = refMatch[1];

    const typeMatch = /\bt="([^"]*)"/i.exec(cTag);
    const cellType = typeMatch ? typeMatch[1] : "";
    const styleMatch = /\bs="(\d+)"/i.exec(cTag);
    const styleIdx = styleMatch ? parseInt(styleMatch[1], 10) : 0;

    // Extract value
    const vMatch = /<v>([\s\S]*?)<\/v>/.exec(cTag);
    const rawValue = vMatch ? vMatch[1] : undefined;

    // Extract formula
    const fMatch = /<f>([\s\S]*?)<\/f>/.exec(cTag);
    const formula = fMatch ? fMatch[1] : undefined;

    // Extract inline string
    const isMatch = /<is>\s*<t[^>]*>([\s\S]*?)<\/t>\s*<\/is>/.exec(cTag);

    let value: unknown;
    let type = "string";

    if (cellType === "s" && rawValue !== undefined) {
      // Shared string
      const idx = parseInt(rawValue, 10);
      value = sharedStrings[idx] ?? "";
      type = "string";
    } else if (cellType === "inlineStr" || isMatch) {
      value = isMatch ? isMatch[1] : "";
      type = "string";
    } else if (cellType === "b") {
      value = rawValue === "1";
      type = "boolean";
    } else if (cellType === "e") {
      value = rawValue ?? "#ERROR";
      type = "error";
    } else if (rawValue !== undefined) {
      const num = parseFloat(rawValue);
      // Check if this is a date style (style index 2 is our date format)
      if (styleIdx === 2 || (styleIdx >= 14 && styleIdx <= 22)) {
        value = excelSerialToDate(num);
        type = "date";
      } else {
        value = isNaN(num) ? rawValue : num;
        type = typeof value === "number" ? "number" : "string";
      }
    } else {
      value = null;
      type = "null";
    }

    cells.set(ref, { value, formula, type });
  }

  return cells;
}

function readXlsx(filePath: string): ParsedWorkbook {
  const buf = fs.readFileSync(filePath);
  const files = readZip(buf);

  // Parse shared strings
  const ssXml = files.get("xl/sharedStrings.xml");
  const sharedStrings = ssXml ? parseSharedStrings(ssXml.toString("utf8")) : [];

  // Parse workbook to get sheet names and ordering
  const wbXml = files.get("xl/workbook.xml");
  if (!wbXml) throw new Error("Invalid XLSX: missing workbook.xml");

  const wbContent = wbXml.toString("utf8");
  const sheetTags = xmlFindTags(wbContent, "sheet");
  const sheetInfos: { name: string; rId: string }[] = [];
  for (const tag of sheetTags) {
    const name = xmlAttr(tag, "name") ?? "Sheet";
    const rId = xmlAttr(tag, "r:id") ?? "";
    sheetInfos.push({ name, rId });
  }

  // Parse workbook.xml.rels to map rId -> target
  const wbRelsXml = files.get("xl/_rels/workbook.xml.rels");
  const rIdMap = new Map<string, string>();
  if (wbRelsXml) {
    const relTags = xmlFindTags(wbRelsXml.toString("utf8"), "Relationship");
    for (const tag of relTags) {
      const id = xmlAttr(tag, "Id") ?? "";
      const target = xmlAttr(tag, "Target") ?? "";
      rIdMap.set(id, target);
    }
  }

  const sheets: ParsedSheet[] = [];
  for (const info of sheetInfos) {
    const target = rIdMap.get(info.rId) ?? "";
    const sheetPath = target.startsWith("/") ? target.slice(1) : `xl/${target}`;
    const sheetXml = files.get(sheetPath);
    if (!sheetXml) continue;

    const cells = parseSheetXml(sheetXml.toString("utf8"), sharedStrings);

    let maxRow = 0;
    let maxCol = 0;
    for (const ref of cells.keys()) {
      const parsed = parseCellRef(ref);
      if (parsed.row > maxRow) maxRow = parsed.row;
      if (parsed.col > maxCol) maxCol = parsed.col;
    }

    sheets.push({ name: info.name, cells, maxRow, maxCol });
  }

  return {
    sheets,
    sheetNames: sheetInfos.map(s => s.name),
  };
}

// ── Helper: Convert parsed sheet to rows ────────────────────────────

function sheetToRows(sheet: ParsedSheet, useHeaders: boolean): { rows: Record<string, unknown>[]; headers: string[] } {
  const headers: string[] = [];
  const rows: Record<string, unknown>[] = [];

  if (sheet.maxRow === 0) return { rows, headers };

  // Build headers from row 1
  if (useHeaders) {
    for (let c = 1; c <= sheet.maxCol; c++) {
      const ref = `${indexToColLetter(c)}1`;
      const cell = sheet.cells.get(ref);
      headers.push(cell?.value != null ? String(cell.value) : `col${c}`);
    }

    // Build data rows
    for (let r = 2; r <= sheet.maxRow; r++) {
      const obj: Record<string, unknown> = {};
      let hasValue = false;
      for (let c = 1; c <= sheet.maxCol; c++) {
        const ref = `${indexToColLetter(c)}${r}`;
        const cell = sheet.cells.get(ref);
        if (cell?.value !== undefined && cell.value !== null) {
          obj[headers[c - 1]] = cell.value;
          hasValue = true;
        }
      }
      if (hasValue) rows.push(obj);
    }
  } else {
    // No headers - use col1, col2, etc.
    for (let c = 1; c <= sheet.maxCol; c++) {
      headers.push(`col${c}`);
    }
    for (let r = 1; r <= sheet.maxRow; r++) {
      const obj: Record<string, unknown> = {};
      let hasValue = false;
      for (let c = 1; c <= sheet.maxCol; c++) {
        const ref = `${indexToColLetter(c)}${r}`;
        const cell = sheet.cells.get(ref);
        if (cell?.value !== undefined && cell.value !== null) {
          obj[headers[c - 1]] = cell.value;
          hasValue = true;
        }
      }
      if (hasValue) rows.push(obj);
    }
  }

  return { rows, headers };
}

// ── Helper: Merge a new sheet into existing workbook data ───────────

function readExistingSheets(filePath: string): SheetData[] {
  try {
    const wb = readXlsx(filePath);
    const sheets: SheetData[] = [];
    for (const parsed of wb.sheets) {
      const { rows, headers } = sheetToRows(parsed, true);
      sheets.push({
        name: parsed.name,
        rows,
        headers,
        colWidth: 15,
        boldHeaders: true,
        autoFilter: false,
      });
    }
    return sheets;
  } catch {
    return [];
  }
}

// ── Function Handlers ───────────────────────────────────────────────

const read: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "");
  const opts = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;
  const sheetName = opts.sheet ? String(opts.sheet) : undefined;

  const wb = readXlsx(filePath);

  const sheet = sheetName
    ? wb.sheets.find(s => s.name === sheetName)
    : wb.sheets[0];
  if (!sheet) throw new Error(`Sheet "${sheetName ?? "first"}" not found`);

  const useHeaders = opts.headers !== false;
  const { rows, headers } = sheetToRows(sheet, useHeaders);

  return { rows, headers, sheetName: sheet.name, rowCount: rows.length };
};

const write: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "output.xlsx");
  const data = Array.isArray(args[1]) ? args[1] : [];
  const opts = (typeof args[2] === "object" && args[2] !== null ? args[2] : {}) as Record<string, unknown>;

  if (data.length === 0) {
    writeXlsx(filePath, [{
      name: String(opts.sheetName ?? "Sheet1"),
      rows: [],
      headers: [],
      colWidth: Number(opts.colWidth ?? 15),
      boldHeaders: true,
      autoFilter: opts.autoFilter !== false,
    }]);
    return { path: filePath, rows: 0 };
  }

  const headers = Object.keys(data[0] as Record<string, unknown>);
  const headerColor = opts.headerColor
    ? String(opts.headerColor).replace("#", "FF")
    : undefined;

  writeXlsx(filePath, [{
    name: String(opts.sheetName ?? "Sheet1"),
    rows: data as Record<string, unknown>[],
    headers,
    colWidth: Number(opts.colWidth ?? 15),
    boldHeaders: true,
    headerColor,
    autoFilter: opts.autoFilter !== false,
  }]);

  return { path: filePath, rows: data.length, columns: headers.length };
};

const readSheetNames: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "");
  const wb = readXlsx(filePath);
  return wb.sheetNames;
};

const addSheet: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "");
  const sheetName = String(args[1] ?? "Sheet");
  const data = Array.isArray(args[2]) ? args[2] : [];

  // Read existing sheets
  const existingSheets = readExistingSheets(filePath);

  // Build new sheet
  const headers = data.length > 0 ? Object.keys(data[0] as Record<string, unknown>) : [];
  existingSheets.push({
    name: sheetName,
    rows: data as Record<string, unknown>[],
    headers,
    colWidth: 15,
    boldHeaders: true,
    autoFilter: false,
  });

  writeXlsx(filePath, existingSheets);
  return { path: filePath, sheet: sheetName, rows: data.length };
};

const toJson: BuiltinHandler = async (args) => {
  const result = await read(args) as { rows: Record<string, unknown>[] };
  return result.rows;
};

const fromJson: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "output.xlsx");
  const jsonData = args[1];
  const data = Array.isArray(jsonData) ? jsonData : typeof jsonData === "string" ? JSON.parse(jsonData) : [jsonData];
  return await write([filePath, data]);
};

const toCsv: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "");
  const result = await read([filePath]) as { rows: Record<string, unknown>[]; headers: string[] };

  const csvLines = [result.headers.join(",")];
  for (const row of result.rows) {
    const values = result.headers.map((h: any) => {
      const v = String(row[h] ?? "");
      return v.includes(",") || v.includes('"') ? `"${v.replace(/"/g, '""')}"` : v;
    });
    csvLines.push(values.join(","));
  }
  return csvLines.join("\n");
};

const getCell: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "");
  const cellRef = String(args[1] ?? "A1").toUpperCase();
  const sheetName = args[2] != null ? String(args[2]) : undefined;

  const wb = readXlsx(filePath);
  const sheet = sheetName
    ? wb.sheets.find(s => s.name === sheetName)
    : wb.sheets[0];
  if (!sheet) return null;

  const cell = sheet.cells.get(cellRef);
  if (!cell) return { value: null, formula: undefined, type: "null" };
  return { value: cell.value, formula: cell.formula, type: cell.type };
};

const setCell: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "");
  const cellRef = String(args[1] ?? "A1").toUpperCase();
  const value = args[2];
  const sheetName = args[3] != null ? String(args[3]) : undefined;

  // Read existing workbook or create new
  let existingSheets: SheetData[];
  try {
    existingSheets = readExistingSheets(filePath);
  } catch {
    existingSheets = [];
  }

  // Find or create target sheet
  const targetName = sheetName ?? existingSheets[0]?.name ?? "Sheet1";
  let targetIdx = existingSheets.findIndex(s => s.name === targetName);
  if (targetIdx === -1) {
    existingSheets.push({
      name: targetName,
      rows: [],
      headers: [],
      colWidth: 15,
      boldHeaders: true,
      autoFilter: false,
    });
    targetIdx = existingSheets.length - 1;
  }

  const sheetData = existingSheets[targetIdx];
  const { col, row } = parseCellRef(cellRef);

  // Ensure headers exist up to the column
  while (sheetData.headers.length < col) {
    sheetData.headers.push(`col${sheetData.headers.length + 1}`);
  }

  if (row === 1) {
    // Setting a header cell
    sheetData.headers[col - 1] = String(value ?? "");
  } else {
    // Ensure enough rows exist
    const dataRowIdx = row - 2; // 0-based data row index
    while (sheetData.rows.length <= dataRowIdx) {
      sheetData.rows.push({});
    }
    const headerKey = sheetData.headers[col - 1];
    sheetData.rows[dataRowIdx][headerKey] = value;
  }

  writeXlsx(filePath, existingSheets);
  return true;
};

// ── Exports ─────────────────────────────────────────────────────────

export const ExcelFunctions: Record<string, BuiltinHandler> = {
  read, write, readSheetNames, addSheet, toJson, fromJson, toCsv, getCell, setCell,
};

export const ExcelFunctionMetadata = {
  read: { description: "Read an Excel file into an array of row objects", parameters: [{ name: "filePath", dataType: "string", description: "Path to .xlsx file", formInputType: "text", required: true }, { name: "options", dataType: "object", description: "{sheet, headers}", formInputType: "text", required: false }], returnType: "object", returnDescription: "{rows, headers, sheetName, rowCount}", example: 'excel.read "./data.xlsx"' },
  write: { description: "Write an array of objects to an Excel file", parameters: [{ name: "filePath", dataType: "string", description: "Output path", formInputType: "text", required: true }, { name: "data", dataType: "array", description: "Array of row objects", formInputType: "text", required: true }, { name: "options", dataType: "object", description: "{sheetName, colWidth, headerColor, autoFilter}", formInputType: "text", required: false }], returnType: "object", returnDescription: "{path, rows, columns}", example: 'excel.write "./output.xlsx" $data {"sheetName": "Users"}' },
  readSheetNames: { description: "List all sheet names in an Excel file", parameters: [{ name: "filePath", dataType: "string", description: "Path to .xlsx file", formInputType: "text", required: true }], returnType: "array", returnDescription: "Array of sheet name strings", example: 'excel.readSheetNames "./data.xlsx"' },
  addSheet: { description: "Add a new sheet with data to an existing Excel file", parameters: [{ name: "filePath", dataType: "string", description: "Path to .xlsx file", formInputType: "text", required: true }, { name: "sheetName", dataType: "string", description: "New sheet name", formInputType: "text", required: true }, { name: "data", dataType: "array", description: "Row data", formInputType: "text", required: false }], returnType: "object", returnDescription: "{path, sheet, rows}", example: 'excel.addSheet "./data.xlsx" "Summary" $summaryData' },
  toJson: { description: "Convert an Excel file to JSON (shortcut for read().rows)", parameters: [{ name: "filePath", dataType: "string", description: "Path to .xlsx file", formInputType: "text", required: true }], returnType: "array", returnDescription: "Array of row objects", example: 'excel.toJson "./data.xlsx"' },
  fromJson: { description: "Create an Excel file from JSON data", parameters: [{ name: "filePath", dataType: "string", description: "Output path", formInputType: "text", required: true }, { name: "data", dataType: "any", description: "JSON array or string", formInputType: "text", required: true }], returnType: "object", returnDescription: "{path, rows, columns}", example: 'excel.fromJson "./output.xlsx" $jsonData' },
  toCsv: { description: "Convert an Excel file to CSV string", parameters: [{ name: "filePath", dataType: "string", description: "Path to .xlsx file", formInputType: "text", required: true }], returnType: "string", returnDescription: "CSV string", example: 'excel.toCsv "./data.xlsx"' },
  getCell: { description: "Get a specific cell value", parameters: [{ name: "filePath", dataType: "string", description: "Path to .xlsx file", formInputType: "text", required: true }, { name: "cell", dataType: "string", description: "Cell reference (e.g. 'A1')", formInputType: "text", required: true }, { name: "sheet", dataType: "string", description: "Sheet name (optional)", formInputType: "text", required: false }], returnType: "object", returnDescription: "{value, formula, type}", example: 'excel.getCell "./data.xlsx" "B2"' },
  setCell: { description: "Set a specific cell value", parameters: [{ name: "filePath", dataType: "string", description: "Path to .xlsx file", formInputType: "text", required: true }, { name: "cell", dataType: "string", description: "Cell reference", formInputType: "text", required: true }, { name: "value", dataType: "any", description: "Cell value", formInputType: "text", required: true }, { name: "sheet", dataType: "string", description: "Sheet name (optional)", formInputType: "text", required: false }], returnType: "boolean", returnDescription: "True", example: 'excel.setCell "./data.xlsx" "A1" "Hello"' },
};

export const ExcelModuleMetadata = {
  description: "Read, write, and manipulate Excel spreadsheets (.xlsx) with sheets, cells, JSON/CSV conversion",
  methods: ["read", "write", "readSheetNames", "addSheet", "toJson", "fromJson", "toCsv", "getCell", "setCell"],
};
