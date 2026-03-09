// @ts-nocheck
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, extname } from "node:path";
import { deflateRawSync, inflateRawSync } from "node:zlib";

// ─── Helpers ────────────────────────────────────────────────────────────────

const getOpts = (v: any): any => (v && typeof v === "object" && !Array.isArray(v) ? v : {});

// ─── CRC-32 ─────────────────────────────────────────────────────────────────

const crc32Table: number[] = [];
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  crc32Table[n] = c;
}
function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = crc32Table[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

// ─── ZIP Reader ─────────────────────────────────────────────────────────────

interface ZipEntry { name: string; data: Buffer; }

function readZip(buf: Buffer): ZipEntry[] {
  const entries: ZipEntry[] = [];
  // Find End of Central Directory
  let eocdOffset = -1;
  for (let i = buf.length - 22; i >= 0; i--) {
    if (buf.readUInt32LE(i) === 0x06054b50) { eocdOffset = i; break; }
  }
  if (eocdOffset < 0) throw new Error("Invalid ZIP: EOCD not found");
  const cdOffset = buf.readUInt32LE(eocdOffset + 16);
  const cdCount = buf.readUInt16LE(eocdOffset + 10);
  let pos = cdOffset;
  for (let i = 0; i < cdCount; i++) {
    if (buf.readUInt32LE(pos) !== 0x02014b50) break;
    const method = buf.readUInt16LE(pos + 10);
    const compSize = buf.readUInt32LE(pos + 20);
    const uncompSize = buf.readUInt32LE(pos + 24);
    const nameLen = buf.readUInt16LE(pos + 28);
    const extraLen = buf.readUInt16LE(pos + 30);
    const commentLen = buf.readUInt16LE(pos + 32);
    const localOffset = buf.readUInt32LE(pos + 42);
    const name = buf.subarray(pos + 46, pos + 46 + nameLen).toString("utf8");
    pos += 46 + nameLen + extraLen + commentLen;
    // Read local file header to get actual data offset
    const localNameLen = buf.readUInt16LE(localOffset + 26);
    const localExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen;
    const compressed = buf.subarray(dataStart, dataStart + compSize);
    let data: Buffer;
    if (method === 0) {
      data = Buffer.from(compressed);
    } else if (method === 8) {
      data = inflateRawSync(compressed);
    } else {
      data = Buffer.alloc(0);
    }
    entries.push({ name, data });
  }
  return entries;
}

// ─── ZIP Writer ─────────────────────────────────────────────────────────────

interface ZipFile { name: string; data: Buffer; }

function writeZip(files: ZipFile[]): Buffer {
  const localHeaders: Buffer[] = [];
  const centralHeaders: Buffer[] = [];
  let offset = 0;
  for (const file of files) {
    const nameBytes = Buffer.from(file.name, "utf8");
    const raw = file.data;
    const crcVal = crc32(raw);
    const compressed = deflateRawSync(raw);
    // Use deflate only if it actually shrinks
    const useDeflate = compressed.length < raw.length;
    const storedData = useDeflate ? compressed : raw;
    const method = useDeflate ? 8 : 0;
    // Local file header
    const local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0, 6);  // flags
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(0, 10); // mod time
    local.writeUInt16LE(0, 12); // mod date
    local.writeUInt32LE(crcVal, 14);
    local.writeUInt32LE(storedData.length, 18);
    local.writeUInt32LE(raw.length, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28); // extra len
    nameBytes.copy(local, 30);
    localHeaders.push(local, storedData);
    // Central directory header
    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);  // version made by
    central.writeUInt16LE(20, 6);  // version needed
    central.writeUInt16LE(0, 8);   // flags
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(0, 12);  // mod time
    central.writeUInt16LE(0, 14);  // mod date
    central.writeUInt32LE(crcVal, 16);
    central.writeUInt32LE(storedData.length, 20);
    central.writeUInt32LE(raw.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(0, 30);  // extra len
    central.writeUInt16LE(0, 32);  // comment len
    central.writeUInt16LE(0, 34);  // disk number
    central.writeUInt16LE(0, 36);  // internal attrs
    central.writeUInt32LE(0, 38);  // external attrs
    central.writeUInt32LE(offset, 42); // local header offset
    nameBytes.copy(central, 46);
    centralHeaders.push(central);
    offset += local.length + storedData.length;
  }
  const cdStart = offset;
  const cdSize = centralHeaders.reduce((s, b) => s + b.length, 0);
  // EOCD
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);  // disk number
  eocd.writeUInt16LE(0, 6);  // disk with CD
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdStart, 16);
  eocd.writeUInt16LE(0, 20); // comment len
  return Buffer.concat([...localHeaders, ...centralHeaders, eocd]);
}

// ─── XML Escaping ───────────────────────────────────────────────────────────

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&apos;");
}

// ─── Document State ─────────────────────────────────────────────────────────

interface RunStyle {
  bold?: boolean; italic?: boolean; underline?: boolean;
  fontSize?: number; font?: string; color?: string;
  strike?: boolean; highlight?: string;
}
interface DocRun { text: string; style: RunStyle; }

interface ContentItem {
  type: "heading" | "paragraph" | "table" | "image" | "pageBreak" | "list" |
        "hyperlink" | "bookmark" | "toc" | "footnote" | "comment" |
        "section" | "checkbox";
  data: any;
}

interface SectionDef {
  children: ContentItem[];
  properties: any;
  header?: { text: string; opts: any };
  footer?: { text: string; opts: any };
}

interface DocState {
  sections: SectionDef[];
  activeSection: number;
  options: any;
  defaults: RunStyle;
  properties: Record<string, string>;
  footnotes: { text: string; footnoteText: string; opts: any }[];
  comments: { text: string; commentText: string; opts: any }[];
  styles: { name: string; opts: any }[];
  images: { data: Buffer; ext: string }[];
  hyperlinks: { url: string }[];
}

const docs = new Map<string, DocState>();

function getActiveSection(doc: DocState): SectionDef {
  return doc.sections[doc.activeSection];
}

function mergeRunStyle(opts: any, defaults: RunStyle = {}): RunStyle {
  return {
    bold: opts.bold ?? defaults.bold,
    italic: opts.italic ?? defaults.italic,
    underline: opts.underline ?? defaults.underline,
    fontSize: opts.fontSize ? Number(opts.fontSize) : defaults.fontSize,
    font: opts.font ? String(opts.font) : defaults.font,
    color: opts.color ? String(opts.color).replace("#", "") : defaults.color,
    strike: opts.strike,
    highlight: opts.highlight,
  };
}

// ─── OOXML Generation Helpers ───────────────────────────────────────────────

function runXml(text: string, style: RunStyle): string {
  let rPr = "";
  if (style.bold) rPr += "<w:b/>";
  if (style.italic) rPr += "<w:i/>";
  if (style.underline) rPr += `<w:u w:val="single"/>`;
  if (style.strike) rPr += "<w:strike/>";
  if (style.font) rPr += `<w:rFonts w:ascii="${esc(style.font)}" w:hAnsi="${esc(style.font)}"/>`;
  if (style.fontSize) rPr += `<w:sz w:val="${Math.round(style.fontSize * 2)}"/><w:szCs w:val="${Math.round(style.fontSize * 2)}"/>`;
  if (style.color) rPr += `<w:color w:val="${esc(style.color)}"/>`;
  if (style.highlight) rPr += `<w:highlight w:val="${esc(style.highlight)}"/>`;
  const rPrXml = rPr ? `<w:rPr>${rPr}</w:rPr>` : "";
  // Handle text with xml:space preserve for leading/trailing whitespace
  return `<w:r>${rPrXml}<w:t xml:space="preserve">${esc(text)}</w:t></w:r>`;
}

function alignmentVal(a: string | undefined): string | null {
  if (!a) return null;
  const map: Record<string, string> = { left: "left", center: "center", right: "right", justify: "both" };
  return map[a.toLowerCase()] || null;
}

function pPrXml(opts: any, headingLevel?: number): string {
  let inner = "";
  const al = alignmentVal(opts.alignment);
  if (al) inner += `<w:jc w:val="${al}"/>`;
  if (headingLevel != null && headingLevel >= 1 && headingLevel <= 6) {
    inner += `<w:pStyle w:val="Heading${headingLevel}"/>`;
  }
  if (opts.style) inner += `<w:pStyle w:val="${esc(String(opts.style).replace(/\s+/g, ""))}"/>`;
  if (opts.spacing) {
    const sp = getOpts(opts.spacing);
    let attr = "";
    if (sp.before) attr += ` w:before="${sp.before}"`;
    if (sp.after) attr += ` w:after="${sp.after}"`;
    if (sp.line) attr += ` w:line="${sp.line}"`;
    if (attr) inner += `<w:spacing${attr}/>`;
  }
  if (opts.indent) {
    const ind = getOpts(opts.indent);
    let attr = "";
    if (ind.left) attr += ` w:left="${ind.left}"`;
    if (ind.right) attr += ` w:right="${ind.right}"`;
    if (ind.firstLine) attr += ` w:firstLine="${ind.firstLine}"`;
    if (ind.hanging) attr += ` w:hanging="${ind.hanging}"`;
    if (attr) inner += `<w:ind${attr}/>`;
  }
  if (opts.keepNext) inner += "<w:keepNext/>";
  if (opts.pageBreakBefore) inner += "<w:pageBreakBefore/>";
  return inner ? `<w:pPr>${inner}</w:pPr>` : "";
}

function paragraphXml(runs: string, opts: any = {}, headingLevel?: number): string {
  return `<w:p>${pPrXml(opts, headingLevel)}${runs}</w:p>`;
}

// ─── Content-to-XML Converters ──────────────────────────────────────────────

function contentToDocXml(
  doc: DocState,
  section: SectionDef,
  ctx: { relId: number; imageRels: { rId: string; target: string }[]; hyperlinkRels: { rId: string; url: string }[]; footnoteId: number; commentId: number }
): string {
  let xml = "";
  for (const item of section.children) {
    switch (item.type) {
      case "heading": {
        const d = item.data;
        const style = mergeRunStyle(d.opts, doc.defaults);
        if (d.opts.keepNext === undefined) d.opts.keepNext = true;
        xml += paragraphXml(runXml(d.text, style), d.opts, d.level);
        break;
      }
      case "paragraph": {
        const d = item.data;
        if (d.runs) {
          const runsXml = d.runs.map((r: any) => runXml(String(r.text ?? ""), mergeRunStyle(r, doc.defaults))).join("");
          xml += paragraphXml(runsXml, d.opts);
        } else {
          xml += paragraphXml(runXml(d.text, mergeRunStyle(d.opts, doc.defaults)), d.opts);
        }
        break;
      }
      case "table": {
        const d = item.data;
        const data: any[][] = d.rows;
        const hStyle = getOpts(d.headerStyle);
        const cStyle = getOpts(d.cellStyle);
        const borders = d.borders !== false;
        const borderXml = borders ? `<w:tblBorders><w:top w:val="single" w:sz="4" w:space="0"/><w:bottom w:val="single" w:sz="4" w:space="0"/><w:left w:val="single" w:sz="4" w:space="0"/><w:right w:val="single" w:sz="4" w:space="0"/><w:insideH w:val="single" w:sz="4" w:space="0"/><w:insideV w:val="single" w:sz="4" w:space="0"/></w:tblBorders>` : "";
        xml += `<w:tbl><w:tblPr><w:tblW w:w="5000" w:type="pct"/>${borderXml}<w:tblLook w:val="04A0"/></w:tblPr>`;
        for (let ri = 0; ri < data.length; ri++) {
          const row = data[ri];
          const isHeader = ri === 0 && d.hasHeaders;
          const isAlt = d.alternateRows && ri > 0 && ri % 2 === 0;
          xml += "<w:tr>";
          for (const cell of row) {
            const cellText = String(cell ?? "");
            const st = isHeader ? { bold: hStyle.bold !== false, fontSize: hStyle.fontSize, font: hStyle.font, color: hStyle.fontColor ?? hStyle.color ?? "FFFFFF" } : { fontSize: cStyle.fontSize, font: cStyle.font, color: cStyle.fontColor ?? cStyle.color };
            const fillColor = isHeader ? (hStyle.fillColor ? String(hStyle.fillColor).replace("#", "") : "2196F3") : (isAlt ? "F5F5F5" : null);
            let tcPr = "";
            if (fillColor) tcPr += `<w:shd w:val="clear" w:color="auto" w:fill="${fillColor}"/>`;
            xml += `<w:tc>${tcPr ? `<w:tcPr>${tcPr}</w:tcPr>` : ""}${paragraphXml(runXml(cellText, mergeRunStyle(st, doc.defaults)), isHeader ? { alignment: hStyle.alignment ?? "center" } : { alignment: cStyle.alignment })}`;
            xml += "</w:tc>";
          }
          xml += "</w:tr>";
        }
        xml += "</w:tbl>";
        break;
      }
      case "image": {
        const d = item.data;
        ctx.relId++;
        const rId = `rId${ctx.relId}`;
        const imgIdx = doc.images.length;
        const ext = d.ext || "png";
        const target = `media/image${imgIdx + 1}.${ext}`;
        ctx.imageRels.push({ rId, target });
        const cx = Math.round((d.width ?? 400) * 9525);
        const cy = Math.round((d.height ?? 300) * 9525);
        const al = alignmentVal(d.opts?.alignment);
        const pPr = al ? `<w:pPr><w:jc w:val="${al}"/></w:pPr>` : "";
        xml += `<w:p>${pPr}<w:r><w:rPr/><w:drawing><wp:inline distT="0" distB="0" distL="0" distR="0"><wp:extent cx="${cx}" cy="${cy}"/><wp:docPr id="${ctx.relId}" name="Image${ctx.relId}"/><a:graphic xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"><a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:pic xmlns:pic="http://schemas.openxmlformats.org/drawingml/2006/picture"><pic:nvPicPr><pic:cNvPr id="${ctx.relId}" name="Image${ctx.relId}"/><pic:cNvPicPr/></pic:nvPicPr><pic:blipFill><a:blip r:embed="${rId}"/><a:stretch><a:fillRect/></a:stretch></pic:blipFill><pic:spPr><a:xfrm><a:off x="0" y="0"/><a:ext cx="${cx}" cy="${cy}"/></a:xfrm><a:prstGeom prst="rect"><a:avLst/></a:prstGeom></pic:spPr></pic:pic></a:graphicData></a:graphic></wp:inline></w:drawing></w:r></w:p>`;
        break;
      }
      case "pageBreak": {
        xml += `<w:p><w:r><w:br w:type="page"/></w:r></w:p>`;
        break;
      }
      case "list": {
        const d = item.data;
        const isOrdered = d.ordered;
        const numId = isOrdered ? 2 : 1;
        const level = d.level ?? 0;
        for (const text of d.items) {
          const style = mergeRunStyle(d.opts, doc.defaults);
          xml += `<w:p><w:pPr><w:numPr><w:ilvl w:val="${level}"/><w:numId w:val="${numId}"/></w:numPr></w:pPr>${runXml(String(text), style)}</w:p>`;
        }
        break;
      }
      case "hyperlink": {
        const d = item.data;
        ctx.relId++;
        const rId = `rId${ctx.relId}`;
        ctx.hyperlinkRels.push({ rId, url: d.url });
        const style = mergeRunStyle({ ...d.opts, color: d.opts.color ?? "0563C1", underline: d.opts.underline !== false }, doc.defaults);
        const al = alignmentVal(d.opts.alignment);
        const pPr = al ? `<w:pPr><w:jc w:val="${al}"/></w:pPr>` : "";
        xml += `<w:p>${pPr}<w:hyperlink r:id="${rId}" w:history="1">${runXml(d.text, style)}</w:hyperlink></w:p>`;
        break;
      }
      case "bookmark": {
        const d = item.data;
        const bmId = Math.floor(Math.random() * 1e6);
        const style = mergeRunStyle(d.opts, doc.defaults);
        const pPrStr = pPrXml(d.opts);
        xml += `<w:p>${pPrStr}<w:bookmarkStart w:id="${bmId}" w:name="${esc(d.name)}"/>${runXml(d.text, style)}<w:bookmarkEnd w:id="${bmId}"/></w:p>`;
        break;
      }
      case "toc": {
        const d = item.data;
        const heading = d.heading ?? "Table of Contents";
        const range = d.headingRange ?? "1-5";
        xml += paragraphXml(runXml(heading, { bold: true, fontSize: 14 }), { alignment: "center" });
        xml += `<w:p><w:pPr/><w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> TOC \\o "${range}" \\h \\z \\u </w:instrText></w:r><w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>Update this field to generate table of contents</w:t></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>`;
        break;
      }
      case "footnote": {
        const d = item.data;
        ctx.footnoteId++;
        const fnId = ctx.footnoteId;
        const style = mergeRunStyle(d.opts, doc.defaults);
        xml += `<w:p>${pPrXml(d.opts)}${runXml(d.text, style)}<w:r><w:rPr><w:rStyle w:val="FootnoteReference"/></w:rPr><w:footnoteReference w:id="${fnId}"/></w:r></w:p>`;
        break;
      }
      case "comment": {
        const d = item.data;
        ctx.commentId++;
        const cmId = ctx.commentId;
        const style = mergeRunStyle(d.opts, doc.defaults);
        xml += `<w:p>${pPrXml(d.opts)}<w:commentRangeStart w:id="${cmId}"/>${runXml(d.text, style)}<w:commentRangeEnd w:id="${cmId}"/><w:r><w:rPr><w:rStyle w:val="CommentReference"/></w:rPr><w:commentReference w:id="${cmId}"/></w:r></w:p>`;
        break;
      }
      case "checkbox": {
        const d = item.data;
        const checked = d.checked;
        const checkChar = checked ? "\u2611" : "\u2610";
        const style = mergeRunStyle(d.opts, doc.defaults);
        xml += paragraphXml(runXml(checkChar + " " + d.label, style), d.opts);
        break;
      }
    }
  }
  return xml;
}

// ─── Section Properties XML ─────────────────────────────────────────────────

function sectionPropsXml(props: any, isLast: boolean): string {
  let inner = "";
  const typeMap: Record<string, string> = { nextPage: "nextPage", continuous: "continuous", evenPage: "evenPage", oddPage: "oddPage" };
  if (props.type && typeMap[props.type]) inner += `<w:type w:val="${typeMap[props.type]}"/>`;
  if (props.orientation === "landscape") {
    inner += `<w:pgSz w:w="15840" w:h="12240" w:orient="landscape"/>`;
  } else {
    inner += `<w:pgSz w:w="12240" w:h="15840"/>`;
  }
  if (props.margins) {
    const m = getOpts(props.margins);
    const conv = (v: number) => Math.round(v * 1440); // inches to twips
    inner += `<w:pgMar w:top="${conv(m.top ?? 1)}" w:right="${conv(m.right ?? 1)}" w:bottom="${conv(m.bottom ?? 1)}" w:left="${conv(m.left ?? 1)}" w:header="720" w:footer="720" w:gutter="0"/>`;
  } else {
    inner += `<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/>`;
  }
  if (props.columns) inner += `<w:cols w:space="720" w:num="${props.columns}"/>`;
  return inner ? `<w:sectPr>${inner}</w:sectPr>` : `<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/></w:sectPr>`;
}

// ─── Build Full DOCX ZIP ────────────────────────────────────────────────────

function buildDocx(doc: DocState, filePath: string): { path: string; size: number } {
  const files: ZipFile[] = [];
  // Track relationships and images per section
  let relIdCounter = 3; // rId1=styles, rId2=numbering, rId3=settings
  const imageRels: { rId: string; target: string; imgIdx: number }[] = [];
  const hyperlinkRels: { rId: string; url: string }[] = [];
  let footnoteIdCounter = 0;
  let commentIdCounter = 0;
  const hasFootnotes = doc.sections.some(s => s.children.some(c => c.type === "footnote"));
  const hasComments = doc.sections.some(s => s.children.some(c => c.type === "comment"));
  const hasHeader = doc.sections.some(s => s.header);
  const hasFooter = doc.sections.some(s => s.footer);

  // Reserve rIds for footnotes, comments, header, footer
  let footnotesRId = "";
  let commentsRId = "";
  const headerRIds: string[] = [];
  const footerRIds: string[] = [];

  if (hasFootnotes) { relIdCounter++; footnotesRId = `rId${relIdCounter}`; }
  if (hasComments) { relIdCounter++; commentsRId = `rId${relIdCounter}`; }
  for (let si = 0; si < doc.sections.length; si++) {
    if (doc.sections[si].header) { relIdCounter++; headerRIds[si] = `rId${relIdCounter}`; }
    if (doc.sections[si].footer) { relIdCounter++; footerRIds[si] = `rId${relIdCounter}`; }
  }

  // Build document body
  let bodyXml = "";
  for (let si = 0; si < doc.sections.length; si++) {
    const section = doc.sections[si];
    const ctx = {
      relId: relIdCounter,
      imageRels: [] as { rId: string; target: string }[],
      hyperlinkRels: [] as { rId: string; url: string }[],
      footnoteId: footnoteIdCounter,
      commentId: commentIdCounter,
    };
    const sectionXml = contentToDocXml(doc, section, ctx);
    relIdCounter = ctx.relId;
    footnoteIdCounter = ctx.footnoteId;
    commentIdCounter = ctx.commentId;
    for (const ir of ctx.imageRels) imageRels.push({ ...ir, imgIdx: imageRels.length });
    hyperlinkRels.push(...ctx.hyperlinkRels);
    bodyXml += sectionXml;

    // Add section properties
    const isLast = si === doc.sections.length - 1;
    let sectPrInner = "";
    if (headerRIds[si]) sectPrInner += `<w:headerReference w:type="default" r:id="${headerRIds[si]}"/>`;
    if (footerRIds[si]) sectPrInner += `<w:footerReference w:type="default" r:id="${footerRIds[si]}"/>`;
    const props = section.properties || {};
    if (props.orientation === "landscape") {
      sectPrInner += `<w:pgSz w:w="15840" w:h="12240" w:orient="landscape"/>`;
    } else {
      sectPrInner += `<w:pgSz w:w="12240" w:h="15840"/>`;
    }
    if (props.margins) {
      const m = getOpts(props.margins);
      const conv = (v: number) => Math.round(v * 1440);
      sectPrInner += `<w:pgMar w:top="${conv(m.top ?? 1)}" w:right="${conv(m.right ?? 1)}" w:bottom="${conv(m.bottom ?? 1)}" w:left="${conv(m.left ?? 1)}" w:header="720" w:footer="720" w:gutter="0"/>`;
    } else {
      sectPrInner += `<w:pgMar w:top="1440" w:right="1440" w:bottom="1440" w:left="1440" w:header="720" w:footer="720" w:gutter="0"/>`;
    }
    if (props.columns) sectPrInner += `<w:cols w:space="720" w:num="${props.columns}"/>`;
    if (props.type) {
      const typeMap: Record<string, string> = { nextPage: "nextPage", nextpage: "nextPage", continuous: "continuous", evenPage: "evenPage", evenpage: "evenPage", oddPage: "oddPage", oddpage: "oddPage" };
      if (typeMap[props.type]) sectPrInner += `<w:type w:val="${typeMap[props.type]}"/>`;
    }
    if (isLast) {
      bodyXml += `<w:sectPr>${sectPrInner}</w:sectPr>`;
    } else {
      // Insert section break as last paragraph's pPr
      bodyXml += `<w:p><w:pPr><w:sectPr>${sectPrInner}</w:sectPr></w:pPr></w:p>`;
    }
  }

  const documentXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:wpc="http://schemas.microsoft.com/office/word/2010/wordprocessingCanvas"
  xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006"
  xmlns:o="urn:schemas-microsoft-com:office:office"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:m="http://schemas.openxmlformats.org/officeDocument/2006/math"
  xmlns:v="urn:schemas-microsoft-com:vml"
  xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing"
  xmlns:w10="urn:schemas-microsoft-com:office:word"
  xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"
  xmlns:w14="http://schemas.microsoft.com/office/word/2010/wordml"
  xmlns:wpg="http://schemas.microsoft.com/office/word/2010/wordprocessingGroup"
  xmlns:wpi="http://schemas.microsoft.com/office/word/2010/wordprocessingInk"
  xmlns:wne="http://schemas.microsoft.com/office/word/2006/wordml"
  xmlns:wps="http://schemas.microsoft.com/office/word/2010/wordprocessingShape"
  mc:Ignorable="w14 wp14">
<w:body>${bodyXml}</w:body></w:document>`;

  files.push({ name: "word/document.xml", data: Buffer.from(documentXml, "utf8") });

  // ── Styles ──
  let stylesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="${esc(doc.defaults.font ?? "Calibri")}" w:hAnsi="${esc(doc.defaults.font ?? "Calibri")}"/><w:sz w:val="${Math.round((doc.defaults.fontSize ?? 11) * 2)}"/><w:szCs w:val="${Math.round((doc.defaults.fontSize ?? 11) * 2)}"/></w:rPr></w:rPrDefault></w:docDefaults>
<w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style>`;
  for (let i = 1; i <= 6; i++) {
    const sz = Math.round((28 - i * 2) * 2);
    stylesXml += `<w:style w:type="paragraph" w:styleId="Heading${i}"><w:name w:val="heading ${i}"/><w:basedOn w:val="Normal"/><w:next w:val="Normal"/><w:pPr><w:keepNext/><w:outlineLvl w:val="${i - 1}"/></w:pPr><w:rPr><w:b/><w:sz w:val="${sz}"/><w:szCs w:val="${sz}"/></w:rPr></w:style>`;
  }
  if (hasFootnotes) {
    stylesXml += `<w:style w:type="character" w:styleId="FootnoteReference"><w:name w:val="Footnote Reference"/><w:rPr><w:vertAlign w:val="superscript"/></w:rPr></w:style>`;
    stylesXml += `<w:style w:type="paragraph" w:styleId="FootnoteText"><w:name w:val="Footnote Text"/><w:basedOn w:val="Normal"/><w:rPr><w:sz w:val="20"/><w:szCs w:val="20"/></w:rPr></w:style>`;
  }
  if (hasComments) {
    stylesXml += `<w:style w:type="character" w:styleId="CommentReference"><w:name w:val="Comment Reference"/><w:rPr><w:sz w:val="16"/><w:szCs w:val="16"/></w:rPr></w:style>`;
  }
  // Custom styles
  for (const st of doc.styles) {
    const o = st.opts;
    const sid = String(st.name).replace(/\s+/g, "");
    const stype = String(o.type ?? "paragraph");
    let rPr = "";
    if (o.font) rPr += `<w:rFonts w:ascii="${esc(o.font)}" w:hAnsi="${esc(o.font)}"/>`;
    if (o.fontSize) rPr += `<w:sz w:val="${Math.round(Number(o.fontSize) * 2)}"/><w:szCs w:val="${Math.round(Number(o.fontSize) * 2)}"/>`;
    if (o.bold) rPr += "<w:b/>";
    if (o.italic) rPr += "<w:i/>";
    if (o.color) rPr += `<w:color w:val="${esc(String(o.color).replace("#", ""))}"/>`;
    let pPr2 = "";
    const al = alignmentVal(o.alignment);
    if (al) pPr2 += `<w:jc w:val="${al}"/>`;
    stylesXml += `<w:style w:type="${stype}" w:styleId="${esc(sid)}"><w:name w:val="${esc(st.name)}"/><w:basedOn w:val="${esc(o.basedOn ?? "Normal")}"/><w:next w:val="${esc(o.next ?? "Normal")}"/><w:qFormat/>${pPr2 ? `<w:pPr>${pPr2}</w:pPr>` : ""}${rPr ? `<w:rPr>${rPr}</w:rPr>` : ""}</w:style>`;
  }
  stylesXml += "</w:styles>";
  files.push({ name: "word/styles.xml", data: Buffer.from(stylesXml, "utf8") });

  // ── Numbering (for lists) ──
  const numberingXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:abstractNum w:abstractNumId="0"><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="bullet"/><w:lvlText w:val="\u2022"/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>
<w:abstractNum w:abstractNumId="1"><w:lvl w:ilvl="0"><w:start w:val="1"/><w:numFmt w:val="decimal"/><w:lvlText w:val="%1."/><w:lvlJc w:val="left"/><w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr></w:lvl></w:abstractNum>
<w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>
<w:num w:numId="2"><w:abstractNumId w:val="1"/></w:num>
</w:numbering>`;
  files.push({ name: "word/numbering.xml", data: Buffer.from(numberingXml, "utf8") });

  // ── Settings ──
  const settingsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:defaultTabStop w:val="720"/>
</w:settings>`;
  files.push({ name: "word/settings.xml", data: Buffer.from(settingsXml, "utf8") });

  // ── Footnotes ──
  if (hasFootnotes) {
    let fnXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:footnotes xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:footnote w:type="separator" w:id="-1"><w:p><w:r><w:separator/></w:r></w:p></w:footnote>
<w:footnote w:type="continuationSeparator" w:id="0"><w:p><w:r><w:continuationSeparator/></w:r></w:p></w:footnote>`;
    let fnIdx = 0;
    for (const section of doc.sections) {
      for (const item of section.children) {
        if (item.type === "footnote") {
          fnIdx++;
          const d = item.data;
          const style = mergeRunStyle(d.opts, doc.defaults);
          fnXml += `<w:footnote w:id="${fnIdx}"><w:p><w:pPr><w:pStyle w:val="FootnoteText"/></w:pPr><w:r><w:rPr><w:rStyle w:val="FootnoteReference"/></w:rPr><w:footnoteRef/></w:r><w:r><w:t xml:space="preserve"> </w:t></w:r>${runXml(d.footnoteText, style)}</w:p></w:footnote>`;
        }
      }
    }
    fnXml += "</w:footnotes>";
    files.push({ name: "word/footnotes.xml", data: Buffer.from(fnXml, "utf8") });
  }

  // ── Comments ──
  if (hasComments) {
    let cmXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:comments xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">`;
    let cmIdx = 0;
    for (const section of doc.sections) {
      for (const item of section.children) {
        if (item.type === "comment") {
          cmIdx++;
          const d = item.data;
          const author = esc(d.opts.author ?? "RobinPath");
          const date = new Date().toISOString();
          cmXml += `<w:comment w:id="${cmIdx}" w:author="${author}" w:date="${date}"><w:p><w:r><w:t>${esc(d.commentText)}</w:t></w:r></w:p></w:comment>`;
        }
      }
    }
    cmXml += "</w:comments>";
    files.push({ name: "word/comments.xml", data: Buffer.from(cmXml, "utf8") });
  }

  // ── Headers ──
  for (let si = 0; si < doc.sections.length; si++) {
    const section = doc.sections[si];
    if (section.header) {
      const h = section.header;
      const style = mergeRunStyle(h.opts, doc.defaults);
      const al = alignmentVal(h.opts.alignment ?? "center");
      const pPr = al ? `<w:pPr><w:jc w:val="${al}"/></w:pPr>` : "";
      const hdrXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:p>${pPr}${runXml(h.text, style)}</w:p></w:hdr>`;
      files.push({ name: `word/header${si + 1}.xml`, data: Buffer.from(hdrXml, "utf8") });
    }
  }

  // ── Footers ──
  for (let si = 0; si < doc.sections.length; si++) {
    const section = doc.sections[si];
    if (section.footer) {
      const f = section.footer;
      const style = mergeRunStyle(f.opts, doc.defaults);
      const al = alignmentVal(f.opts.alignment ?? "center");
      const pPr = al ? `<w:pPr><w:jc w:val="${al}"/></w:pPr>` : "";
      let ftrContent = `<w:p>${pPr}${runXml(f.text, style)}</w:p>`;
      if (f.opts.pageNumbers) {
        const pnAl = alignmentVal(f.opts.pageNumberAlignment ?? f.opts.alignment ?? "center");
        const pnPPr = pnAl ? `<w:pPr><w:jc w:val="${pnAl}"/></w:pPr>` : "";
        ftrContent += `<w:p>${pnPPr}<w:r><w:fldChar w:fldCharType="begin"/></w:r><w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r><w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>`;
      }
      const ftrXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">${ftrContent}</w:ftr>`;
      files.push({ name: `word/footer${si + 1}.xml`, data: Buffer.from(ftrXml, "utf8") });
    }
  }

  // ── Images ──
  for (let i = 0; i < doc.images.length; i++) {
    const img = doc.images[i];
    files.push({ name: `word/media/image${i + 1}.${img.ext}`, data: img.data });
  }

  // ── Document Relationships ──
  let docRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>
<Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>`;
  if (hasFootnotes) {
    docRelsXml += `\n<Relationship Id="${footnotesRId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footnotes" Target="footnotes.xml"/>`;
  }
  if (hasComments) {
    docRelsXml += `\n<Relationship Id="${commentsRId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/comments" Target="comments.xml"/>`;
  }
  for (let si = 0; si < doc.sections.length; si++) {
    if (headerRIds[si]) {
      docRelsXml += `\n<Relationship Id="${headerRIds[si]}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Target="header${si + 1}.xml"/>`;
    }
    if (footerRIds[si]) {
      docRelsXml += `\n<Relationship Id="${footerRIds[si]}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/footer" Target="footer${si + 1}.xml"/>`;
    }
  }
  for (const ir of imageRels) {
    const ext = ir.target.split(".").pop() ?? "png";
    const mime = ext === "jpg" || ext === "jpeg" ? "image/jpeg" : ext === "gif" ? "image/gif" : "image/png";
    docRelsXml += `\n<Relationship Id="${ir.rId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" Target="${ir.target}"/>`;
  }
  for (const hr of hyperlinkRels) {
    docRelsXml += `\n<Relationship Id="${hr.rId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" Target="${esc(hr.url)}" TargetMode="External"/>`;
  }
  docRelsXml += "\n</Relationships>";
  files.push({ name: "word/_rels/document.xml.rels", data: Buffer.from(docRelsXml, "utf8") });

  // ── Root Relationships ──
  const rootRelsXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`;
  files.push({ name: "_rels/.rels", data: Buffer.from(rootRelsXml, "utf8") });

  // ── Content Types ──
  let contentTypesXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
<Default Extension="xml" ContentType="application/xml"/>
<Default Extension="png" ContentType="image/png"/>
<Default Extension="jpg" ContentType="image/jpeg"/>
<Default Extension="jpeg" ContentType="image/jpeg"/>
<Default Extension="gif" ContentType="image/gif"/>
<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
<Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
<Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>
<Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>`;
  if (hasFootnotes) contentTypesXml += `\n<Override PartName="/word/footnotes.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footnotes+xml"/>`;
  if (hasComments) contentTypesXml += `\n<Override PartName="/word/comments.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.comments+xml"/>`;
  for (let si = 0; si < doc.sections.length; si++) {
    if (doc.sections[si].header) contentTypesXml += `\n<Override PartName="/word/header${si + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml"/>`;
    if (doc.sections[si].footer) contentTypesXml += `\n<Override PartName="/word/footer${si + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml"/>`;
  }
  contentTypesXml += "\n</Types>";
  files.push({ name: "[Content_Types].xml", data: Buffer.from(contentTypesXml, "utf8") });

  // ── Core Properties ──
  const props = doc.properties;
  let coreXml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
  xmlns:dc="http://purl.org/dc/elements/1.1/"
  xmlns:dcterms="http://purl.org/dc/terms/"
  xmlns:dcmitype="http://purl.org/dc/dcmitype/"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">`;
  if (props.title) coreXml += `<dc:title>${esc(props.title)}</dc:title>`;
  if (props.author) coreXml += `<dc:creator>${esc(props.author)}</dc:creator>`;
  if (props.subject) coreXml += `<dc:subject>${esc(props.subject)}</dc:subject>`;
  if (props.keywords) coreXml += `<cp:keywords>${esc(props.keywords)}</cp:keywords>`;
  if (props.description) coreXml += `<dc:description>${esc(props.description)}</dc:description>`;
  coreXml += `<dcterms:created xsi:type="dcterms:W3CDTF">${new Date().toISOString()}</dcterms:created>`;
  coreXml += "</cp:coreProperties>";
  files.push({ name: "docProps/core.xml", data: Buffer.from(coreXml, "utf8") });

  // Write ZIP
  const zipBuf = writeZip(files);
  writeFileSync(filePath, zipBuf);
  docs.delete(doc as any); // cleanup handled by caller
  return { path: filePath, size: zipBuf.length };
}

// ─── readDoc: parse ZIP, extract text or HTML ───────────────────────────────

function parseDocxText(buf: Buffer): string {
  const entries = readZip(buf);
  const docEntry = entries.find(e => e.name === "word/document.xml");
  if (!docEntry) throw new Error("Invalid .docx: word/document.xml not found");
  const xml = docEntry.data.toString("utf8");
  // Extract text from <w:t> tags, grouping by <w:p>
  const paragraphs: string[] = [];
  const pRegex = /<w:p[\s>][\s\S]*?<\/w:p>/g;
  let pMatch;
  while ((pMatch = pRegex.exec(xml)) !== null) {
    const pXml = pMatch[0];
    const texts: string[] = [];
    const tRegex = /<w:t[^>]*>([\s\S]*?)<\/w:t>/g;
    let tMatch;
    while ((tMatch = tRegex.exec(pXml)) !== null) {
      texts.push(tMatch[1].replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'"));
    }
    if (texts.length > 0) paragraphs.push(texts.join(""));
  }
  return paragraphs.join("\n");
}

function parseDocxHtml(buf: Buffer): string {
  const entries = readZip(buf);
  const docEntry = entries.find(e => e.name === "word/document.xml");
  if (!docEntry) throw new Error("Invalid .docx: word/document.xml not found");
  const xml = docEntry.data.toString("utf8");
  const htmlParts: string[] = [];
  const pRegex = /<w:p[\s>][\s\S]*?<\/w:p>/g;
  let pMatch;
  while ((pMatch = pRegex.exec(xml)) !== null) {
    const pXml = pMatch[0];
    // Check for heading
    const headingMatch = pXml.match(/<w:pStyle\s+w:val="Heading(\d)"/);
    const headingLevel = headingMatch ? parseInt(headingMatch[1]) : 0;
    // Process runs
    const runs: string[] = [];
    const rRegex = /<w:r>([\s\S]*?)<\/w:r>/g;
    let rMatch;
    while ((rMatch = rRegex.exec(pXml)) !== null) {
      const rXml = rMatch[1];
      const tMatch = rXml.match(/<w:t[^>]*>([\s\S]*?)<\/w:t>/);
      if (!tMatch) continue;
      let text = tMatch[1].replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'");
      text = esc(text); // re-escape for HTML
      if (/<w:b\/>/.test(rXml) || /<w:b\s/.test(rXml)) text = `<b>${text}</b>`;
      if (/<w:i\/>/.test(rXml) || /<w:i\s/.test(rXml)) text = `<i>${text}</i>`;
      if (/<w:u\s/.test(rXml)) text = `<u>${text}</u>`;
      if (/<w:strike\/>/.test(rXml)) text = `<s>${text}</s>`;
      runs.push(text);
    }
    if (runs.length === 0) continue;
    const content = runs.join("");
    if (headingLevel >= 1 && headingLevel <= 6) {
      htmlParts.push(`<h${headingLevel}>${content}</h${headingLevel}>`);
    } else {
      htmlParts.push(`<p>${content}</p>`);
    }
  }
  return htmlParts.join("\n");
}

// ─── patchDoc: read ZIP, replace placeholders, write ZIP ────────────────────

function patchDocImpl(inputPath: string, outputPath: string, patches: Record<string, any>, opts: any): { path: string } {
  const buf = readFileSync(inputPath);
  const entries = readZip(buf);
  const newFiles: ZipFile[] = [];
  for (const entry of entries) {
    if (entry.name === "word/document.xml") {
      let xml = entry.data.toString("utf8");
      for (const [placeholder, replacement] of Object.entries(patches)) {
        // Placeholders may be split across runs in the XML. We handle both cases:
        // 1. Simple: placeholder fully in one <w:t>
        // 2. We also try replacing across the raw XML text (handles split runs approximately)
        const rep = typeof replacement === "string" ? replacement :
                    (replacement && typeof replacement === "object" && replacement.text) ? String(replacement.text) :
                    (replacement && typeof replacement === "object" && Array.isArray(replacement.runs)) ?
                      replacement.runs.map((r: any) => String(r.text ?? "")).join("") :
                    String(replacement ?? "");
        // Escape for XML
        const escapedRep = esc(rep);
        // Replace in raw XML - handles cases where placeholder is intact in one <w:t>
        xml = xml.split(esc(placeholder)).join(escapedRep);
        // Also try the raw placeholder (in case it wasn't escaped in the original doc)
        xml = xml.split(placeholder).join(escapedRep);
      }
      newFiles.push({ name: entry.name, data: Buffer.from(xml, "utf8") });
    } else {
      newFiles.push({ name: entry.name, data: entry.data });
    }
  }
  const zipBuf = writeZip(newFiles);
  writeFileSync(outputPath, zipBuf);
  return { path: outputPath };
}

// ═══════════════════════════════════════════════════════════════════════════════
// ─── 21 Word Functions (Handlers) ───────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

const createDoc = (args: any[]) => {
  const id = String(args[0] ?? `doc_${Date.now()}`);
  const opts = getOpts(args[1]);
  const defaultStyle = getOpts(opts.defaultStyle ?? opts.defaults ?? {});
  const defaults: RunStyle = {
    font: defaultStyle.font ? String(defaultStyle.font) : undefined,
    fontSize: defaultStyle.fontSize ? Number(defaultStyle.fontSize) : undefined,
    color: defaultStyle.color ? String(defaultStyle.color).replace("#", "") : undefined,
  };
  docs.set(id, {
    sections: [{ children: [], properties: opts.margins ? { margins: opts.margins } : {} }],
    activeSection: 0,
    options: opts,
    defaults,
    properties: {},
    footnotes: [],
    comments: [],
    styles: [],
    images: [],
    hyperlinks: [],
  });
  return id;
};

const readDoc = async (args: any[]) => {
  const filePath = String(args[0] ?? "");
  const format = String(args[1] ?? "text").toLowerCase();
  const buffer = readFileSync(filePath);
  if (format === "html") return parseDocxHtml(buffer);
  return parseDocxText(buffer);
};

const addHeading = (args: any[]) => {
  const id = String(args[0] ?? "");
  const text = String(args[1] ?? "");
  const level = Number(args[2] ?? 1);
  const opts = getOpts(args[3]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  getActiveSection(doc).children.push({
    type: "heading",
    data: { text, level, opts: { ...opts, keepNext: opts.keepNext ?? true } },
  });
  return true;
};

const addParagraph = (args: any[]) => {
  const id = String(args[0] ?? "");
  const text = String(args[1] ?? "");
  const opts = getOpts(args[2]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  const runs = Array.isArray(opts.runs) ? opts.runs : null;
  getActiveSection(doc).children.push({
    type: "paragraph",
    data: { text, runs, opts },
  });
  return true;
};

const addTable = (args: any[]) => {
  const id = String(args[0] ?? "");
  const data = args[1];
  const opts = getOpts(args[2]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  if (!Array.isArray(data) || data.length === 0) throw new Error("Table data must be a non-empty array");
  const isObjectArray = typeof data[0] === "object" && !Array.isArray(data[0]);
  const headers = isObjectArray ? Object.keys(data[0]) : null;
  const rows: any[][] = [];
  if (headers) {
    rows.push(headers);
    for (const item of data) rows.push(headers.map(h => String(item[h] ?? "")));
  } else {
    for (const row of data) rows.push(Array.isArray(row) ? row.map(String) : [String(row)]);
  }
  getActiveSection(doc).children.push({
    type: "table",
    data: { rows, hasHeaders: !!headers, headerStyle: opts.headerStyle, cellStyle: opts.cellStyle, columnWidths: opts.columnWidths, borders: opts.borders, alternateRows: opts.alternateRows },
  });
  return true;
};

const addImage = (args: any[]) => {
  const id = String(args[0] ?? "");
  const imagePath = String(args[1] ?? "");
  const opts = getOpts(args[2]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  const imageData = readFileSync(imagePath);
  const ext = extname(imagePath).replace(".", "").toLowerCase() || "png";
  const imgIdx = doc.images.length;
  doc.images.push({ data: imageData, ext });
  getActiveSection(doc).children.push({
    type: "image",
    data: { imgIdx, width: opts.width ?? 400, height: opts.height ?? 300, ext, opts },
  });
  return true;
};

const addPageBreak = (args: any[]) => {
  const id = String(args[0] ?? "");
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  getActiveSection(doc).children.push({ type: "pageBreak", data: {} });
  return true;
};

const addList = (args: any[]) => {
  const id = String(args[0] ?? "");
  const items = args[1];
  const opts = getOpts(args[2]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  if (!Array.isArray(items)) throw new Error("List items must be an array");
  const ordered = opts.ordered === true || opts.type === "numbered";
  getActiveSection(doc).children.push({
    type: "list",
    data: { items, ordered, level: opts.level ?? 0, opts },
  });
  return true;
};

const addHyperlink = (args: any[]) => {
  const id = String(args[0] ?? "");
  const text = String(args[1] ?? "");
  const url = String(args[2] ?? "");
  const opts = getOpts(args[3]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  getActiveSection(doc).children.push({
    type: "hyperlink",
    data: { text, url, opts },
  });
  return true;
};

const addBookmark = (args: any[]) => {
  const id = String(args[0] ?? "");
  const name = String(args[1] ?? "");
  const text = String(args[2] ?? "");
  const opts = getOpts(args[3]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  getActiveSection(doc).children.push({
    type: "bookmark",
    data: { name, text, opts },
  });
  return true;
};

const addTableOfContents = (args: any[]) => {
  const id = String(args[0] ?? "");
  const opts = getOpts(args[1]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  getActiveSection(doc).children.push({
    type: "toc",
    data: { heading: opts.heading ?? "Table of Contents", headingRange: opts.headingRange ?? "1-5", hyperlink: opts.hyperlink },
  });
  return true;
};

const addFootnote = (args: any[]) => {
  const id = String(args[0] ?? "");
  const text = String(args[1] ?? "");
  const footnoteText = String(args[2] ?? "");
  const opts = getOpts(args[3]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  doc.footnotes.push({ text, footnoteText, opts });
  getActiveSection(doc).children.push({
    type: "footnote",
    data: { text, footnoteText, opts },
  });
  return doc.footnotes.length;
};

const addComment = (args: any[]) => {
  const id = String(args[0] ?? "");
  const text = String(args[1] ?? "");
  const commentText = String(args[2] ?? "");
  const opts = getOpts(args[3]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  doc.comments.push({ text, commentText, opts });
  getActiveSection(doc).children.push({
    type: "comment",
    data: { text, commentText, opts },
  });
  return doc.comments.length - 1;
};

const addSection = (args: any[]) => {
  const id = String(args[0] ?? "");
  const opts = getOpts(args[1]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  const sectionProps: any = {};
  if (opts.type) sectionProps.type = String(opts.type).toLowerCase();
  if (opts.orientation) sectionProps.orientation = String(opts.orientation).toLowerCase();
  if (opts.columns) sectionProps.columns = Number(opts.columns);
  if (opts.margins) sectionProps.margins = opts.margins;
  doc.sections.push({ children: [], properties: sectionProps });
  doc.activeSection = doc.sections.length - 1;
  return doc.activeSection;
};

const setDocProperties = (args: any[]) => {
  const id = String(args[0] ?? "");
  const opts = getOpts(args[1]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  if (opts.title) doc.properties.title = String(opts.title);
  if (opts.author) doc.properties.author = String(opts.author);
  if (opts.subject) doc.properties.subject = String(opts.subject);
  if (opts.keywords) doc.properties.keywords = String(opts.keywords);
  if (opts.description) doc.properties.description = String(opts.description);
  return true;
};

const addDocStyle = (args: any[]) => {
  const id = String(args[0] ?? "");
  const styleName = String(args[1] ?? "");
  const opts = getOpts(args[2]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  doc.styles.push({ name: styleName, opts });
  return true;
};

const addHeader = (args: any[]) => {
  const id = String(args[0] ?? "");
  const text = String(args[1] ?? "");
  const opts = getOpts(args[2]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  getActiveSection(doc).header = { text, opts };
  return true;
};

const addFooter = (args: any[]) => {
  const id = String(args[0] ?? "");
  const text = String(args[1] ?? "");
  const opts = getOpts(args[2]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  getActiveSection(doc).footer = { text, opts };
  return true;
};

const patchDoc = async (args: any[]) => {
  const inputPath = String(args[0] ?? "");
  const outputPath = String(args[1] ?? "");
  const patches = getOpts(args[2]);
  const opts = getOpts(args[3]);
  return patchDocImpl(inputPath, outputPath, patches, opts);
};

const addCheckbox = (args: any[]) => {
  const id = String(args[0] ?? "");
  const label = String(args[1] ?? "");
  const opts = getOpts(args[2]);
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  getActiveSection(doc).children.push({
    type: "checkbox",
    data: { label, checked: Boolean(opts.checked), opts },
  });
  return true;
};

const saveDoc = (args: any[]) => {
  const id = String(args[0] ?? "");
  const filePath = String(args[1] ?? "");
  const doc = docs.get(id);
  if (!doc) throw new Error(`Document "${id}" not found`);
  const result = buildDocx(doc, filePath);
  docs.delete(id);
  return result;
};

// ═══════════════════════════════════════════════════════════════════════════════
// ─── Exports ────────────────────────────────────────────────────────────────
// ═══════════════════════════════════════════════════════════════════════════════

export const DocxFunctions: Record<string, (...args: any[]) => any> = {
  createDoc,
  readDoc,
  addHeading,
  addParagraph,
  addTable,
  addImage,
  addPageBreak,
  addList,
  addHyperlink,
  addBookmark,
  addTableOfContents,
  addFootnote,
  addComment,
  addSection,
  setDocProperties,
  addDocStyle,
  addHeader,
  addFooter,
  patchDoc,
  addCheckbox,
  saveDoc,
};

export const DocxFunctionMetadata = {
  createDoc: {
    description: "Create a new Word document",
    parameters: [
      { name: "id", dataType: "string", description: "Document ID", formInputType: "text", required: false },
      { name: "options", dataType: "object", description: "{margins: {top, bottom, left, right}}", formInputType: "json", required: false }
    ],
    returnType: "string",
    returnDescription: "Document ID",
    example: 'docx.createDoc "report" {"margins": {"top": 1, "bottom": 1}} into $doc'
  },
  readDoc: {
    description: "Read text or HTML from an existing Word document",
    parameters: [
      { name: "filePath", dataType: "string", description: "Path to .docx file", formInputType: "text", required: true },
      { name: "format", dataType: "string", description: "'text' (default) or 'html'", formInputType: "text", required: false }
    ],
    returnType: "string",
    returnDescription: "Document content as text or HTML",
    example: 'docx.readDoc "./contract.docx" "text" into $content'
  },
  addHeading: {
    description: "Add a heading with level and formatting",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "text", dataType: "string", description: "Heading text", formInputType: "text", required: true },
      { name: "level", dataType: "number", description: "Heading level 1-6", formInputType: "number", required: false },
      { name: "options", dataType: "object", description: "{bold, italic, fontSize, font, color, alignment, spacing}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addHeading $doc "Sales Report" 1 {"color": "#2196F3", "alignment": "center"}'
  },
  addParagraph: {
    description: "Add a paragraph with rich text formatting",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "text", dataType: "string", description: "Paragraph text", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{bold, italic, underline, fontSize, font, color, alignment, spacing, indent, runs: [{text, bold, color}]}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addParagraph $doc "Revenue increased by 23%" {"bold": true, "fontSize": 12, "alignment": "justify", "spacing": {"after": 200}}'
  },
  addTable: {
    description: "Add a table with full styling (headers, borders, colors, widths)",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "data", dataType: "array", description: "Array of objects or array of arrays", formInputType: "json", required: true },
      { name: "options", dataType: "object", description: "{headerStyle: {bold, fillColor, fontColor}, cellStyle, columnWidths, borders, alternateRows}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addTable $doc $data {"headerStyle": {"fillColor": "#2196F3", "fontColor": "#FFFFFF"}, "alternateRows": true}'
  },
  addImage: {
    description: "Add an image to the document",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "imagePath", dataType: "string", description: "Path to image file", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{width, height, alignment}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addImage $doc "./chart.png" {"width": 500, "height": 300, "alignment": "center"}'
  },
  addPageBreak: {
    description: "Add a page break",
    parameters: [{ name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true }],
    returnType: "boolean",
    returnDescription: "true",
    example: "docx.addPageBreak $doc"
  },
  addList: {
    description: "Add a bulleted or numbered list",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "items", dataType: "array", description: "Array of strings", formInputType: "json", required: true },
      { name: "options", dataType: "object", description: "{ordered: bool, bold, fontSize, font, color}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addList $doc ["Item 1", "Item 2", "Item 3"] {"ordered": true, "fontSize": 11}'
  },
  addHyperlink: {
    description: "Add a clickable hyperlink to the document",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "text", dataType: "string", description: "Display text", formInputType: "text", required: true },
      { name: "url", dataType: "string", description: "Target URL", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{color, bold, fontSize, font, underline, alignment}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addHyperlink $doc "Visit our site" "https://example.com" {"bold": true}'
  },
  addBookmark: {
    description: "Add a named bookmark for cross-references",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "name", dataType: "string", description: "Bookmark name", formInputType: "text", required: true },
      { name: "text", dataType: "string", description: "Bookmark text", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{bold, fontSize, font, color}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addBookmark $doc "section1" "Introduction" {"bold": true}'
  },
  addTableOfContents: {
    description: "Add an auto-generated table of contents from headings",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{heading, hyperlink, headingRange: '1-5'}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addTableOfContents $doc {"heading": "Contents", "headingRange": "1-3"}'
  },
  addFootnote: {
    description: "Add a footnote reference in text with footnote content at bottom",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "text", dataType: "string", description: "Paragraph text", formInputType: "text", required: true },
      { name: "footnoteText", dataType: "string", description: "Footnote content", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{bold, fontSize, font, color, alignment}", formInputType: "json", required: false }
    ],
    returnType: "number",
    returnDescription: "Footnote ID",
    example: 'docx.addFootnote $doc "See reference" "Source: IEEE 2024 paper" {}'
  },
  addComment: {
    description: "Add a comment annotation on a text range",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "text", dataType: "string", description: "Commented text", formInputType: "text", required: true },
      { name: "commentText", dataType: "string", description: "Comment content", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{author, bold, fontSize}", formInputType: "json", required: false }
    ],
    returnType: "number",
    returnDescription: "Comment ID",
    example: 'docx.addComment $doc "This needs review" "Please verify the figures" {"author": "Editor"}'
  },
  addSection: {
    description: "Add a new document section with separate formatting (orientation, columns, margins)",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{type: nextPage|continuous|evenPage|oddPage, orientation: portrait|landscape, columns, margins}", formInputType: "json", required: false }
    ],
    returnType: "number",
    returnDescription: "Section index",
    example: 'docx.addSection $doc {"orientation": "landscape", "type": "nextPage"}'
  },
  setDocProperties: {
    description: "Set document metadata properties (title, author, keywords)",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{title, author, subject, keywords, description}", formInputType: "json", required: true }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.setDocProperties $doc {"title": "Annual Report", "author": "Finance Dept"}'
  },
  addDocStyle: {
    description: "Define a reusable named paragraph or character style",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "styleName", dataType: "string", description: "Style name", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{type: paragraph|character, font, fontSize, bold, italic, color, alignment, spacing, basedOn}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addDocStyle $doc "Code Block" {"font": "Courier New", "fontSize": 10, "color": "333333"}'
  },
  addHeader: {
    description: "Add a custom header to the current section",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "text", dataType: "string", description: "Header text", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{type: default|first|even, alignment, bold, fontSize, font, color}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addHeader $doc "Company Report 2026" {"alignment": "right", "fontSize": 9}'
  },
  addFooter: {
    description: "Add a custom footer with optional page numbers",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "text", dataType: "string", description: "Footer text", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{type: default|first|even, alignment, pageNumbers: bool, pageNumberAlignment}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addFooter $doc "Confidential" {"pageNumbers": true, "alignment": "center"}'
  },
  patchDoc: {
    description: "Modify an existing .docx by replacing placeholders with new content",
    parameters: [
      { name: "inputPath", dataType: "string", description: "Path to existing .docx", formInputType: "text", required: true },
      { name: "outputPath", dataType: "string", description: "Output .docx path", formInputType: "text", required: true },
      { name: "patches", dataType: "object", description: '{"{{PLACEHOLDER}}": "replacement text"} or {"{{KEY}}": {runs: [{text, bold, color}]}}', formInputType: "json", required: true },
      { name: "options", dataType: "object", description: "{keepStyles}", formInputType: "json", required: false }
    ],
    returnType: "object",
    returnDescription: "{path}",
    example: 'docx.patchDoc "./template.docx" "./output.docx" {"{{NAME}}": "John", "{{DATE}}": "2026-01-15"}'
  },
  addCheckbox: {
    description: "Add a checkbox with label text",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "label", dataType: "string", description: "Checkbox label", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{checked: bool, bold, fontSize, font, color}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'docx.addCheckbox $doc "I agree to the terms" {"checked": false}'
  },
  saveDoc: {
    description: "Save the Word document to a .docx file",
    parameters: [
      { name: "docId", dataType: "string", description: "Document ID", formInputType: "text", required: true },
      { name: "filePath", dataType: "string", description: "Output .docx path", formInputType: "text", required: true }
    ],
    returnType: "object",
    returnDescription: "{path, size}",
    example: 'docx.saveDoc $doc "./report.docx"'
  },
};

export const DocxModuleMetadata = {
  description: "Word document (.docx) creation and reading \u2014 headings, paragraphs, tables, images, lists, hyperlinks, bookmarks, TOC, footnotes, comments, sections, headers/footers, styles, checkboxes, document patching, and more. Zero npm dependencies.",
  methods: [
    "createDoc",
    "readDoc",
    "addHeading",
    "addParagraph",
    "addTable",
    "addImage",
    "addPageBreak",
    "addList",
    "addHyperlink",
    "addBookmark",
    "addTableOfContents",
    "addFootnote",
    "addComment",
    "addSection",
    "setDocProperties",
    "addDocStyle",
    "addHeader",
    "addFooter",
    "patchDoc",
    "addCheckbox",
    "saveDoc",
  ],
};
