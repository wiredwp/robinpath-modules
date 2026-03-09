import type { BuiltinHandler } from "@wiredwp/robinpath";
import { writeFileSync, readFileSync } from "node:fs";
import { deflateSync, inflateSync } from "node:zlib";

// ── Pure JS PDF Writer ──────────────────────────────────────────────

const PAGE_SIZES: Record<string, [number, number]> = {
  A4: [595.28, 841.89],
  letter: [612, 792],
  legal: [612, 1008],
  A3: [841.89, 1190.55],
  A5: [419.53, 595.28],
};

const FONT_METRICS: Record<string, { widths: Record<number, number>; ascent: number; descent: number }> = {
  "Helvetica": { ascent: 718, descent: -207, widths: {} },
  "Helvetica-Bold": { ascent: 718, descent: -207, widths: {} },
  "Times-Roman": { ascent: 683, descent: -217, widths: {} },
  "Times-Bold": { ascent: 683, descent: -217, widths: {} },
  "Courier": { ascent: 629, descent: -157, widths: {} },
  "Courier-Bold": { ascent: 629, descent: -157, widths: {} },
};

function estimateTextWidth(text: string, fontName: string, fontSize: number): number {
  // Average character widths for standard PDF fonts (in 1/1000 of a unit)
  const avgWidths: Record<string, number> = {
    "Helvetica": 530, "Helvetica-Bold": 560,
    "Times-Roman": 500, "Times-Bold": 530,
    "Courier": 600, "Courier-Bold": 600,
  };
  const avg = avgWidths[fontName] ?? 530;
  return (text.length * avg * fontSize) / 1000;
}

function escapeText(text: string): string {
  return text
    .replace(/\\/g, "\\\\")
    .replace(/\(/g, "\\(")
    .replace(/\)/g, "\\)")
    .replace(/\r/g, "\\r");
}

interface PdfObj {
  id: number;
  generation: number;
  data: string;
}

class PdfWriter {
  private objects: PdfObj[] = [];
  private nextId = 1;
  private pages: number[] = [];
  private pageContents: { objId: number; stream: string }[] = [];
  private pagesObjId = 0;
  private catalogObjId = 0;
  private infoObjId = 0;
  private fontObjIds: Record<string, number> = {};

  private currentStream = "";
  private currentPageWidth = 595.28;
  private currentPageHeight = 841.89;
  private cursorX = 50;
  private cursorY = 50;
  private margin = 50;
  private currentFont = "Helvetica";
  private currentFontSize = 12;
  private currentFontKey = "F1";
  private lineHeight = 1.2;
  private pageCount = 0;

  private info: Record<string, string> = {};

  private allocId(): number {
    return this.nextId++;
  }

  private addObj(id: number, content: string): void {
    this.objects.push({ id, generation: 0, data: content });
  }

  setInfo(info: Record<string, string>): void {
    this.info = info;
  }

  private setupFonts(): void {
    const standardFonts = ["Helvetica", "Helvetica-Bold", "Times-Roman", "Times-Bold", "Courier", "Courier-Bold"];
    const keyMap: Record<string, string> = {
      "Helvetica": "F1", "Helvetica-Bold": "F2",
      "Times-Roman": "F3", "Times-Bold": "F4",
      "Courier": "F5", "Courier-Bold": "F6",
    };
    for (const font of standardFonts) {
      const id = this.allocId();
      this.fontObjIds[font] = id;
      this.addObj(id, `<< /Type /Font /Subtype /Type1 /BaseFont /${font} /Encoding /WinAnsiEncoding >>`);
    }
    this.currentFontKey = keyMap[this.currentFont] ?? "F1";
  }

  private fontResourceDict(): string {
    const entries = Object.entries(this.fontObjIds).map(([name, id]) => {
      const keyMap: Record<string, string> = {
        "Helvetica": "F1", "Helvetica-Bold": "F2",
        "Times-Roman": "F3", "Times-Bold": "F4",
        "Courier": "F5", "Courier-Bold": "F6",
      };
      return `/${keyMap[name]} ${id} 0 R`;
    });
    return `<< ${entries.join(" ")} >>`;
  }

  private getFontKey(fontName: string): string {
    const keyMap: Record<string, string> = {
      "Helvetica": "F1", "Helvetica-Bold": "F2",
      "Times-Roman": "F3", "Times-Bold": "F4",
      "Courier": "F5", "Courier-Bold": "F6",
    };
    return keyMap[fontName] ?? "F1";
  }

  initDocument(width: number, height: number, margin: number): void {
    this.currentPageWidth = width;
    this.currentPageHeight = height;
    this.margin = margin;
    this.catalogObjId = this.allocId();
    this.pagesObjId = this.allocId();
    this.infoObjId = this.allocId();
    this.setupFonts();
    this.addPage();
  }

  addPage(): void {
    // Finalize previous page if any
    if (this.pageCount > 0) {
      this.finalizePage();
    }
    this.pageCount++;
    this.currentStream = "";
    this.cursorX = this.margin;
    this.cursorY = this.currentPageHeight - this.margin;
    // Set initial font
    this.currentStream += `BT\n/${this.currentFontKey} ${this.currentFontSize} Tf\n`;
  }

  private finalizePage(): void {
    // Close any open BT block
    this.currentStream += "ET\n";
    const contentId = this.allocId();
    const pageId = this.allocId();

    const compressed = deflateSync(Buffer.from(this.currentStream, "latin1"));
    this.addObj(contentId, `<< /Length ${compressed.length} /Filter /FlateDecode >>\nstream\n` +
      String.fromCharCode(...compressed) + "\nendstream");

    this.addObj(pageId,
      `<< /Type /Page /Parent ${this.pagesObjId} 0 R ` +
      `/MediaBox [0 0 ${this.currentPageWidth} ${this.currentPageHeight}] ` +
      `/Contents ${contentId} 0 R ` +
      `/Resources << /Font ${this.fontResourceDict()} >> >>`
    );
    this.pages.push(pageId);
  }

  setFont(name: string, size: number): void {
    if (FONT_METRICS[name]) {
      this.currentFont = name;
      this.currentFontKey = this.getFontKey(name);
    }
    this.currentFontSize = size;
    this.currentStream += `/${this.currentFontKey} ${this.currentFontSize} Tf\n`;
  }

  setColor(r: number, g: number, b: number): void {
    this.currentStream += `${(r / 255).toFixed(3)} ${(g / 255).toFixed(3)} ${(b / 255).toFixed(3)} rg\n`;
  }

  setColorHex(hex: string): void {
    const h = hex.replace("#", "");
    const r = parseInt(h.substring(0, 2), 16);
    const g = parseInt(h.substring(2, 4), 16);
    const b = parseInt(h.substring(4, 6), 16);
    this.setColor(r, g, b);
  }

  textAt(text: string, x: number, y: number): void {
    // y in PDF coords (bottom-up)
    this.currentStream += `1 0 0 1 ${x.toFixed(2)} ${y.toFixed(2)} Tm\n(${escapeText(text)}) Tj\n`;
  }

  writeText(text: string, options?: { align?: string; width?: number }): void {
    const maxWidth = (options?.width ?? this.currentPageWidth - 2 * this.margin);
    const lines = text.split("\n");
    const lineSpacing = this.currentFontSize * this.lineHeight;

    for (const line of lines) {
      // Word-wrap
      const words = line.split(" ");
      let currentLine = "";
      for (const word of words) {
        const testLine = currentLine ? currentLine + " " + word : word;
        const testWidth = estimateTextWidth(testLine, this.currentFont, this.currentFontSize);
        if (testWidth > maxWidth && currentLine) {
          this.renderLine(currentLine, options?.align, maxWidth);
          this.cursorY -= lineSpacing;
          if (this.cursorY < this.margin + 20) {
            this.addPage();
          }
          currentLine = word;
        } else {
          currentLine = testLine;
        }
      }
      if (currentLine) {
        this.renderLine(currentLine, options?.align, maxWidth);
        this.cursorY -= lineSpacing;
        if (this.cursorY < this.margin + 20) {
          this.addPage();
        }
      }
      // Empty line
      if (line === "") {
        this.cursorY -= lineSpacing;
        if (this.cursorY < this.margin + 20) {
          this.addPage();
        }
      }
    }
  }

  private renderLine(text: string, align?: string, maxWidth?: number): void {
    let x = this.margin;
    const w = maxWidth ?? (this.currentPageWidth - 2 * this.margin);
    if (align === "center") {
      const tw = estimateTextWidth(text, this.currentFont, this.currentFontSize);
      x = this.margin + (w - tw) / 2;
    } else if (align === "right") {
      const tw = estimateTextWidth(text, this.currentFont, this.currentFontSize);
      x = this.margin + w - tw;
    }
    this.textAt(text, x, this.cursorY);
  }

  moveDown(lines = 1): void {
    this.cursorY -= this.currentFontSize * this.lineHeight * lines;
    if (this.cursorY < this.margin + 20) {
      this.addPage();
    }
  }

  getCursorY(): number { return this.cursorY; }
  getPageWidth(): number { return this.currentPageWidth; }
  getPageHeight(): number { return this.currentPageHeight; }
  getMargin(): number { return this.margin; }
  getPageCount(): number { return this.pageCount; }

  drawLine(x1: number, y1: number, x2: number, y2: number, lineWidth = 1): void {
    // Need to end text block, draw, and start a new text block
    this.currentStream += `ET\n${lineWidth} w\n${x1.toFixed(2)} ${y1.toFixed(2)} m ${x2.toFixed(2)} ${y2.toFixed(2)} l S\nBT\n/${this.currentFontKey} ${this.currentFontSize} Tf\n`;
  }

  toBuffer(): Buffer {
    // Finalize last page
    this.finalizePage();

    // Build info object
    let infoDict = "<< ";
    if (this.info.title) infoDict += `/Title (${escapeText(this.info.title)}) `;
    if (this.info.author) infoDict += `/Author (${escapeText(this.info.author)}) `;
    if (this.info.subject) infoDict += `/Subject (${escapeText(this.info.subject)}) `;
    infoDict += `/Producer (RobinPath PDF Writer) `;
    infoDict += `/CreationDate (D:${new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14)}) `;
    infoDict += ">>";
    this.addObj(this.infoObjId, infoDict);

    // Pages object
    const pageRefs = this.pages.map(p => `${p} 0 R`).join(" ");
    this.addObj(this.pagesObjId, `<< /Type /Pages /Kids [${pageRefs}] /Count ${this.pages.length} >>`);

    // Catalog
    this.addObj(this.catalogObjId, `<< /Type /Catalog /Pages ${this.pagesObjId} 0 R >>`);

    // Sort objects by id
    this.objects.sort((a, b) => a.id - b.id);

    // Build PDF bytes
    let pdf = "%PDF-1.4\n%\xE2\xE3\xCF\xD3\n";
    const offsets: number[] = [];

    for (const obj of this.objects) {
      offsets[obj.id] = pdf.length;
      pdf += `${obj.id} 0 obj\n${obj.data}\nendobj\n`;
    }

    // Cross-reference table
    const xrefOffset = pdf.length;
    pdf += "xref\n";
    pdf += `0 ${this.nextId}\n`;
    pdf += "0000000000 65535 f \n";
    for (let i = 1; i < this.nextId; i++) {
      const off = offsets[i] ?? 0;
      pdf += `${String(off).padStart(10, "0")} 00000 n \n`;
    }

    // Trailer
    pdf += "trailer\n";
    pdf += `<< /Size ${this.nextId} /Root ${this.catalogObjId} 0 R /Info ${this.infoObjId} 0 R >>\n`;
    pdf += "startxref\n";
    pdf += `${xrefOffset}\n`;
    pdf += "%%EOF\n";

    return Buffer.from(pdf, "latin1");
  }
}

// ── Pure JS PDF Reader / Text Extractor ─────────────────────────────

function extractPdfText(buffer: Buffer): string {
  const raw = buffer.toString("latin1");
  const texts: string[] = [];

  // Find all stream...endstream blocks
  const streamRegex = /stream\r?\n([\s\S]*?)endstream/g;
  let match: RegExpExecArray | null;

  while ((match = streamRegex.exec(raw)) !== null) {
    let data = match[1];
    // Remove trailing \r\n if present
    if (data.endsWith("\r\n")) data = data.slice(0, -2);
    else if (data.endsWith("\n")) data = data.slice(0, -1);

    let decoded: string;
    try {
      // Try FlateDecode decompression
      const buf = Buffer.from(data, "latin1");
      const inflated = inflateSync(buf);
      decoded = inflated.toString("latin1");
    } catch {
      // Not compressed or different encoding, use raw
      decoded = data;
    }

    // Extract text operators: Tj, TJ, ', "
    const extracted = extractTextOperators(decoded);
    if (extracted.trim()) {
      texts.push(extracted);
    }
  }

  return texts.join("\n").trim();
}

function extractTextOperators(stream: string): string {
  const parts: string[] = [];

  // Handle Tj operator: (text) Tj
  const tjRegex = /\(([^)]*)\)\s*Tj/g;
  let m: RegExpExecArray | null;
  while ((m = tjRegex.exec(stream)) !== null) {
    parts.push(unescapePdfString(m[1]));
  }

  // Handle TJ operator: [(text) num (text) ...] TJ
  const tjArrayRegex = /\[((?:[^]]*?))\]\s*TJ/g;
  while ((m = tjArrayRegex.exec(stream)) !== null) {
    const inner = m[1];
    const strRegex = /\(([^)]*)\)/g;
    let sm: RegExpExecArray | null;
    while ((sm = strRegex.exec(inner)) !== null) {
      parts.push(unescapePdfString(sm[1]));
    }
  }

  // Handle ' operator (move to next line and show text): (text) '
  const quoteRegex = /\(([^)]*)\)\s*'/g;
  while ((m = quoteRegex.exec(stream)) !== null) {
    parts.push(unescapePdfString(m[1]));
  }

  // Handle " operator: num num (text) "
  const dblQuoteRegex = /[\d.]+\s+[\d.]+\s+\(([^)]*)\)\s*"/g;
  while ((m = dblQuoteRegex.exec(stream)) !== null) {
    parts.push(unescapePdfString(m[1]));
  }

  // Also handle text positioning context: detect Td/TD for newlines
  // Simple heuristic: check for significant Y changes between Tm/Td commands
  // This gives rough line separation
  if (parts.length === 0) return "";

  return parts.join(" ");
}

function unescapePdfString(s: string): string {
  return s
    .replace(/\\n/g, "\n")
    .replace(/\\r/g, "\r")
    .replace(/\\t/g, "\t")
    .replace(/\\\(/g, "(")
    .replace(/\\\)/g, ")")
    .replace(/\\\\/g, "\\");
}

function getPdfPageCount(buffer: Buffer): number {
  const raw = buffer.toString("latin1");
  // Look for /Pages ... /Count N
  const countMatch = raw.match(/\/Type\s*\/Pages[^>]*\/Count\s+(\d+)/);
  if (countMatch) return parseInt(countMatch[1], 10);

  // Alternative: /Count before /Type
  const altMatch = raw.match(/\/Count\s+(\d+)[^>]*\/Type\s*\/Pages/);
  if (altMatch) return parseInt(altMatch[1], 10);

  // Fallback: count /Type /Page (not /Pages)
  const pageMatches = raw.match(/\/Type\s*\/Page(?!\s*s)\b/g);
  return pageMatches ? pageMatches.length : 0;
}

function getPdfMetadata(buffer: Buffer): Record<string, string> {
  const raw = buffer.toString("latin1");
  const info: Record<string, string> = {};

  // Find /Info dictionary reference or inline
  const fields = ["Title", "Author", "Subject", "Creator", "Producer", "CreationDate", "ModDate", "Keywords"];

  for (const field of fields) {
    // Match /Field (value) or /Field <hex>
    const regex = new RegExp(`\\/${field}\\s*\\(([^)]*)\\)`, "i");
    const m = raw.match(regex);
    if (m) {
      info[field.toLowerCase()] = unescapePdfString(m[1]);
    }
    // Also try hex string
    const hexRegex = new RegExp(`\\/${field}\\s*<([0-9a-fA-F]+)>`, "i");
    const hm = raw.match(hexRegex);
    if (hm && !info[field.toLowerCase()]) {
      const hex = hm[1];
      let str = "";
      for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substring(i, i + 2), 16));
      }
      info[field.toLowerCase()] = str;
    }
  }

  return info;
}

// ── Function Handlers ───────────────────────────────────────────────

const generate: BuiltinHandler = async (args) => {
  const outputPath = String(args[0] ?? "output.pdf");
  const opts = (typeof args[1] === "object" && args[1] !== null ? args[1] : {}) as Record<string, unknown>;

  const sizeKey = String(opts.size ?? "A4");
  const [w, h] = PAGE_SIZES[sizeKey] ?? PAGE_SIZES.A4;
  const margin = Number(opts.margin ?? 50);

  const pdf = new PdfWriter();
  pdf.setInfo({
    title: opts.title ? String(opts.title) : "",
    author: opts.author ? String(opts.author) : "",
  });
  pdf.initDocument(w, h, margin);

  // Title
  if (opts.title) {
    pdf.setFont("Helvetica-Bold", Number(opts.titleSize ?? 24));
    pdf.writeText(String(opts.title), { align: "center" });
    pdf.moveDown();
  }

  // Author
  if (opts.author) {
    pdf.setFont("Helvetica", 12);
    pdf.writeText(`By: ${opts.author}`, { align: "center" });
    pdf.moveDown(2);
  }

  // Content
  if (opts.content) {
    pdf.setFont("Helvetica", Number(opts.fontSize ?? 12));
    pdf.writeText(String(opts.content));
  }

  // Sections
  if (Array.isArray(opts.sections)) {
    for (const section of opts.sections as Record<string, unknown>[]) {
      if (section.heading) {
        pdf.moveDown();
        pdf.setFont("Helvetica-Bold", Number(section.headingSize ?? 18));
        pdf.writeText(String(section.heading));
        pdf.moveDown(0.5);
      }
      if (section.text) {
        pdf.setFont("Helvetica", Number(section.fontSize ?? 12));
        pdf.writeText(String(section.text));
      }
      if (section.list && Array.isArray(section.list)) {
        pdf.setFont("Helvetica", 12);
        for (const item of section.list as string[]) {
          pdf.writeText(`  \u2022 ${item}`);
        }
      }
      if (section.pageBreak) pdf.addPage();
    }
  }

  // Footer - write on each page is complex with this approach;
  // for simplicity we add footer text at bottom of last page if present
  if (opts.footer) {
    pdf.setFont("Helvetica", 10);
    const footerY = margin;
    pdf.textAt(String(opts.footer), w / 2 - estimateTextWidth(String(opts.footer), "Helvetica", 10) / 2, footerY);
  }

  const buf = pdf.toBuffer();
  writeFileSync(outputPath, buf);

  return { path: outputPath, pages: pdf.getPageCount() };
};

const parse: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "");
  const buffer = readFileSync(filePath);
  const text = extractPdfText(buffer);
  const pages = getPdfPageCount(buffer);
  const info = getPdfMetadata(buffer);
  return {
    text,
    pages,
    info,
    metadata: info,
  };
};

const extractText: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "");
  const buffer = readFileSync(filePath);
  return extractPdfText(buffer);
};

const pageCount: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "");
  const buffer = readFileSync(filePath);
  return getPdfPageCount(buffer);
};

const metadata: BuiltinHandler = async (args) => {
  const filePath = String(args[0] ?? "");
  const buffer = readFileSync(filePath);
  const info = getPdfMetadata(buffer);
  const pages = getPdfPageCount(buffer);
  return { info, metadata: info, pages };
};

const generateTable: BuiltinHandler = async (args) => {
  const outputPath = String(args[0] ?? "table.pdf");
  const headers = Array.isArray(args[1]) ? args[1].map(String) : [];
  const rows = Array.isArray(args[2]) ? args[2] : [];
  const opts = (typeof args[3] === "object" && args[3] !== null ? args[3] : {}) as Record<string, unknown>;

  const [w, h] = opts.landscape ? [841.89, 595.28] : [595.28, 841.89];
  const margin = 40;

  const pdf = new PdfWriter();
  pdf.setInfo({ title: opts.title ? String(opts.title) : "" });
  pdf.initDocument(w, h, margin);

  if (opts.title) {
    pdf.setFont("Helvetica-Bold", 16);
    pdf.writeText(String(opts.title), { align: "center" });
    pdf.moveDown();
  }

  const colWidth = (w - 2 * margin) / headers.length;
  let y = pdf.getCursorY();

  // Headers
  pdf.setFont("Helvetica-Bold", 10);
  headers.forEach((hdr: string, i: number) => {
    pdf.textAt(hdr, margin + i * colWidth, y);
  });
  y -= 20;
  pdf.drawLine(margin, y, w - margin, y);
  y -= 5;

  // Rows
  pdf.setFont("Helvetica", 9);
  for (const row of rows) {
    const cells = Array.isArray(row) ? row.map(String) : Object.values(row as Record<string, unknown>).map(String);
    if (y < margin + 30) {
      pdf.addPage();
      y = pdf.getCursorY();
    }
    cells.forEach((cell: string, i: number) => {
      pdf.textAt(cell, margin + i * colWidth, y);
    });
    y -= 18;
  }

  const buf = pdf.toBuffer();
  writeFileSync(outputPath, buf);

  return { path: outputPath };
};

const generateFromHtml: BuiltinHandler = async (args) => {
  const outputPath = String(args[0] ?? "output.pdf");
  const html = String(args[1] ?? "");

  // Simple HTML to text conversion (basic support)
  const text = html
    .replace(/<h1[^>]*>(.*?)<\/h1>/gi, (_, t) => `\n\n### ${t}\n`)
    .replace(/<h2[^>]*>(.*?)<\/h2>/gi, (_, t) => `\n\n## ${t}\n`)
    .replace(/<h3[^>]*>(.*?)<\/h3>/gi, (_, t) => `\n# ${t}\n`)
    .replace(/<p[^>]*>(.*?)<\/p>/gi, (_, t) => `${t}\n\n`)
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<li[^>]*>(.*?)<\/li>/gi, (_, t) => `\u2022 ${t}\n`)
    .replace(/<[^>]+>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .trim();

  return await generate([outputPath, { content: text }]);
};

// ── Exports ─────────────────────────────────────────────────────────

export const PdfFunctions: Record<string, BuiltinHandler> = {
  generate, parse, extractText, pageCount, metadata, generateTable, generateFromHtml,
};

export const PdfFunctionMetadata = {
  generate: { description: "Generate a PDF document with title, content, and sections", parameters: [{ name: "outputPath", dataType: "string", description: "Output file path", formInputType: "text", required: true }, { name: "options", dataType: "object", description: "{title, author, content, sections, footer, size, margin, fontSize}", formInputType: "text", required: true }], returnType: "object", returnDescription: "{path, pages}", example: 'pdf.generate "./report.pdf" {"title": "Monthly Report", "content": "..."}' },
  parse: { description: "Parse a PDF file and extract text, metadata, and page count", parameters: [{ name: "filePath", dataType: "string", description: "Path to PDF file", formInputType: "text", required: true }], returnType: "object", returnDescription: "{text, pages, info, metadata}", example: 'pdf.parse "./document.pdf"' },
  extractText: { description: "Extract all text from a PDF file", parameters: [{ name: "filePath", dataType: "string", description: "Path to PDF file", formInputType: "text", required: true }], returnType: "string", returnDescription: "Extracted text content", example: 'pdf.extractText "./document.pdf"' },
  pageCount: { description: "Get the number of pages in a PDF", parameters: [{ name: "filePath", dataType: "string", description: "Path to PDF file", formInputType: "text", required: true }], returnType: "number", returnDescription: "Page count", example: 'pdf.pageCount "./document.pdf"' },
  metadata: { description: "Get PDF metadata (author, title, creation date, etc.)", parameters: [{ name: "filePath", dataType: "string", description: "Path to PDF file", formInputType: "text", required: true }], returnType: "object", returnDescription: "{info, metadata, pages}", example: 'pdf.metadata "./document.pdf"' },
  generateTable: { description: "Generate a PDF with a formatted table", parameters: [{ name: "outputPath", dataType: "string", description: "Output file path", formInputType: "text", required: true }, { name: "headers", dataType: "array", description: "Column headers", formInputType: "text", required: true }, { name: "rows", dataType: "array", description: "Array of row arrays or objects", formInputType: "text", required: true }, { name: "options", dataType: "object", description: "{title, landscape}", formInputType: "text", required: false }], returnType: "object", returnDescription: "{path}", example: 'pdf.generateTable "./table.pdf" ["Name","Email"] $rows' },
  generateFromHtml: { description: "Generate a PDF from basic HTML content", parameters: [{ name: "outputPath", dataType: "string", description: "Output file path", formInputType: "text", required: true }, { name: "html", dataType: "string", description: "HTML content", formInputType: "text", required: true }], returnType: "object", returnDescription: "{path, pages}", example: 'pdf.generateFromHtml "./output.pdf" "<h1>Title</h1><p>Content</p>"' },
};

export const PdfModuleMetadata = {
  description: "PDF generation (documents, tables, HTML-to-PDF) and parsing (text extraction, metadata, page count)",
  methods: ["generate", "parse", "extractText", "pageCount", "metadata", "generateTable", "generateFromHtml"],
};
