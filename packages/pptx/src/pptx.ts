// @ts-nocheck
import * as fs from "node:fs";
import * as path from "node:path";
import { deflateRawSync } from "node:zlib";

// ─── ZIP Writer (pure JS, no npm) ───────────────────────────────────────────

const CRC32_TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC32_TABLE[n] = c;
}

function crc32(buf: Buffer): number {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) crc = CRC32_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function buildZip(entries: Array<{ name: string; data: Buffer }>): Buffer {
  const localHeaders: Buffer[] = [];
  const centralHeaders: Buffer[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = Buffer.from(entry.name, "utf-8");
    const compressed = deflateRawSync(entry.data, { level: 6 });
    const crc = crc32(entry.data);
    const uncompSize = entry.data.length;
    const compSize = compressed.length;

    // Local file header (30 + nameLen + compData)
    const local = Buffer.alloc(30 + nameBytes.length + compSize);
    local.writeUInt32LE(0x04034b50, 0);  // signature
    local.writeUInt16LE(20, 4);           // version needed
    local.writeUInt16LE(0, 6);            // flags
    local.writeUInt16LE(8, 8);            // compression: deflate
    local.writeUInt16LE(0, 10);           // mod time
    local.writeUInt16LE(0, 12);           // mod date
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(compSize, 18);
    local.writeUInt32LE(uncompSize, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    local.writeUInt16LE(0, 28);           // extra field length
    nameBytes.copy(local, 30);
    compressed.copy(local, 30 + nameBytes.length);
    localHeaders.push(local);

    // Central directory header
    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);         // version made by
    central.writeUInt16LE(20, 6);         // version needed
    central.writeUInt16LE(0, 8);          // flags
    central.writeUInt16LE(8, 10);         // compression
    central.writeUInt16LE(0, 12);         // mod time
    central.writeUInt16LE(0, 14);         // mod date
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(compSize, 20);
    central.writeUInt32LE(uncompSize, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(0, 30);         // extra field length
    central.writeUInt16LE(0, 32);         // comment length
    central.writeUInt16LE(0, 34);         // disk number start
    central.writeUInt16LE(0, 36);         // internal attrs
    central.writeUInt32LE(0, 38);         // external attrs
    central.writeUInt32LE(offset, 42);    // offset of local header
    nameBytes.copy(central, 46);
    centralHeaders.push(central);

    offset += local.length;
  }

  const centralDirStart = offset;
  let centralDirSize = 0;
  for (const c of centralHeaders) centralDirSize += c.length;

  // End of central directory record
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);              // disk number
  eocd.writeUInt16LE(0, 6);              // central dir disk
  eocd.writeUInt16LE(entries.length, 8); // entries on disk
  eocd.writeUInt16LE(entries.length, 10);// total entries
  eocd.writeUInt32LE(centralDirSize, 12);
  eocd.writeUInt32LE(centralDirStart, 16);
  eocd.writeUInt16LE(0, 20);             // comment length

  return Buffer.concat([...localHeaders, ...centralHeaders, eocd]);
}

// ─── XML Escaping ────────────────────────────────────────────────────────────

function esc(s: string): string {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ─── EMU Helpers ─────────────────────────────────────────────────────────────
// 1 inch = 914400 EMU, standard slide = 10" x 7.5"

const EMU_PER_INCH = 914400;
const SLIDE_W = 9144000; // 10 inches
const SLIDE_H = 6858000; // 7.5 inches

function inchToEmu(v: number): number {
  return Math.round(v * EMU_PER_INCH);
}

function parsePos(v: any, totalEmu: number): number {
  if (typeof v === "string" && v.endsWith("%")) {
    return Math.round((parseFloat(v) / 100) * totalEmu);
  }
  return inchToEmu(Number(v));
}

// ─── Color Helpers ───────────────────────────────────────────────────────────

function normalizeColor(c: string): string {
  return String(c).replace(/^#/, "").toUpperCase();
}

// ─── Opts Helper ─────────────────────────────────────────────────────────────

function getOpts(v: any): Record<string, any> {
  if (v && typeof v === "object" && !Array.isArray(v)) return v;
  return {};
}

// ─── Presentation State ──────────────────────────────────────────────────────

interface TextRun {
  text: string;
  bold?: boolean;
  italic?: boolean;
  underline?: boolean;
  strike?: boolean;
  superscript?: boolean;
  subscript?: boolean;
  fontSize?: number;
  font?: string;
  color?: string;
  hyperlink?: string;
  breakType?: string;
}

interface SlideItem {
  type: "text" | "image" | "table" | "chart" | "shape" | "multiText" | "slideNumber";
  // text
  text?: string;
  runs?: TextRun[];
  // image
  imagePath?: string;
  imageData?: Buffer;
  imageExt?: string;
  // table
  tableData?: any[];
  // chart
  chartData?: any[];
  // shape
  shapeType?: string;
  // common positioning (in inches)
  x?: number;
  y?: number;
  w?: number;
  h?: number;
  // text formatting
  fontSize?: number;
  font?: string;
  bold?: boolean;
  italic?: boolean;
  underline?: boolean;
  color?: string;
  alignment?: string;
  verticalAlign?: string;
  fillColor?: string;
  lineColor?: string;
  lineWidth?: number;
  bullet?: any;
  lineSpacing?: number;
  spaceAfter?: number;
  spaceBefore?: number;
  margin?: number;
  // table options
  headerStyle?: any;
  cellStyle?: any;
  columnWidths?: number[];
  alternateRows?: boolean;
  borders?: boolean;
  // chart options
  chartType?: string;
  chartTitle?: string;
  showLegend?: boolean;
  showValues?: boolean;
  // image options
  rounding?: boolean;
  hyperlink?: string;
  // slideNumber options
  slideNumberOpts?: any;
}

interface SlideData {
  items: SlideItem[];
  notes?: string;
  backgroundColor?: string;
  title?: string;
  subtitle?: string;
  titleSize?: number;
  titleColor?: string;
  subtitleSize?: number;
  subtitleColor?: string;
  masterName?: string;
}

interface SlideMaster {
  name: string;
  bgColor?: string;
  background?: string;
  margin?: any;
  slideNumber?: any;
  objects?: any[];
}

interface PresentationState {
  title: string;
  author: string;
  subject: string;
  layout: string;
  slides: SlideData[];
  masters: Map<string, SlideMaster>;
}

const presentations = new Map<string, PresentationState>();

// ─── XML Generation ──────────────────────────────────────────────────────────

function genContentTypes(pres: PresentationState): string {
  let xml = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Default Extension="png" ContentType="image/png"/>
  <Default Extension="jpg" ContentType="image/jpeg"/>
  <Default Extension="jpeg" ContentType="image/jpeg"/>
  <Default Extension="gif" ContentType="image/gif"/>
  <Default Extension="bmp" ContentType="image/bmp"/>
  <Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/>
  <Override PartName="/ppt/theme/theme1.xml" ContentType="application/vnd.openxmlformats-officedocument.theme+xml"/>
  <Override PartName="/ppt/slideMasters/slideMaster1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideMaster+xml"/>
  <Override PartName="/ppt/slideLayouts/slideLayout1.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slideLayout+xml"/>`;

  for (let i = 0; i < pres.slides.length; i++) {
    xml += `\n  <Override PartName="/ppt/slides/slide${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>`;
    if (pres.slides[i].notes) {
      xml += `\n  <Override PartName="/ppt/notesSlides/notesSlide${i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"/>`;
    }
  }

  // check for charts
  let chartIdx = 0;
  for (const slide of pres.slides) {
    for (const item of slide.items) {
      if (item.type === "chart") {
        chartIdx++;
        xml += `\n  <Override PartName="/ppt/charts/chart${chartIdx}.xml" ContentType="application/vnd.openxmlformats-officedocument.drawingml.chart+xml"/>`;
      }
    }
  }

  xml += `\n</Types>`;
  return xml;
}

function genRootRels(): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="ppt/presentation.xml"/>
</Relationships>`;
}

function genPresentation(pres: PresentationState): string {
  let slideListXml = "";
  for (let i = 0; i < pres.slides.length; i++) {
    slideListXml += `\n      <p:sldId id="${256 + i}" r:id="rId${i + 2}"/>`;
  }

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:presentation xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:sldMasterIdLst>
    <p:sldMasterId id="2147483648" r:id="rId1"/>
  </p:sldMasterIdLst>
  <p:sldIdLst>${slideListXml}
  </p:sldIdLst>
  <p:sldSz cx="${SLIDE_W}" cy="${SLIDE_H}"/>
  <p:notesSz cx="${SLIDE_H}" cy="${SLIDE_W}"/>
</p:presentation>`;
}

function genPresentationRels(pres: PresentationState): string {
  let rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="slideMasters/slideMaster1.xml"/>`;

  for (let i = 0; i < pres.slides.length; i++) {
    rels += `\n  <Relationship Id="rId${i + 2}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="slides/slide${i + 1}.xml"/>`;
  }

  const themeId = pres.slides.length + 2;
  rels += `\n  <Relationship Id="rId${themeId}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="theme/theme1.xml"/>`;
  rels += `\n</Relationships>`;
  return rels;
}

function genTheme(): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" name="Office Theme">
  <a:themeElements>
    <a:clrScheme name="Office">
      <a:dk1><a:sysClr val="windowText" lastClr="000000"/></a:dk1>
      <a:lt1><a:sysClr val="window" lastClr="FFFFFF"/></a:lt1>
      <a:dk2><a:srgbClr val="44546A"/></a:dk2>
      <a:lt2><a:srgbClr val="E7E6E6"/></a:lt2>
      <a:accent1><a:srgbClr val="4472C4"/></a:accent1>
      <a:accent2><a:srgbClr val="ED7D31"/></a:accent2>
      <a:accent3><a:srgbClr val="A5A5A5"/></a:accent3>
      <a:accent4><a:srgbClr val="FFC000"/></a:accent4>
      <a:accent5><a:srgbClr val="5B9BD5"/></a:accent5>
      <a:accent6><a:srgbClr val="70AD47"/></a:accent6>
      <a:hlink><a:srgbClr val="0563C1"/></a:hlink>
      <a:folHlink><a:srgbClr val="954F72"/></a:folHlink>
    </a:clrScheme>
    <a:fontScheme name="Office">
      <a:majorFont><a:latin typeface="Calibri Light"/><a:ea typeface=""/><a:cs typeface=""/></a:majorFont>
      <a:minorFont><a:latin typeface="Calibri"/><a:ea typeface=""/><a:cs typeface=""/></a:minorFont>
    </a:fontScheme>
    <a:fmtScheme name="Office">
      <a:fillStyleLst>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
      </a:fillStyleLst>
      <a:lnStyleLst>
        <a:ln w="6350"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>
        <a:ln w="12700"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>
        <a:ln w="19050"><a:solidFill><a:schemeClr val="phClr"/></a:solidFill></a:ln>
      </a:lnStyleLst>
      <a:effectStyleLst>
        <a:effectStyle><a:effectLst/></a:effectStyle>
        <a:effectStyle><a:effectLst/></a:effectStyle>
        <a:effectStyle><a:effectLst/></a:effectStyle>
      </a:effectStyleLst>
      <a:bgFillStyleLst>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
        <a:solidFill><a:schemeClr val="phClr"/></a:solidFill>
      </a:bgFillStyleLst>
    </a:fmtScheme>
  </a:themeElements>
</a:theme>`;
}

function genSlideMaster(): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldMaster xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:bg>
      <p:bgRef idx="1001"><a:schemeClr val="bg1"/></p:bgRef>
    </p:bg>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr>
        <a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm>
      </p:grpSpPr>
    </p:spTree>
  </p:cSld>
  <p:clrMap bg1="lt1" tx1="dk1" bg2="lt2" tx2="dk2" accent1="accent1" accent2="accent2" accent3="accent3" accent4="accent4" accent5="accent5" accent6="accent6" hlink="hlink" folHlink="folHlink"/>
  <p:sldLayoutIdLst>
    <p:sldLayoutId id="2147483649" r:id="rId1"/>
  </p:sldLayoutIdLst>
</p:sldMaster>`;
}

function genSlideMasterRels(): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/theme" Target="../theme/theme1.xml"/>
</Relationships>`;
}

function genSlideLayout(): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sldLayout xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main" type="blank">
  <p:cSld name="Blank">
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr>
        <a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm>
      </p:grpSpPr>
    </p:spTree>
  </p:cSld>
</p:sldLayout>`;
}

function genSlideLayoutRels(): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideMaster" Target="../slideMasters/slideMaster1.xml"/>
</Relationships>`;
}

function genTextRunXml(run: TextRun): string {
  let rPr = `<a:rPr lang="en-US"`;
  if (run.fontSize) rPr += ` sz="${run.fontSize * 100}"`;
  if (run.bold) rPr += ` b="1"`;
  if (run.italic) rPr += ` i="1"`;
  if (run.underline) rPr += ` u="sng"`;
  if (run.strike) rPr += ` strike="sngStrike"`;
  if (run.superscript) rPr += ` baseline="30000"`;
  if (run.subscript) rPr += ` baseline="-25000"`;
  rPr += `>`;
  if (run.color) {
    rPr += `<a:solidFill><a:srgbClr val="${normalizeColor(run.color)}"/></a:solidFill>`;
  }
  if (run.font) {
    rPr += `<a:latin typeface="${esc(run.font)}"/><a:cs typeface="${esc(run.font)}"/>`;
  }
  if (run.hyperlink) {
    rPr += `<a:hlinkClick r:id="" tooltip="${esc(run.hyperlink)}"/>`;
  }
  rPr += `</a:rPr>`;

  if (run.breakType === "line") {
    return `<a:br>${rPr}</a:br>`;
  }

  return `<a:r>${rPr}<a:t>${esc(run.text)}</a:t></a:r>`;
}

function genParagraphXml(
  text: string | undefined,
  runs: TextRun[] | undefined,
  opts: {
    fontSize?: number; font?: string; bold?: boolean; italic?: boolean;
    underline?: boolean; color?: string; alignment?: string; bullet?: any;
    lineSpacing?: number; spaceAfter?: number; spaceBefore?: number;
  }
): string {
  let pPr = `<a:pPr`;
  const align = opts.alignment ?? "l";
  const alignMap: Record<string, string> = { left: "l", center: "ctr", right: "r", justify: "just", l: "l", ctr: "ctr", r: "r", just: "just" };
  pPr += ` algn="${alignMap[align] ?? "l"}"`;
  pPr += `>`;

  if (opts.lineSpacing) {
    pPr += `<a:lnSpc><a:spcPts val="${Math.round(opts.lineSpacing * 100)}"/></a:lnSpc>`;
  }
  if (opts.spaceAfter) {
    pPr += `<a:spcAft><a:spcPts val="${Math.round(opts.spaceAfter * 100)}"/></a:spcAft>`;
  }
  if (opts.spaceBefore) {
    pPr += `<a:spcBef><a:spcPts val="${Math.round(opts.spaceBefore * 100)}"/></a:spcBef>`;
  }
  if (opts.bullet) {
    pPr += `<a:buChar char="\u2022"/>`;
  }

  // default run properties
  let defRPr = `<a:defRPr`;
  if (opts.fontSize) defRPr += ` sz="${opts.fontSize * 100}"`;
  if (opts.bold) defRPr += ` b="1"`;
  if (opts.italic) defRPr += ` i="1"`;
  if (opts.underline) defRPr += ` u="sng"`;
  defRPr += `>`;
  if (opts.color) {
    defRPr += `<a:solidFill><a:srgbClr val="${normalizeColor(opts.color)}"/></a:solidFill>`;
  }
  if (opts.font) {
    defRPr += `<a:latin typeface="${esc(opts.font)}"/><a:cs typeface="${esc(opts.font)}"/>`;
  }
  defRPr += `</a:defRPr>`;
  pPr += defRPr;
  pPr += `</a:pPr>`;

  let runsXml = "";
  if (runs && runs.length > 0) {
    for (const run of runs) {
      runsXml += genTextRunXml(run);
    }
  } else if (text !== undefined) {
    runsXml += genTextRunXml({
      text,
      fontSize: opts.fontSize,
      font: opts.font,
      bold: opts.bold,
      italic: opts.italic,
      underline: opts.underline,
      color: opts.color,
    });
  }

  return `<a:p>${pPr}${runsXml}</a:p>`;
}

function genTextBoxSp(
  id: number,
  item: SlideItem
): string {
  const x = inchToEmu(item.x ?? 0.5);
  const y = inchToEmu(item.y ?? 0.5);
  const w = inchToEmu(item.w ?? 9);
  const h = inchToEmu(item.h ?? 1);

  let fillXml = "";
  if (item.fillColor) {
    fillXml = `<a:solidFill><a:srgbClr val="${normalizeColor(item.fillColor)}"/></a:solidFill>`;
  } else {
    fillXml = `<a:noFill/>`;
  }

  const paragraphXml = genParagraphXml(item.text, item.runs, {
    fontSize: item.fontSize,
    font: item.font,
    bold: item.bold,
    italic: item.italic,
    underline: item.underline,
    color: item.color,
    alignment: item.alignment,
    bullet: item.bullet,
    lineSpacing: item.lineSpacing,
    spaceAfter: item.spaceAfter,
    spaceBefore: item.spaceBefore,
  });

  let bodyPr = `<a:bodyPr wrap="square" rtlCol="0"`;
  if (item.margin !== undefined) {
    const m = inchToEmu(item.margin);
    bodyPr += ` lIns="${m}" tIns="${m}" rIns="${m}" bIns="${m}"`;
  }
  if (item.verticalAlign) {
    const vaMap: Record<string, string> = { top: "t", middle: "ctr", bottom: "b", t: "t", ctr: "ctr", b: "b" };
    bodyPr += ` anchor="${vaMap[item.verticalAlign] ?? "t"}"`;
  }
  bodyPr += `/>`;

  return `<p:sp>
  <p:nvSpPr><p:cNvPr id="${id}" name="TextBox ${id}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
  <p:spPr>
    <a:xfrm><a:off x="${x}" y="${y}"/><a:ext cx="${w}" cy="${h}"/></a:xfrm>
    <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
    ${fillXml}
    <a:ln><a:noFill/></a:ln>
  </p:spPr>
  <p:txBody>
    ${bodyPr}
    <a:lstStyle/>
    ${paragraphXml}
  </p:txBody>
</p:sp>`;
}

function genImageSp(id: number, item: SlideItem, relId: string): string {
  const x = inchToEmu(item.x ?? 1);
  const y = inchToEmu(item.y ?? 1);
  const w = inchToEmu(item.w ?? 4);
  const h = inchToEmu(item.h ?? 3);

  return `<p:pic>
  <p:nvPicPr>
    <p:cNvPr id="${id}" name="Image ${id}"/>
    <p:cNvPicPr><a:picLocks noChangeAspect="1"/></p:cNvPicPr>
    <p:nvPr/>
  </p:nvPicPr>
  <p:blipFill>
    <a:blip r:embed="${relId}"/>
    <a:stretch><a:fillRect/></a:stretch>
  </p:blipFill>
  <p:spPr>
    <a:xfrm><a:off x="${x}" y="${y}"/><a:ext cx="${w}" cy="${h}"/></a:xfrm>
    <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
  </p:spPr>
</p:pic>`;
}

function genTableSp(id: number, item: SlideItem): string {
  const data = item.tableData ?? [];
  if (data.length === 0) return "";

  const x = inchToEmu(item.x ?? 0.5);
  const y = inchToEmu(item.y ?? 1.5);
  const w = inchToEmu(item.w ?? 9);

  const headerStyle = getOpts(item.headerStyle);
  const cellStyleOpts = getOpts(item.cellStyle);
  const isObjectArray = typeof data[0] === "object" && !Array.isArray(data[0]);
  const headers = isObjectArray ? Object.keys(data[0]) : null;

  // Build rows
  const allRows: string[][] = [];
  if (headers) {
    allRows.push(headers);
    for (const row of data) {
      allRows.push(headers.map(h => String(row[h] ?? "")));
    }
  } else {
    for (const row of data) {
      allRows.push(Array.isArray(row) ? row.map(String) : [String(row)]);
    }
  }

  const numCols = allRows.length > 0 ? Math.max(...allRows.map(r => r.length)) : 1;
  const colWidths = item.columnWidths
    ? item.columnWidths.map(cw => inchToEmu(cw))
    : Array(numCols).fill(Math.floor(inchToEmu(item.w ?? 9) / numCols));

  const rowHeight = inchToEmu(0.4);
  const totalHeight = allRows.length * rowHeight;

  let gridColsXml = "";
  for (const cw of colWidths) gridColsXml += `<a:gridCol w="${cw}"/>`;

  let rowsXml = "";
  for (let ri = 0; ri < allRows.length; ri++) {
    const isHeader = headers && ri === 0;
    const isAlt = !isHeader && ri % 2 === 1;
    let cellsXml = "";
    for (let ci = 0; ci < numCols; ci++) {
      const cellText = ri < allRows.length && ci < allRows[ri].length ? allRows[ri][ci] : "";
      const fontSize = isHeader
        ? Number(headerStyle.fontSize ?? 12)
        : Number(cellStyleOpts.fontSize ?? 10);
      const fontColor = isHeader
        ? normalizeColor(String(headerStyle.color ?? headerStyle.fontColor ?? "FFFFFF"))
        : cellStyleOpts.color ? normalizeColor(String(cellStyleOpts.color)) : "000000";
      const fillColor = isHeader
        ? normalizeColor(String(headerStyle.fillColor ?? "2196F3"))
        : (item.alternateRows && isAlt) ? "F5F5F5" : "";
      const cellAlign = isHeader
        ? (headerStyle.alignment ?? "center")
        : (cellStyleOpts.alignment ?? "left");

      let tcPr = `<a:tcPr`;
      if (item.borders !== false) {
        tcPr += `>`;
        const borderXml = `<a:ln w="6350"><a:solidFill><a:srgbClr val="CCCCCC"/></a:solidFill></a:ln>`;
        tcPr += `<a:lnL>${borderXml.slice(4)}</a:lnL>`;
        tcPr += `<a:lnR>${borderXml.slice(4)}</a:lnR>`;
        tcPr += `<a:lnT>${borderXml.slice(4)}</a:lnT>`;
        tcPr += `<a:lnB>${borderXml.slice(4)}</a:lnB>`;
      } else {
        tcPr += `>`;
      }
      if (fillColor) {
        tcPr += `<a:solidFill><a:srgbClr val="${fillColor}"/></a:solidFill>`;
      }
      tcPr += `</a:tcPr>`;

      const alignMap: Record<string, string> = { left: "l", center: "ctr", right: "r", l: "l", ctr: "ctr", r: "r" };

      cellsXml += `<a:tc>
  <a:txBody>
    <a:bodyPr/>
    <a:lstStyle/>
    <a:p>
      <a:pPr algn="${alignMap[cellAlign] ?? "l"}"/>
      <a:r>
        <a:rPr lang="en-US" sz="${fontSize * 100}"${isHeader ? ' b="1"' : ""}>
          <a:solidFill><a:srgbClr val="${fontColor}"/></a:solidFill>
        </a:rPr>
        <a:t>${esc(cellText)}</a:t>
      </a:r>
    </a:p>
  </a:txBody>
  ${tcPr}
</a:tc>`;
    }
    rowsXml += `<a:tr h="${rowHeight}">${cellsXml}</a:tr>\n`;
  }

  return `<p:graphicFrame>
  <p:nvGraphicFramePr>
    <p:cNvPr id="${id}" name="Table ${id}"/>
    <p:cNvGraphicFramePr><a:graphicFrameLocks noGrp="1"/></p:cNvGraphicFramePr>
    <p:nvPr/>
  </p:nvGraphicFramePr>
  <p:xfrm><a:off x="${x}" y="${y}"/><a:ext cx="${w}" cy="${totalHeight}"/></p:xfrm>
  <a:graphic>
    <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/table">
      <a:tbl>
        <a:tblPr firstRow="1" bandRow="1"/>
        <a:tblGrid>${gridColsXml}</a:tblGrid>
        ${rowsXml}
      </a:tbl>
    </a:graphicData>
  </a:graphic>
</p:graphicFrame>`;
}

function genShapeSp(id: number, item: SlideItem): string {
  const x = inchToEmu(item.x ?? 1);
  const y = inchToEmu(item.y ?? 1);
  const w = inchToEmu(item.w ?? 2);
  const h = inchToEmu(item.h ?? 2);

  const shapeType = String(item.shapeType ?? "rect").toLowerCase();
  const prstMap: Record<string, string> = {
    rect: "rect",
    ellipse: "ellipse",
    roundrect: "roundRect",
    roundRect: "roundRect",
    line: "line",
    triangle: "triangle",
  };
  const prst = prstMap[shapeType] ?? "rect";

  let fillXml = "";
  if (item.fillColor) {
    fillXml = `<a:solidFill><a:srgbClr val="${normalizeColor(item.fillColor)}"/></a:solidFill>`;
  } else {
    fillXml = `<a:noFill/>`;
  }

  let lineXml = "";
  if (item.lineColor) {
    lineXml = `<a:ln w="${Math.round((item.lineWidth ?? 1) * 12700)}"><a:solidFill><a:srgbClr val="${normalizeColor(item.lineColor)}"/></a:solidFill></a:ln>`;
  } else {
    lineXml = `<a:ln><a:noFill/></a:ln>`;
  }

  return `<p:sp>
  <p:nvSpPr><p:cNvPr id="${id}" name="Shape ${id}"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr>
  <p:spPr>
    <a:xfrm><a:off x="${x}" y="${y}"/><a:ext cx="${w}" cy="${h}"/></a:xfrm>
    <a:prstGeom prst="${prst}"><a:avLst/></a:prstGeom>
    ${fillXml}
    ${lineXml}
  </p:spPr>
</p:sp>`;
}

function genChartXml(chartIdx: number, item: SlideItem): string {
  const data = Array.isArray(item.chartData) ? item.chartData : [item.chartData];
  const chartType = String(item.chartType ?? "bar").toLowerCase();

  // Map chart type to OOXML element names
  const typeMap: Record<string, string> = {
    bar: "c:barChart",
    line: "c:lineChart",
    pie: "c:pieChart",
    doughnut: "c:doughnutChart",
    area: "c:areaChart",
    scatter: "c:scatterChart",
  };
  const chartTag = typeMap[chartType] ?? "c:barChart";

  let seriesXml = "";
  for (let si = 0; si < data.length; si++) {
    const series = data[si];
    const name = series.name ?? `Series ${si + 1}`;
    const labels = Array.isArray(series.labels) ? series.labels : [];
    const values = Array.isArray(series.values) ? series.values : [];

    let catXml = "";
    if (labels.length > 0) {
      let ptXml = "";
      for (let i = 0; i < labels.length; i++) {
        ptXml += `<c:pt idx="${i}"><c:v>${esc(String(labels[i]))}</c:v></c:pt>`;
      }
      catXml = `<c:cat><c:strRef><c:strCache><c:ptCount val="${labels.length}"/>${ptXml}</c:strCache></c:strRef></c:cat>`;
    }

    let valXml = "";
    if (values.length > 0) {
      let ptXml = "";
      for (let i = 0; i < values.length; i++) {
        ptXml += `<c:pt idx="${i}"><c:v>${Number(values[i])}</c:v></c:pt>`;
      }
      valXml = `<c:val><c:numRef><c:numCache><c:formatCode>General</c:formatCode><c:ptCount val="${values.length}"/>${ptXml}</c:numCache></c:numRef></c:val>`;
    }

    seriesXml += `<c:ser>
  <c:idx val="${si}"/><c:order val="${si}"/>
  <c:tx><c:strRef><c:strCache><c:ptCount val="1"/><c:pt idx="0"><c:v>${esc(name)}</c:v></c:pt></c:strCache></c:strRef></c:tx>
  ${catXml}
  ${valXml}
</c:ser>`;
  }

  let chartInner = "";
  if (chartType === "bar") {
    chartInner = `<${chartTag}><c:barDir val="col"/><c:grouping val="clustered"/>${seriesXml}<c:axId val="1"/><c:axId val="2"/></${chartTag}>
<c:catAx><c:axId val="1"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="b"/><c:crossAx val="2"/></c:catAx>
<c:valAx><c:axId val="2"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="l"/><c:crossAx val="1"/></c:valAx>`;
  } else if (chartType === "line" || chartType === "area") {
    chartInner = `<${chartTag}><c:grouping val="standard"/>${seriesXml}<c:axId val="1"/><c:axId val="2"/></${chartTag}>
<c:catAx><c:axId val="1"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="b"/><c:crossAx val="2"/></c:catAx>
<c:valAx><c:axId val="2"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="l"/><c:crossAx val="1"/></c:valAx>`;
  } else if (chartType === "pie" || chartType === "doughnut") {
    chartInner = `<${chartTag}>${seriesXml}</${chartTag}>`;
  } else if (chartType === "scatter") {
    chartInner = `<${chartTag}><c:scatterStyle val="lineMarker"/>${seriesXml}<c:axId val="1"/><c:axId val="2"/></${chartTag}>
<c:valAx><c:axId val="1"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="b"/><c:crossAx val="2"/></c:valAx>
<c:valAx><c:axId val="2"/><c:scaling><c:orientation val="minMax"/></c:scaling><c:delete val="0"/><c:axPos val="l"/><c:crossAx val="1"/></c:valAx>`;
  } else {
    chartInner = `<${chartTag}>${seriesXml}</${chartTag}>`;
  }

  let titleXml = "";
  if (item.chartTitle) {
    titleXml = `<c:title><c:tx><c:rich><a:bodyPr/><a:lstStyle/><a:p><a:r><a:t>${esc(item.chartTitle)}</a:t></a:r></a:p></c:rich></c:tx><c:overlay val="0"/></c:title>`;
  } else {
    titleXml = `<c:autoTitleDeleted val="1"/>`;
  }

  let legendXml = "";
  if (item.showLegend !== false) {
    legendXml = `<c:legend><c:legendPos val="b"/></c:legend>`;
  }

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<c:chartSpace xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart"
  xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <c:chart>
    ${titleXml}
    ${legendXml}
    <c:plotArea>
      <c:layout/>
      ${chartInner}
    </c:plotArea>
    <c:plotVisOnly val="1"/>
  </c:chart>
</c:chartSpace>`;
}

function genChartGraphicFrame(id: number, item: SlideItem, relId: string): string {
  const x = inchToEmu(item.x ?? 0.5);
  const y = inchToEmu(item.y ?? 1.5);
  const w = inchToEmu(item.w ?? 8);
  const h = inchToEmu(item.h ?? 4);

  return `<p:graphicFrame>
  <p:nvGraphicFramePr>
    <p:cNvPr id="${id}" name="Chart ${id}"/>
    <p:cNvGraphicFramePr><a:graphicFrameLocks noGrp="1"/></p:cNvGraphicFramePr>
    <p:nvPr/>
  </p:nvGraphicFramePr>
  <p:xfrm><a:off x="${x}" y="${y}"/><a:ext cx="${w}" cy="${h}"/></p:xfrm>
  <a:graphic>
    <a:graphicData uri="http://schemas.openxmlformats.org/drawingml/2006/chart">
      <c:chart xmlns:c="http://schemas.openxmlformats.org/drawingml/2006/chart" r:id="${relId}"/>
    </a:graphicData>
  </a:graphic>
</p:graphicFrame>`;
}

function genSlideNumberSp(id: number, item: SlideItem, slideIdx: number): string {
  const opts = item.slideNumberOpts ?? {};
  const xVal = opts.x !== undefined ? opts.x : 0.3;
  const yVal = opts.y !== undefined ? opts.y : "95%";
  const color = normalizeColor(String(opts.color ?? "696969"));
  const fontSize = Number(opts.fontSize ?? 10);

  const x = parsePos(xVal, SLIDE_W);
  const y = parsePos(yVal, SLIDE_H);
  const w = inchToEmu(1);
  const h = inchToEmu(0.4);

  return `<p:sp>
  <p:nvSpPr><p:cNvPr id="${id}" name="SlideNumber ${id}"/><p:cNvSpPr txBox="1"/><p:nvPr/></p:nvSpPr>
  <p:spPr>
    <a:xfrm><a:off x="${x}" y="${y}"/><a:ext cx="${w}" cy="${h}"/></a:xfrm>
    <a:prstGeom prst="rect"><a:avLst/></a:prstGeom>
    <a:noFill/>
  </p:spPr>
  <p:txBody>
    <a:bodyPr wrap="square" rtlCol="0"/>
    <a:lstStyle/>
    <a:p>
      <a:pPr algn="r"/>
      <a:fld id="{B6F15528-F159-4107-2D19-BAA0F7E2AAAA}" type="slidenum">
        <a:rPr lang="en-US" sz="${fontSize * 100}">
          <a:solidFill><a:srgbClr val="${color}"/></a:solidFill>
        </a:rPr>
        <a:t>&lt;#&gt;</a:t>
      </a:fld>
    </a:p>
  </p:txBody>
</p:sp>`;
}

interface SlideRelEntry {
  id: string;
  type: string;
  target: string;
}

function genSlide(
  slideData: SlideData,
  slideIdx: number,
  imageRels: SlideRelEntry[],
  chartRels: SlideRelEntry[]
): string {
  let bgXml = "";
  if (slideData.backgroundColor) {
    bgXml = `<p:bg><p:bgPr><a:solidFill><a:srgbClr val="${normalizeColor(slideData.backgroundColor)}"/></a:solidFill><a:effectLst/></p:bgPr></p:bg>`;
  }

  // For master-based slides: render master objects first
  let masterObjectsXml = "";
  // (Master objects are rendered by the slide master definition)

  let spTreeContent = "";
  let spId = 2;

  // Render title/subtitle if present (these come from addSlide options)
  if (slideData.title) {
    const titleItem: SlideItem = {
      type: "text",
      text: slideData.title,
      x: 0.5, y: 0.5, w: 9, h: 1,
      fontSize: slideData.titleSize ?? 32,
      bold: true,
      color: slideData.titleColor ?? "333333",
      alignment: "center",
    };
    spTreeContent += genTextBoxSp(spId++, titleItem);
  }
  if (slideData.subtitle) {
    const subItem: SlideItem = {
      type: "text",
      text: slideData.subtitle,
      x: 0.5, y: 1.6, w: 9, h: 0.8,
      fontSize: slideData.subtitleSize ?? 18,
      color: slideData.subtitleColor ?? "666666",
      alignment: "center",
    };
    spTreeContent += genTextBoxSp(spId++, subItem);
  }

  let imgRelIdx = 0;
  let chartRelIdx = 0;

  for (const item of slideData.items) {
    switch (item.type) {
      case "text":
      case "multiText":
        spTreeContent += genTextBoxSp(spId++, item);
        break;
      case "image": {
        const rel = imageRels[imgRelIdx++];
        if (rel) {
          spTreeContent += genImageSp(spId++, item, rel.id);
        }
        break;
      }
      case "table":
        spTreeContent += genTableSp(spId++, item);
        break;
      case "chart": {
        const cRel = chartRels[chartRelIdx++];
        if (cRel) {
          spTreeContent += genChartGraphicFrame(spId++, item, cRel.id);
        }
        break;
      }
      case "shape":
        spTreeContent += genShapeSp(spId++, item);
        break;
      case "slideNumber":
        spTreeContent += genSlideNumberSp(spId++, item, slideIdx);
        break;
    }
  }

  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    ${bgXml}
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr>
        <a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm>
      </p:grpSpPr>
      ${spTreeContent}
    </p:spTree>
  </p:cSld>
</p:sld>`;
}

function genSlideRels(
  slideIdx: number,
  imageRels: SlideRelEntry[],
  chartRels: SlideRelEntry[],
  hasNotes: boolean
): string {
  let rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slideLayout" Target="../slideLayouts/slideLayout1.xml"/>`;

  for (const rel of imageRels) {
    rels += `\n  <Relationship Id="${rel.id}" Type="${rel.type}" Target="${rel.target}"/>`;
  }
  for (const rel of chartRels) {
    rels += `\n  <Relationship Id="${rel.id}" Type="${rel.type}" Target="${rel.target}"/>`;
  }

  if (hasNotes) {
    rels += `\n  <Relationship Id="rIdNotes" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/notesSlide" Target="../notesSlides/notesSlide${slideIdx + 1}.xml"/>`;
  }

  rels += `\n</Relationships>`;
  return rels;
}

function genNotesSlide(slideIdx: number, notesText: string): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<p:notes xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main"
  xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"
  xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">
  <p:cSld>
    <p:spTree>
      <p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr>
      <p:grpSpPr>
        <a:xfrm><a:off x="0" y="0"/><a:ext cx="0" cy="0"/><a:chOff x="0" y="0"/><a:chExt cx="0" cy="0"/></a:xfrm>
      </p:grpSpPr>
      <p:sp>
        <p:nvSpPr><p:cNvPr id="2" name="Notes Placeholder"/><p:cNvSpPr><a:spLocks noGrp="1"/></p:cNvSpPr><p:nvPr><p:ph type="body" idx="1"/></p:nvPr></p:nvSpPr>
        <p:spPr/>
        <p:txBody>
          <a:bodyPr/>
          <a:lstStyle/>
          <a:p><a:r><a:rPr lang="en-US"/><a:t>${esc(notesText)}</a:t></a:r></a:p>
        </p:txBody>
      </p:sp>
    </p:spTree>
  </p:cSld>
</p:notes>`;
}

function genNotesSlideRels(slideIdx: number): string {
  return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/slide" Target="../slides/slide${slideIdx + 1}.xml"/>
</Relationships>`;
}

// ─── Build the full PPTX ────────────────────────────────────────────────────

function buildPptx(pres: PresentationState): Buffer {
  const entries: Array<{ name: string; data: Buffer }> = [];

  const addXml = (name: string, xml: string) => {
    entries.push({ name, data: Buffer.from(xml, "utf-8") });
  };

  // Collect all images and charts across slides for proper numbering
  let globalImageIdx = 0;
  let globalChartIdx = 0;

  // Per-slide image/chart tracking
  const slideImageRels: SlideRelEntry[][] = [];
  const slideChartRels: SlideRelEntry[][] = [];
  const slideImageFiles: Array<{ entryName: string; data: Buffer }>[] = [];
  const slideChartXmls: Array<{ entryName: string; xml: string }>[] = [];

  for (let si = 0; si < pres.slides.length; si++) {
    const slide = pres.slides[si];
    const imgRels: SlideRelEntry[] = [];
    const chRels: SlideRelEntry[] = [];
    const imgFiles: Array<{ entryName: string; data: Buffer }> = [];
    const chXmls: Array<{ entryName: string; xml: string }> = [];
    let relCounter = 2; // rId1 is slideLayout

    for (const item of slide.items) {
      if (item.type === "image") {
        globalImageIdx++;
        const ext = item.imageExt ?? "png";
        const mediaName = `image${globalImageIdx}.${ext}`;
        const relId = `rId${relCounter++}`;
        imgRels.push({
          id: relId,
          type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image",
          target: `../media/${mediaName}`,
        });

        let imageData: Buffer;
        if (item.imageData) {
          imageData = item.imageData;
        } else if (item.imagePath) {
          try {
            imageData = fs.readFileSync(item.imagePath);
          } catch {
            imageData = Buffer.alloc(0);
          }
        } else {
          imageData = Buffer.alloc(0);
        }
        imgFiles.push({ entryName: `ppt/media/${mediaName}`, data: imageData });
      } else if (item.type === "chart") {
        globalChartIdx++;
        const chartName = `chart${globalChartIdx}.xml`;
        const relId = `rId${relCounter++}`;
        chRels.push({
          id: relId,
          type: "http://schemas.openxmlformats.org/officeDocument/2006/relationships/chart",
          target: `../charts/${chartName}`,
        });
        chXmls.push({
          entryName: `ppt/charts/${chartName}`,
          xml: genChartXml(globalChartIdx, item),
        });
      }
    }

    slideImageRels.push(imgRels);
    slideChartRels.push(chRels);
    slideImageFiles.push(imgFiles);
    slideChartXmls.push(chXmls);
  }

  // [Content_Types].xml
  addXml("[Content_Types].xml", genContentTypes(pres));

  // _rels/.rels
  addXml("_rels/.rels", genRootRels());

  // ppt/presentation.xml
  addXml("ppt/presentation.xml", genPresentation(pres));

  // ppt/_rels/presentation.xml.rels
  addXml("ppt/_rels/presentation.xml.rels", genPresentationRels(pres));

  // ppt/theme/theme1.xml
  addXml("ppt/theme/theme1.xml", genTheme());

  // ppt/slideMasters/slideMaster1.xml
  addXml("ppt/slideMasters/slideMaster1.xml", genSlideMaster());
  addXml("ppt/slideMasters/_rels/slideMaster1.xml.rels", genSlideMasterRels());

  // ppt/slideLayouts/slideLayout1.xml
  addXml("ppt/slideLayouts/slideLayout1.xml", genSlideLayout());
  addXml("ppt/slideLayouts/_rels/slideLayout1.xml.rels", genSlideLayoutRels());

  // Slides
  for (let si = 0; si < pres.slides.length; si++) {
    const slideData = pres.slides[si];
    const imgRels = slideImageRels[si];
    const chRels = slideChartRels[si];

    addXml(
      `ppt/slides/slide${si + 1}.xml`,
      genSlide(slideData, si, imgRels, chRels)
    );

    addXml(
      `ppt/slides/_rels/slide${si + 1}.xml.rels`,
      genSlideRels(si, imgRels, chRels, !!slideData.notes)
    );

    // Notes
    if (slideData.notes) {
      addXml(`ppt/notesSlides/notesSlide${si + 1}.xml`, genNotesSlide(si, slideData.notes));
      addXml(`ppt/notesSlides/_rels/notesSlide${si + 1}.xml.rels`, genNotesSlideRels(si));
    }

    // Media files
    for (const img of slideImageFiles[si]) {
      entries.push({ name: img.entryName, data: img.data });
    }

    // Chart files
    for (const ch of slideChartXmls[si]) {
      addXml(ch.entryName, ch.xml);
    }
  }

  return buildZip(entries);
}

// ─── Handlers ────────────────────────────────────────────────────────────────

var createSlides = (args: any[]): string => {
  const id = String(args[0] ?? `ppt_${Date.now()}`);
  const opts = getOpts(args[1]);
  const pres: PresentationState = {
    title: opts.title ? String(opts.title) : "",
    author: opts.author ? String(opts.author) : "",
    subject: opts.subject ? String(opts.subject) : "",
    layout: opts.layout ? String(opts.layout) : "LAYOUT_WIDE",
    slides: [],
    masters: new Map(),
  };
  presentations.set(id, pres);
  return id;
};

var addSlide = (args: any[]): number => {
  const id = String(args[0] ?? "");
  const opts = getOpts(args[1]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);

  const slide: SlideData = {
    items: [],
    backgroundColor: opts.backgroundColor || opts.bgColor
      ? String(opts.backgroundColor ?? opts.bgColor).replace("#", "")
      : undefined,
    title: opts.title ? String(opts.title) : undefined,
    subtitle: opts.subtitle ? String(opts.subtitle) : undefined,
    titleSize: opts.titleSize ? Number(opts.titleSize) : undefined,
    titleColor: opts.titleColor ? String(opts.titleColor).replace("#", "") : undefined,
    subtitleSize: opts.subtitleSize ? Number(opts.subtitleSize) : undefined,
    subtitleColor: opts.subtitleColor ? String(opts.subtitleColor).replace("#", "") : undefined,
    masterName: opts.masterName ? String(opts.masterName) : undefined,
  };

  pres.slides.push(slide);
  return pres.slides.length - 1;
};

var addSlideText = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const slideIdx = Number(args[1] ?? 0);
  const text = String(args[2] ?? "");
  const opts = getOpts(args[3]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);
  const slide = pres.slides[slideIdx];
  if (!slide) throw new Error(`Slide ${slideIdx} not found`);

  slide.items.push({
    type: "text",
    text,
    x: opts.x !== undefined ? Number(opts.x) : undefined,
    y: opts.y !== undefined ? Number(opts.y) : undefined,
    w: opts.w ?? opts.width !== undefined ? Number(opts.w ?? opts.width) : undefined,
    h: opts.h ?? opts.height !== undefined ? Number(opts.h ?? opts.height) : undefined,
    fontSize: opts.fontSize ? Number(opts.fontSize) : 14,
    font: opts.font ? String(opts.font) : undefined,
    bold: opts.bold ? true : undefined,
    italic: opts.italic ? true : undefined,
    underline: opts.underline ? true : undefined,
    color: opts.color ? String(opts.color).replace("#", "") : undefined,
    alignment: opts.alignment ?? opts.align ? String(opts.alignment ?? opts.align) : undefined,
    verticalAlign: opts.verticalAlign ? String(opts.verticalAlign) : undefined,
    fillColor: opts.fillColor ? String(opts.fillColor).replace("#", "") : undefined,
    bullet: opts.bullet ?? undefined,
    lineSpacing: opts.lineSpacing ? Number(opts.lineSpacing) : undefined,
    spaceAfter: opts.spaceAfter ? Number(opts.spaceAfter) : undefined,
    spaceBefore: opts.spaceBefore ? Number(opts.spaceBefore) : undefined,
    margin: opts.margin !== undefined ? Number(opts.margin) : undefined,
  });
  return true;
};

var addSlideImage = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const slideIdx = Number(args[1] ?? 0);
  const imagePath = String(args[2] ?? "");
  const opts = getOpts(args[3]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);
  const slide = pres.slides[slideIdx];
  if (!slide) throw new Error(`Slide ${slideIdx} not found`);

  const ext = path.extname(imagePath).replace(".", "").toLowerCase() || "png";

  slide.items.push({
    type: "image",
    imagePath,
    imageExt: ext === "jpg" ? "jpeg" : ext,
    x: opts.x !== undefined ? Number(opts.x) : 1,
    y: opts.y !== undefined ? Number(opts.y) : 1,
    w: opts.w ?? opts.width !== undefined ? Number(opts.w ?? opts.width) : 4,
    h: opts.h ?? opts.height !== undefined ? Number(opts.h ?? opts.height) : 3,
    rounding: opts.rounding ? true : undefined,
    hyperlink: opts.hyperlink ? String(opts.hyperlink) : undefined,
  });
  return true;
};

var addSlideTable = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const slideIdx = Number(args[1] ?? 0);
  const data = args[2];
  const opts = getOpts(args[3]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);
  const slide = pres.slides[slideIdx];
  if (!slide) throw new Error(`Slide ${slideIdx} not found`);
  if (!Array.isArray(data) || data.length === 0) throw new Error("Table data required");

  slide.items.push({
    type: "table",
    tableData: data,
    x: opts.x !== undefined ? Number(opts.x) : 0.5,
    y: opts.y !== undefined ? Number(opts.y) : 1.5,
    w: opts.w ?? opts.width !== undefined ? Number(opts.w ?? opts.width) : 9,
    headerStyle: opts.headerStyle ?? {},
    cellStyle: opts.cellStyle ?? {},
    columnWidths: Array.isArray(opts.columnWidths) ? opts.columnWidths.map(Number) : undefined,
    alternateRows: opts.alternateRows ? true : false,
    borders: opts.borders !== false,
    fontSize: opts.fontSize ? Number(opts.fontSize) : 10,
  });
  return true;
};

var addSlideChart = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const slideIdx = Number(args[1] ?? 0);
  const chartData = args[2];
  const opts = getOpts(args[3]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);
  const slide = pres.slides[slideIdx];
  if (!slide) throw new Error(`Slide ${slideIdx} not found`);

  slide.items.push({
    type: "chart",
    chartData: Array.isArray(chartData) ? chartData : [chartData],
    chartType: opts.type ? String(opts.type).toLowerCase() : "bar",
    x: opts.x !== undefined ? Number(opts.x) : 0.5,
    y: opts.y !== undefined ? Number(opts.y) : 1.5,
    w: opts.w ?? opts.width !== undefined ? Number(opts.w ?? opts.width) : 8,
    h: opts.h ?? opts.height !== undefined ? Number(opts.h ?? opts.height) : 4,
    chartTitle: opts.title ? String(opts.title) : undefined,
    showLegend: opts.legend !== false,
    showValues: opts.showValues ? true : false,
  });
  return true;
};

var addSlideShape = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const slideIdx = Number(args[1] ?? 0);
  const opts = getOpts(args[2]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);
  const slide = pres.slides[slideIdx];
  if (!slide) throw new Error(`Slide ${slideIdx} not found`);

  slide.items.push({
    type: "shape",
    shapeType: opts.shape ? String(opts.shape).toLowerCase() : "rect",
    x: opts.x !== undefined ? Number(opts.x) : 1,
    y: opts.y !== undefined ? Number(opts.y) : 1,
    w: opts.w ?? opts.width !== undefined ? Number(opts.w ?? opts.width) : 2,
    h: opts.h ?? opts.height !== undefined ? Number(opts.h ?? opts.height) : 2,
    fillColor: opts.fillColor ? String(opts.fillColor).replace("#", "") : undefined,
    lineColor: opts.lineColor ? String(opts.lineColor).replace("#", "") : undefined,
    lineWidth: opts.lineWidth ? Number(opts.lineWidth) : undefined,
  });
  return true;
};

var addSlideNotes = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const slideIdx = Number(args[1] ?? 0);
  const text = String(args[2] ?? "");
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);
  const slide = pres.slides[slideIdx];
  if (!slide) throw new Error(`Slide ${slideIdx} not found`);
  slide.notes = text;
  return true;
};

var addSlideMultiText = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const slideIdx = Number(args[1] ?? 0);
  const runs = args[2];
  const opts = getOpts(args[3]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);
  const slide = pres.slides[slideIdx];
  if (!slide) throw new Error(`Slide ${slideIdx} not found`);
  if (!Array.isArray(runs)) throw new Error("runs must be an array of text run objects");

  const textRuns: TextRun[] = runs.map((r: any) => ({
    text: String(r.text ?? ""),
    bold: r.bold ? true : undefined,
    italic: r.italic ? true : undefined,
    underline: r.underline ? true : undefined,
    strike: r.strike ? true : undefined,
    superscript: r.superscript ? true : undefined,
    subscript: r.subscript ? true : undefined,
    fontSize: r.fontSize ? Number(r.fontSize) : undefined,
    font: r.font ? String(r.font) : undefined,
    color: r.color ? String(r.color).replace("#", "") : undefined,
    hyperlink: r.hyperlink ? String(r.hyperlink) : undefined,
    breakType: r.breakType === "line" ? "line" : undefined,
  }));

  slide.items.push({
    type: "multiText",
    runs: textRuns,
    x: opts.x !== undefined ? Number(opts.x) : 0.5,
    y: opts.y !== undefined ? Number(opts.y) : 0.5,
    w: opts.w ?? opts.width !== undefined ? Number(opts.w ?? opts.width) : 9,
    h: opts.h ?? opts.height !== undefined ? Number(opts.h ?? opts.height) : 1,
    alignment: opts.alignment ?? opts.align ? String(opts.alignment ?? opts.align) : undefined,
    verticalAlign: opts.verticalAlign ? String(opts.verticalAlign) : undefined,
    fillColor: opts.fillColor ? String(opts.fillColor).replace("#", "") : undefined,
    lineSpacing: opts.lineSpacing ? Number(opts.lineSpacing) : undefined,
    margin: opts.margin !== undefined ? Number(opts.margin) : undefined,
  });
  return true;
};

var setSlideNumber = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const slideIdx = Number(args[1] ?? 0);
  const opts = getOpts(args[2]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);
  const slide = pres.slides[slideIdx];
  if (!slide) throw new Error(`Slide ${slideIdx} not found`);

  slide.items.push({
    type: "slideNumber",
    slideNumberOpts: {
      x: opts.x !== undefined ? opts.x : 0.3,
      y: opts.y !== undefined ? opts.y : "95%",
      color: opts.color ? String(opts.color).replace("#", "") : "696969",
      fontSize: opts.fontSize ? Number(opts.fontSize) : 10,
    },
  });
  return true;
};

var defineSlideMaster = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const name = String(args[1] ?? "");
  const opts = getOpts(args[2]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);

  const master: SlideMaster = { name };
  if (opts.background || opts.bgColor) {
    master.bgColor = String(opts.background ?? opts.bgColor).replace("#", "");
  }
  if (opts.margin) master.margin = opts.margin;
  if (opts.slideNumber) master.slideNumber = opts.slideNumber;
  if (Array.isArray(opts.objects)) master.objects = opts.objects;

  pres.masters.set(name, master);
  return true;
};

var addSlideFromMaster = (args: any[]): number => {
  const id = String(args[0] ?? "");
  const masterName = String(args[1] ?? "");
  const opts = getOpts(args[2]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);

  const master = pres.masters.get(masterName);

  const slide: SlideData = {
    items: [],
    masterName,
    backgroundColor: opts.backgroundColor || opts.bgColor
      ? String(opts.backgroundColor ?? opts.bgColor).replace("#", "")
      : master?.bgColor ?? undefined,
  };

  // Apply master objects as slide items
  if (master && Array.isArray(master.objects)) {
    for (const obj of master.objects) {
      if (obj.rect) {
        const r = getOpts(obj.rect);
        slide.items.push({
          type: "shape",
          shapeType: "rect",
          x: r.x !== undefined ? Number(r.x) : 0,
          y: r.y !== undefined ? Number(r.y) : 0,
          w: r.w !== undefined ? (String(r.w) === "100%" ? 10 : Number(r.w)) : 10,
          h: r.h !== undefined ? Number(r.h) : 0.5,
          fillColor: r.fillColor ? String(r.fillColor).replace("#", "") : r.fill ? String(r.fill).replace("#", "") : undefined,
        });
      } else if (obj.text) {
        const t = getOpts(obj.text);
        slide.items.push({
          type: "text",
          text: String(t.text ?? ""),
          x: t.x !== undefined ? Number(t.x) : 0.5,
          y: t.y !== undefined ? Number(t.y) : 0.5,
          w: t.w !== undefined ? Number(t.w) : 9,
          h: t.h !== undefined ? Number(t.h) : 1,
          color: t.color ? String(t.color).replace("#", "") : undefined,
          fontSize: t.fontSize ? Number(t.fontSize) : undefined,
          bold: t.bold ? true : undefined,
          alignment: t.alignment ?? t.align ? String(t.alignment ?? t.align) : undefined,
        });
      } else if (obj.image) {
        const im = getOpts(obj.image);
        slide.items.push({
          type: "image",
          imagePath: String(im.path ?? ""),
          imageExt: im.path ? (path.extname(String(im.path)).replace(".", "").toLowerCase() || "png") : "png",
          x: im.x !== undefined ? Number(im.x) : 0,
          y: im.y !== undefined ? Number(im.y) : 0,
          w: im.w !== undefined ? Number(im.w) : 2,
          h: im.h !== undefined ? Number(im.h) : 2,
        });
      }
    }
  }

  // Apply master slide number
  if (master?.slideNumber) {
    const sn = getOpts(master.slideNumber);
    slide.items.push({
      type: "slideNumber",
      slideNumberOpts: {
        x: sn.x ?? 0.3,
        y: sn.y ?? "95%",
        color: sn.color ? String(sn.color).replace("#", "") : "696969",
        fontSize: sn.fontSize ? Number(sn.fontSize) : 8,
      },
    });
  }

  pres.slides.push(slide);
  return pres.slides.length - 1;
};

var saveSlides = (args: any[]): { path: string } => {
  const id = String(args[0] ?? "");
  const filePath = String(args[1] ?? "");
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);

  const buf = buildPptx(pres);
  const dir = path.dirname(filePath);
  if (dir && !fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  fs.writeFileSync(filePath, buf);

  presentations.delete(id);
  return { path: filePath };
};

// ─── Cross-format: setSheetPrint ─────────────────────────────────────────────
// These are pass-through stubs for the cross-format functions.
// In the standalone pptx module they operate on the presentation state
// but preserve the same API signature.

var setSheetPrint = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const opts = getOpts(args[1]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);
  // PowerPoint doesn't have print areas per se, but we store the config
  // so the API remains compatible. No-op for PPTX.
  return true;
};

// ─── Cross-format: groupRows ─────────────────────────────────────────────────

var groupRows = (args: any[]): boolean => {
  const id = String(args[0] ?? "");
  const _start = Number(args[1] ?? 1);
  const _end = Number(args[2] ?? 1);
  const opts = getOpts(args[3]);
  const pres = presentations.get(id);
  if (!pres) throw new Error(`Presentation "${id}" not found`);
  // groupRows is an Excel/Sheet concept. In PPTX context this is a no-op
  // but we keep the function for cross-format compatibility.
  return true;
};

// ─── Exports ─────────────────────────────────────────────────────────────────

export const PptxFunctions: Record<string, (...args: any[]) => any> = {
  createSlides,
  addSlide,
  addSlideText,
  addSlideImage,
  addSlideTable,
  addSlideChart,
  addSlideShape,
  addSlideNotes,
  addSlideMultiText,
  setSlideNumber,
  defineSlideMaster,
  addSlideFromMaster,
  saveSlides,
  setSheetPrint,
  groupRows,
};

export const PptxFunctionMetadata = {
  createSlides: {
    description: "Create a new PowerPoint presentation",
    parameters: [
      { name: "id", dataType: "string", description: "Presentation ID", formInputType: "text", required: false },
      { name: "options", dataType: "object", description: "{title, author, layout}", formInputType: "json", required: false }
    ],
    returnType: "string",
    returnDescription: "Presentation ID",
    example: 'pptx.createSlides "deck" {"title": "Q4 Report"} into $ppt'
  },
  addSlide: {
    description: "Add a slide with optional title/subtitle and background",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{title, subtitle, titleSize, backgroundColor}", formInputType: "json", required: false }
    ],
    returnType: "number",
    returnDescription: "Slide index",
    example: 'pptx.addSlide $ppt {"title": "Overview", "subtitle": "Q4 2026", "backgroundColor": "#1a1a2e"} into $slideIdx'
  },
  addSlideText: {
    description: "Add a text box to a slide with full formatting",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "slideIndex", dataType: "number", description: "Slide index", formInputType: "number", required: true },
      { name: "text", dataType: "string", description: "Text content", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{x, y, w, h, fontSize, font, bold, italic, color, alignment, fillColor, bullet, lineSpacing}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.addSlideText $ppt 0 "Revenue: +23%" {"x": 1, "y": 3, "fontSize": 24, "bold": true, "color": "#27ae60"}'
  },
  addSlideImage: {
    description: "Add an image to a slide with positioning",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "slideIndex", dataType: "number", description: "Slide index", formInputType: "number", required: true },
      { name: "imagePath", dataType: "string", description: "Path to image", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{x, y, w, h, rounding, hyperlink}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.addSlideImage $ppt 0 "./chart.png" {"x": 1, "y": 2, "w": 6, "h": 4}'
  },
  addSlideTable: {
    description: "Add a data table to a slide with styling",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "slideIndex", dataType: "number", description: "Slide index", formInputType: "number", required: true },
      { name: "data", dataType: "array", description: "Array of objects or arrays", formInputType: "json", required: true },
      { name: "options", dataType: "object", description: "{x, y, w, headerStyle, cellStyle, columnWidths, alternateRows, borders}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.addSlideTable $ppt 1 $data {"headerStyle": {"fillColor": "#2196F3"}, "alternateRows": true}'
  },
  addSlideChart: {
    description: "Add a chart to a slide",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "slideIndex", dataType: "number", description: "Slide index", formInputType: "number", required: true },
      { name: "chartData", dataType: "array", description: "Chart data series [{name, labels, values}]", formInputType: "json", required: true },
      { name: "options", dataType: "object", description: "{type: bar|line|pie|doughnut|area, x, y, w, h, title, legend, showValues}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.addSlideChart $ppt 2 $chartData {"type": "bar", "title": "Sales by Region"}'
  },
  addSlideShape: {
    description: "Add a shape to a slide",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "slideIndex", dataType: "number", description: "Slide index", formInputType: "number", required: true },
      { name: "options", dataType: "object", description: "{shape: rect|ellipse|roundRect|line|triangle, x, y, w, h, fillColor, lineColor, lineWidth}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.addSlideShape $ppt 0 {"shape": "rect", "x": 0, "y": 0, "w": 10, "h": 0.5, "fillColor": "#2196F3"}'
  },
  addSlideNotes: {
    description: "Add speaker notes to a slide",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "slideIndex", dataType: "number", description: "Slide index", formInputType: "number", required: true },
      { name: "text", dataType: "string", description: "Speaker notes text", formInputType: "text", required: true }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.addSlideNotes $ppt 0 "Remember to mention Q4 targets"'
  },
  addSlideMultiText: {
    description: "Add rich text with mixed formatting (bold/italic/color) in one text box",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "slideIndex", dataType: "number", description: "Slide index", formInputType: "number", required: true },
      { name: "runs", dataType: "array", description: "Array of text runs [{text, bold, italic, color, fontSize, font, hyperlink}]", formInputType: "json", required: true },
      { name: "options", dataType: "object", description: "{x, y, w, h, alignment, fillColor, lineSpacing, margin}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.addSlideMultiText $ppt 0 [{"text": "Revenue: ", "bold": true}, {"text": "+23%", "color": "#27ae60", "bold": true}] {"x": 1, "y": 3}'
  },
  setSlideNumber: {
    description: "Add a slide number to a slide",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "slideIndex", dataType: "number", description: "Slide index", formInputType: "number", required: true },
      { name: "options", dataType: "object", description: "{x, y, color, fontSize}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.setSlideNumber $ppt 0 {"x": 9.5, "y": "95%", "color": "#888888", "fontSize": 10}'
  },
  defineSlideMaster: {
    description: "Define a reusable slide master template with logo, background, and placeholders",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "name", dataType: "string", description: "Master template name", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{background, bgColor, margin, slideNumber, objects: [{rect: {...}}, {text: {...}}, {image: {...}}]}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.defineSlideMaster $ppt "BRAND" {"bgColor": "#FFFFFF", "objects": [{"rect": {"x": 0, "y": 0, "w": "100%", "h": 0.5, "fillColor": "#003366"}}]}'
  },
  addSlideFromMaster: {
    description: "Create a new slide from a defined master template",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "masterName", dataType: "string", description: "Master template name", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{backgroundColor}", formInputType: "json", required: false }
    ],
    returnType: "number",
    returnDescription: "Slide index",
    example: 'pptx.addSlideFromMaster $ppt "BRAND" {} into $slideIdx'
  },
  saveSlides: {
    description: "Save the presentation to a .pptx file",
    parameters: [
      { name: "pptId", dataType: "string", description: "Presentation ID", formInputType: "text", required: true },
      { name: "filePath", dataType: "string", description: "Output .pptx path", formInputType: "text", required: true }
    ],
    returnType: "object",
    returnDescription: "{path}",
    example: 'pptx.saveSlides $ppt "./presentation.pptx"'
  },
  // Cross-format
  setSheetPrint: {
    description: "Configure print layout: paper size, orientation, print area, margins",
    parameters: [
      { name: "wbId", dataType: "string", description: "Workbook ID", formInputType: "text", required: true },
      { name: "options", dataType: "object", description: "{sheet, paperSize: 9=A4, orientation, fitToPage, fitToWidth, fitToHeight, printArea, margins: {left, right, top, bottom, header, footer}, printTitlesRow}", formInputType: "json", required: true }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.setSheetPrint $wb {"sheet": "Sheet1", "paperSize": 9, "orientation": "landscape", "printArea": "A1:F20"}'
  },
  groupRows: {
    description: "Group rows (or columns) into collapsible outline groups",
    parameters: [
      { name: "wbId", dataType: "string", description: "Workbook ID", formInputType: "text", required: true },
      { name: "start", dataType: "number", description: "Start row number", formInputType: "number", required: true },
      { name: "end", dataType: "number", description: "End row number", formInputType: "number", required: true },
      { name: "options", dataType: "object", description: "{sheet, level, collapsed, columns: {start, end, level}}", formInputType: "json", required: false }
    ],
    returnType: "boolean",
    returnDescription: "true",
    example: 'pptx.groupRows $wb 2 10 {"sheet": "Sheet1", "collapsed": false}'
  },
};

export const PptxModuleMetadata = {
  description: "PowerPoint presentation (.pptx) creation — slides, text boxes, images, tables, charts, shapes, speaker notes, slide masters, and more. Zero npm dependencies.",
  methods: [
    "createSlides",
    "addSlide",
    "addSlideText",
    "addSlideImage",
    "addSlideTable",
    "addSlideChart",
    "addSlideShape",
    "addSlideNotes",
    "addSlideMultiText",
    "setSlideNumber",
    "defineSlideMaster",
    "addSlideFromMaster",
    "saveSlides",
    "setSheetPrint",
    "groupRows",
  ],
};
