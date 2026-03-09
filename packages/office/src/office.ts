// @ts-nocheck
import type { BuiltinHandler, FunctionMetadata, ModuleMetadata, Value } from "@wiredwp/robinpath";
import { extname } from "node:path";
import { readFileSync } from "node:fs";

// ─── Helpers ────────────────────────────────────────────────────────────────

const getOpts = (v: any): any => (v && typeof v === "object" && !Array.isArray(v) ? v : {});

// ─── Office file type detection ─────────────────────────────────────────────

const EXTENSION_MAP: Record<string, { type: string; format: string; mime: string }> = {
	".docx": { type: "word", format: "docx", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document" },
	".doc": { type: "word", format: "doc", mime: "application/msword" },
	".xlsx": { type: "excel", format: "xlsx", mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" },
	".xls": { type: "excel", format: "xls", mime: "application/vnd.ms-excel" },
	".csv": { type: "excel", format: "csv", mime: "text/csv" },
	".pptx": { type: "powerpoint", format: "pptx", mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation" },
	".ppt": { type: "powerpoint", format: "ppt", mime: "application/vnd.ms-powerpoint" },
	".pdf": { type: "pdf", format: "pdf", mime: "application/pdf" },
	".rtf": { type: "word", format: "rtf", mime: "application/rtf" },
	".txt": { type: "text", format: "txt", mime: "text/plain" },
	".md": { type: "text", format: "markdown", mime: "text/markdown" },
	".json": { type: "data", format: "json", mime: "application/json" },
	".xml": { type: "data", format: "xml", mime: "application/xml" },
	".html": { type: "web", format: "html", mime: "text/html" },
	".htm": { type: "web", format: "html", mime: "text/html" },
	".odt": { type: "word", format: "odt", mime: "application/vnd.oasis.opendocument.text" },
	".ods": { type: "excel", format: "ods", mime: "application/vnd.oasis.opendocument.spreadsheet" },
	".odp": { type: "powerpoint", format: "odp", mime: "application/vnd.oasis.opendocument.presentation" },
};

// ZIP-based Office formats have specific magic bytes: PK (0x50 0x4B 0x03 0x04)
const ZIP_MAGIC = [0x50, 0x4b, 0x03, 0x04];
// OLE2 Compound Document (legacy .doc, .xls, .ppt): 0xD0CF11E0A1B11AE1
const OLE2_MAGIC = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
// PDF magic: %PDF
const PDF_MAGIC = [0x25, 0x50, 0x44, 0x46];
// RTF magic: {\rtf
const RTF_MAGIC = [0x7b, 0x5c, 0x72, 0x74, 0x66];

function bufferStartsWith(buf: Buffer, sig: number[]): boolean {
	if (buf.length < sig.length) return false;
	for (let i = 0; i < sig.length; i++) {
		if (buf[i] !== sig[i]) return false;
	}
	return true;
}

function detect(...args: Value[]): Value {
	const input = args[0];
	if (typeof input === "string") {
		// Treat as file path or extension
		const ext = input.startsWith(".") ? input.toLowerCase() : extname(input).toLowerCase();
		const info = EXTENSION_MAP[ext];
		if (!info) return { type: "unknown", format: ext.replace(".", "") || "unknown", mime: "application/octet-stream", source: "extension" };
		return { ...info, source: "extension" };
	}
	if (Buffer.isBuffer(input) || (input instanceof Uint8Array)) {
		const buf = Buffer.isBuffer(input) ? input : Buffer.from(input);
		if (bufferStartsWith(buf, PDF_MAGIC)) return { type: "pdf", format: "pdf", mime: "application/pdf", source: "magic" };
		if (bufferStartsWith(buf, RTF_MAGIC)) return { type: "word", format: "rtf", mime: "application/rtf", source: "magic" };
		if (bufferStartsWith(buf, OLE2_MAGIC)) return { type: "office-legacy", format: "ole2", mime: "application/x-ole-storage", source: "magic" };
		if (bufferStartsWith(buf, ZIP_MAGIC)) return { type: "office-xml", format: "ooxml", mime: "application/zip", source: "magic" };
		return { type: "unknown", format: "binary", mime: "application/octet-stream", source: "magic" };
	}
	throw new Error("detect expects a file path (string) or buffer");
}

// ─── Convert ────────────────────────────────────────────────────────────────

function convert(...args: Value[]): Value {
	const data = args[0];
	const fromFormat = String(args[1]).toLowerCase();
	const toFormat = String(args[2]).toLowerCase();
	const opts = getOpts(args[3]);

	// CSV → JSON
	if (fromFormat === "csv" && toFormat === "json") {
		const text = typeof data === "string" ? data : String(data);
		const delimiter = opts.delimiter || ",";
		const lines = parseCsvLines(text, delimiter);
		if (lines.length === 0) return [];
		const headers = lines[0];
		const result = [];
		for (let i = 1; i < lines.length; i++) {
			const row: Record<string, string> = {};
			for (let j = 0; j < headers.length; j++) {
				row[headers[j]] = lines[i][j] ?? "";
			}
			result.push(row);
		}
		return result;
	}

	// JSON → CSV
	if (fromFormat === "json" && toFormat === "csv") {
		const arr = Array.isArray(data) ? data : JSON.parse(String(data));
		if (!Array.isArray(arr) || arr.length === 0) return "";
		const delimiter = opts.delimiter || ",";
		const headers = Object.keys(arr[0]);
		const lines = [headers.map((h) => csvEscape(h, delimiter)).join(delimiter)];
		for (const row of arr) {
			lines.push(headers.map((h) => csvEscape(String(row[h] ?? ""), delimiter)).join(delimiter));
		}
		return lines.join("\n");
	}

	// Markdown → Text (strip markdown formatting)
	if ((fromFormat === "markdown" || fromFormat === "md") && (toFormat === "text" || toFormat === "txt")) {
		return stripMarkdown(String(data));
	}

	// Text → Markdown (wrap as code block or return as-is)
	if ((fromFormat === "text" || fromFormat === "txt") && (toFormat === "markdown" || toFormat === "md")) {
		const lang = opts.language || "";
		if (opts.codeBlock) return "```" + lang + "\n" + String(data) + "\n```";
		return String(data);
	}

	// JSON → Text (pretty print)
	if (fromFormat === "json" && (toFormat === "text" || toFormat === "txt")) {
		const parsed = typeof data === "string" ? JSON.parse(data) : data;
		return JSON.stringify(parsed, null, opts.indent ?? 2);
	}

	// Text → JSON (parse)
	if ((fromFormat === "text" || fromFormat === "txt") && toFormat === "json") {
		return JSON.parse(String(data));
	}

	// TSV → JSON
	if (fromFormat === "tsv" && toFormat === "json") {
		const text = typeof data === "string" ? data : String(data);
		const lines = parseCsvLines(text, "\t");
		if (lines.length === 0) return [];
		const headers = lines[0];
		const result = [];
		for (let i = 1; i < lines.length; i++) {
			const row: Record<string, string> = {};
			for (let j = 0; j < headers.length; j++) {
				row[headers[j]] = lines[i][j] ?? "";
			}
			result.push(row);
		}
		return result;
	}

	// JSON → TSV
	if (fromFormat === "json" && toFormat === "tsv") {
		const arr = Array.isArray(data) ? data : JSON.parse(String(data));
		if (!Array.isArray(arr) || arr.length === 0) return "";
		const headers = Object.keys(arr[0]);
		const lines = [headers.join("\t")];
		for (const row of arr) {
			lines.push(headers.map((h) => String(row[h] ?? "").replace(/\t/g, " ")).join("\t"));
		}
		return lines.join("\n");
	}

	throw new Error(`Unsupported conversion: ${fromFormat} → ${toFormat}. Supported: csv↔json, tsv↔json, markdown→text, text→markdown, json↔text`);
}

// ─── CSV helpers ────────────────────────────────────────────────────────────

function parseCsvLines(text: string, delimiter: string): string[][] {
	const rows: string[][] = [];
	let row: string[] = [];
	let field = "";
	let inQuotes = false;
	for (let i = 0; i < text.length; i++) {
		const ch = text[i];
		if (inQuotes) {
			if (ch === '"') {
				if (i + 1 < text.length && text[i + 1] === '"') {
					field += '"';
					i++;
				} else {
					inQuotes = false;
				}
			} else {
				field += ch;
			}
		} else {
			if (ch === '"') {
				inQuotes = true;
			} else if (ch === delimiter) {
				row.push(field);
				field = "";
			} else if (ch === "\r") {
				// skip
			} else if (ch === "\n") {
				row.push(field);
				field = "";
				if (row.length > 0) rows.push(row);
				row = [];
			} else {
				field += ch;
			}
		}
	}
	row.push(field);
	if (row.some((f) => f !== "")) rows.push(row);
	return rows;
}

function csvEscape(value: string, delimiter: string): string {
	if (value.includes(delimiter) || value.includes('"') || value.includes("\n")) {
		return '"' + value.replace(/"/g, '""') + '"';
	}
	return value;
}

function stripMarkdown(text: string): string {
	return text
		.replace(/^#{1,6}\s+/gm, "") // headings
		.replace(/\*\*(.+?)\*\*/g, "$1") // bold
		.replace(/\*(.+?)\*/g, "$1") // italic
		.replace(/__(.+?)__/g, "$1") // bold alt
		.replace(/_(.+?)_/g, "$1") // italic alt
		.replace(/~~(.+?)~~/g, "$1") // strikethrough
		.replace(/`{3}[\s\S]*?`{3}/g, (m) => m.replace(/^`{3}.*\n?/, "").replace(/`{3}$/, "")) // code blocks
		.replace(/`(.+?)`/g, "$1") // inline code
		.replace(/^\s*[-*+]\s+/gm, "") // unordered lists
		.replace(/^\s*\d+\.\s+/gm, "") // ordered lists
		.replace(/\[([^\]]+)\]\([^)]+\)/g, "$1") // links
		.replace(/!\[([^\]]*)\]\([^)]+\)/g, "$1") // images
		.replace(/^\s*>\s+/gm, "") // blockquotes
		.replace(/^\s*---+\s*$/gm, "") // horizontal rules
		.replace(/\n{3,}/g, "\n\n") // collapse blank lines
		.trim();
}

// ─── Metadata ───────────────────────────────────────────────────────────────

function metadata(...args: Value[]): Value {
	const filePath = String(args[0]);
	const buf = readFileSync(filePath);
	const ext = extname(filePath).toLowerCase();
	const fileInfo = EXTENSION_MAP[ext] || { type: "unknown", format: ext.replace(".", ""), mime: "application/octet-stream" };

	const result: Record<string, any> = {
		fileName: filePath.replace(/.*[/\\]/, ""),
		extension: ext,
		size: buf.length,
		sizeFormatted: formatBytes(buf.length),
		type: fileInfo.type,
		format: fileInfo.format,
		mime: fileInfo.mime,
	};

	// For ZIP-based formats, try to detect content type entries
	if (bufferStartsWith(buf, ZIP_MAGIC)) {
		result.isZipBased = true;
		result.magicBytes = "PK";
	} else if (bufferStartsWith(buf, OLE2_MAGIC)) {
		result.isLegacyFormat = true;
		result.magicBytes = "OLE2";
	} else if (bufferStartsWith(buf, PDF_MAGIC)) {
		result.magicBytes = "PDF";
	} else if (bufferStartsWith(buf, RTF_MAGIC)) {
		result.magicBytes = "RTF";
	}

	// For text-based formats, add line/char counts
	if (["csv", "txt", "markdown", "json", "xml", "html", "tsv"].includes(fileInfo.format)) {
		const text = buf.toString("utf-8");
		result.lineCount = text.split("\n").length;
		result.charCount = text.length;
		if (fileInfo.format === "csv" || fileInfo.format === "tsv") {
			const delim = fileInfo.format === "tsv" ? "\t" : ",";
			const lines = parseCsvLines(text, delim);
			result.rowCount = lines.length > 0 ? lines.length - 1 : 0; // exclude header
			result.columnCount = lines.length > 0 ? lines[0].length : 0;
			if (lines.length > 0) result.headers = lines[0];
		}
	}

	return result;
}

function formatBytes(bytes: number): string {
	if (bytes === 0) return "0 B";
	const units = ["B", "KB", "MB", "GB"];
	const i = Math.floor(Math.log(bytes) / Math.log(1024));
	return (bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 2) + " " + units[i];
}

// ─── Template ───────────────────────────────────────────────────────────────

function template(...args: Value[]): Value {
	const templateStr = String(args[0]);
	const variables = getOpts(args[1]);
	const opts = getOpts(args[2]);
	const openDelim = opts.open || "{{";
	const closeDelim = opts.close || "}}";
	const missingAction = opts.missing || "keep"; // keep | remove | error

	let result = templateStr;
	const missing: string[] = [];

	// Replace all known variables
	for (const [key, value] of Object.entries(variables)) {
		const pattern = escapeRegex(openDelim) + "\\s*" + escapeRegex(key) + "\\s*" + escapeRegex(closeDelim);
		result = result.replace(new RegExp(pattern, "g"), String(value));
	}

	// Check for remaining placeholders
	const remainingPattern = new RegExp(escapeRegex(openDelim) + "\\s*(\\w+)\\s*" + escapeRegex(closeDelim), "g");
	let match;
	while ((match = remainingPattern.exec(result)) !== null) {
		missing.push(match[1]);
	}

	if (missing.length > 0 && missingAction === "error") {
		throw new Error(`Missing template variables: ${missing.join(", ")}`);
	}
	if (missing.length > 0 && missingAction === "remove") {
		result = result.replace(remainingPattern, "");
	}

	return result;
}

function escapeRegex(str: string): string {
	return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

// ─── Merge (mail-merge style) ───────────────────────────────────────────────

function merge(...args: Value[]): Value {
	const templateStr = String(args[0]);
	const records = args[1];
	const opts = getOpts(args[2]);

	if (!Array.isArray(records)) throw new Error("merge expects an array of records as the second argument");

	const openDelim = opts.open || "{{";
	const closeDelim = opts.close || "}}";
	const separator = opts.separator ?? "\n---\n";

	const results: string[] = [];
	for (const record of records) {
		const vars = getOpts(record);
		let result = templateStr;
		for (const [key, value] of Object.entries(vars)) {
			const pattern = escapeRegex(openDelim) + "\\s*" + escapeRegex(key) + "\\s*" + escapeRegex(closeDelim);
			result = result.replace(new RegExp(pattern, "g"), String(value));
		}
		// Remove any remaining placeholders
		const remainingPattern = new RegExp(escapeRegex(openDelim) + "\\s*\\w+\\s*" + escapeRegex(closeDelim), "g");
		result = result.replace(remainingPattern, "");
		results.push(result);
	}

	return opts.asArray ? results : results.join(separator);
}

// ─── Table ↔ JSON ───────────────────────────────────────────────────────────

function tableToJson(...args: Value[]): Value {
	const table = args[0];
	const opts = getOpts(args[1]);

	if (!Array.isArray(table) || table.length === 0) throw new Error("tableToJson expects a non-empty 2D array");

	let headers: string[];
	let startRow: number;

	if (opts.headers && Array.isArray(opts.headers)) {
		headers = opts.headers.map(String);
		startRow = 0;
	} else {
		headers = (table[0] as any[]).map(String);
		startRow = 1;
	}

	const result = [];
	for (let i = startRow; i < table.length; i++) {
		const row = table[i] as any[];
		const obj: Record<string, any> = {};
		for (let j = 0; j < headers.length; j++) {
			let val = j < row.length ? row[j] : null;
			if (opts.parseNumbers && typeof val === "string" && val !== "" && !isNaN(Number(val))) {
				val = Number(val);
			}
			obj[headers[j]] = val;
		}
		result.push(obj);
	}
	return result;
}

function jsonToTable(...args: Value[]): Value {
	const data = args[0];
	const opts = getOpts(args[1]);

	if (!Array.isArray(data)) throw new Error("jsonToTable expects an array of objects");
	if (data.length === 0) return [[]];

	let headers: string[];
	if (opts.columns && Array.isArray(opts.columns)) {
		headers = opts.columns.map(String);
	} else {
		// Collect all unique keys across all objects
		const keySet = new Set<string>();
		for (const row of data) {
			if (row && typeof row === "object") {
				for (const key of Object.keys(row)) keySet.add(key);
			}
		}
		headers = [...keySet];
	}

	const table: any[][] = [];
	if (opts.noHeader !== true) {
		table.push(headers);
	}
	for (const row of data) {
		const obj = getOpts(row);
		table.push(headers.map((h) => obj[h] ?? null));
	}
	return table;
}

// ─── Sanitize ───────────────────────────────────────────────────────────────

function sanitize(...args: Value[]): Value {
	const text = String(args[0]);
	const opts = getOpts(args[1]);

	let result = text;

	// Strip HTML tags
	if (opts.stripHtml !== false) {
		result = result.replace(/<script[\s\S]*?<\/script>/gi, "");
		result = result.replace(/<style[\s\S]*?<\/style>/gi, "");
		result = result.replace(/<[^>]+>/g, "");
	}

	// Remove control characters (except newlines and tabs)
	if (opts.stripControl !== false) {
		result = result.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
	}

	// Trim excessive whitespace
	if (opts.normalizeWhitespace) {
		result = result.replace(/[ \t]+/g, " ");
		result = result.replace(/\n{3,}/g, "\n\n");
	}

	// Remove null bytes
	result = result.replace(/\0/g, "");

	// Escape special characters if requested
	if (opts.escapeHtml) {
		result = result
			.replace(/&/g, "&amp;")
			.replace(/</g, "&lt;")
			.replace(/>/g, "&gt;")
			.replace(/"/g, "&quot;")
			.replace(/'/g, "&#39;");
	}

	// Limit length
	if (opts.maxLength && typeof opts.maxLength === "number" && result.length > opts.maxLength) {
		result = result.substring(0, opts.maxLength);
		if (opts.ellipsis !== false) result += "…";
	}

	return result;
}

// ─── Exports ────────────────────────────────────────────────────────────────

export const OfficeFunctions: Record<string, BuiltinHandler> = {
	detect,
	convert,
	metadata,
	template,
	merge,
	tableToJson,
	jsonToTable,
	sanitize,
};

export const OfficeFunctionMetadata = {
	detect: {
		description: "Detect the type of an Office/document file from its extension or buffer magic bytes",
		parameters: [
			{ name: "input", dataType: "any", description: "File path (string) or file buffer to detect", formInputType: "text", required: true },
		],
		returnType: "object",
		returnDescription: "{type, format, mime, source}",
		example: 'office.detect "./report.docx"',
	},
	convert: {
		description: "Convert data between common formats (csv↔json, tsv↔json, markdown→text, json↔text)",
		parameters: [
			{ name: "data", dataType: "any", description: "The data to convert (string or array/object)", formInputType: "text", required: true },
			{ name: "from", dataType: "string", description: "Source format: csv, tsv, json, text, markdown", formInputType: "text", required: true },
			{ name: "to", dataType: "string", description: "Target format: csv, tsv, json, text, markdown", formInputType: "text", required: true },
			{ name: "options", dataType: "object", description: "{delimiter, language, codeBlock, indent}", formInputType: "json", required: false },
		],
		returnType: "any",
		returnDescription: "Converted data in the target format",
		example: 'office.convert $csvString "csv" "json"',
	},
	metadata: {
		description: "Extract metadata from an Office/document file (size, type, line count, headers for CSV)",
		parameters: [
			{ name: "filePath", dataType: "string", description: "Path to the file", formInputType: "text", required: true },
		],
		returnType: "object",
		returnDescription: "{fileName, extension, size, sizeFormatted, type, format, mime, ...}",
		example: 'office.metadata "./data.csv"',
	},
	template: {
		description: "Render a string template by replacing {{variable}} placeholders with values",
		parameters: [
			{ name: "template", dataType: "string", description: "Template string with {{placeholders}}", formInputType: "textarea", required: true },
			{ name: "variables", dataType: "object", description: "Key-value pairs for replacement", formInputType: "json", required: true },
			{ name: "options", dataType: "object", description: "{open, close, missing: keep|remove|error}", formInputType: "json", required: false },
		],
		returnType: "string",
		returnDescription: "Rendered string with placeholders replaced",
		example: 'office.template "Hello {{name}}, welcome to {{company}}!" {"name": "Alice", "company": "Acme"}',
	},
	merge: {
		description: "Mail-merge: apply a template to an array of records, producing one output per record",
		parameters: [
			{ name: "template", dataType: "string", description: "Template string with {{placeholders}}", formInputType: "textarea", required: true },
			{ name: "records", dataType: "array", description: "Array of objects with values for each merge", formInputType: "json", required: true },
			{ name: "options", dataType: "object", description: "{open, close, separator, asArray: bool}", formInputType: "json", required: false },
		],
		returnType: "string",
		returnDescription: "Merged results joined by separator (or array if asArray is true)",
		example: 'office.merge "Dear {{name}},\\nYour order #{{order}} is ready." [{"name": "Alice", "order": "1001"}, {"name": "Bob", "order": "1002"}]',
	},
	tableToJson: {
		description: "Convert a 2D array (table) to an array of objects using the first row as headers",
		parameters: [
			{ name: "table", dataType: "array", description: "2D array where first row is headers", formInputType: "json", required: true },
			{ name: "options", dataType: "object", description: "{headers: string[], parseNumbers: bool}", formInputType: "json", required: false },
		],
		returnType: "array",
		returnDescription: "Array of objects keyed by header names",
		example: 'office.tableToJson [["name", "age"], ["Alice", "30"], ["Bob", "25"]]',
	},
	jsonToTable: {
		description: "Convert an array of objects to a 2D array (table) with a header row",
		parameters: [
			{ name: "data", dataType: "array", description: "Array of objects", formInputType: "json", required: true },
			{ name: "options", dataType: "object", description: "{columns: string[], noHeader: bool}", formInputType: "json", required: false },
		],
		returnType: "array",
		returnDescription: "2D array with header row followed by data rows",
		example: 'office.jsonToTable [{"name": "Alice", "age": 30}, {"name": "Bob", "age": 25}]',
	},
	sanitize: {
		description: "Strip potentially unsafe content (HTML tags, scripts, control characters) from text",
		parameters: [
			{ name: "text", dataType: "string", description: "Text to sanitize", formInputType: "textarea", required: true },
			{ name: "options", dataType: "object", description: "{stripHtml, stripControl, normalizeWhitespace, escapeHtml, maxLength, ellipsis}", formInputType: "json", required: false },
		],
		returnType: "string",
		returnDescription: "Sanitized text",
		example: 'office.sanitize "<script>alert(1)</script><b>Hello</b> World" {"normalizeWhitespace": true}',
	},
};

export const OfficeModuleMetadata = {
	description:
		"Cross-format Office utilities — file type detection, format conversion (CSV↔JSON, TSV↔JSON, Markdown→text), file metadata extraction, template rendering with variable replacement, mail-merge, table↔JSON conversion, and text sanitization. Zero npm dependencies.",
	methods: ["detect", "convert", "metadata", "template", "merge", "tableToJson", "jsonToTable", "sanitize"],
};
