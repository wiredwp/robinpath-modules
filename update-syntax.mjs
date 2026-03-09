#!/usr/bin/env node
/**
 * update-syntax.mjs
 *
 * Updates all MODULE.md files to use @desc + do/enddo syntax in code examples.
 * Then regenerates README.md from the updated MODULE.md files.
 *
 * Transforms recipe/example code blocks from flat style to structured style:
 *
 * BEFORE:
 *   slack.setToken $token
 *   set $result as slack.send "default" "#general" "Hello"
 *   print "Done"
 *
 * AFTER:
 *   @desc "Setup authentication"
 *   do
 *     slack.setToken $token
 *   enddo
 *
 *   @desc "Send message and print result"
 *   do
 *     set $result as slack.send "default" "#general" "Hello"
 *     print "Done"
 *   enddo
 */

import { readdir, readFile, writeFile, access } from "node:fs/promises";
import { join } from "node:path";

const PACKAGES_DIR = join(import.meta.dirname, "packages");

// ─── Auth detection ──────────────────────────────────────────────────────────

const AUTH_PATTERNS = [
	/^\w+\.setToken\b/,
	/^\w+\.setCredentials\b/,
	/^\w+\.setApiKey\b/,
	/^\w+\.setKey\b/,
	/^\w+\.setAuth\b/,
	/^\w+\.setConfig\b/,
	/^\w+\.configure\b/,
	/^\w+\.init\b/,
	/^\w+\.connect\b/,
	/^\w+\.login\b/,
	/^\w+\.authenticate\b/,
	/^\w+\.setup\b/,
];

function isAuthLine(line) {
	const trimmed = line.trim();
	return AUTH_PATTERNS.some((p) => p.test(trimmed));
}

// ─── Block structure detection ───────────────────────────────────────────────

const BLOCK_STARTS = ['if ', 'each ', 'for ', 'together', 'on '];
const BLOCK_ENDS = ['end', 'endif', 'endfor', 'endon', 'endtogether'];

function isBlockStart(line) {
	const trimmed = line.trim();
	return BLOCK_STARTS.some((s) => trimmed.startsWith(s));
}

function isBlockEnd(line) {
	const trimmed = line.trim();
	return BLOCK_ENDS.some((s) => trimmed === s);
}

function isComment(line) {
	return line.trim().startsWith('#') || line.trim().startsWith('//');
}

function isEmpty(line) {
	return line.trim() === '';
}

// ─── Grouping lines into logical blocks ──────────────────────────────────────

/**
 * Groups code lines into logical blocks that each get wrapped in @desc/do/enddo.
 * Returns array of { desc: string, lines: string[] }
 */
function groupLines(lines, moduleName) {
	if (lines.length === 0) return [];
	if (lines.length === 1) {
		// Single-line examples don't need wrapping
		return [{ desc: null, lines }];
	}

	const groups = [];
	let i = 0;

	// Phase 1: Extract auth block if present
	if (isAuthLine(lines[0])) {
		const authLines = [lines[0]];
		i = 1;
		// Grab any continuation auth lines
		while (i < lines.length && isAuthLine(lines[i])) {
			authLines.push(lines[i]);
			i++;
		}
		groups.push({ desc: 'Setup authentication', lines: authLines });
	}

	// Phase 2: Group remaining lines
	while (i < lines.length) {
		// Skip empty lines and comments between groups
		if (isEmpty(lines[i])) {
			i++;
			continue;
		}

		const blockLines = [];
		let desc = '';

		// Check for a comment that describes the next block
		if (isComment(lines[i])) {
			desc = lines[i].trim().replace(/^#\s*/, '').replace(/^\/\/\s*/, '');
			i++;
			if (i >= lines.length) break;
		}

		// Collect lines for this logical block
		let nestingDepth = 0;
		while (i < lines.length) {
			const line = lines[i];

			if (isEmpty(line) && nestingDepth === 0 && blockLines.length > 0) {
				// Empty line at top level = block separator
				break;
			}

			if (isBlockStart(line)) nestingDepth++;
			if (isBlockEnd(line)) nestingDepth = Math.max(0, nestingDepth - 1);

			blockLines.push(line);
			i++;

			// If we just closed a block at top level, end this group
			if (nestingDepth === 0 && isBlockEnd(line)) break;
		}

		if (blockLines.length > 0) {
			if (!desc) {
				desc = inferDescription(blockLines, moduleName);
			}
			groups.push({ desc, lines: blockLines });
		}
	}

	return groups;
}

/**
 * Infer a description from the code lines
 */
function inferDescription(lines, moduleName) {
	// Collect all function calls in this block
	const funcCalls = [];
	const hasIf = lines.some((l) => l.trim().startsWith('if '));
	const hasLoop = lines.some((l) => l.trim().startsWith('each ') || l.trim().startsWith('for '));

	for (const line of lines) {
		const trimmed = line.trim();
		const setMatch = trimmed.match(/^set\s+\$\w+\s+as\s+(\w+)\.(\w+)/);
		if (setMatch) {
			funcCalls.push(setMatch[2]);
			continue;
		}
		const callMatch = trimmed.match(/^(\w+)\.(\w+)/);
		if (callMatch) {
			funcCalls.push(callMatch[2]);
		}
	}

	// Build description from collected calls
	if (funcCalls.length === 0) {
		if (hasIf) return 'Validate result';
		if (hasLoop) return 'Iterate results';
		const first = lines[0].trim();
		if (first.startsWith('print ')) return 'Output result';
		return 'Execute operation';
	}

	// Deduplicate function names
	const unique = [...new Set(funcCalls)];

	if (unique.length === 1) {
		const base = capitalize(humanize(unique[0]));
		if (hasLoop) return `${base} and iterate results`;
		if (hasIf) return `${base} and validate result`;
		return base;
	}

	if (unique.length === 2) {
		return `${capitalize(humanize(unique[0]))} and ${humanize(unique[1])}`;
	}

	// 3+ operations
	return `${capitalize(humanize(unique[0]))}, ${humanize(unique[1])}, and more`;
}

function humanize(camelCase) {
	return camelCase
		.replace(/([A-Z])/g, ' $1')
		.replace(/^./, (s) => s.toUpperCase())
		.trim()
		.toLowerCase();
}

function capitalize(s) {
	return s.charAt(0).toUpperCase() + s.slice(1);
}

// ─── Code transformation ─────────────────────────────────────────────────────

function transformCodeBlock(code, moduleName) {
	const lines = code.split('\n');

	// Don't transform single-line examples (function reference examples)
	if (lines.length <= 2) return code;

	// Don't transform if it already uses do/enddo
	if (lines.some((l) => l.trim() === 'enddo')) return code;

	const groups = groupLines(lines, moduleName);

	// If only one group and it's short, don't wrap (it would be redundant)
	if (groups.length === 1 && groups[0].lines.length <= 2 && !groups[0].desc) {
		return code;
	}

	// If grouping produced nothing meaningful, return original
	if (groups.length === 0) return code;

	// Build the transformed code
	const outputParts = [];

	for (const group of groups) {
		if (group.desc === null) {
			// No wrapping needed (single line)
			outputParts.push(group.lines.join('\n'));
		} else {
			const indentedLines = group.lines.map((l) => '  ' + l);
			outputParts.push(
				`@desc "${group.desc}"\ndo\n${indentedLines.join('\n')}\nenddo`
			);
		}
	}

	return outputParts.join('\n\n');
}

// ─── MODULE.md processing ────────────────────────────────────────────────────

function transformModuleMd(content, moduleName) {
	// Find all ```robinpath code blocks and transform them
	// But only transform blocks in Recipes, Error Handling sections
	// Function reference examples (single-line) stay as-is

	const sectionsToTransform = ['Recipes', 'Error Handling'];

	let result = content;

	for (const sectionName of sectionsToTransform) {
		const sectionMarker = `## ${sectionName}`;
		const sectionStart = result.indexOf(sectionMarker);
		if (sectionStart === -1) continue;

		// Find next ## section or end of file
		const nextSection = result.indexOf('\n## ', sectionStart + sectionMarker.length);
		const sectionEnd = nextSection === -1 ? result.length : nextSection;

		let section = result.slice(sectionStart, sectionEnd);

		// Transform all ```robinpath blocks within this section
		section = section.replace(
			/```robinpath\n([\s\S]*?)```/g,
			(match, code) => {
				const transformed = transformCodeBlock(code.trimEnd(), moduleName);
				return '```robinpath\n' + transformed + '\n```';
			}
		);

		result = result.slice(0, sectionStart) + section + result.slice(sectionEnd);
	}

	return result;
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
	const dirs = await readdir(PACKAGES_DIR);
	let processed = 0;
	let skipped = 0;
	const errors = [];

	for (const dir of dirs.sort()) {
		const pkgDir = join(PACKAGES_DIR, dir);
		const modulePath = join(pkgDir, 'MODULE.md');

		try {
			await access(modulePath);
		} catch {
			skipped++;
			continue;
		}

		try {
			const raw = await readFile(modulePath, 'utf-8');
			const content = raw.replace(/\r\n/g, '\n').replace(/\r/g, '\n');

			// Extract module name from frontmatter
			const fmMatch = content.match(/^---\n[\s\S]*?module:\s*"?(\w[\w-]*)"?/);
			const moduleName = fmMatch ? fmMatch[1] : dir;

			const transformed = transformModuleMd(content, moduleName);

			if (transformed !== content) {
				await writeFile(modulePath, transformed, 'utf-8');
				processed++;
				if (processed % 20 === 0) {
					console.log(`  ... ${processed} modules updated`);
				}
			} else {
				skipped++;
			}
		} catch (err) {
			errors.push({ dir, error: err.message });
		}
	}

	console.log(`\nDone!`);
	console.log(`  Updated: ${processed}`);
	console.log(`  Unchanged/Skipped: ${skipped}`);
	if (errors.length > 0) {
		console.log(`  Errors: ${errors.length}`);
		for (const e of errors) {
			console.log(`    - ${e.dir}: ${e.error}`);
		}
	}
}

main().catch((err) => {
	console.error('Fatal error:', err);
	process.exit(1);
});
