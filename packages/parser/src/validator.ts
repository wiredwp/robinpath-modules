/**
 * Enterprise RobinPath Code Validator
 *
 * Two-layer validation:
 * 1. Parser validation — uses the real @wiredwp/robinpath Parser (catches structural errors)
 * 2. Semantic validation — catches patterns the parser accepts but fail at runtime
 *
 * Common LLM mistakes caught:
 * - Bare `end` instead of `endfor`/`endif`/`enddo`/`endon`/`enddef`
 * - Invalid keywords: `while`, `each`, `import`, `try` (parser accepts as commands)
 * - Unclosed blocks, mismatched block pairs
 * - Non-existent function calls (checked against known function index)
 * - Wrong call style: parenthesized calls like fn(a, b) instead of fn a b
 * - Pipe operator |> (not in language)
 * - Semicolons at end of lines
 */

import { Parser } from "@wiredwp/robinpath";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ValidationError {
	line: number;
	type: "parse" | "semantic";
	error: string;
}

export interface ValidationResult {
	valid: boolean;
	blockCount: number;
	errors: ValidationError[];
}

export interface ValidatorOptions {
	/** Known function names for registry validation (e.g. ["math.add", "string.capitalize"]) */
	knownFunctions?: Set<string>;
}

// ─── Code block extraction ───────────────────────────────────────────────────

const CODE_BLOCK_REGEX = /```(?:robinpath|robin|rp)\s*\n([\s\S]*?)```/g;

export function extractCodeBlocks(text: string): string[] {
	const blocks: string[] = [];
	let match: RegExpExecArray | null;
	CODE_BLOCK_REGEX.lastIndex = 0;
	while ((match = CODE_BLOCK_REGEX.exec(text)) !== null) {
		blocks.push(match[1].trim());
	}
	return blocks;
}

// ─── Layer 1: Parser validation ──────────────────────────────────────────────

export async function parserValidate(
	code: string,
): Promise<ValidationError[]> {
	try {
		const parser = new Parser(code);
		await parser.parse();
		return [];
	} catch (err: unknown) {
		const msg = err instanceof Error ? err.message : String(err);
		const lineMatch = msg.match(/line (\d+)/i);
		const line = lineMatch ? parseInt(lineMatch[1], 10) : 1;
		return [{ line, type: "parse", error: enrichParserError(msg, code, line) }];
	}
}

/** Rewrite cryptic parser errors into actionable messages */
function enrichParserError(msg: string, code: string, line: number): string {
	const lines = code.split("\n");
	const srcLine = (lines[line - 1] || "").trim();

	// "missing endif" when the real problem is function-call in if condition
	if (/missing endif/i.test(msg) && /^if\s+[a-zA-Z]\w*\.?\w*\s+\$/i.test(srcLine) && !/^if\s+\$/.test(srcLine) && !/^if\s+not\s+\$/i.test(srcLine)) {
		return `${msg}. Line ${line} uses a function call as if-condition ('${srcLine.slice(0, 50)}...'). Compute the result into a variable first, then use 'if $var ...'`;
	}

	// DECORATOR '@desc' inside unclosed block — usually def nested inside do
	if (/DECORATOR '@desc'/.test(msg)) {
		// Scan earlier lines for def inside do
		const priorLines = lines.slice(0, line - 1);
		let inDo = false;
		let defInsideDo = false;
		for (const pl of priorLines) {
			const t = pl.trim().split(/\s/)[0]?.toLowerCase();
			if (t === "do") inDo = true;
			if (t === "enddo") inDo = false;
			if (t === "def" && inDo) defInsideDo = true;
		}
		if (defInsideDo) {
			return `${msg}. You nested a 'def' block inside a 'do' block — this is not allowed. Move 'def/enddef' OUTSIDE of 'do/enddo'. Define functions separately, then call them from inside 'do' blocks`;
		}
		return `${msg}. Make sure every 'do' block is closed with 'enddo' BEFORE starting a new @desc section`;
	}

	// RPAREN — parenthesized function calls
	if (/RPAREN|Unexpected token.*\)/.test(msg)) {
		// Find what looks like fn(...) on that line
		const parenMatch = srcLine.match(/([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)?)\s*\(/);
		if (parenMatch) {
			return `${msg}. Do NOT use parentheses for function calls. Write '${parenMatch[1]} arg1 arg2' instead of '${parenMatch[1]}(arg1, arg2)'`;
		}
	}

	// "Invalid property access: .." — usually range syntax like [$x..$y]
	if (/Invalid property access.*\.\./.test(msg)) {
		return `${msg}. The '..' range operator does not exist. Use 'for $i from $start to $end'. If you need $n-1, compute first: 'math.subtract $n 1 into $limit'`;
	}

	// "Expected '=' or 'as' after variable" — usually wrong assignment syntax
	if (/Expected '=' or 'as' after variable/.test(msg)) {
		return `${msg}. To capture output, use 'command arg1 arg2 into $var' — not '$var = command(args)' or '$var command args'`;
	}

	return msg;
}

// ─── Layer 2: Semantic validation ────────────────────────────────────────────

/** Keywords that LLMs generate but don't exist in RobinPath */
const INVALID_FIRST_WORDS: Record<string, string> = {
	while: "No 'while' keyword in RobinPath. Use 'for $i from 1 to N ... endfor'",
	each: "No 'each' keyword. Use 'for $item in $collection ... endfor'",
	import: "No 'import' keyword. Installed modules are auto-loaded",
	try: "No 'try' keyword. Use 'do ... catch $err ... enddo' for error handling",
	finally: "No 'finally' keyword. Use 'do ... enddo'",
	switch: "No 'switch' keyword. Use if/elseif/else/endif",
	case: "No 'case' keyword. Use if/elseif/else/endif",
	class: "No 'class' keyword. RobinPath uses 'def' for functions",
	function: "No 'function' keyword. Use 'def name ... enddef'",
	fn: "No 'fn' keyword. Use 'def name ... enddef'",
	endfn: "No 'endfn' keyword. Use 'enddef' to close a 'def' block",
	let: "No 'let' keyword. Use 'set $var = value' or '$var = value'",
	const: "No 'const' as statement. Use 'set $var = value'",
	var: "No 'var' as statement. Use 'set $var = value'",
	print: "No 'print' command. Use 'log' instead",
	echo: "No 'echo' command. Use 'log' instead",
	puts: "No 'puts' command. Use 'log' instead",
	"console.log": "No 'console.log'. Use 'log' instead",
	require: "No 'require'. Modules are auto-loaded when installed",
	export: "No 'export' keyword in RobinPath scripts",
	async: "No 'async' keyword. RobinPath handles async transparently",
	await: "No 'await' keyword. RobinPath handles async transparently",
	return: "No 'return' keyword. Use 'respond' inside 'def' blocks",
	throw: "No 'throw' keyword. Errors propagate automatically or use 'do/catch/enddo'",
	new: "No 'new' keyword. RobinPath is not object-oriented",
	delete: "No 'delete' keyword.",
	typeof: "No 'typeof' keyword.",
	instanceof: "No 'instanceof' keyword.",
	"endif;": "Remove the semicolon — RobinPath doesn't use semicolons",
	"endfor;": "Remove the semicolon — RobinPath doesn't use semicolons",
	"enddo;": "Remove the semicolon — RobinPath doesn't use semicolons",
};

/** Block opener → expected closer */
const BLOCK_OPENERS: Record<string, string> = {
	for: "endfor",
	if: "endif",
	do: "enddo",
	on: "endon",
	def: "enddef",
	define: "enddef",
	together: "endtogether",
	with: "endwith",
};

const BLOCK_CLOSERS = new Set(Object.values(BLOCK_OPENERS));

/** Strip string literals to avoid false positives */
function stripStrings(line: string): string {
	return line
		.replace(/"(?:[^"\\]|\\.)*"/g, '""')
		.replace(/'(?:[^'\\]|\\.)*'/g, "''")
		.replace(/`(?:[^`\\]|\\.)*`/g, "``");
}

export function semanticValidate(
	code: string,
	options?: ValidatorOptions,
): ValidationError[] {
	const errors: ValidationError[] = [];
	const lines = code.split("\n");
	const blockStack: { keyword: string; line: number }[] = [];

	for (let i = 0; i < lines.length; i++) {
		const trimmed = lines[i].trim();
		const lineNum = i + 1;

		// Skip comments and empty lines
		if (trimmed === "" || trimmed.startsWith("#")) continue;

		const noStrings = stripStrings(trimmed);
		const firstWord = noStrings.split(/[\s(]/)[0].toLowerCase();

		// ── Check 1: Invalid keywords ──
		if (firstWord in INVALID_FIRST_WORDS) {
			errors.push({
				line: lineNum,
				type: "semantic",
				error: INVALID_FIRST_WORDS[firstWord],
			});
			continue;
		}

		// ── Check 2: Bare 'end' keyword ──
		if (firstWord === "end" && noStrings === "end") {
			if (blockStack.length > 0) {
				const top = blockStack[blockStack.length - 1];
				const expected = BLOCK_OPENERS[top.keyword];
				errors.push({
					line: lineNum,
					type: "semantic",
					error: `Bare 'end' is invalid. Use '${expected}' to close the '${top.keyword}' block from line ${top.line}`,
				});
			} else {
				errors.push({
					line: lineNum,
					type: "semantic",
					error: "Bare 'end' is invalid. Use 'endfor', 'endif', 'enddo', 'endon', or 'enddef'",
				});
			}
			continue;
		}

		// ── Check 3: Semicolons at end of line ──
		if (noStrings.endsWith(";") && !noStrings.startsWith("#")) {
			errors.push({
				line: lineNum,
				type: "semantic",
				error: "Remove the semicolon — RobinPath does not use semicolons",
			});
		}

		// ── Check 4: Pipe operator |> ──
		if (noStrings.includes("|>")) {
			errors.push({
				line: lineNum,
				type: "semantic",
				error: "Pipe operator '|>' is not supported. Chain operations with variables instead",
			});
		}

		// ── Check 5: Function call in if condition ──
		// Catches: if isEqual $x $y, if array.length $arr < 5, if string.contains $s "x"
		if (/^(if|elseif)\s+/i.test(noStrings) && !/^(if|elseif)\s+\$/i.test(noStrings) && !/^(if|elseif)\s+not\s+\$/i.test(noStrings)) {
			const condMatch = noStrings.match(/^(?:if|elseif)\s+([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)?)/i);
			if (condMatch) {
				const condWord = condMatch[1].toLowerCase();
				if (!["true", "false", "not"].includes(condWord)) {
					const isModuleCall = condMatch[1].includes(".");
					errors.push({
						line: lineNum,
						type: "semantic",
						error: isModuleCall
							? `Don't use function calls in if conditions. Compute first: '${condMatch[1]} ... into $result', then 'if $result ...'`
							: `Don't use function calls in if conditions. Use operators: 'if $x == $y', 'if $x > 5' — not 'if ${condMatch[1]} $x $y'`,
					});
				}
			}
		}

		// ── Check 5a2: Function call after and/or in if conditions ──
		if (/^(if|elseif)\s+/.test(noStrings) && /\b(and|or)\s+[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)\s+\$/.test(noStrings)) {
			errors.push({
				line: lineNum,
				type: "semantic",
				error: "Don't use function calls inside if conditions (even after 'and'/'or'). Compute each value first into a variable, then compare variables in the if",
			});
		}

		// ── Check 5b: Parenthesized range/expression in for loops ──
		if (/^for\s+\$\w+\s+in\s+\(/.test(noStrings)) {
			errors.push({
				line: lineNum,
				type: "semantic",
				error: "Don't use parenthesized expressions in 'for'. Use 'for $i from 0 to $n' instead of 'for $i in (0..$n)' or 'for $i in (range 0 $n)'",
			});
		}

		// ── Check 5b2: for ... in range — 'range' is not a keyword ──
		if (/^for\s+\$\w+\s+in\s+range\b/i.test(noStrings)) {
			errors.push({
				line: lineNum,
				type: "semantic",
				error: "No 'range' keyword in RobinPath. Use 'for $i from 0 to $n' instead of 'for $i in range 0 $n'. If you need ($n-1), compute it first: 'math.subtract $n 1 into $limit', then 'for $i from 0 to $limit'",
			});
		}

		// ── Check 5b3: for ... in [$x..$y] — '..' range syntax not supported ──
		if (/^for\s+.*\.\./.test(noStrings)) {
			errors.push({
				line: lineNum,
				type: "semantic",
				error: "Range syntax '..' is not supported. Use 'for $i from $start to $end' instead of 'for $i in [$start..$end]'",
			});
		}

		// ── Check 5c: Parenthesized subexpression as function argument ──
		// Catches: array.get $arr ($i+1), math.subtract (array.length $arr) 1, fn (call + 1)
		if (!noStrings.startsWith("if") && !noStrings.startsWith("elseif")) {
			const hasMathParens = /\w\s+\([^)]*[\+\-\*\/][^)]*\)/.test(noStrings);
			const hasNestedCallParens = /^[a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)?\s+.*\([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)?\s+\$/.test(noStrings);
			if (hasMathParens || hasNestedCallParens) {
				const isForLine = noStrings.startsWith("for");
				errors.push({
					line: lineNum,
					type: "semantic",
					error: isForLine
						? "Don't use parenthesized math in 'for' ranges. Compute the limit BEFORE the loop: 'math.subtract $n 1 into $limit', then 'for $i from 0 to $limit'"
						: "Don't use parenthesized expressions as arguments. Compute each step separately: 'array.length $arr into $len', then 'math.subtract $len 1 into $result'",
				});
			}
		}

		// ── Check 5e: Inline arithmetic in function call arguments ──
		// Catches: quicksort $arr $low $pi - 1, array.get $arr $j + 1
		// But NOT: if $x > 5, set $x = $y + 1, $x = $y - 1 (those are valid)
		if (
			!noStrings.startsWith("if") &&
			!noStrings.startsWith("elseif") &&
			!noStrings.startsWith("set ") &&
			!noStrings.startsWith("$") &&
			!/\binto\b/.test(noStrings)
		) {
			// Look for: command args $var +/- number (arithmetic as trailing args)
			const inlineArithMatch = noStrings.match(/^([a-zA-Z_]\w*(?:\.[a-zA-Z_]\w*)?)\s+.*\$\w+\s*[\+\-]\s*\d+\s*$/);
			if (inlineArithMatch) {
				errors.push({
					line: lineNum,
					type: "semantic",
					error: `Don't use inline arithmetic in function arguments. Compute first: 'math.subtract $var 1 into $temp', then pass $temp to '${inlineArithMatch[1]}'`,
				});
			}
		}

		// ── Check 5d: def nested inside do block ──
		if (firstWord === "def" && blockStack.some((b) => b.keyword === "do")) {
			errors.push({
				line: lineNum,
				type: "semantic",
				error: "Don't nest 'def/enddef' inside 'do/enddo'. Define functions at the top level in their own @desc section, then call them from 'do' blocks",
			});
		}

		// ── Check 6: Curly braces (JS/JSON style blocks) ──
		if (
			(noStrings.includes("{") || noStrings.includes("}")) &&
			!noStrings.startsWith("set ") &&
			!noStrings.startsWith("$") &&
			!noStrings.startsWith("log") &&
			!noStrings.includes("=")
		) {
			// Allow braces in assignments and log statements (JSON data)
			const braceContext =
				noStrings.startsWith("if") ||
				noStrings.startsWith("for") ||
				noStrings.startsWith("do") ||
				noStrings.startsWith("def");
			if (braceContext) {
				errors.push({
					line: lineNum,
					type: "semantic",
					error: "Curly braces '{}' are not used for blocks. Use keyword/endkeyword pairs",
				});
			}
		}

		// ── Check 6: Function registry validation ──
		if (options?.knownFunctions && noStrings.includes(".")) {
			const funcMatch = noStrings.match(
				/^([a-zA-Z_]\w*\.[a-zA-Z_]\w*)/,
			);
			if (funcMatch) {
				const funcName = funcMatch[1].toLowerCase();
				if (!options.knownFunctions.has(funcName)) {
					// Don't flag variables like $obj.prop
					if (!trimmed.startsWith("$")) {
						errors.push({
							line: lineNum,
							type: "semantic",
							error: `Unknown function '${funcMatch[1]}'. Check module name and function name`,
						});
					}
				}
			}
		}

		// ── Track block structure ──
		if (firstWord in BLOCK_OPENERS) {
			// Inline if with 'then' on same line (action after then, no block opened)
			if (
				firstWord === "if" &&
				noStrings.includes(" then ") &&
				!noStrings.endsWith(" then")
			) {
				continue; // inline if — no endif needed
			}
			blockStack.push({ keyword: firstWord, line: lineNum });
		}

		// Track closers
		if (BLOCK_CLOSERS.has(firstWord)) {
			if (blockStack.length === 0) {
				const opener =
					Object.entries(BLOCK_OPENERS).find(
						([, v]) => v === firstWord,
					)?.[0] || "?";
				errors.push({
					line: lineNum,
					type: "semantic",
					error: `Unexpected '${firstWord}' — no matching '${opener}' block is open`,
				});
			} else {
				const top = blockStack[blockStack.length - 1];
				const expected = BLOCK_OPENERS[top.keyword];
				if (firstWord === expected) {
					blockStack.pop();
				} else {
					errors.push({
						line: lineNum,
						type: "semantic",
						error: `Mismatched: expected '${expected}' to close '${top.keyword}' (line ${top.line}), got '${firstWord}'`,
					});
					blockStack.pop(); // pop to avoid cascading
				}
			}
		}

		// 'else', 'elseif', 'catch' are valid mid-block keywords, no stack change
	}

	// Unclosed blocks
	for (const open of blockStack) {
		errors.push({
			line: open.line,
			type: "semantic",
			error: `Unclosed '${open.keyword}' block — missing '${BLOCK_OPENERS[open.keyword]}'`,
		});
	}

	return errors;
}

// ─── Combined validation ─────────────────────────────────────────────────────

/**
 * Validate all RobinPath code blocks in an LLM response.
 * Runs both parser (structural) and semantic (runtime-safety) checks.
 */
export async function validateCode(
	text: string,
	options?: ValidatorOptions,
): Promise<ValidationResult> {
	const blocks = extractCodeBlocks(text);
	if (blocks.length === 0)
		return { valid: true, blockCount: 0, errors: [] };

	const allErrors: ValidationError[] = [];

	for (const block of blocks) {
		// Layer 1: Real parser
		const parseErrors = await parserValidate(block);
		allErrors.push(...parseErrors);

		// Layer 2: Semantic checks (always run — catches what parser misses)
		const semanticErrors = semanticValidate(block, options);
		allErrors.push(...semanticErrors);
	}

	// Deduplicate errors on same line with same message
	const seen = new Set<string>();
	const deduped = allErrors.filter((e) => {
		const key = `${e.line}:${e.error}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});

	return {
		valid: deduped.length === 0,
		blockCount: blocks.length,
		errors: deduped,
	};
}

/**
 * Validate a single code string directly (not wrapped in markdown fences).
 */
export async function validateCodeDirect(
	code: string,
	options?: ValidatorOptions,
): Promise<ValidationResult> {
	const allErrors: ValidationError[] = [];

	const parseErrors = await parserValidate(code);
	allErrors.push(...parseErrors);

	const semanticErrors = semanticValidate(code, options);
	allErrors.push(...semanticErrors);

	const seen = new Set<string>();
	const deduped = allErrors.filter((e) => {
		const key = `${e.line}:${e.error}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});

	return { valid: deduped.length === 0, blockCount: 1, errors: deduped };
}

// ─── Fix prompt builder ──────────────────────────────────────────────────────

/**
 * Build a prompt instructing the LLM to fix validation errors.
 * Used for auto-retry when validation fails.
 */
export function buildFixPrompt(errors: ValidationError[]): string {
	const errorDetails = errors
		.map((e) => `Line ${e.line} [${e.type}]: ${e.error}`)
		.join("\n");

	// Detect specific error patterns to give targeted fix instructions
	const allErrors = errors.map((e) => e.error).join(" ");
	const tips: string[] = [];

	// Pattern 1: Parenthesized function calls — the #1 LLM mistake
	if (/RPAREN|Expected '\)'/.test(allErrors)) {
		tips.push(
			`⚠️ CRITICAL: You used parentheses for function calls. RobinPath uses SPACE-SEPARATED arguments, NEVER parentheses.
  WRONG: http.get("https://api.example.com")
  WRONG: math.add(1, 2)
  WRONG: string.length("hello")
  RIGHT: http.get "https://api.example.com"
  RIGHT: math.add 1 2
  RIGHT: string.length "hello"
  RIGHT: array.filter $items (condition) — only use parens for inline expressions, never for function calls`
		);
	}

	// Pattern 2: Curly braces for blocks
	if (/[Cc]urly brace/.test(allErrors)) {
		tips.push(
			`⚠️ CRITICAL: You used curly braces {} for blocks. RobinPath uses keyword/endkeyword pairs.
  WRONG: if $x > 5 { log "big" }
  WRONG: for $i in $items { log $i }
  RIGHT: if $x > 5 \\n  log "big" \\n endif
  RIGHT: for $i in $items \\n  log $i \\n endfor`
		);
	}

	// Pattern 3: Unexpected enddo / block mismatch
	if (/[Uu]nexpected 'enddo'|no matching 'do'/.test(allErrors)) {
		tips.push(
			`⚠️ BLOCK MISMATCH: You have an 'enddo' without a matching 'do'. Count your blocks carefully:
  - Every 'do' needs exactly one 'enddo'
  - Every 'if' needs exactly one 'endif'
  - Every 'for' needs exactly one 'endfor'
  - Close the current block BEFORE starting a new @desc section
  - do/catch uses: do ... catch $err ... enddo (ONE enddo, not two)`
		);
	}

	// Pattern 4: @desc unexpected inside expression/block
	if (/DECORATOR '@desc'/.test(allErrors)) {
		tips.push(
			`⚠️ BLOCK NOT CLOSED: You have @desc inside an unclosed block. You MUST close the previous block before starting a new section.
  WRONG:
    @desc "Step 1"
    do
      log "hello"
      @desc "Step 2"    ← ERROR: previous do block not closed!
      do
  RIGHT:
    @desc "Step 1"
    do
      log "hello"
    enddo                ← close first!
    @desc "Step 2"
    do`
		);
	}

	// Pattern 4b: def nested inside do
	if (/nest.*def.*inside.*do|def\/enddef.*outside/i.test(allErrors) || (/DECORATOR '@desc'/.test(allErrors) && /def/.test(allErrors))) {
		tips.push(
			`⚠️ DEF INSIDE DO: You nested a function definition inside a 'do' block. This is NOT allowed.
  WRONG:
    @desc "My function"
    do
      def myFunc $arg
        log $arg
      enddef
    enddo
  RIGHT:
    @desc "My function"
    def myFunc $arg
      log $arg
    enddef
  Functions (def/enddef) must be at the TOP LEVEL, not inside do/enddo blocks. Define them in their own @desc section.`
		);
	}

	// Pattern 5: Missing endif/endfor/enddo
	if (/missing end(if|for|do)/.test(allErrors)) {
		tips.push(
			`⚠️ UNCLOSED BLOCK: You opened a block but never closed it. Make sure every block has its closing keyword:
  if → endif, for → endfor, do → enddo, def → enddef
  Check nested blocks carefully — each one needs its own closing keyword.`
		);
	}

	// Pattern 6: Mismatched block pairs
	if (/[Mm]ismatched/.test(allErrors)) {
		tips.push(
			`⚠️ MISMATCHED BLOCKS: Your closing keywords don't match the opening keywords.
  WRONG: do ... endfor (should be enddo)
  WRONG: for ... enddo (should be endfor)
  Make sure each closing keyword matches its opening keyword exactly.`
		);
	}

	// Pattern 7: Variable assignment syntax
	if (/Expected '=' or 'as' after variable/.test(allErrors)) {
		tips.push(
			`⚠️ ASSIGNMENT SYNTAX: Variable assignment must use 'set $var as value' or '$var = value'.
  WRONG: $result http.get "url"
  RIGHT: http.get "url" into $result
  RIGHT: set $result as http.get "url"
  To capture function output, use 'into $var' at the end of the command.`
		);
	}

	// Pattern 8: Parenthesized expressions / ranges
	if (/parenthesized|in \(|range/.test(allErrors)) {
		tips.push(
			`⚠️ PARENTHESIZED EXPRESSIONS: Don't wrap expressions in parentheses.
  WRONG: for $i in (0..$n)
  WRONG: array.get $arr ($i+1)
  WRONG: for $i in (range 0 $n)
  RIGHT: for $i from 0 to $n
  RIGHT: math.add $i 1 into $next \\n array.get $arr $next
  Compute complex expressions into a variable first, then use that variable.`
		);
	}

	// Pattern 9: Comma issues in objects
	if (/expected comma|COMMA/.test(allErrors)) {
		tips.push(
			`⚠️ OBJECT SYNTAX: Object properties MUST be separated by commas.
  WRONG: { "name": "test" "age": 25 }
  RIGHT: { "name": "test", "age": 25 }`
		);
	}

	const tipsBlock = tips.length > 0 ? `\n\nSPECIFIC FIXES NEEDED:\n${tips.join("\n\n")}` : "";

	return `Your RobinPath code has ${errors.length} error${errors.length > 1 ? "s" : ""}. Fix ALL errors and regenerate the COMPLETE corrected response.

Errors found:
${errorDetails}${tipsBlock}

RobinPath syntax reminder:
- COMMAND-STYLE calls: module.fn arg1 arg2 — NEVER use parentheses like module.fn(arg1, arg2)
- Capture results: command arg1 arg2 into $result
- Blocks: for/endfor, if/elseif/else/endif, do/catch/enddo, on/endon, def/enddef
- Close EVERY block before starting a new @desc section
- Variables always start with $
- No semicolons, no curly braces for blocks, no pipe operator
- Output: use 'log' — not print, echo, or console.log`;
}
