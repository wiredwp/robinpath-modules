/**
 * @robinpath/parser
 *
 * RobinPath code parser, validator, and function registry.
 * Validates AI-generated RobinPath code without execution.
 *
 * Usage:
 *   import { validateCode, buildFixPrompt, FunctionRegistry } from "@robinpath/parser";
 *
 *   const result = await validateCode(llmResponse);
 *   if (!result.valid) {
 *     const fixPrompt = buildFixPrompt(result.errors);
 *     // send fixPrompt back to LLM for retry
 *   }
 */

// Re-export the Parser from @wiredwp/robinpath
export { Parser } from "@wiredwp/robinpath";

// Validator
export {
	validateCode,
	validateCodeDirect,
	buildFixPrompt,
	extractCodeBlocks,
	parserValidate,
	semanticValidate,
} from "./validator.js";

export type {
	ValidationError,
	ValidationResult,
	ValidatorOptions,
} from "./validator.js";

// Function registry
export { FunctionRegistry } from "./registry.js";
export type { FunctionEntry } from "./registry.js";
