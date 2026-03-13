/**
 * Function Registry
 *
 * Maintains a set of known module.function names so the validator
 * can flag calls to non-existent functions.
 *
 * The registry can be:
 * 1. Built at compile time from the monorepo (see build-registry.ts)
 * 2. Loaded from a generated JSON file
 * 3. Populated dynamically at runtime
 */

export interface FunctionEntry {
	module: string;
	name: string;
	/** Fully qualified: module.name */
	qualifiedName: string;
}

export class FunctionRegistry {
	private functions = new Map<string, FunctionEntry>();

	/** Register a single function */
	register(module: string, name: string): void {
		const qualifiedName = `${module}.${name}`.toLowerCase();
		this.functions.set(qualifiedName, {
			module,
			name,
			qualifiedName,
		});
	}

	/** Register all functions from a module */
	registerModule(module: string, functionNames: string[]): void {
		for (const name of functionNames) {
			this.register(module, name);
		}
	}

	/** Check if a qualified function name exists */
	has(qualifiedName: string): boolean {
		return this.functions.has(qualifiedName.toLowerCase());
	}

	/** Get all registered function names as a Set (for validator) */
	toSet(): Set<string> {
		return new Set(this.functions.keys());
	}

	/** Get all entries */
	entries(): FunctionEntry[] {
		return Array.from(this.functions.values());
	}

	/** Get all module names */
	modules(): string[] {
		const mods = new Set<string>();
		for (const entry of this.functions.values()) {
			mods.add(entry.module);
		}
		return Array.from(mods);
	}

	/** Total number of registered functions */
	get size(): number {
		return this.functions.size;
	}

	/** Load from a plain object { moduleName: ["func1", "func2"] } */
	static fromObject(data: Record<string, string[]>): FunctionRegistry {
		const registry = new FunctionRegistry();
		for (const [module, functions] of Object.entries(data)) {
			registry.registerModule(module, functions);
		}
		return registry;
	}

	/** Serialize to a plain object */
	toObject(): Record<string, string[]> {
		const result: Record<string, string[]> = {};
		for (const entry of this.functions.values()) {
			if (!result[entry.module]) result[entry.module] = [];
			result[entry.module].push(entry.name);
		}
		return result;
	}
}
