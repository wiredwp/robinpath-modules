/**
 * Build-time script: scans all sibling packages in the monorepo and extracts
 * function names from their package.json metadata and source exports.
 *
 * Outputs: src/generated-registry.json
 *
 * Usage: npm run build:registry
 */

import { readFileSync, readdirSync, writeFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";

interface PackageJson {
	name?: string;
	robinpath?: {
		category?: string;
		type?: string;
		auth?: string;
		functionCount?: number;
	};
}

interface ModuleMetadata {
	methods?: string[];
}

const packagesDir = resolve(import.meta.dirname, "../../");
const outputPath = resolve(import.meta.dirname, "generated-registry.json");

function scanPackages(): Record<string, string[]> {
	const registry: Record<string, string[]> = {};
	const entries = readdirSync(packagesDir, { withFileTypes: true });

	for (const entry of entries) {
		if (!entry.isDirectory()) continue;
		if (entry.name === "parser") continue; // skip ourselves

		const pkgJsonPath = join(packagesDir, entry.name, "package.json");
		if (!existsSync(pkgJsonPath)) continue;

		const pkgJson: PackageJson = JSON.parse(
			readFileSync(pkgJsonPath, "utf-8"),
		);

		// Skip packages with no functions
		if (
			!pkgJson.robinpath ||
			pkgJson.robinpath.functionCount === 0 ||
			pkgJson.robinpath.type === "tooling"
		)
			continue;

		const moduleName = entry.name;

		// Try to find function names from the dist metadata or source
		const methods = extractMethods(packagesDir, entry.name);
		if (methods.length > 0) {
			registry[moduleName] = methods;
		}
	}

	return registry;
}

function extractMethods(
	packagesRoot: string,
	packageName: string,
): string[] {
	const methods: string[] = [];

	// Strategy 1: Check dist/index.js for exported metadata with methods array
	const distIndex = join(packagesRoot, packageName, "dist", "index.js");
	if (existsSync(distIndex)) {
		const content = readFileSync(distIndex, "utf-8");
		// Look for ModuleMetadata export with methods array
		const methodsMatch = content.match(
			/methods:\s*\[([^\]]+)\]/,
		);
		if (methodsMatch) {
			const names = methodsMatch[1]
				.split(",")
				.map((s) => s.trim().replace(/['"]/g, ""))
				.filter(Boolean);
			methods.push(...names);
		}
	}

	// Strategy 2: Check source files for exported Functions record
	const srcDir = join(packagesRoot, packageName, "src");
	if (existsSync(srcDir) && methods.length === 0) {
		const srcFiles = readdirSync(srcDir).filter(
			(f) => f.endsWith(".ts") && !f.endsWith(".test.ts"),
		);
		for (const file of srcFiles) {
			const content = readFileSync(join(srcDir, file), "utf-8");
			// Match: export const XxxFunctions: Record<string, BuiltinHandler> = { func1, func2, ... }
			const funcRecordMatch = content.match(
				/export\s+const\s+\w+Functions[^=]*=\s*\{([^}]+)\}/s,
			);
			if (funcRecordMatch) {
				const names = funcRecordMatch[1]
					.split(",")
					.map((s) => s.trim().split(":")[0].split("//")[0].trim())
					.filter((s) => s && !s.startsWith("//") && !s.startsWith("*"));
				methods.push(...names);
			}
			// Match: methods: ["func1", "func2", ...]
			const methodsMatch = content.match(
				/methods:\s*\[([^\]]+)\]/,
			);
			if (methodsMatch && methods.length === 0) {
				const names = methodsMatch[1]
					.split(",")
					.map((s) => s.trim().replace(/['"]/g, ""))
					.filter(Boolean);
				methods.push(...names);
			}
		}
	}

	return [...new Set(methods)];
}

// ─── Main ────────────────────────────────────────────────────────────────────

const registry = scanPackages();
const moduleCount = Object.keys(registry).length;
const funcCount = Object.values(registry).reduce(
	(sum, fns) => sum + fns.length,
	0,
);

writeFileSync(outputPath, JSON.stringify(registry, null, 2) + "\n");

console.log(
	`Registry built: ${moduleCount} modules, ${funcCount} functions → ${outputPath}`,
);
