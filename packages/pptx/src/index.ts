import type { ModuleAdapter } from "@wiredwp/robinpath";
import { PptxFunctions, PptxFunctionMetadata, PptxModuleMetadata } from "./pptx.js";

const PptxModule: ModuleAdapter = {
  name: "pptx",
  functions: PptxFunctions,
  functionMetadata: PptxFunctionMetadata as any,
  moduleMetadata: PptxModuleMetadata as any,
  global: false,
}; // as ModuleAdapter

export default PptxModule;
export { PptxModule };
export { PptxFunctions, PptxFunctionMetadata, PptxModuleMetadata } from "./pptx.js";
