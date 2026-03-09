import type { ModuleAdapter } from "@wiredwp/robinpath";
import { DocxFunctions, DocxFunctionMetadata, DocxModuleMetadata } from "./docx.js";

const DocxModule: ModuleAdapter = {
  name: "docx",
  functions: DocxFunctions,
  functionMetadata: DocxFunctionMetadata as any,
  moduleMetadata: DocxModuleMetadata as any,
  global: false,
};

export default DocxModule;
export { DocxModule };
export { DocxFunctions, DocxFunctionMetadata, DocxModuleMetadata } from "./docx.js";
