import type { LifecycleScripts, BinaryField } from "../types.js";

const LIFECYCLE_HOOKS: ReadonlyArray<string> = [
  "preinstall",
  "install",
  "postinstall",
  "prepare",
  "prepublish",
  "prepublishOnly",
  "prepack",
  "postpack",
];

export function extractLifecycleScripts(
  packageJson: Record<string, unknown>
): LifecycleScripts {
  const scripts = packageJson["scripts"];
  if (!scripts || typeof scripts !== "object" || Array.isArray(scripts)) {
    return {};
  }
  const result: LifecycleScripts = {};
  for (const hook of LIFECYCLE_HOOKS) {
    const val = (scripts as Record<string, unknown>)[hook];
    if (typeof val === "string") {
      result[hook] = val;
    }
  }
  return result;
}

export function hasLifecycleScripts(scripts: LifecycleScripts): boolean {
  return Object.keys(scripts).length > 0;
}

export function extractBinaryField(
  packageJson: Record<string, unknown>
): BinaryField | null {
  const binary = packageJson["binary"];
  if (!binary || typeof binary !== "object" || Array.isArray(binary)) {
    return null;
  }
  const b = binary as Record<string, unknown>;
  return {
    host: typeof b["host"] === "string" ? b["host"] : null,
    remote_path: typeof b["remote_path"] === "string" ? b["remote_path"] : null,
    module_name: typeof b["module_name"] === "string" ? b["module_name"] : null,
  };
}
