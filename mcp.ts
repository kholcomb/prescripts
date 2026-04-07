import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { runScan, runCheck, scanSinglePackage } from "./src/cli.js";
import { MCP_TOOL_DESCRIPTIONS, mcpReplacer } from "./src/report/mcp-tools.js";
import { compareReports } from "./src/analyzer/compare.js";
import type { ScanOptions } from "./src/types.js";

const DEFAULT_OPTS: ScanOptions = {
  severity: "medium",
  minRisk: "low",
  onlyFlagged: false,
  concurrency: 5,
  registry: "https://registry.npmjs.org",
  noCache: false,
  cacheDir: null,
  depth: 5,
  timeout: 30_000,
  verbose: false,
  json: true,
  sarif: false,
  outputDir: null,
  apiUrl: null,
  trust: { signed: true, attested: true, minVersions: 10 },
  pypiAttestations: true,
  strict: false,
};

const server = new Server(
  { name: "prescripts", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: [
    {
      name: "scan_package",
      description: MCP_TOOL_DESCRIPTIONS["scan_package"] ?? "",
      inputSchema: {
        type: "object" as const,
        properties: {
          name: {
            type: "string",
            description: "Package name (e.g. 'express', 'requests', 'serde')",
          },
          version: {
            type: "string",
            description: "Package version or range (default: latest)",
          },
          pm: {
            type: "string",
            enum: ["npm", "pip", "cargo", "gem"],
            description: "Package manager / ecosystem (default: npm)",
          },
          severity: {
            type: "string",
            enum: ["low", "medium", "high", "critical"],
            description: "Minimum severity to include in findings (default: medium)",
          },
          depth: {
            type: "number",
            description: "Max transitive dependency depth to scan (default: 5)",
          },
        },
        required: ["name"],
      },
    },
    {
      name: "compare_versions",
      description: MCP_TOOL_DESCRIPTIONS["compare_versions"] ?? "",
      inputSchema: {
        type: "object" as const,
        properties: {
          name: {
            type: "string",
            description: "Package name",
          },
          fromVersion: {
            type: "string",
            description: "Version to compare from (e.g. currently installed version)",
          },
          toVersion: {
            type: "string",
            description: "Version to compare to (e.g. the upgrade candidate)",
          },
          pm: {
            type: "string",
            enum: ["npm", "pip", "cargo", "gem"],
            description: "Package manager / ecosystem (default: npm)",
          },
          severity: {
            type: "string",
            enum: ["low", "medium", "high", "critical"],
            description: "Minimum severity for findings (default: medium)",
          },
        },
        required: ["name", "fromVersion", "toVersion"],
      },
    },
    {
      name: "scan_project",
      description: MCP_TOOL_DESCRIPTIONS["scan_project"] ?? "",
      inputSchema: {
        type: "object" as const,
        properties: {
          path: {
            type: "string",
            description: "Absolute path to project directory (auto-detects lockfile)",
          },
          pm: {
            type: "string",
            enum: ["npm", "pip", "cargo", "gem"],
            description: "Restrict scan to one ecosystem (default: auto-detect all)",
          },
          severity: {
            type: "string",
            enum: ["low", "medium", "high", "critical"],
            description: "Minimum severity to include in findings (default: medium)",
          },
          onlyFlagged: {
            type: "boolean",
            description: "Only return packages with findings (default: false)",
          },
        },
        required: ["path"],
      },
    },
  ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  const typedArgs = (args ?? {}) as Record<string, unknown>;

  if (name === "scan_package") {
    const pkgName = String(typedArgs["name"] ?? "");
    const version = typedArgs["version"] ? String(typedArgs["version"]) : "latest";
    const pm = typedArgs["pm"] ? String(typedArgs["pm"]) : undefined;
    const packageSpec = `${pkgName}@${version}`;

    const opts: ScanOptions = {
      ...DEFAULT_OPTS,
      severity: (typedArgs["severity"] as ScanOptions["severity"]) ?? "medium",
      depth: typeof typedArgs["depth"] === "number" ? typedArgs["depth"] : 5,
      onlyFlagged: false,
    };

    const chunks: string[] = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: string | Uint8Array): boolean => {
      chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf-8"));
      return true;
    };

    try {
      await runCheck(packageSpec, opts, pm);
    } finally {
      process.stdout.write = origWrite;
    }

    const raw = chunks.join("");
    let text: string;
    try {
      text = JSON.stringify(JSON.parse(raw), mcpReplacer, 2);
    } catch {
      text = raw;
    }
    return {
      content: [{ type: "text", text }],
    };
  }

  if (name === "compare_versions") {
    const pkgName = String(typedArgs["name"] ?? "");
    const fromVersion = String(typedArgs["fromVersion"] ?? "");
    const toVersion = String(typedArgs["toVersion"] ?? "");
    const pm = typedArgs["pm"] ? String(typedArgs["pm"]) : undefined;
    const opts: ScanOptions = {
      ...DEFAULT_OPTS,
      severity: (typedArgs["severity"] as ScanOptions["severity"]) ?? "medium",
    };

    const [fromReport, toReport] = await Promise.all([
      scanSinglePackage(pkgName, fromVersion, opts, pm),
      scanSinglePackage(pkgName, toVersion, opts, pm),
    ]);

    if (!fromReport || !toReport) {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            error: `Could not scan one or both versions of ${pkgName}`,
            fromVersion,
            toVersion,
            fromFound: fromReport !== null,
            toFound: toReport !== null,
          }, null, 2),
        }],
      };
    }

    const diff = compareReports(fromReport, toReport);
    return {
      content: [{ type: "text", text: JSON.stringify(diff, mcpReplacer, 2) }],
    };
  }

  if (name === "scan_project") {
    const path = String(typedArgs["path"] ?? ".");
    const pm = typedArgs["pm"] ? String(typedArgs["pm"]) : undefined;
    const opts: ScanOptions = {
      ...DEFAULT_OPTS,
      severity: (typedArgs["severity"] as ScanOptions["severity"]) ?? "medium",
      onlyFlagged: typeof typedArgs["onlyFlagged"] === "boolean"
        ? typedArgs["onlyFlagged"]
        : false,
    };

    const chunks: string[] = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: string | Uint8Array): boolean => {
      chunks.push(typeof chunk === "string" ? chunk : Buffer.from(chunk).toString("utf-8"));
      return true;
    };

    try {
      await runScan(path, opts, pm);
    } finally {
      process.stdout.write = origWrite;
    }

    const raw = chunks.join("");
    let text: string;
    try {
      text = JSON.stringify(JSON.parse(raw), mcpReplacer, 2);
    } catch {
      text = raw;
    }
    return {
      content: [{ type: "text", text }],
    };
  }

  return {
    content: [{ type: "text", text: `Unknown tool: ${name}` }],
    isError: true,
  };
});

async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("prescripts MCP server running\n");
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${String(err)}\n`);
  process.exit(1);
});
