// ============================================================
// Native TS clients for the plugins under plugins-side/.
//
// Each client is a thin fetch() wrapper around the plugin's HTTP
// surface. Zero deps. If the plugin isn't running the client returns
// an actionable "backend unreachable" message that points at
// plugins-side/<tool>/README.md for install.
// ============================================================

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

interface Backend {
  name: string;
  port: number;
  hostEnv: string;
  portEnv: string;
  installHint: string;
}

const B = {
  ghidra: { name: "Ghidra bridge", port: 48760, hostEnv: "MCP_GHIDRA_HOST", portEnv: "MCP_GHIDRA_PORT", installHint: "plugins-side/ghidra/mcp_bridge.py" },
  ida:    { name: "IDA bridge",    port: 48761, hostEnv: "MCP_IDA_HOST",    portEnv: "MCP_IDA_PORT",    installHint: "plugins-side/ida-pro/mcp_bridge.py" },
  reclass:{ name: "ReClass bridge",port: 48762, hostEnv: "MCP_RECLASS_HOST",portEnv: "MCP_RECLASS_PORT",installHint: "plugins-side/reclass-net/" },
  dnspy:  { name: "dnSpy bridge",  port: 48763, hostEnv: "MCP_DNSPY_HOST",  portEnv: "MCP_DNSPY_PORT",  installHint: "plugins-side/dnspy/" },
  ilspy:  { name: "ILSpy bridge",  port: 48764, hostEnv: "MCP_ILSPY_HOST",  portEnv: "MCP_ILSPY_PORT",  installHint: "plugins-side/ilspy/" },
  x64dbg: { name: "x64dbg bridge", port: 48765, hostEnv: "MCP_X64DBG_HOST", portEnv: "MCP_X64DBG_PORT", installHint: "plugins-side/x64dbg/" },
  binja:  { name: "Binja bridge",  port: 48766, hostEnv: "MCP_BINJA_HOST",  portEnv: "MCP_BINJA_PORT",  installHint: "plugins-side/binaryninja/mcp_bridge.py" },
  frida:  { name: "Frida bridge",  port: 48767, hostEnv: "MCP_FRIDA_HOST",  portEnv: "MCP_FRIDA_PORT",  installHint: "plugins-side/frida/mcp_bridge.py (pip install frida)" },
} as const satisfies Record<string, Backend>;

type Bk = keyof typeof B;

function url(b: Backend, path: string): string {
  const host = process.env[b.hostEnv] ?? "127.0.0.1";
  const port = Number(process.env[b.portEnv] ?? b.port);
  return `http://${host}:${port}${path.startsWith("/") ? path : "/" + path}`;
}

async function call(b: Backend, path: string, body: unknown = {}, timeoutMs = 60_000): Promise<string> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    // /healthz is the GET-only liveness probe shared by every bridge;
    // everything else — including action RPCs — POSTs.
    const method = path === "/healthz" ? "GET" : "POST";
    const resp = await fetch(url(b, path), {
      method,
      headers: { "content-type": "application/json" },
      body: method === "POST" ? JSON.stringify(body) : undefined,
      signal: ctrl.signal,
    });
    const text = await resp.text();
    if (!resp.ok) throw new Error(`${b.name} HTTP ${resp.status}: ${text.slice(0, 300)}`);
    return text;
  } finally { clearTimeout(timer); }
}

function unreachable(b: Backend, e: unknown): string {
  const msg = e instanceof Error ? e.message : String(e);
  return [
    `${b.name} unreachable: ${msg}`,
    ``,
    `Install the plugin inside the host tool first:`,
    `  ${b.installHint}`,
    ``,
    `Env overrides: ${b.hostEnv} / ${b.portEnv} (defaults 127.0.0.1:${b.port})`,
  ].join("\n");
}

async function run(b: Backend, path: string, body: unknown, label: string): Promise<{ content: { type: "text"; text: string }[]; isError?: true }> {
  try {
    const text = await call(b, path, body);
    return { content: [{ type: "text" as const, text: `# ${label}\n\n${text}` }] };
  } catch (e) {
    return { content: [{ type: "text" as const, text: unreachable(b, e) }], isError: true as const };
  }
}

export function registerPluginClients(server: McpServer): void {
  // -------- Ghidra ---------
  server.tool("ghidra_health", "Probe the Ghidra bridge (plugins-side/ghidra/mcp_bridge.py).", {},
    async () => run(B.ghidra, "/healthz", {}, "ghidra_health"));
  server.tool("ghidra_functions", "List functions from the open Ghidra program.", { limit: z.number().min(1).max(50000).default(1000) },
    async ({ limit }: { limit: number }) => run(B.ghidra, "/tool/functions", { limit }, "ghidra_functions"));
  server.tool("ghidra_decomp", "Decompile a function by name or address via the Ghidra bridge (uses the in-Ghidra DecompInterface; `ghidra_decompile` is the retools variant that routes through superghidra-mcp HTTP instead).", { function: z.string() },
    async ({ function: fn }: { function: string }) => run(B.ghidra, "/tool/decompile", { function: fn }, `ghidra_decomp ${fn}`));
  server.tool("ghidra_xrefs", "List xrefs to a symbol / address via the Ghidra bridge.", { to: z.string() },
    async ({ to }: { to: string }) => run(B.ghidra, "/tool/xrefs", { to }, `ghidra_xrefs ${to}`));
  server.tool("ghidra_strings", "List defined strings via the Ghidra bridge.", { min: z.number().min(2).max(1024).default(6) },
    async ({ min }: { min: number }) => run(B.ghidra, "/tool/strings", { min }, "ghidra_strings"));

  // -------- IDA Pro ---------
  server.tool("ida_health", "Probe the IDA Pro bridge (plugins-side/ida-pro/mcp_bridge.py).", {},
    async () => run(B.ida, "/healthz", {}, "ida_health"));
  server.tool("ida_functions", "List functions from the open IDB.", { limit: z.number().min(1).max(50000).default(5000) },
    async ({ limit }: { limit: number }) => run(B.ida, "/tool/functions", { limit }, "ida_functions"));
  server.tool("ida_decompile", "Hex-Rays decompile by name or address via the IDA bridge.", { function: z.string() },
    async ({ function: fn }: { function: string }) => run(B.ida, "/tool/decompile", { function: fn }, `ida_decompile ${fn}`));
  server.tool("ida_disasm", "Linear disassembly starting at an EA.", { ea: z.string(), size: z.number().min(1).max(1 << 20).default(256) },
    async ({ ea, size }: { ea: string; size: number }) => run(B.ida, "/tool/disasm", { ea, size }, `ida_disasm ${ea}`));
  server.tool("ida_xrefs", "List xrefs to a symbol / address via the IDA bridge.", { to: z.string() },
    async ({ to }: { to: string }) => run(B.ida, "/tool/xrefs", { to }, `ida_xrefs ${to}`));
  server.tool("ida_strings", "List strings via the IDA bridge.", { min: z.number().min(2).max(1024).default(6) },
    async ({ min }: { min: number }) => run(B.ida, "/tool/strings", { min }, "ida_strings"));
  server.tool("ida_rename", "Rename a symbol at EA via the IDA bridge.", { ea: z.string(), name: z.string() },
    async ({ ea, name }: { ea: string; name: string }) => run(B.ida, "/tool/rename", { ea, name }, `ida_rename ${ea} → ${name}`));

  // -------- ReClass.NET ---------
  server.tool("reclass_health", "Probe the ReClass.NET bridge.", {},
    async () => run(B.reclass, "/healthz", {}, "reclass_health"));
  server.tool("reclass_classes_live", "List classes from a running ReClass.NET project.", {},
    async () => run(B.reclass, "/tool/classes", {}, "reclass_classes_live"));
  server.tool("reclass_nodes_live", "List nodes of a class in a running ReClass.NET project.", { class: z.string() },
    async ({ class: cn }: { class: string }) => run(B.reclass, "/tool/nodes", { class: cn }, `reclass_nodes_live ${cn}`));
  server.tool("reclass_cpp_live", "Export the current ReClass.NET project as XML and let the native reclass_to_cpp tool render it.", {},
    async () => run(B.reclass, "/tool/cpp", {}, "reclass_cpp_live"));

  // -------- dnSpy ---------
  server.tool("dnspy_health", "Probe the dnSpy bridge.", {},
    async () => run(B.dnspy, "/healthz", {}, "dnspy_health"));
  server.tool("dnspy_modules", "List loaded .NET modules in dnSpy.", {},
    async () => run(B.dnspy, "/tool/modules", {}, "dnspy_modules"));
  server.tool("dnspy_types", "List types in a loaded dnSpy module.", { module: z.string() },
    async ({ module: m }: { module: string }) => run(B.dnspy, "/tool/types", { module: m }, `dnspy_types ${m}`));
  server.tool("dnspy_decompile", "Decompile a method via dnSpy (returns IL body).", { type: z.string(), method: z.string() },
    async ({ type, method }: { type: string; method: string }) => run(B.dnspy, "/tool/decompile", { type, method }, `dnspy_decompile ${type}.${method}`));
  server.tool("dnspy_strings", "List Ldstr strings from a loaded dnSpy module.", { module: z.string() },
    async ({ module: m }: { module: string }) => run(B.dnspy, "/tool/strings", { module: m }, `dnspy_strings ${m}`));

  // -------- ILSpy ---------
  server.tool("ilspy_health", "Probe the ILSpy bridge.", {},
    async () => run(B.ilspy, "/healthz", {}, "ilspy_health"));
  server.tool("ilspy_assemblies", "List loaded assemblies in ILSpy.", {},
    async () => run(B.ilspy, "/tool/assemblies", {}, "ilspy_assemblies"));
  server.tool("ilspy_types", "List types in a loaded ILSpy assembly.", { assembly: z.string() },
    async ({ assembly }: { assembly: string }) => run(B.ilspy, "/tool/types", { assembly }, `ilspy_types ${assembly}`));
  server.tool("ilspy_decompile", "C# decompile a type via ILSpy.", { type: z.string() },
    async ({ type }: { type: string }) => run(B.ilspy, "/tool/decompile", { type }, `ilspy_decompile ${type}`));

  // -------- x64dbg ---------
  server.tool("x64dbg_health", "Probe the x64dbg bridge.", {},
    async () => run(B.x64dbg, "/healthz", {}, "x64dbg_health"));
  server.tool("x64dbg_state", "Debug state (paused / running / notarget).", {},
    async () => run(B.x64dbg, "/tool/state", {}, "x64dbg_state"));
  server.tool("x64dbg_registers", "Register snapshot.", {},
    async () => run(B.x64dbg, "/tool/registers", {}, "x64dbg_registers"));
  server.tool("x64dbg_bp", "Set / clear a breakpoint.", { ea: z.string(), op: z.enum(["set", "clear"]).default("set") },
    async ({ ea, op }: { ea: string; op: "set" | "clear" }) => run(B.x64dbg, "/tool/bp", { ea, op }, `x64dbg_bp ${op} ${ea}`));
  server.tool("x64dbg_readmem", "Read process memory via x64dbg.", { ea: z.string(), size: z.number().min(1).max(1 << 20).default(256) },
    async ({ ea, size }: { ea: string; size: number }) => run(B.x64dbg, "/tool/readmem", { ea, size }, `x64dbg_readmem ${ea}`));
  server.tool("x64dbg_writemem", "Write process memory via x64dbg (space-separated hex bytes).", { ea: z.string(), bytes: z.string() },
    async ({ ea, bytes }: { ea: string; bytes: string }) => run(B.x64dbg, "/tool/writemem", { ea, bytes }, `x64dbg_writemem ${ea}`));
  server.tool("x64dbg_step", "Step into / over / out.", { mode: z.enum(["into", "over", "out"]).default("into") },
    async ({ mode }: { mode: "into" | "over" | "out" }) => run(B.x64dbg, "/tool/step", { mode }, `x64dbg_step ${mode}`));
  server.tool("x64dbg_run", "Run a raw x64dbg script line (direct bridge). `x64dbg_cmd` from retools routes through the x64dbg-mcp backend process instead.", { line: z.string() },
    async ({ line }: { line: string }) => run(B.x64dbg, "/tool/cmd", { line }, `x64dbg_run ${line}`));

  // -------- Binary Ninja ---------
  server.tool("binja_health", "Probe the Binary Ninja bridge.", {},
    async () => run(B.binja, "/healthz", {}, "binja_health"));
  server.tool("binja_functions", "List functions from the open BNDB.", { limit: z.number().min(1).max(50000).default(5000) },
    async ({ limit }: { limit: number }) => run(B.binja, "/tool/functions", { limit }, "binja_functions"));
  server.tool("binja_decompile", "Binja HLIL decompile by name or address.", { function: z.string() },
    async ({ function: fn }: { function: string }) => run(B.binja, "/tool/decompile", { function: fn }, `binja_decompile ${fn}`));
  server.tool("binja_xrefs", "List xrefs to a symbol / address.", { to: z.string() },
    async ({ to }: { to: string }) => run(B.binja, "/tool/xrefs", { to }, `binja_xrefs ${to}`));
  server.tool("binja_strings", "List strings via the Binja bridge.", { min: z.number().min(2).max(1024).default(6) },
    async ({ min }: { min: number }) => run(B.binja, "/tool/strings", { min }, "binja_strings"));
  server.tool("binja_rename", "Rename a function at EA via Binja.", { ea: z.string(), name: z.string() },
    async ({ ea, name }: { ea: string; name: string }) => run(B.binja, "/tool/rename", { ea, name }, `binja_rename ${ea} → ${name}`));

  // -------- Frida (dynamic instrumentation) ---------
  server.tool("frida_health", "Probe the Frida bridge (plugins-side/frida/mcp_bridge.py).", {},
    async () => run(B.frida, "/healthz", {}, "frida_health"));
  server.tool("frida_devices", "List Frida devices (local, usb, remote).", {},
    async () => run(B.frida, "/tool/devices", {}, "frida_devices"));
  server.tool("frida_ps", "List processes on a Frida device.", { device: z.string().default("local") },
    async ({ device }: { device: string }) => run(B.frida, "/tool/ps", { device }, `frida_ps ${device}`));
  server.tool("frida_spawn", "Spawn a program under Frida.", { program: z.string(), device: z.string().default("local"), args: z.array(z.string()).default([]) },
    async ({ program, device, args }: { program: string; device: string; args: string[] }) => run(B.frida, "/tool/spawn", { program, device, args }, `frida_spawn ${program}`));
  server.tool("frida_attach", "Attach to a process by pid or name; returns a session id.", { target: z.string(), device: z.string().default("local") },
    async ({ target, device }: { target: string; device: string }) => run(B.frida, "/tool/attach", { target: isNaN(Number(target)) ? target : Number(target), device }, `frida_attach ${target}`));
  server.tool("frida_detach", "Detach a Frida session.", { session: z.string() },
    async ({ session }: { session: string }) => run(B.frida, "/tool/detach", { session }, `frida_detach ${session}`));
  server.tool("frida_inject", "Inject a raw Frida JS script into a session.", { session: z.string(), script: z.string() },
    async ({ session, script }: { session: string; script: string }) => run(B.frida, "/tool/inject", { session, script }, `frida_inject ${session}`));
  server.tool("frida_trace", "Attach an Interceptor to a target like `exports:kernel32!CreateFileW`.", { session: z.string(), pattern: z.string() },
    async ({ session, pattern }: { session: string; pattern: string }) => run(B.frida, "/tool/trace", { session, pattern }, `frida_trace ${pattern}`));
  server.tool("frida_dump", "Read raw memory from a Frida session as hex.", { session: z.string(), addr: z.string(), size: z.number().min(1).max(1 << 24).default(256) },
    async ({ session, addr, size }: { session: string; addr: string; size: number }) => run(B.frida, "/tool/dump", { session, addr, size }, `frida_dump ${addr}`));
  server.tool("frida_replace", "Overwrite memory at an address with space-separated hex bytes.", { session: z.string(), addr: z.string(), bytes: z.string() },
    async ({ session, addr, bytes }: { session: string; addr: string; bytes: string }) => run(B.frida, "/tool/replace", { session, addr, bytes }, `frida_replace ${addr}`));
  server.tool("frida_exports", "Enumerate exports from a module in a Frida session.", { session: z.string(), module: z.string().optional() },
    async ({ session, module }: { session: string; module?: string }) => run(B.frida, "/tool/exports", { session, module }, `frida_exports ${module ?? "(main)"}`));
  server.tool("frida_modules", "Enumerate loaded modules in a Frida session.", { session: z.string() },
    async ({ session }: { session: string }) => run(B.frida, "/tool/modules", { session }, `frida_modules ${session}`));

  // -------- bridge_health_all: one-shot probe of every bridge ---------
  server.tool("bridge_health_all", "Probe every plugins-side bridge in parallel and report which are up.", {},
    async () => {
      const results = await Promise.all((Object.entries(B) as [Bk, Backend][]).map(async ([k, b]) => {
        try {
          const t = await call(b, "/healthz", {}, 1500);
          return `- **${k}** (${b.name}, :${b.port})  UP  — ${t.slice(0, 160)}`;
        } catch (e) {
          return `- **${k}** (${b.name}, :${b.port})  DOWN  — ${(e as Error).message.slice(0, 160)}`;
        }
      }));
      return { content: [{ type: "text" as const, text: `# bridge_health_all\n\n${results.join("\n")}` }] };
    });
}
