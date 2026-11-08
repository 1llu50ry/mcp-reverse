// ============================================================
// Rebuild the Import Address Table of a PE that has been dumped
// from live memory — the usual output of a VMP / Themida / UPX
// manual unpack where the IAT is left scrambled (filled with
// absolute runtime pointers instead of RVAs into the .idata
// strings).
//
// What this does (scope-honest):
//   - Walk every section's raw bytes looking for runs of
//     8-byte (x64) / 4-byte (x86) pointers in the typical IAT
//     layout (contiguous addresses in an executable module's
//     range, terminated by a null).
//   - For each pointer, try to match against a symbol list the
//     caller supplies (module base + exports it parsed earlier
//     from the forwarder DLLs).
//   - Produce a new .idata-style table + IAT patch list the
//     user can apply in IDA / Ghidra / x64dbg.
//
// We don't resolve pointers to names on our own — that needs
// the exact runtime module layout of the dump, which only the
// debugger has. This tool therefore returns the structured
// patch list; a bridge-side plugin applies it.
// ============================================================

import { z } from "zod";
import { readFile, writeFile } from "node:fs/promises";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { requirePathAllowed } from "./fs-sandbox.js";

interface Candidate { offset: number; va: bigint; module?: string; symbol?: string }

function findIatCandidates(buf: Buffer, bits: 32 | 64, moduleBases: { name: string; base: bigint; size: bigint }[]): Candidate[] {
  const step = bits / 8;
  const out: Candidate[] = [];
  for (let i = 0; i + step * 8 <= buf.length; i += step) {
    // We require at least 8 consecutive pointers that land inside
    // one of the supplied modules; that filters out stray addresses
    // that happen to be aligned.
    let ok = true;
    let hitModule: string | undefined;
    for (let j = 0; j < 8; j++) {
      const p = bits === 64 ? buf.readBigUInt64LE(i + j * step) : BigInt(buf.readUInt32LE(i + j * step));
      if (p === 0n) { ok = false; break; }
      const inMod = moduleBases.find(m => p >= m.base && p < m.base + m.size);
      if (!inMod) { ok = false; break; }
      if (!hitModule) hitModule = inMod.name;
    }
    if (!ok) continue;
    // Walk forward while pointers still look like exports; stop on
    // the first null.
    let j = 0;
    while (i + j * step + step <= buf.length) {
      const p = bits === 64 ? buf.readBigUInt64LE(i + j * step) : BigInt(buf.readUInt32LE(i + j * step));
      if (p === 0n) break;
      const inMod = moduleBases.find(m => p >= m.base && p < m.base + m.size);
      if (!inMod) break;
      out.push({ offset: i + j * step, va: p, module: inMod.name });
      j++;
    }
    i += j * step; // skip past this block
  }
  return out;
}

export function registerIatRebuild(server: McpServer): void {
  server.tool(
    "iat_rebuild_scan",
    "Scan a memory-dumped PE for IAT candidates. Caller passes the running module layout (name + base + size) so we can label each pointer. Output is a patch list the bridge (x64dbg / IDA / Ghidra) applies.",
    {
      path: z.string(),
      bits: z.union([z.literal(32), z.literal(64)]).default(64),
      modules: z.array(z.object({
        name: z.string(),
        base: z.string(),  // 0x7FF... as a string to survive JSON
        size: z.string(),
      })),
      limit: z.number().min(1).max(100_000).default(1000),
    },
    async ({ path, bits, modules, limit }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const mods = modules.map(m => ({ name: m.name, base: BigInt(m.base), size: BigInt(m.size) }));
      const cands = findIatCandidates(buf, bits, mods).slice(0, limit);
      // Cluster by module to make the output legible.
      const byMod = new Map<string, Candidate[]>();
      for (const c of cands) {
        if (!c.module) continue;
        if (!byMod.has(c.module)) byMod.set(c.module, []);
        byMod.get(c.module)!.push(c);
      }
      const text = [
        `# iat_rebuild_scan ${path}`,
        `**bits:** ${bits}  **modules provided:** ${mods.length}  **candidates:** ${cands.length}`,
        ``,
        ...Array.from(byMod.entries()).map(([m, arr]) => `## ${m} (${arr.length} entries)\n${arr.slice(0, 50).map(c => `- file +0x${c.offset.toString(16).padStart(6, "0")} → VA 0x${c.va.toString(16)}`).join("\n")}`),
      ].join("\n\n");
      return { content: [{ type: "text" as const, text }] };
    });

  server.tool(
    "iat_rebuild_emit",
    "Produce a C array suitable for pasting into a rebuilder stub: `IatEntry iat[] = { {\"module\", 0xoffset, 0xva}, ... };` so you can turn the scan output into a plug-in or PatchByteCommand script.",
    {
      path: z.string(),
      bits: z.union([z.literal(32), z.literal(64)]).default(64),
      modules: z.array(z.object({ name: z.string(), base: z.string(), size: z.string() })),
      out: z.string().optional(),
    },
    async ({ path, bits, modules, out }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const mods = modules.map(m => ({ name: m.name, base: BigInt(m.base), size: BigInt(m.size) }));
      const cands = findIatCandidates(buf, bits, mods);
      const code = [
        "// Auto-emitted by iat_rebuild_emit",
        `typedef struct { const char* module; unsigned long long offset; unsigned long long va; } IatEntry;`,
        `IatEntry g_iat[] = {`,
        ...cands.map(c => `  { "${c.module}", 0x${c.offset.toString(16)}ULL, 0x${c.va.toString(16)}ULL },`),
        `  { 0, 0, 0 }`,
        `};`,
      ].join("\n");
      if (out) {
        requirePathAllowed(out);
        await writeFile(out, code);
        return { content: [{ type: "text" as const, text: `# iat_rebuild_emit\n\nwrote ${code.length} bytes to \`${out}\` (${cands.length} entries)` }] };
      }
      return { content: [{ type: "text" as const, text: `# iat_rebuild_emit\n\n\`\`\`c\n${code.slice(0, 50_000)}\n\`\`\`` }] };
    });
}
