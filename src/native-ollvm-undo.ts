// ============================================================
// OLLVM detection — the three classic passes (sub, bcf, fla)
// leave tell-tale markers in the compiled code. We spot them by
// disassembly-pattern alone; the actual CFG un-flattening still
// needs a real decompiler (Hex-Rays, Ghidra, Hyperion), but the
// detector points you at the functions worth attacking.
//
//   Instruction Substitution (sub):
//     A + B is rewritten as A - (-B), A ^ B as (A & ~B) | (~A & B),
//     etc. Marker: suspiciously-dense `and` / `or` / `not` runs
//     with constant operands, no obvious data flow.
//
//   Bogus Control Flow (bcf):
//     Every basic block gets a `if (opaque_predicate)` prefix
//     that always runs the real branch. Marker: a cmp against
//     the result of a two-step `(x * x - k)` style predicate
//     and a conditional jump whose target is... the next block.
//
//   Control-Flow Flattening (fla):
//     The function becomes one big switch(state) with each
//     original BB a case + an update-state tail. Marker: a
//     single dominating `cmp state, imm; je/jmp table`
//     dispatcher, >= 6 state values, each handler short.
//
// Tools:
//   ollvm_scan     — classify functions in an r2 / Ghidra JSON
//                    function list; agents feed us the output of
//                    r2_functions / ghidra_functions.
//   ollvm_patterns — list every signature this scanner understands.
// ============================================================

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

interface FuncInfo {
  name: string;
  size: number;
  bb_count?: number;
  edges?: number;
  disasm?: string;   // optional raw disasm; makes detection much better
}

interface OllvmFinding {
  function: string;
  pass: "sub" | "bcf" | "fla" | "mixed";
  confidence: "low" | "medium" | "high";
  evidence: string[];
}

export function classifyOllvm(f: FuncInfo): OllvmFinding | null {
  const evidence: string[] = [];
  let pass: OllvmFinding["pass"] | null = null;
  let confidence: OllvmFinding["confidence"] = "low";

  // FLA: many BBs but small cyclomatic complexity → textbook
  // dispatcher pattern.
  if (f.bb_count && f.bb_count >= 20 && f.size / f.bb_count < 40) {
    evidence.push(`bb_count=${f.bb_count} with avg bb size ${(f.size / f.bb_count).toFixed(1)} B — flattened`);
    pass = "fla";
    confidence = "medium";
  }

  // Look at disasm if provided
  if (f.disasm) {
    const d = f.disasm.toLowerCase();

    // Count AND/OR/NOT density
    const ands = (d.match(/\band\b/g) ?? []).length;
    const ors  = (d.match(/\bor\b/g) ?? []).length;
    const nots = (d.match(/\bnot\b/g) ?? []).length;
    const total = (d.match(/\n/g) ?? []).length + 1;
    if (total > 20 && (ands + ors + nots) / total > 0.25) {
      evidence.push(`AND/OR/NOT density ${((ands + ors + nots) / total * 100).toFixed(1)}% over ${total} lines — substitution`);
      pass = pass === null ? "sub" : "mixed";
      confidence = "medium";
    }

    // Dispatcher pattern: `cmp [state], imm` followed by `jmp table[...]`
    if (/cmp\s+\[[^\]]+\],\s*0x[0-9a-f]+[\s\S]{0,64}(?:jmp|je|jne)/.test(d)) {
      evidence.push("dispatcher `cmp state, imm; j*` pattern — flattened");
      pass = pass === null ? "fla" : "mixed";
      confidence = "high";
    }

    // Opaque predicate: multiplication followed by compare against a prime.
    if (/imul[\s\S]{0,32}sub[\s\S]{0,32}test/.test(d)) {
      evidence.push("imul; sub; test — opaque predicate (bcf)");
      pass = pass === null ? "bcf" : "mixed";
      confidence = confidence === "low" ? "medium" : confidence;
    }
  }

  // If no evidence at all and no disasm, return null.
  if (!pass) return null;
  return { function: f.name, pass, confidence, evidence };
}

export function registerOllvmUndo(server: McpServer): void {
  server.tool(
    "ollvm_scan",
    "Classify functions as OLLVM-obfuscated (sub / bcf / fla / mixed). Feed the list from r2_functions or ghidra_functions, with optional per-function disasm.",
    {
      functions: z.array(z.object({
        name: z.string(),
        size: z.number(),
        bb_count: z.number().optional(),
        edges: z.number().optional(),
        disasm: z.string().optional(),
      })),
      limit: z.number().min(1).max(10_000).default(200),
    },
    async ({ functions, limit }) => {
      const findings = functions.map(classifyOllvm).filter((x): x is OllvmFinding => !!x).slice(0, limit);
      const byPass = findings.reduce((acc, f) => { acc[f.pass] = (acc[f.pass] ?? 0) + 1; return acc; }, {} as Record<string, number>);
      const text = [
        `# ollvm_scan`,
        `**scanned:** ${functions.length}  **flagged:** ${findings.length}  (${Object.entries(byPass).map(([k, v]) => `${k}=${v}`).join(", ")})`,
        ``,
        ...findings.map(f => `- \`${f.function}\` — **${f.pass}** (${f.confidence})\n${f.evidence.map(e => "  - " + e).join("\n")}`),
      ].join("\n");
      return { content: [{ type: "text" as const, text }] };
    });

  server.tool(
    "ollvm_patterns",
    "List every OLLVM pattern this scanner understands and the signal it looks for.",
    {},
    async () => {
      const text = [
        "# ollvm_patterns",
        "",
        "## Instruction Substitution (sub)",
        "- AND/OR/NOT density in disasm > 25% over 20+ lines",
        "",
        "## Bogus Control Flow (bcf)",
        "- `imul; sub; test` sequence — opaque predicate on a squared value",
        "",
        "## Control-Flow Flattening (fla)",
        "- bb_count ≥ 20 AND avg basic-block size < 40 B",
        "- `cmp [state], imm; j*` dispatcher pattern in disasm",
        "",
        "## Mixed",
        "- any function tripping two or more of the above signals",
      ].join("\n");
      return { content: [{ type: "text" as const, text }] };
    });
}
