// ============================================================
// Erlang BEAM file parser. BEAM uses the IFF container: FOR1
// magic, 4-byte big-endian size, 'BEAM' tag, then 4-byte-aligned
// chunks each with a 4-char tag + size + payload.
//
// We decode the chunks REA-style: Atom / AtU8 / ExpT (exports) /
// ImpT (imports) / FunT (lambdas) / Code header. The remaining
// chunks are surfaced as (tag, size).
// ============================================================

import { z } from "zod";
import { readFile } from "node:fs/promises";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { requirePathAllowed } from "./fs-sandbox.js";

interface BeamSummary {
  chunks: { tag: string; size: number; off: number }[];
  atoms: string[];
  exports: { name: string; arity: number; label: number }[];
  imports: { module: string; function: string; arity: number }[];
  code_header?: { sub_size: number; instr_set: number; opcode_max: number; n_labels: number; n_functions: number };
}

export function parseBeam(buf: Buffer): BeamSummary {
  if (buf.slice(0, 4).toString("ascii") !== "FOR1") throw new Error("not a BEAM file (missing FOR1)");
  if (buf.slice(8, 12).toString("ascii") !== "BEAM") throw new Error("not a BEAM file (missing BEAM tag)");
  const chunks: BeamSummary["chunks"] = [];
  let off = 12;
  while (off + 8 <= buf.length) {
    const tag = buf.slice(off, off + 4).toString("ascii");
    const size = buf.readUInt32BE(off + 4);
    chunks.push({ tag, size, off });
    off += 8 + size;
    if (off % 4) off += 4 - (off % 4);
  }

  const find = (t: string) => chunks.find(c => c.tag === t);
  const summary: BeamSummary = { chunks, atoms: [], exports: [], imports: [] };

  // Atoms (latin-1) or AtU8 (utf-8).
  const atC = find("AtU8") ?? find("Atom");
  if (atC) {
    const p = atC.off + 8;
    const n = buf.readUInt32BE(p);
    let i = p + 4;
    for (let k = 0; k < n && i < buf.length; k++) {
      const alen = buf.readUInt8(i); i += 1;
      summary.atoms.push(buf.slice(i, i + alen).toString(atC.tag === "AtU8" ? "utf-8" : "latin1"));
      i += alen;
    }
  }

  const expC = find("ExpT");
  if (expC) {
    const p = expC.off + 8;
    const n = buf.readUInt32BE(p);
    for (let k = 0; k < n; k++) {
      const atom  = buf.readUInt32BE(p + 4 + k * 12);
      const arity = buf.readUInt32BE(p + 8 + k * 12);
      const label = buf.readUInt32BE(p + 12 + k * 12);
      summary.exports.push({ name: summary.atoms[atom - 1] ?? `atom#${atom}`, arity, label });
    }
  }

  const impC = find("ImpT");
  if (impC) {
    const p = impC.off + 8;
    const n = buf.readUInt32BE(p);
    for (let k = 0; k < n; k++) {
      const mod  = buf.readUInt32BE(p + 4 + k * 12);
      const fn   = buf.readUInt32BE(p + 8 + k * 12);
      const ar   = buf.readUInt32BE(p + 12 + k * 12);
      summary.imports.push({ module: summary.atoms[mod - 1] ?? `atom#${mod}`, function: summary.atoms[fn - 1] ?? `atom#${fn}`, arity: ar });
    }
  }

  const codeC = find("Code");
  if (codeC) {
    const p = codeC.off + 8;
    summary.code_header = {
      sub_size: buf.readUInt32BE(p),
      instr_set: buf.readUInt32BE(p + 4),
      opcode_max: buf.readUInt32BE(p + 8),
      n_labels: buf.readUInt32BE(p + 12),
      n_functions: buf.readUInt32BE(p + 16),
    };
  }

  return summary;
}

export function registerBeam(server: McpServer): void {
  server.tool(
    "beam_parse",
    "Parse an Erlang BEAM module: chunk inventory + atom table + exports + imports + code-header stats.",
    { path: z.string(), limit: z.number().min(1).max(5000).default(200) },
    async ({ path, limit }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const s = parseBeam(buf);
      const text = [
        `# beam_parse ${path}`,
        `**chunks:** ${s.chunks.length}  **atoms:** ${s.atoms.length}  **exports:** ${s.exports.length}  **imports:** ${s.imports.length}`,
        s.code_header ? `**code:** subsize=${s.code_header.sub_size} iset=${s.code_header.instr_set} opcmax=${s.code_header.opcode_max} labels=${s.code_header.n_labels} funcs=${s.code_header.n_functions}` : "",
        ``,
        `## chunks`,
        ...s.chunks.map(c => `- \`${c.tag}\` ${c.size} B @ 0x${c.off.toString(16)}`),
        ``,
        `## exports (first ${Math.min(limit, s.exports.length)})`,
        ...s.exports.slice(0, limit).map(e => `- \`${e.name}/${e.arity}\` -> label ${e.label}`),
        ``,
        `## imports (first ${Math.min(limit, s.imports.length)})`,
        ...s.imports.slice(0, limit).map(i => `- \`${i.module}:${i.function}/${i.arity}\``),
      ].filter(Boolean).join("\n");
      return { content: [{ type: "text" as const, text }] };
    });
}
