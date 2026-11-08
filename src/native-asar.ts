// ============================================================
// Electron ASAR archive parser + extractor. ASAR is the format
// Electron apps use to bundle their JS/HTML/CSS/assets into a
// single blob; the format is public and simple:
//
//   [4-byte LE pickleHeaderSize]
//   [pickleHeaderSize bytes: 4-byte LE jsonHeaderSize + JSON tree]
//   [content blob — files concatenated]
//
// JSON tree is `{"files": {name: {size, offset} | {files: {...}}}}`
// with offsets being decimal strings into the content blob.
//
// Tools:
//   asar_list   — tree walk, print path + size for every file
//   asar_cat    — pull a single file by path, return as text or hex
//   asar_extract — write every file into a target directory
// ============================================================

import { z } from "zod";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { requirePathAllowed } from "./fs-sandbox.js";

interface AsarNode {
  files?: Record<string, AsarNode>;
  size?: number;
  offset?: string;
  unpacked?: boolean;
}

function parseHeader(buf: Buffer): { tree: AsarNode; contentStart: number } {
  // pickle layout: uint32 payloadSize; then payloadSize bytes of pickle.
  // Inside: uint32 jsonSize; then jsonSize bytes of JSON; then padding.
  if (buf.length < 16) throw new Error("asar too small");
  const pickleSize = buf.readUInt32LE(0);
  const _pickleTotal = buf.readUInt32LE(4);
  void _pickleTotal;
  const jsonSize = buf.readUInt32LE(8);
  const _jsonTotal = buf.readUInt32LE(12);
  void _jsonTotal;
  const jsonStart = 16;
  const jsonEnd = jsonStart + jsonSize;
  const contentStart = 8 + pickleSize;   // align boundary
  const tree = JSON.parse(buf.slice(jsonStart, jsonEnd).toString("utf-8")) as AsarNode;
  return { tree, contentStart };
}

function walk(node: AsarNode, prefix: string, out: { path: string; size: number; offset: number; unpacked: boolean }[]) {
  if (node.files) {
    for (const [name, child] of Object.entries(node.files)) {
      walk(child, prefix ? `${prefix}/${name}` : name, out);
    }
    return;
  }
  out.push({
    path: prefix,
    size: node.size ?? 0,
    offset: Number(node.offset ?? "0"),
    unpacked: !!node.unpacked,
  });
}

export function registerAsar(server: McpServer): void {
  server.tool(
    "asar_list",
    "List every file in an Electron ASAR archive (path + size + offset). Pure-TS parser; no external asar CLI needed.",
    { path: z.string(), limit: z.number().min(1).max(100_000).default(2000) },
    async ({ path, limit }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const { tree } = parseHeader(buf);
      const files: { path: string; size: number; offset: number; unpacked: boolean }[] = [];
      walk(tree, "", files);
      const shown = files.slice(0, limit);
      return { content: [{ type: "text" as const, text:
        `# asar_list ${path}\n\n**files:** ${files.length}\n\n` +
        shown.map(f => `- \`${f.path}\` — ${f.size} B${f.unpacked ? " (unpacked)" : ""}`).join("\n")
      }] };
    });

  server.tool(
    "asar_cat",
    "Read one file out of an ASAR archive by its internal path. Set `kind=hex` for binary blobs.",
    { path: z.string(), inner: z.string(), kind: z.enum(["utf8", "hex"]).default("utf8"), maxBytes: z.number().min(16).max(2_000_000).default(100_000) },
    async ({ path, inner, kind, maxBytes }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const { tree, contentStart } = parseHeader(buf);
      // Walk the tree by name to find the inner entry.
      const parts = inner.replace(/^\/+/, "").split(/[\\/]/);
      let cur: AsarNode | undefined = tree;
      for (const p of parts) {
        cur = cur?.files?.[p];
        if (!cur) throw new Error(`not found inside archive: ${inner}`);
      }
      if (cur.files) throw new Error(`${inner} is a directory, not a file`);
      const off = contentStart + Number(cur.offset ?? "0");
      const slice = buf.subarray(off, off + Math.min(maxBytes, cur.size ?? 0));
      const payload = kind === "utf8" ? slice.toString("utf-8") : slice.toString("hex");
      return { content: [{ type: "text" as const, text: `# asar_cat ${inner} (${slice.length} B)\n\n\`\`\`${kind === "utf8" ? "" : "hex"}\n${payload}\n\`\`\`` }] };
    });

  server.tool(
    "asar_extract",
    "Extract every file from an ASAR archive into a target directory (writes + mkdirs).",
    { path: z.string(), out: z.string(), limit: z.number().min(1).max(10_000).default(2000) },
    async ({ path, out, limit }) => {
      requirePathAllowed(path);
      requirePathAllowed(out);
      const buf = await readFile(path);
      const { tree, contentStart } = parseHeader(buf);
      const files: { path: string; size: number; offset: number; unpacked: boolean }[] = [];
      walk(tree, "", files);
      let written = 0;
      for (const f of files.slice(0, limit)) {
        const dest = join(out, f.path);
        await mkdir(dirname(dest), { recursive: true });
        const off = contentStart + f.offset;
        await writeFile(dest, buf.subarray(off, off + f.size));
        written++;
      }
      return { content: [{ type: "text" as const, text: `# asar_extract\n\n**wrote:** ${written} files under \`${out}\`` }] };
    });
}
