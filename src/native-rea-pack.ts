// ============================================================
// Grab-bag of smaller single-purpose parsers to reach feature
// parity with popular artifact catalogs — PyInstaller, HAR
// captures, SQLite inspect, ELF notes, Apple IPS crash files.
// Each tool is a few dozen lines because the file formats are
// self-describing and well-documented.
// ============================================================

import { z } from "zod";
import { readFile } from "node:fs/promises";
import { DatabaseSync } from "node:sqlite";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { requirePathAllowed } from "./fs-sandbox.js";

// ---- PyInstaller CArchive -----------------------------------------
// At the file tail there is a `MEI\014\013\012\013\016` magic with a
// 24-byte cookie: magic(8) + size(4) + toc_off(4) + toc_size(4) +
// python_version(4) + python_lib_name(64). The TOC is a list of
// variable-length entries describing each embedded file.

export function parsePyInstaller(buf: Buffer): { magic: string; python_ver: string; toc: { name: string; off: number; size: number; kind: string }[] } | null {
  const MAGIC = Buffer.from([0x4D, 0x45, 0x49, 0x0C, 0x0B, 0x0A, 0x0B, 0x0E]);
  const magicOff = buf.lastIndexOf(MAGIC);
  if (magicOff < 0) return null;
  const size = buf.readUInt32BE(magicOff + 8);
  const tocRel = buf.readUInt32BE(magicOff + 12);
  const _tocSize = buf.readUInt32BE(magicOff + 16);
  void _tocSize;
  const pyVer = buf.readUInt32BE(magicOff + 20);
  const baseOff = magicOff + 24 - size;
  const tocStart = baseOff + tocRel;
  const toc: { name: string; off: number; size: number; kind: string }[] = [];
  let p = tocStart;
  while (p < buf.length - 24) {
    const entryLen = buf.readUInt32BE(p);
    if (entryLen < 18 || p + entryLen > buf.length - 24) break;
    const off  = buf.readUInt32BE(p + 4);
    const sz   = buf.readUInt32BE(p + 8);
    const _usz = buf.readUInt32BE(p + 12);
    void _usz;
    const _cmp = buf[p + 16];
    void _cmp;
    const kind = String.fromCharCode(buf[p + 17]);
    const name = buf.slice(p + 18, p + entryLen).toString("utf-8").replace(/\0+$/, "");
    toc.push({ name, off: baseOff + off, size: sz, kind });
    p += entryLen;
  }
  return { magic: "MEI", python_ver: `${(pyVer >> 8) & 0xFF}.${pyVer & 0xFF}`, toc };
}

// ---- HAR (HTTP ARchive) -------------------------------------------

interface HarSummary { entries: number; hosts: string[]; methods: Record<string, number>; status: Record<number, number>; sample: { method: string; url: string; status: number; mime?: string }[] }

export function summariseHar(txt: string): HarSummary {
  const obj = JSON.parse(txt);
  const entries: unknown[] = obj?.log?.entries ?? [];
  const sum: HarSummary = { entries: entries.length, hosts: [], methods: {}, status: {}, sample: [] };
  const hostSet = new Set<string>();
  for (const e of entries) {
    const req = (e as { request?: { method: string; url: string } }).request;
    const resp = (e as { response?: { status: number; content?: { mimeType?: string } } }).response;
    if (!req) continue;
    sum.methods[req.method] = (sum.methods[req.method] ?? 0) + 1;
    if (resp) sum.status[resp.status] = (sum.status[resp.status] ?? 0) + 1;
    try { hostSet.add(new URL(req.url).host); } catch { /* ignore malformed */ }
    if (sum.sample.length < 50) sum.sample.push({ method: req.method, url: req.url, status: resp?.status ?? 0, mime: resp?.content?.mimeType });
  }
  sum.hosts = Array.from(hostSet).sort();
  return sum;
}

// ---- ELF notes ----------------------------------------------------

export function parseElfNotes(buf: Buffer): { owner: string; type: number; desc: string }[] {
  if (buf.readUInt32LE(0) !== 0x464C457F) return [];
  const is64 = buf[4] === 2;
  const le = buf[5] === 1;
  if (!le) return [];
  const phoff = is64 ? Number(buf.readBigUInt64LE(0x20)) : buf.readUInt32LE(0x1C);
  const phentsize = buf.readUInt16LE(is64 ? 0x36 : 0x2A);
  const phnum = buf.readUInt16LE(is64 ? 0x38 : 0x2C);
  const out: { owner: string; type: number; desc: string }[] = [];
  for (let i = 0; i < phnum; i++) {
    const base = phoff + i * phentsize;
    const type = buf.readUInt32LE(base);
    if (type !== 4 /* PT_NOTE */) continue;
    const off  = is64 ? Number(buf.readBigUInt64LE(base + 8))  : buf.readUInt32LE(base + 4);
    const size = is64 ? Number(buf.readBigUInt64LE(base + 32)) : buf.readUInt32LE(base + 16);
    let p = off;
    const end = Math.min(off + size, buf.length);
    while (p + 12 <= end) {
      const namesz = buf.readUInt32LE(p);
      const descsz = buf.readUInt32LE(p + 4);
      const ntype  = buf.readUInt32LE(p + 8);
      const name   = buf.slice(p + 12, p + 12 + namesz).toString("ascii").replace(/\0+$/, "");
      const descStart = p + 12 + ((namesz + 3) & ~3);
      const desc = buf.slice(descStart, descStart + descsz).toString("hex");
      out.push({ owner: name, type: ntype, desc });
      p = descStart + ((descsz + 3) & ~3);
      if (out.length > 200) break;
    }
  }
  return out;
}

// ---- Apple IPS crash --------------------------------------------
// .ips files are two JSON documents joined by a newline: a small
// summary header, then a detailed body with threads / frames /
// registers.

export function parseIps(text: string): { summary: unknown; body?: unknown } {
  const nl = text.indexOf("\n");
  if (nl < 0) return { summary: JSON.parse(text) };
  const summary = JSON.parse(text.slice(0, nl));
  try { return { summary, body: JSON.parse(text.slice(nl + 1)) }; }
  catch { return { summary }; }
}

// ---- Registration -----------------------------------------------

export function registerReaPack(server: McpServer): void {
  server.tool(
    "pyinstaller_toc",
    "List the CArchive TOC of a PyInstaller exe: every embedded file's offset, size, and kind flag.",
    { path: z.string(), limit: z.number().min(1).max(10_000).default(200) },
    async ({ path, limit }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const r = parsePyInstaller(buf);
      if (!r) return { content: [{ type: "text" as const, text: `# pyinstaller_toc\n\nno MEI cookie in ${path}` }] };
      const text = [
        `# pyinstaller_toc ${path}`,
        `**python:** ${r.python_ver}  **entries:** ${r.toc.length}`,
        ``,
        ...r.toc.slice(0, limit).map(t => `- \`${t.name}\` kind=${t.kind} offset=0x${t.off.toString(16)} size=${t.size}`),
      ].join("\n");
      return { content: [{ type: "text" as const, text }] };
    });

  server.tool(
    "har_summary",
    "Summarise a HAR capture: entries, hosts, HTTP methods, status-code tally, first 50 requests.",
    { path: z.string(), limit: z.number().min(1).max(10_000).default(50) },
    async ({ path, limit }) => {
      requirePathAllowed(path);
      const txt = (await readFile(path)).toString("utf-8");
      const s = summariseHar(txt);
      const text = [
        `# har_summary ${path}`,
        `**entries:** ${s.entries}  **hosts:** ${s.hosts.length}`,
        ``,
        `## methods`,
        ...Object.entries(s.methods).map(([k, v]) => `- ${k}: ${v}`),
        ``,
        `## status codes`,
        ...Object.entries(s.status).map(([k, v]) => `- ${k}: ${v}`),
        ``,
        `## hosts (first 30)`,
        ...s.hosts.slice(0, 30).map(h => `- ${h}`),
        ``,
        `## requests (first ${Math.min(limit, s.sample.length)})`,
        ...s.sample.slice(0, limit).map(r => `- ${r.method} ${r.url.slice(0, 120)} → ${r.status}${r.mime ? "  _(" + r.mime + ")_" : ""}`),
      ].join("\n");
      return { content: [{ type: "text" as const, text }] };
    });

  server.tool(
    "sqlite_inspect",
    "Open a SQLite database (read-only) and return its schema + row counts. Optional `limit` cuts the per-table row dump.",
    { path: z.string(), dumpRows: z.number().min(0).max(1000).default(0) },
    async ({ path, dumpRows }) => {
      requirePathAllowed(path);
      const db = new DatabaseSync(path, { readOnly: true });
      try {
        const schema = db.prepare("SELECT type, name, tbl_name, sql FROM sqlite_master WHERE type IN ('table', 'index', 'view', 'trigger') ORDER BY type, name").all() as { type: string; name: string; tbl_name: string; sql: string | null }[];
        const tables = schema.filter(s => s.type === "table" && !s.name.startsWith("sqlite_"));
        const counts = tables.map(t => ({ name: t.name, count: (db.prepare(`SELECT COUNT(*) c FROM "${t.name.replace(/"/g, '""')}"`).get() as { c: number }).c }));
        const samples: { name: string; rows: unknown[] }[] = [];
        if (dumpRows > 0) {
          for (const t of tables) {
            const rows = db.prepare(`SELECT * FROM "${t.name.replace(/"/g, '""')}" LIMIT ?`).all(dumpRows);
            samples.push({ name: t.name, rows });
          }
        }
        const text = [
          `# sqlite_inspect ${path}`,
          `**objects:** ${schema.length}  **tables:** ${tables.length}`,
          ``,
          `## schema`,
          ...schema.map(s => `- **${s.type}** \`${s.name}\`${s.sql ? "\n  \n  ```sql\n  " + s.sql.replace(/\n/g, "\n  ") + "\n  ```" : ""}`),
          ``,
          `## row counts`,
          ...counts.map(c => `- \`${c.name}\`: ${c.count}`),
          dumpRows > 0 ? `\n## samples (first ${dumpRows} per table)\n` + samples.map(s => `### ${s.name}\n\`\`\`json\n${JSON.stringify(s.rows, null, 2).slice(0, 10_000)}\n\`\`\``).join("\n") : "",
        ].filter(Boolean).join("\n");
        return { content: [{ type: "text" as const, text }] };
      } finally { db.close(); }
    });

  server.tool(
    "elf_notes",
    "Walk every PT_NOTE / SHT_NOTE in an ELF, surface GNU build-id, ABI tag, custom notes.",
    { path: z.string() },
    async ({ path }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const notes = parseElfNotes(buf);
      const lines = notes.map(n => `- owner \`${n.owner}\`  type=${n.type}  desc=\`${n.desc.slice(0, 80)}${n.desc.length > 80 ? "…" : ""}\``);
      return { content: [{ type: "text" as const, text: `# elf_notes ${path}\n\n**notes:** ${notes.length}\n\n${lines.join("\n")}` }] };
    });

  server.tool(
    "ips_parse",
    "Parse an Apple .ips crash file (two JSON documents separated by newline): summary + optional detailed body.",
    { path: z.string() },
    async ({ path }) => {
      requirePathAllowed(path);
      const txt = (await readFile(path)).toString("utf-8");
      const r = parseIps(txt);
      return { content: [{ type: "text" as const, text:
        `# ips_parse ${path}\n\n## summary\n\`\`\`json\n${JSON.stringify(r.summary, null, 2).slice(0, 10_000)}\n\`\`\`` +
        (r.body ? `\n\n## body (truncated)\n\`\`\`json\n${JSON.stringify(r.body, null, 2).slice(0, 30_000)}\n\`\`\`` : "")
      }] };
    });
}
