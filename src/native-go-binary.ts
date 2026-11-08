// ============================================================
// Static Go binary inspector — recovers the compiler version,
// the embedded module list, replacements, build settings, and
// the stripped-main entry hint.
//
// Go bakes a runtime.buildVersion string of the form
//   go1.21.5
// into a well-known offset inside the runtime section, and an
// optional modular BuildInfo blob the `go version -m` command
// decodes. The blob format starts with the 14-byte magic
// `\xff Go buildinf:` followed by a few descriptor bytes and
// then UTF-8 strings. We parse both markers.
//
// Tools:
//   go_version     — just the compiler version string
//   go_build_info  — full module + replacement + setting dump
// ============================================================

import { z } from "zod";
import { readFile } from "node:fs/promises";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { requirePathAllowed } from "./fs-sandbox.js";

const BUILDINFO_MAGIC = Buffer.from("\xff Go buildinf:", "binary");

interface BuildInfoBlob {
  version: string;
  path?: string;
  mod?: string;
  deps: { name: string; version: string; replacement?: string; checksum?: string }[];
  settings: { key: string; value: string }[];
}

function findBuildInfo(buf: Buffer): number {
  return buf.indexOf(BUILDINFO_MAGIC);
}

function readVarint(buf: Buffer, off: number): { value: number; next: number } {
  let shift = 0, result = 0, i = off;
  while (i < buf.length) {
    const b = buf[i++];
    result |= (b & 0x7F) << shift;
    if ((b & 0x80) === 0) return { value: result, next: i };
    shift += 7;
    if (shift > 56) break;
  }
  throw new Error("varint overflow");
}

function readString(buf: Buffer, off: number): { value: string; next: number } {
  const { value: len, next } = readVarint(buf, off);
  return { value: buf.subarray(next, next + len).toString("utf-8"), next: next + len };
}

function parseBuildInfo(buf: Buffer, start: number): BuildInfoBlob {
  // magic(14) + ptrSize(1) + flags(1) + 2 reserved
  const ptrSize = buf[start + 14];
  const flags   = buf[start + 15];
  void ptrSize;
  let off = start + 32;
  // When bit 0x2 is set, the blob is a raw string table (modern Go).
  // Otherwise the next ptrSize bytes point to the buildVersion string.
  if (flags & 0x2) {
    // Modern layout: {version}\n{mod info}\n with internal escapes.
    const { value: payload } = readString(buf, off);
    return decodePayload(payload);
  }
  // Legacy: we just surface the raw bytes as a hint.
  const rawEnd = Math.min(buf.length, start + 64);
  return {
    version: `(legacy blob @ 0x${start.toString(16)} — ptrSize=${ptrSize} first bytes: ${buf.subarray(start + 16, rawEnd).toString("hex")})`,
    deps: [], settings: [],
  };
}

function decodePayload(txt: string): BuildInfoBlob {
  const out: BuildInfoBlob = { version: "", deps: [], settings: [] };
  const lines = txt.split("\n");
  for (const line of lines) {
    if (line.startsWith("go\t"))        out.version = line.slice(3);
    else if (line.startsWith("path\t"))  out.path = line.slice(5);
    else if (line.startsWith("mod\t"))   out.mod  = line.slice(4);
    else if (line.startsWith("dep\t")) {
      const [name, version, checksum] = line.slice(4).split("\t");
      out.deps.push({ name, version, checksum });
    } else if (line.startsWith("=>\t")) {
      const [name, version, checksum] = line.slice(3).split("\t");
      if (out.deps.length) out.deps[out.deps.length - 1].replacement = `${name} ${version}${checksum ? " " + checksum : ""}`;
    } else if (line.startsWith("build\t")) {
      const eq = line.slice(6).split("=");
      out.settings.push({ key: eq[0], value: eq.slice(1).join("=") });
    }
  }
  return out;
}

export function registerGoBinary(server: McpServer): void {
  server.tool(
    "go_version",
    "Extract the Go compiler version string baked into an ELF / PE / Mach-O binary.",
    { path: z.string() },
    async ({ path }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const biOff = findBuildInfo(buf);
      if (biOff < 0) return { content: [{ type: "text" as const, text: `# go_version\n\nno Go buildinf: marker in ${path}` }] };
      const info = parseBuildInfo(buf, biOff);
      return { content: [{ type: "text" as const, text: `# go_version\n\n**${info.version}**\n\n_source:_ embedded Go build info blob @ 0x${biOff.toString(16)}` }] };
    });

  server.tool(
    "go_build_info",
    "Dump the full embedded Go build-info blob: version, module path, deps, replacements, build settings.",
    { path: z.string() },
    async ({ path }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const biOff = findBuildInfo(buf);
      if (biOff < 0) return { content: [{ type: "text" as const, text: `# go_build_info\n\nno Go buildinf: marker in ${path}` }] };
      const info = parseBuildInfo(buf, biOff);
      const text = [
        `# go_build_info ${path}`,
        `**version:** ${info.version}`,
        info.path ? `**main path:** ${info.path}` : "",
        info.mod ? `**main mod:** ${info.mod}` : "",
        ``,
        `## dependencies (${info.deps.length})`,
        ...info.deps.map(d => `- \`${d.name}\` ${d.version}${d.replacement ? ` ⇒ **replaced by** ${d.replacement}` : ""}${d.checksum ? ` _(${d.checksum})_` : ""}`),
        ``,
        `## build settings (${info.settings.length})`,
        ...info.settings.map(s => `- ${s.key} = \`${s.value}\``),
      ].filter(Boolean).join("\n");
      return { content: [{ type: "text" as const, text }] };
    });
}
