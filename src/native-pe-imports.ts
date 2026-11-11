// ============================================================
// PE Import Table walker + C++ vector emitter.
//
// Walks the PE's data directory #1 (IMAGE_DIRECTORY_ENTRY_IMPORT),
// resolves each IMAGE_IMPORT_DESCRIPTOR into its DLL name + the
// chain of named imports, and can emit the result as:
//   - JSON  (default, agent-consumable)
//   - a C++ std::vector<std::tuple<uintptr_t, std::string, std::string>>
//     ready to paste into a manual-mapper's import-resolver table.
//
// The C++ emit takes an optional baseAddress offset so dumps taken
// from a running process (where ASLR has shifted the DLL) subtract
// cleanly down to the module-local VA used by the call sites.
//
// Zero deps.
// ============================================================

import { z } from "zod";
import { readFile, writeFile } from "node:fs/promises";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { requirePathAllowed } from "./fs-sandbox.js";

export interface PeImport { dll: string; function: string; iat_rva: number; ordinal?: number }

interface Section { vaddr: number; vsize: number; raw: number; rsize: number }

function rvaToFile(sections: Section[], rva: number): number {
  for (const s of sections) {
    if (rva >= s.vaddr && rva < s.vaddr + Math.max(s.vsize, s.rsize)) {
      return s.raw + (rva - s.vaddr);
    }
  }
  return -1;
}

function readCString(buf: Buffer, off: number, max = 512): string {
  let end = off;
  while (end < buf.length && end - off < max && buf[end] !== 0) end++;
  return buf.slice(off, end).toString("ascii");
}

export function parsePeImports(buf: Buffer): { is64: boolean; image_base: bigint; imports: PeImport[] } {
  if (buf.length < 0x40 || buf[0] !== 0x4D || buf[1] !== 0x5A) throw new Error("not a PE");
  const peOff = buf.readUInt32LE(0x3C);
  if (peOff + 24 >= buf.length || buf.readUInt32LE(peOff) !== 0x00004550) throw new Error("not a PE");
  const nSec  = buf.readUInt16LE(peOff + 6);
  const magic = buf.readUInt16LE(peOff + 24);
  const is64  = magic === 0x20B;
  const image_base = is64 ? buf.readBigUInt64LE(peOff + 24 + 24) : BigInt(buf.readUInt32LE(peOff + 24 + 28));
  const dataDirs = peOff + 24 + (is64 ? 112 : 96);
  const importRva  = buf.readUInt32LE(dataDirs + 1 * 8);
  const importSize = buf.readUInt32LE(dataDirs + 1 * 8 + 4);

  const secStart = peOff + 24 + (is64 ? 240 : 224);
  const sections: Section[] = [];
  for (let i = 0; i < nSec; i++) {
    const base = secStart + i * 40;
    sections.push({
      vaddr: buf.readUInt32LE(base + 12),
      vsize: buf.readUInt32LE(base + 8),
      raw:   buf.readUInt32LE(base + 20),
      rsize: buf.readUInt32LE(base + 16),
    });
  }

  const imports: PeImport[] = [];
  if (!importRva || !importSize) return { is64, image_base, imports };

  const importOff = rvaToFile(sections, importRva);
  if (importOff < 0) return { is64, image_base, imports };

  // Each IMAGE_IMPORT_DESCRIPTOR is 20 bytes: {OriginalFirstThunk, TimeStamp,
  // ForwarderChain, Name, FirstThunk}.
  const entrySize = 20;
  const ptrSize = is64 ? 8 : 4;
  for (let p = importOff; p + entrySize <= buf.length; p += entrySize) {
    const olt   = buf.readUInt32LE(p);
    const name  = buf.readUInt32LE(p + 12);
    const iat   = buf.readUInt32LE(p + 16);
    if (olt === 0 && name === 0 && iat === 0) break;
    if (name === 0) continue;
    const nameOff = rvaToFile(sections, name);
    if (nameOff < 0) continue;
    const dllName = readCString(buf, nameOff);
    if (!dllName || /\*invalid\*/i.test(dllName)) continue;
    // Walk the IAT (prefer OLT if present — it's not overwritten by the
    // loader, so the names stay resolvable against the on-disk image).
    const thunkRva = olt || iat;
    if (!thunkRva) continue;
    let tOff = rvaToFile(sections, thunkRva);
    if (tOff < 0) continue;
    let slot = 0;
    while (tOff + ptrSize <= buf.length) {
      const v = is64 ? buf.readBigUInt64LE(tOff) : BigInt(buf.readUInt32LE(tOff));
      if (v === 0n) break;
      const ordinalBit = is64 ? 0x8000000000000000n : 0x80000000n;
      if (v & ordinalBit) {
        imports.push({ dll: dllName, function: "", iat_rva: iat + slot * ptrSize, ordinal: Number(v & 0xFFFFn) });
      } else {
        // Value points to IMAGE_IMPORT_BY_NAME: WORD hint + null-terminated name.
        const hintOff = rvaToFile(sections, Number(v));
        if (hintOff >= 0) {
          const funcName = readCString(buf, hintOff + 2);
          if (funcName && !/\*invalid\*/i.test(funcName)) {
            imports.push({ dll: dllName, function: funcName, iat_rva: iat + slot * ptrSize });
          }
        }
      }
      tOff += ptrSize;
      slot++;
      if (slot > 20_000) break; // safety
    }
  }

  return { is64, image_base, imports };
}

export function emitCppVector(imports: PeImport[], baseAddress: bigint, is64: boolean, withAddrOffset: bigint = 0n): string {
  // Group by DLL for readability; subtract baseAddress from the
  // runtime VA so the emitted address matches the module-local RVA
  // used by the call sites in a dumped image.
  const byDll = new Map<string, PeImport[]>();
  for (const im of imports) {
    if (!byDll.has(im.dll)) byDll.set(im.dll, []);
    byDll.get(im.dll)!.push(im);
  }
  const lines: string[] = [
    "std::vector<std::tuple<uintptr_t, std::string, std::string>> g_aImports =",
    "{",
  ];
  for (const [dll, funcs] of byDll) {
    lines.push(`    // ${dll}`);
    for (const im of funcs.sort((a, b) => a.iat_rva - b.iat_rva)) {
      const rva = BigInt(im.iat_rva) + withAddrOffset - baseAddress;
      const hex = rva.toString(16).padStart(is64 ? 16 : 8, "0").toUpperCase();
      const name = im.function || `#${im.ordinal}`;
      lines.push(`    { 0x${hex}, "${dll}", "${name}" },`);
    }
  }
  lines.push("};");
  return lines.join("\n");
}

// ---- Hex-Rays switch-trap detector + template emitter ------------
//
// Technique: a dispatcher that reads a jump-table index and then
// overwrites that index register with a small constant before the
// indirect jump makes Hex-Rays prune the "unreachable" branch and
// show only the stub. Detector scans for:
//    48 63 ??            — movsxd r?, dword ptr [...]
//    .{0,12}             — up to 12 bytes of filler
//    B8 ?? 00 00 00       — mov eax, small imm (< 0x100)
//    .{0,8}              — up to 8 bytes of filler
//    48 01 ??             — add r?, r?
//    .{0,4}              — slack
//    FF E?                — jmp reg
//
// The pattern alone has false positives (any real switch); we
// filter by also requiring a `movsxd` + `jmp reg` within the same
// 64-byte window. Good enough for triage.

export function scanHexRaysSwitchTrap(buf: Uint8Array): { offset: string; evidence: string }[] {
  const hits: { offset: string; evidence: string }[] = [];
  const b = Buffer.from(buf);
  for (let i = 0; i + 3 < b.length; i++) {
    if (b[i] !== 0x48 || b[i + 1] !== 0x63) continue; // movsxd r?, m32
    // Look within a 64-byte window for the full chain.
    const windowEnd = Math.min(b.length, i + 64);
    let movEax = -1, addRR = -1, jmpReg = -1;
    for (let j = i + 3; j + 4 < windowEnd; j++) {
      if (movEax < 0 && b[j] === 0xB8 && b[j + 2] === 0 && b[j + 3] === 0 && b[j + 4] === 0 && b[j + 1] < 0x10) movEax = j;
      if (movEax > 0 && addRR < 0 && j > movEax && b[j] === 0x48 && b[j + 1] === 0x01) addRR = j;
      if (addRR > 0 && jmpReg < 0 && j > addRR && b[j] === 0xFF && (b[j + 1] & 0xF8) === 0xE0) { jmpReg = j; break; }
    }
    if (movEax > 0 && addRR > 0 && jmpReg > 0) {
      hits.push({
        offset: "0x" + i.toString(16),
        evidence: `movsxd @${i.toString(16)} -> mov eax,${b[movEax + 1]} @${movEax.toString(16)} -> add @${addRR.toString(16)} -> jmp reg @${jmpReg.toString(16)}`,
      });
      i = jmpReg; // skip past this match
    }
    if (hits.length > 500) break;
  }
  return hits;
}

const HEXRAYS_TRAP_TEMPLATE = `; --- Hex-Rays switch-trap template ---
; Wrap an entry point so decompilation shows only the stub.
; IDA Pro <= 9.4 prunes the real branch; the CPU still runs it.

section .text
    global  trapped_entry

trapped_entry:
    xor     eax, eax                    ; index = 0 (real branch)
    lea     r10, [rel jump_table]
    movsxd  r11, dword [r10 + rax*4]
    mov     eax, 1                      ; <-- the trap (decompiler reads this)
    add     r11, r10
    jmp     r11

jump_table:
    dd  original_code - jump_table
    dd  return_stub   - jump_table

original_code:
    jmp     real_entry                  ; your actual OEP

return_stub:
    xor     eax, eax
    ret

; --- end template ---`;

export function registerPeImports(server: McpServer): void {
  server.tool(
    "pe_imports_json",
    "Walk a PE's Import Directory and return every (DLL, function, IAT RVA, ordinal?). Zero deps; native parser.",
    { path: z.string(), limit: z.number().min(1).max(100_000).default(5000) },
    async ({ path, limit }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const r = parsePeImports(buf);
      const text = [
        `# pe_imports_json ${path}`,
        `**bits:** ${r.is64 ? 64 : 32}  **image_base:** 0x${r.image_base.toString(16)}  **imports:** ${r.imports.length}`,
        ``,
        "```json",
        JSON.stringify(r.imports.slice(0, limit), null, 2),
        "```",
      ].join("\n");
      return { content: [{ type: "text" as const, text }] };
    });

  server.tool(
    "pe_imports_cpp_vector",
    "Emit a C++ std::vector<std::tuple<uintptr_t, std::string, std::string>> for a manual-mapper's import resolver. `baseAddress` is subtracted from every IAT RVA so dumps taken under ASLR convert back to module-local VAs. `withAddrOffset` adds an extra constant if the runtime dump sits at a non-base VA.",
    {
      path: z.string(),
      baseAddress: z.string().default("0x0").describe("hex / dec string; default 0x0 for a raw on-disk PE. Use 0x7ffe00000000 for the shift the original PoC uses."),
      withAddrOffset: z.string().default("0x0").describe("extra offset added to each IAT RVA before the subtraction."),
      out: z.string().optional().describe("optional output path"),
    },
    async ({ path, baseAddress, withAddrOffset, out }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const r = parsePeImports(buf);
      const code = emitCppVector(r.imports, BigInt(baseAddress), r.is64, BigInt(withAddrOffset));
      if (out) {
        requirePathAllowed(out);
        await writeFile(out, code);
        return { content: [{ type: "text" as const, text: `# pe_imports_cpp_vector\n\n**wrote:** \`${out}\` (${r.imports.length} imports)` }] };
      }
      return { content: [{ type: "text" as const, text:
        `# pe_imports_cpp_vector ${path}\n\n**imports:** ${r.imports.length}  **bits:** ${r.is64 ? 64 : 32}\n\n\`\`\`cpp\n${code.slice(0, 80_000)}\n\`\`\``
      }] };
    });

  server.tool(
    "hexrays_switch_trap_scan",
    "Scan a PE for the Hex-Rays switch-trap anti-decompilation pattern (movsxd ... mov eax,imm ... add ... jmp reg). IDA <= 9.4 prunes the real branch and shows only the stub — see skill `technique-hexrays-switch-trap`.",
    { path: z.string(), limit: z.number().min(1).max(10_000).default(200) },
    async ({ path, limit }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const hits = scanHexRaysSwitchTrap(new Uint8Array(buf));
      const shown = hits.slice(0, limit);
      return { content: [{ type: "text" as const, text:
        `# hexrays_switch_trap_scan ${path}\n\n**hits:** ${hits.length}\n\n` +
        shown.map(h => `- @ ${h.offset}  _${h.evidence}_`).join("\n")
      }] };
    });

  server.tool(
    "hexrays_switch_trap_emit",
    "Emit a NASM template that wraps `real_entry` with the Hex-Rays switch trap. Paste into an .asm file, assemble, and use as the new entry point.",
    {},
    async () => ({ content: [{ type: "text" as const, text: `# hexrays_switch_trap_emit\n\n\`\`\`nasm\n${HEXRAYS_TRAP_TEMPLATE}\n\`\`\`` }] }));

  server.tool(
    "pe_dump_sections",
    "Parse a raw PE dump (from a running process via x64dbg → Dump Memory to File) and print the architecture, number of sections, header-declared ImageBase, and every section's RVA + virtual size + computed VA range + characteristics. `baseAddress` overrides the header ImageBase when the dump was taken at an ASLR-shifted location.",
    { path: z.string(), baseAddress: z.string().optional().describe("hex / decimal; defaults to the header's ImageBase") },
    async ({ path, baseAddress }) => {
      requirePathAllowed(path);
      const data = await readFile(path);
      if (data.length < 0x40 || data[0] !== 0x4D || data[1] !== 0x5A) throw new Error("no MZ signature — headers likely wiped");
      const peOff = data.readUInt32LE(0x3C);
      if (peOff + 4 > data.length || data.readUInt32LE(peOff) !== 0x00004550) throw new Error("no PE\\0\\0 signature at e_lfanew");
      const fileHdr = peOff + 4;
      const nSections = data.readUInt16LE(fileHdr + 2);
      const sizeOfOpt = data.readUInt16LE(fileHdr + 16);
      const optOff = fileHdr + 20;
      const magic = data.readUInt16LE(optOff);
      const is64 = magic === 0x20B;
      const arch = is64 ? "x64 (PE32+)" : magic === 0x10B ? "x86 (PE32)" : `unknown 0x${magic.toString(16)}`;
      const imageBase = is64 ? data.readBigUInt64LE(optOff + 24) : BigInt(data.readUInt32LE(optOff + 28));
      const base = baseAddress ? BigInt(baseAddress) : imageBase;

      const secOff = optOff + sizeOfOpt;
      const rows: string[] = [];
      for (let i = 0; i < nSections; i++) {
        const e = secOff + i * 40;
        if (e + 40 > data.length) break;
        const name  = data.slice(e, e + 8).toString("ascii").replace(/\0.*$/, "");
        const vsize = data.readUInt32LE(e + 8);
        const vrva  = data.readUInt32LE(e + 12);
        const chars = data.readUInt32LE(e + 36);
        const start = base + BigInt(vrva);
        const end   = start + BigInt(vsize);
        rows.push(`| \`${name.padEnd(8)}\` | 0x${vrva.toString(16).padStart(6, "0")} | 0x${vsize.toString(16).padStart(5, "0")} | 0x${start.toString(16)} – 0x${end.toString(16)} | 0x${chars.toString(16).padStart(8, "0")} |`);
      }
      return { content: [{ type: "text" as const, text:
        `# pe_dump_sections ${path}\n\n` +
        `- **architecture:** ${arch}\n- **sections:** ${nSections}\n- **ImageBase (header):** 0x${imageBase.toString(16)}\n` +
        (baseAddress ? `- **base override:** 0x${base.toString(16)}\n` : "") + `\n` +
        `| Section | RVA | VirtSize | VA range | Characteristics |\n|---|---|---|---|---|\n` + rows.join("\n")
      }] };
    });
}
