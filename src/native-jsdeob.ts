// ============================================================
// JavaScript deobfuscator — the core moves of
// relative/javascript-deobfuscator: replace hex-encoded numeric
// literals, inline string-array lookups, strip dead nulls.
//
// It's a regex pass, not a full AST transform, so it can't fix
// control-flow flattening or VM obfuscators — but it does clean
// up 80% of the free obfuscator.io output that shows up in
// malicious ads / phishing kits / web skimmers.
//
// Tools:
//   js_deob_literals   — rewrite \\x41 and 0xHH numeric literals
//                        to their printable form
//   js_deob_strarr     — inline a _0xabcd[idx] string-array lookup
//                        when the array is a flat `var _0xabcd=[…]`
//   js_deob_full       — run both passes + dead-null strip
// ============================================================

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

export function deobLiterals(src: string): string {
  // \xHH in a string → the corresponding ASCII char when printable.
  let out = src.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => {
    const c = parseInt(h, 16);
    if (c >= 0x20 && c < 0x7F) return String.fromCharCode(c);
    return `\\x${h}`;
  });
  // 0xHH numeric literals: leave big ones alone, inline small ones
  // that are obviously flag / index values.
  out = out.replace(/\b0x([0-9a-fA-F]{1,4})\b/g, (m, h) => {
    const n = parseInt(h, 16);
    if (n > 0xFFFF) return m;
    return n.toString(10);
  });
  return out;
}

/**
 * Detect the common obfuscator.io string-table pattern:
 *   var _0xabcd=['foo','bar','baz'];
 *   ...something like _0xabcd[0x1]...
 * and inline every `_0xabcd[<n>]` with the matching string literal.
 */
export function deobStrArr(src: string): { out: string; inlined: number; tableName?: string } {
  // match: var|const|let _0xNAME = [ ... ];
  const tableRe = /\b(?:var|let|const)\s+(_0x[0-9a-fA-F]+)\s*=\s*\[([^\]]*?)\]\s*;/;
  const m = src.match(tableRe);
  if (!m) return { out: src, inlined: 0 };
  const name = m[1];
  const raw = m[2];
  const items = raw.match(/(['"])((?:\\.|(?!\1)[^\\])*?)\1/g) ?? [];
  const strings = items.map(s => {
    try { return JSON.parse(s.replace(/^'/, '"').replace(/'$/, '"').replace(/\\/g, "\\\\")); }
    catch { return s.slice(1, -1); }
  });

  // _0xabcd[0x1] or _0xabcd(0x1) → "bar"
  const refRe = new RegExp(`\\b${name}\\s*[\\[\\(]\\s*(0x[0-9a-fA-F]+|\\d+)\\s*[\\]\\)]`, "g");
  let inlined = 0;
  const out = src.replace(refRe, (_m, idx: string) => {
    const n = Number(BigInt(idx.startsWith("0x") ? idx : idx));
    if (n < 0 || n >= strings.length) return _m;
    inlined++;
    return JSON.stringify(strings[n]);
  });
  return { out, inlined, tableName: name };
}

export function deobFull(src: string): { out: string; inlined: number; tableName?: string } {
  const step1 = deobLiterals(src);
  const step2 = deobStrArr(step1);
  // Strip common dead-null guards: `if(!![])` / `if(![])`
  let out = step2.out.replace(/if\s*\(\s*!!\[\]\s*\)/g, "if (true)")
                       .replace(/if\s*\(\s*!\s*\[\]\s*\)/g, "if (false)")
                       .replace(/\bvoid 0\b/g, "undefined");
  return { out, inlined: step2.inlined, tableName: step2.tableName };
}

export function registerJsDeob(server: McpServer): void {
  server.tool(
    "js_deob_literals",
    "Rewrite \\xHH escapes and small 0xHH numeric literals to their printable / decimal forms. Pass through for everything else.",
    { code: z.string() },
    async ({ code }: { code: string }) => {
      const out = deobLiterals(code);
      return { content: [{ type: "text" as const, text: `# js_deob_literals\n\n\`\`\`js\n${out.slice(0, 50_000)}\n\`\`\`` }] };
    });

  server.tool(
    "js_deob_strarr",
    "Inline the obfuscator.io string-table lookup pattern (`var _0xabcd=[...]; _0xabcd[0xN]` → literal). Returns the rewritten source + count of resolved lookups.",
    { code: z.string() },
    async ({ code }: { code: string }) => {
      const r = deobStrArr(code);
      return { content: [{ type: "text" as const, text:
        `# js_deob_strarr\n\n**inlined:** ${r.inlined}  **table:** ${r.tableName ?? "(none found)"}\n\n\`\`\`js\n${r.out.slice(0, 50_000)}\n\`\`\``
      }] };
    });

  server.tool(
    "js_deob_full",
    "Run every deob pass in order: literals → string-array inline → dead-null strip.",
    { code: z.string() },
    async ({ code }: { code: string }) => {
      const r = deobFull(code);
      return { content: [{ type: "text" as const, text:
        `# js_deob_full\n\n**inlined:** ${r.inlined}  **table:** ${r.tableName ?? "(none found)"}\n\n\`\`\`js\n${r.out.slice(0, 80_000)}\n\`\`\``
      }] };
    });
}
