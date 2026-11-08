// ============================================================
// Bit-manipulation helpers — the operations that reversingBits
// collects into cheatsheets, offered here as callable tools so
// agents can test an idea without pulling out a scratch REPL.
//
// All ops are 64-bit max; bigints throughout so callers don't
// have to care about 32-bit truncation surprises.
//
// Tools:
//   bits_extract      — pull a field from a word (LSB, width)
//   bits_insert       — set a field in a word
//   bits_rotate       — rotl / rotr for any width
//   bits_byteswap     — endian flip for N bytes
//   bits_popcount     — Hamming weight
//   bits_ctz / bits_clz — count trailing / leading zeros
//   bits_reverse      — reverse the bit order within a width
// ============================================================

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

const toBig = (s: string | number) => BigInt(typeof s === "number" ? s : s);

function mask(width: number): bigint { return (1n << BigInt(width)) - 1n; }

export function bitsExtract(word: bigint, lsb: number, width: number): bigint {
  return (word >> BigInt(lsb)) & mask(width);
}

export function bitsInsert(word: bigint, value: bigint, lsb: number, width: number): bigint {
  const m = mask(width) << BigInt(lsb);
  return (word & ~m) | ((value << BigInt(lsb)) & m);
}

export function bitsRotate(word: bigint, amount: number, width: number, dir: "left" | "right"): bigint {
  const w = BigInt(width); const a = BigInt(((amount % width) + width) % width);
  const m = mask(width); const v = word & m;
  return dir === "left"
    ? (((v << a) | (v >> (w - a))) & m)
    : (((v >> a) | (v << (w - a))) & m);
}

export function bitsByteswap(word: bigint, bytes: number): bigint {
  let v = word & mask(bytes * 8);
  let r = 0n;
  for (let i = 0; i < bytes; i++) { r = (r << 8n) | (v & 0xFFn); v >>= 8n; }
  return r;
}

export function bitsPopcount(word: bigint): number {
  let v = word; let c = 0;
  while (v > 0n) { c += Number(v & 1n); v >>= 1n; }
  return c;
}

export function bitsCtz(word: bigint, width: number): number {
  const m = mask(width); let v = word & m;
  if (v === 0n) return width;
  let c = 0;
  while ((v & 1n) === 0n) { v >>= 1n; c++; }
  return c;
}

export function bitsClz(word: bigint, width: number): number {
  const m = mask(width); let v = word & m;
  if (v === 0n) return width;
  let c = 0;
  while ((v >> BigInt(width - 1 - c)) === 0n) c++;
  return c;
}

export function bitsReverse(word: bigint, width: number): bigint {
  let r = 0n; let v = word & mask(width);
  for (let i = 0; i < width; i++) { r = (r << 1n) | (v & 1n); v >>= 1n; }
  return r;
}

const HEX = z.string().transform(s => toBig(s));

export function registerBitmanip(server: McpServer): void {
  server.tool("bits_extract", "Extract a bit field from a word: `(word >> lsb) & ((1<<width)-1)`.",
    { word: HEX, lsb: z.number().min(0).max(63), width: z.number().min(1).max(64) },
    async ({ word, lsb, width }) => ({ content: [{ type: "text" as const, text: `# bits_extract\n\n**result:** 0x${bitsExtract(word, lsb, width).toString(16)}` }] }));

  server.tool("bits_insert", "Overwrite a bit field inside a word.",
    { word: HEX, value: HEX, lsb: z.number().min(0).max(63), width: z.number().min(1).max(64) },
    async ({ word, value, lsb, width }) => ({ content: [{ type: "text" as const, text: `# bits_insert\n\n**result:** 0x${bitsInsert(word, value, lsb, width).toString(16)}` }] }));

  server.tool("bits_rotate", "Rotate a word left or right within a configurable width (8/16/32/64).",
    { word: HEX, amount: z.number(), width: z.number().min(2).max(64).default(32), dir: z.enum(["left", "right"]).default("left") },
    async ({ word, amount, width, dir }) => ({ content: [{ type: "text" as const, text: `# bits_rotate ${dir} ${amount}\n\n**result:** 0x${bitsRotate(word, amount, width, dir).toString(16)}` }] }));

  server.tool("bits_byteswap", "Endian flip a word across N bytes.",
    { word: HEX, bytes: z.number().min(2).max(8).default(4) },
    async ({ word, bytes }) => ({ content: [{ type: "text" as const, text: `# bits_byteswap ${bytes}B\n\n**result:** 0x${bitsByteswap(word, bytes).toString(16)}` }] }));

  server.tool("bits_popcount", "Count the number of 1-bits in a word (Hamming weight).",
    { word: HEX },
    async ({ word }) => ({ content: [{ type: "text" as const, text: `# bits_popcount\n\n**result:** ${bitsPopcount(word)}` }] }));

  server.tool("bits_ctz", "Count trailing zeros (lowest set bit position).",
    { word: HEX, width: z.number().min(2).max(64).default(64) },
    async ({ word, width }) => ({ content: [{ type: "text" as const, text: `# bits_ctz width=${width}\n\n**result:** ${bitsCtz(word, width)}` }] }));

  server.tool("bits_clz", "Count leading zeros from the top bit of a width.",
    { word: HEX, width: z.number().min(2).max(64).default(64) },
    async ({ word, width }) => ({ content: [{ type: "text" as const, text: `# bits_clz width=${width}\n\n**result:** ${bitsClz(word, width)}` }] }));

  server.tool("bits_reverse", "Reverse the bit order within a configurable width.",
    { word: HEX, width: z.number().min(2).max(64).default(32) },
    async ({ word, width }) => ({ content: [{ type: "text" as const, text: `# bits_reverse width=${width}\n\n**result:** 0x${bitsReverse(word, width).toString(16)}` }] }));
}
