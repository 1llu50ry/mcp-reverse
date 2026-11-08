// ============================================================
// Model-artifact metadata parsers:
//   GGUF           — llama.cpp family (tensor layout + kv metadata)
//   safetensors    — HuggingFace standard (JSON header + bytes)
//
// Both formats are open and self-describing; we parse the header
// only, so even multi-GB weights stay off-disk until the caller
// asks for them explicitly.
//
// Tools:
//   gguf_header       — magic / version / tensor count + first N
//                       kv entries + first N tensors
//   safetensors_meta  — shape + dtype for every tensor in the file
// ============================================================

import { z } from "zod";
import { open } from "node:fs/promises";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { requirePathAllowed } from "./fs-sandbox.js";

const GGUF_MAGIC = 0x46554747; // "GGUF"

// Partial GGUF value type enum
const GGUF_TYPE = {
  U8: 0, I8: 1, U16: 2, I16: 3, U32: 4, I32: 5, F32: 6,
  BOOL: 7, STRING: 8, ARRAY: 9, U64: 10, I64: 11, F64: 12,
} as const;

interface GgufHeader {
  magic: string;
  version: number;
  tensor_count: bigint;
  kv_count: bigint;
  kv: { key: string; type: number; value: unknown }[];
  tensors: { name: string; ndims: number; shape: bigint[]; dtype: number; offset: bigint }[];
}

async function readAll(path: string): Promise<Buffer> {
  const fh = await open(path, "r");
  try { return await fh.readFile(); }
  finally { await fh.close(); }
}

function readStr(buf: Buffer, off: number): { value: string; next: number } {
  const len = Number(buf.readBigUInt64LE(off));
  return { value: buf.subarray(off + 8, off + 8 + len).toString("utf-8"), next: off + 8 + len };
}

function readValue(buf: Buffer, off: number, type: number): { value: unknown; next: number } {
  switch (type) {
    case GGUF_TYPE.U8:  return { value: buf.readUInt8(off), next: off + 1 };
    case GGUF_TYPE.I8:  return { value: buf.readInt8(off), next: off + 1 };
    case GGUF_TYPE.U16: return { value: buf.readUInt16LE(off), next: off + 2 };
    case GGUF_TYPE.I16: return { value: buf.readInt16LE(off), next: off + 2 };
    case GGUF_TYPE.U32: return { value: buf.readUInt32LE(off), next: off + 4 };
    case GGUF_TYPE.I32: return { value: buf.readInt32LE(off), next: off + 4 };
    case GGUF_TYPE.F32: return { value: buf.readFloatLE(off), next: off + 4 };
    case GGUF_TYPE.BOOL: return { value: buf.readUInt8(off) !== 0, next: off + 1 };
    case GGUF_TYPE.STRING: {
      const r = readStr(buf, off);
      return { value: r.value, next: r.next };
    }
    case GGUF_TYPE.U64: return { value: buf.readBigUInt64LE(off).toString(), next: off + 8 };
    case GGUF_TYPE.I64: return { value: buf.readBigInt64LE(off).toString(), next: off + 8 };
    case GGUF_TYPE.F64: return { value: buf.readDoubleLE(off), next: off + 8 };
    case GGUF_TYPE.ARRAY: {
      const elemType = buf.readUInt32LE(off);
      const len = Number(buf.readBigUInt64LE(off + 4));
      let i = off + 12;
      const values: unknown[] = [];
      for (let k = 0; k < len && values.length < 32; k++) {
        const v = readValue(buf, i, elemType);
        values.push(v.value); i = v.next;
      }
      return { value: { kind: "array", elem: elemType, length: len, preview: values }, next: i };
    }
    default: throw new Error(`unsupported GGUF type: ${type}`);
  }
}

export async function parseGguf(path: string, { maxKv = 50, maxTensors = 100 }: { maxKv?: number; maxTensors?: number } = {}): Promise<GgufHeader> {
  const buf = await readAll(path);
  if (buf.readUInt32LE(0) !== GGUF_MAGIC) throw new Error("not a GGUF file");
  const version = buf.readUInt32LE(4);
  const tensor_count = buf.readBigUInt64LE(8);
  const kv_count = buf.readBigUInt64LE(16);
  let off = 24;
  const kv: GgufHeader["kv"] = [];
  for (let i = 0n; i < kv_count; i++) {
    const k = readStr(buf, off); off = k.next;
    const type = buf.readUInt32LE(off); off += 4;
    const v = readValue(buf, off, type); off = v.next;
    if (kv.length < maxKv) kv.push({ key: k.value, type, value: v.value });
  }
  const tensors: GgufHeader["tensors"] = [];
  for (let i = 0n; i < tensor_count; i++) {
    const n = readStr(buf, off); off = n.next;
    const nd = buf.readUInt32LE(off); off += 4;
    const shape: bigint[] = [];
    for (let d = 0; d < nd; d++) { shape.push(buf.readBigUInt64LE(off)); off += 8; }
    const dtype = buf.readUInt32LE(off); off += 4;
    const toff = buf.readBigUInt64LE(off); off += 8;
    if (tensors.length < maxTensors) tensors.push({ name: n.value, ndims: nd, shape, dtype, offset: toff });
  }
  return { magic: "GGUF", version, tensor_count, kv_count, kv, tensors };
}

async function parseSafetensors(path: string, maxTensors = 200): Promise<{ total: number; tensors: { name: string; dtype: string; shape: number[]; data_offsets: [number, number] }[]; metadata?: Record<string, string> }> {
  const fh = await open(path, "r");
  try {
    const sizeBuf = Buffer.alloc(8);
    await fh.read(sizeBuf, 0, 8, 0);
    const headerLen = Number(sizeBuf.readBigUInt64LE(0));
    const headerBuf = Buffer.alloc(headerLen);
    await fh.read(headerBuf, 0, headerLen, 8);
    const header = JSON.parse(headerBuf.toString("utf-8"));
    const metadata = header.__metadata__ as Record<string, string> | undefined;
    const tensors: { name: string; dtype: string; shape: number[]; data_offsets: [number, number] }[] = [];
    for (const [name, meta] of Object.entries(header)) {
      if (name === "__metadata__") continue;
      const t = meta as { dtype: string; shape: number[]; data_offsets: [number, number] };
      if (tensors.length < maxTensors) tensors.push({ name, dtype: t.dtype, shape: t.shape, data_offsets: t.data_offsets });
    }
    return { total: tensors.length, tensors, metadata };
  } finally { await fh.close(); }
}

export function registerGguf(server: McpServer): void {
  server.tool(
    "gguf_header",
    "Parse a GGUF model file's header: magic / version / tensor count + first N key-value metadata entries + first N tensor descriptors. Reads just the header, not the weight bytes.",
    { path: z.string(), maxKv: z.number().min(1).max(500).default(50), maxTensors: z.number().min(1).max(1000).default(100) },
    async ({ path, maxKv, maxTensors }) => {
      requirePathAllowed(path);
      const h = await parseGguf(path, { maxKv, maxTensors });
      const text = [
        `# gguf_header ${path}`,
        `**magic:** ${h.magic}  **version:** ${h.version}  **tensors:** ${h.tensor_count}  **kv entries:** ${h.kv_count}`,
        ``,
        `## metadata (first ${h.kv.length})`,
        ...h.kv.map(k => `- \`${k.key}\` (type ${k.type}) = \`${JSON.stringify(k.value)?.slice(0, 200)}\``),
        ``,
        `## tensors (first ${h.tensors.length})`,
        ...h.tensors.map(t => `- \`${t.name}\` dtype=${t.dtype} shape=[${t.shape.map(String).join(", ")}] offset=${t.offset}`),
      ].join("\n");
      return { content: [{ type: "text" as const, text }] };
    });

  server.tool(
    "safetensors_meta",
    "Parse a .safetensors file's JSON header: __metadata__ + every tensor's dtype / shape / byte offsets.",
    { path: z.string(), maxTensors: z.number().min(1).max(10_000).default(200) },
    async ({ path, maxTensors }) => {
      requirePathAllowed(path);
      const h = await parseSafetensors(path, maxTensors);
      const text = [
        `# safetensors_meta ${path}`,
        `**tensors:** ${h.total}`,
        ``,
        `## __metadata__`,
        ...(h.metadata ? Object.entries(h.metadata).map(([k, v]) => `- ${k}: \`${v}\``) : ["(none)"]),
        ``,
        `## tensors (first ${h.tensors.length})`,
        ...h.tensors.map(t => `- \`${t.name}\` ${t.dtype} shape=[${t.shape.join(", ")}] bytes=${t.data_offsets[1] - t.data_offsets[0]}`),
      ].join("\n");
      return { content: [{ type: "text" as const, text }] };
    });
}
