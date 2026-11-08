// ============================================================
// PE Authenticode certificate extractor.
//
// The Certificate Table is data directory index 4 of the PE
// optional header. Its payload is a sequence of WIN_CERTIFICATE
// entries (dwLength LE, wRevision LE16, wCertType LE16, bytes[])
// where wCertType == 0x0002 means PKCS#7 signedData. The PKCS#7
// blob contains the X.509 cert chain + the actual signature.
//
// We don't verify the signature here (that needs a PKI chain and
// time-stamp trust); we just extract:
//   - the raw WIN_CERTIFICATE entries
//   - the signer certificate's Common Name + issuer + serial
//     (parsed minimally from the DER)
//
// Tools:
//   pe_authenticode  — enumerate WIN_CERTIFICATE entries
//   pe_signer_cn     — surface the first signer's CN + issuer + serial
// ============================================================

import { z } from "zod";
import { readFile } from "node:fs/promises";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { requirePathAllowed } from "./fs-sandbox.js";

interface WinCertEntry { length: number; revision: number; type: number; off: number; der: Uint8Array }

export function readCertTable(buf: Buffer): WinCertEntry[] {
  if (buf.length < 0x40 || buf[0] !== 0x4D || buf[1] !== 0x5A) return [];
  const peOff = buf.readUInt32LE(0x3C);
  if (peOff + 24 >= buf.length || buf.readUInt32LE(peOff) !== 0x00004550) return [];
  const magic = buf.readUInt16LE(peOff + 24);
  const is64 = magic === 0x20B;
  const dataDirs = peOff + 24 + (is64 ? 112 : 96);
  const certRva = buf.readUInt32LE(dataDirs + 4 * 8);       // Note: cert table uses file offset, not RVA
  const certSize = buf.readUInt32LE(dataDirs + 4 * 8 + 4);
  if (!certRva || !certSize) return [];
  const out: WinCertEntry[] = [];
  let off = certRva;
  const end = Math.min(certRva + certSize, buf.length);
  while (off + 8 <= end) {
    const length = buf.readUInt32LE(off);
    if (length < 8 || off + length > end) break;
    const revision = buf.readUInt16LE(off + 4);
    const type = buf.readUInt16LE(off + 6);
    const der = buf.subarray(off + 8, off + length);
    out.push({ length, revision, type, off, der: new Uint8Array(der) });
    off += length;
    if (off % 8) off += 8 - (off % 8);
  }
  return out;
}

// Tiny DER reader that recognises the common OIDs we need.
function derReadTLV(buf: Uint8Array, off: number): { tag: number; length: number; valueOff: number; nextOff: number } | null {
  if (off >= buf.length) return null;
  const tag = buf[off];
  let len = buf[off + 1];
  let lenBytes = 1;
  if (len & 0x80) {
    const n = len & 0x7F;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[off + 2 + i];
    lenBytes = 1 + n;
  }
  return { tag, length: len, valueOff: off + 1 + lenBytes, nextOff: off + 1 + lenBytes + len };
}

/** Find the first X509 certificate's commonName field. */
export function pickSignerIdentity(der: Uint8Array): { cn?: string; serial?: string; issuerCn?: string } {
  // PKCS#7 SignedData -> SET of CertificateChoices -> X509 TBS
  // We just search for `OID commonName (2.5.4.3)` DER pattern
  // 06 03 55 04 03 followed by `UTF8String | PrintableString`.
  const needle = Buffer.from([0x06, 0x03, 0x55, 0x04, 0x03]);
  const idxs: number[] = [];
  const b = Buffer.from(der);
  let p = 0;
  while ((p = b.indexOf(needle, p)) !== -1 && idxs.length < 10) { idxs.push(p); p += needle.length; }
  const out: { cn?: string; serial?: string; issuerCn?: string } = {};
  for (let i = 0; i < idxs.length; i++) {
    const off = idxs[i] + needle.length;
    const tlv = derReadTLV(der, off);
    if (!tlv) continue;
    if (tlv.tag === 0x0C || tlv.tag === 0x13 || tlv.tag === 0x16) {
      const cn = Buffer.from(der.slice(tlv.valueOff, tlv.valueOff + tlv.length)).toString("utf-8");
      if (i === 0) out.issuerCn = cn;
      else if (i === 1) out.cn = cn;
    }
  }
  // Serial: INTEGER right after `TBSCertificate` version — we skip
  // a proper parse and just note the first INTEGER tag inside the DER.
  const firstInt = Buffer.from(der).indexOf(Buffer.from([0x02]));
  if (firstInt > 0) {
    const tlv = derReadTLV(der, firstInt);
    if (tlv) out.serial = Buffer.from(der.slice(tlv.valueOff, tlv.valueOff + tlv.length)).toString("hex");
  }
  return out;
}

export function registerAuthenticode(server: McpServer): void {
  server.tool(
    "pe_authenticode",
    "Enumerate WIN_CERTIFICATE entries in a PE's Security Directory (data dir #4). Returns per-entry length / revision / type (0x0002 = PKCS#7).",
    { path: z.string() },
    async ({ path }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const entries = readCertTable(buf);
      const text = [
        `# pe_authenticode ${path}`,
        `**entries:** ${entries.length}`,
        ``,
        ...entries.map(e => `- @ 0x${e.off.toString(16)} length=${e.length} revision=${e.revision} type=0x${e.type.toString(16)} (${e.type === 2 ? "PKCS#7 signedData" : "unknown"})`),
      ].join("\n");
      return { content: [{ type: "text" as const, text }] };
    });

  server.tool(
    "pe_signer_cn",
    "Decode the first Authenticode signer's Common Name + issuer + serial from the PKCS#7 cert chain.",
    { path: z.string() },
    async ({ path }) => {
      requirePathAllowed(path);
      const buf = await readFile(path);
      const entries = readCertTable(buf);
      const first = entries.find(e => e.type === 2);
      if (!first) return { content: [{ type: "text" as const, text: `# pe_signer_cn\n\nno PKCS#7 WIN_CERTIFICATE entry in ${path}` }] };
      const id = pickSignerIdentity(first.der);
      return { content: [{ type: "text" as const, text:
        `# pe_signer_cn ${path}\n\n` +
        `- **CN:** ${id.cn ?? "(not found)"}\n` +
        `- **Issuer CN:** ${id.issuerCn ?? "(not found)"}\n` +
        `- **Serial:** ${id.serial ?? "(not found)"}`
      }] };
    });
}
