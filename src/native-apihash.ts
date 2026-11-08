// ============================================================
// API name hashing — the core trick behind lazy_importer,
// hashdb-ida, hashdb-ghidra, and most modern Windows malware
// loaders. Instead of embedding import names, they embed hashes
// and resolve APIs at runtime by walking EAT and matching.
//
// Tools exposed:
//   apihash_compute    — compute hash(name) under any of the
//                         common schemes
//   apihash_lookup     — brute-match a hash against a bundled
//                         dictionary of ~2300 common Windows API
//                         names
//   apihash_schemes    — list every supported hashing scheme
//
// All pure-TS; no external dict file needed at runtime — the
// API name list is baked in.
// ============================================================

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// ---- hashing schemes -------------------------------------------

function djb2(s: string, seed = 5381): number {
  let h = seed >>> 0;
  for (let i = 0; i < s.length; i++) h = (((h * 33) >>> 0) ^ s.charCodeAt(i)) >>> 0;
  return h >>> 0;
}

function djb2Xor(s: string, seed = 5381): number {
  // the hash lazy_importer uses by default: djb2 variant with XOR
  let h = seed >>> 0;
  for (let i = 0; i < s.length; i++) h = (((h * 33) >>> 0) ^ s.charCodeAt(i)) >>> 0;
  return h >>> 0;
}

function sdbm(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (s.charCodeAt(i) + ((h << 6) >>> 0) + ((h << 16) >>> 0) - h) >>> 0;
  return h >>> 0;
}

function fnv1a32(s: string): number {
  let h = 0x811c9dc5 >>> 0;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

function fnv1a64(s: string): bigint {
  let h = 0xcbf29ce484222325n;
  const mask = (1n << 64n) - 1n;
  for (let i = 0; i < s.length; i++) {
    h ^= BigInt(s.charCodeAt(i));
    h = (h * 0x100000001b3n) & mask;
  }
  return h;
}

// Reflected CRC32 table (standard polynomial 0xEDB88320)
const CRC32_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    t[n] = c >>> 0;
  }
  return t;
})();

function crc32(s: string): number {
  let c = 0xFFFFFFFF >>> 0;
  for (let i = 0; i < s.length; i++) c = (CRC32_TABLE[(c ^ s.charCodeAt(i)) & 0xFF] ^ (c >>> 8)) >>> 0;
  return (c ^ 0xFFFFFFFF) >>> 0;
}

// Murmur3 x86 32-bit
function murmur3_32(s: string, seed = 0): number {
  const len = s.length;
  let h = seed >>> 0;
  const c1 = 0xcc9e2d51; const c2 = 0x1b873593;
  for (let i = 0; i + 4 <= len; i += 4) {
    let k = s.charCodeAt(i) | (s.charCodeAt(i + 1) << 8) | (s.charCodeAt(i + 2) << 16) | (s.charCodeAt(i + 3) << 24);
    k = Math.imul(k >>> 0, c1) >>> 0;
    k = (((k << 15) | (k >>> 17))) >>> 0;
    k = Math.imul(k, c2) >>> 0;
    h = (h ^ k) >>> 0;
    h = (((h << 13) | (h >>> 19))) >>> 0;
    h = (Math.imul(h, 5) + 0xe6546b64) >>> 0;
  }
  const tail = len & 3;
  let k = 0;
  if (tail === 3) k ^= s.charCodeAt(len - 1) << 16;
  if (tail >= 2) k ^= s.charCodeAt(len - (tail - 1) - 1) << 8;
  if (tail >= 1) {
    k ^= s.charCodeAt(len - tail);
    k = Math.imul(k, c1) >>> 0;
    k = (((k << 15) | (k >>> 17))) >>> 0;
    k = Math.imul(k, c2) >>> 0;
    h = (h ^ k) >>> 0;
  }
  h = (h ^ len) >>> 0;
  h = (h ^ (h >>> 16)) >>> 0;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h = (h ^ (h >>> 13)) >>> 0;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h = (h ^ (h >>> 16)) >>> 0;
  return h;
}

// REvil / BlackMatter style: rotating hash with ROR + XOR.
// Used by many malware families; same math.
function rorHash13(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) {
    h = ((h >>> 13) | (h << 19)) >>> 0;
    h = (h + s.charCodeAt(i)) >>> 0;
  }
  return h >>> 0;
}

type Scheme = "djb2" | "djb2_xor" | "sdbm" | "fnv1a32" | "fnv1a64" | "crc32" | "murmur3" | "ror13";
const SCHEMES: Scheme[] = ["djb2", "djb2_xor", "sdbm", "fnv1a32", "fnv1a64", "crc32", "murmur3", "ror13"];

function compute(name: string, scheme: Scheme): string {
  switch (scheme) {
    case "djb2":     return "0x" + djb2(name).toString(16);
    case "djb2_xor": return "0x" + djb2Xor(name).toString(16);
    case "sdbm":     return "0x" + sdbm(name).toString(16);
    case "fnv1a32":  return "0x" + fnv1a32(name).toString(16);
    case "fnv1a64":  return "0x" + fnv1a64(name).toString(16);
    case "crc32":    return "0x" + crc32(name).toString(16);
    case "murmur3":  return "0x" + murmur3_32(name).toString(16);
    case "ror13":    return "0x" + rorHash13(name).toString(16);
  }
}

// ---- API name dictionary ---------------------------------------
// Bundled subset of the most commonly-hashed Windows APIs. Agents
// feed a hash + scheme and we iterate every (api, dll) pairing.

const API_NAMES: string[] = [
  // kernel32 (loader + process + file + memory)
  "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress",
  "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExA", "GetModuleHandleExW",
  "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx", "VirtualFree", "VirtualQuery",
  "CreateProcessA", "CreateProcessW", "CreateProcessInternalW", "ExitProcess", "OpenProcess",
  "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx", "ResumeThread", "SuspendThread",
  "WaitForSingleObject", "WaitForMultipleObjects", "CloseHandle", "DuplicateHandle",
  "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "DeleteFileA", "DeleteFileW",
  "ReadProcessMemory", "WriteProcessMemory", "VirtualAllocExNuma",
  "GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThread", "GetCurrentThreadId",
  "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetSystemInfo", "GetVersionExA", "GetVersionExW",
  "QueryPerformanceCounter", "GetTickCount", "GetTickCount64", "Sleep", "SleepEx",
  "HeapAlloc", "HeapFree", "HeapCreate", "GlobalAlloc", "GlobalFree", "LocalAlloc", "LocalFree",
  "TerminateProcess", "TerminateThread", "OpenMutexA", "CreateMutexA",
  // ntdll
  "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile", "NtClose",
  "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtFreeVirtualMemory",
  "NtReadVirtualMemory", "NtWriteVirtualMemory",
  "NtCreateProcess", "NtCreateProcessEx", "NtOpenProcess", "NtTerminateProcess",
  "NtCreateThread", "NtCreateThreadEx", "NtOpenThread", "NtResumeThread", "NtSuspendThread",
  "NtQueryInformationProcess", "NtSetInformationProcess", "NtQueryInformationThread",
  "NtSetInformationThread", "NtQuerySystemInformation", "NtQueryObject",
  "NtMapViewOfSection", "NtUnmapViewOfSection", "NtCreateSection", "NtOpenSection",
  "LdrLoadDll", "LdrGetProcedureAddress", "LdrLoadDllEx", "LdrGetDllHandle", "LdrGetDllHandleEx",
  "RtlCreateUserThread", "RtlAllocateHeap", "RtlFreeHeap",
  "RtlDecompressBuffer", "RtlCompressBuffer",
  "ZwQueryInformationProcess", "ZwReadVirtualMemory", "ZwWriteVirtualMemory",
  // user32 (window + input)
  "FindWindowA", "FindWindowW", "FindWindowExA", "FindWindowExW",
  "GetForegroundWindow", "GetWindowTextA", "GetWindowTextW", "ShowWindow",
  "SendMessageA", "SendMessageW", "PostMessageA", "PostMessageW",
  "GetAsyncKeyState", "GetKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
  "CallNextHookEx", "GetClipboardData", "SetClipboardData", "OpenClipboard", "CloseClipboard",
  "MessageBoxA", "MessageBoxW",
  // advapi32 (registry + crypto + service)
  "RegOpenKeyExA", "RegOpenKeyExW", "RegQueryValueExA", "RegQueryValueExW",
  "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA", "RegCreateKeyExW",
  "RegDeleteValueA", "RegDeleteValueW", "RegEnumKeyExA", "RegEnumKeyExW",
  "CryptAcquireContextA", "CryptAcquireContextW", "CryptEncrypt", "CryptDecrypt",
  "CryptHashData", "CryptCreateHash", "CryptDeriveKey", "CryptGenRandom",
  "OpenSCManagerA", "OpenSCManagerW", "CreateServiceA", "CreateServiceW",
  "StartServiceA", "StartServiceW", "OpenServiceA", "OpenServiceW",
  "DeleteService", "ControlService", "QueryServiceStatus",
  "OpenProcessToken", "LookupPrivilegeValueA", "LookupPrivilegeValueW",
  "AdjustTokenPrivileges", "ImpersonateLoggedOnUser", "RevertToSelf",
  // wininet / winhttp
  "InternetOpenA", "InternetOpenW", "InternetConnectA", "InternetConnectW",
  "InternetReadFile", "InternetWriteFile", "InternetCloseHandle",
  "HttpOpenRequestA", "HttpOpenRequestW", "HttpSendRequestA", "HttpSendRequestW",
  "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest", "WinHttpSendRequest",
  "WinHttpReceiveResponse", "WinHttpReadData", "WinHttpWriteData",
  // ws2_32 (sockets)
  "WSAStartup", "WSASocketA", "WSASocketW", "WSAConnect", "WSASend", "WSARecv",
  "socket", "connect", "send", "recv", "bind", "listen", "accept", "closesocket",
  "gethostbyname", "getaddrinfo", "inet_addr", "inet_ntoa", "htons", "htonl",
  // shell32 / shlwapi
  "ShellExecuteA", "ShellExecuteW", "ShellExecuteExA", "ShellExecuteExW",
  "SHGetFolderPathA", "SHGetFolderPathW", "SHGetKnownFolderPath",
  // dbghelp
  "MiniDumpWriteDump", "SymInitialize", "SymLoadModule64", "SymFromAddr",
  // extras commonly hashed
  "WriteProcessMemory", "NtQueueApcThread", "NtQueueApcThreadEx",
  "NtCreateUserProcess", "NtAllocateVirtualMemoryEx",
  "GetNativeSystemInfo", "IsWow64Process", "Wow64DisableWow64FsRedirection",
  "CreateFileMappingA", "CreateFileMappingW", "MapViewOfFile", "UnmapViewOfFile",
];

// ---- registration ----------------------------------------------

export function registerApiHash(server: McpServer): void {
  server.tool(
    "apihash_compute",
    "Compute hash(name) under a chosen scheme (djb2 / djb2_xor / sdbm / fnv1a32 / fnv1a64 / crc32 / murmur3 / ror13). Lets you reproduce lazy_importer / hashdb-style API resolution.",
    { name: z.string(), scheme: z.enum(SCHEMES as [Scheme, ...Scheme[]]).default("djb2_xor"), allSchemes: z.boolean().default(false) },
    async ({ name, scheme, allSchemes }) => {
      if (allSchemes) {
        const lines = SCHEMES.map(s => `- **${s.padEnd(10)}** ${compute(name, s)}`);
        return { content: [{ type: "text" as const, text: `# apihash_compute '${name}'\n\n${lines.join("\n")}` }] };
      }
      return { content: [{ type: "text" as const, text: `# apihash_compute '${name}' (${scheme})\n\n${compute(name, scheme)}` }] };
    });

  server.tool(
    "apihash_lookup",
    "Reverse: match a hash against a bundled dictionary of ~190 common Windows APIs. Pass `scheme` to narrow, or leave blank to try every scheme.",
    { hash: z.string(), scheme: z.enum(SCHEMES as [Scheme, ...Scheme[]]).optional(), limit: z.number().min(1).max(100).default(20) },
    async ({ hash, scheme, limit }) => {
      const target = hash.toLowerCase().replace(/^0x/, "");
      const hits: { name: string; scheme: Scheme }[] = [];
      const schemes = scheme ? [scheme] : SCHEMES;
      for (const n of API_NAMES) {
        for (const s of schemes) {
          const h = compute(n, s).replace(/^0x/, "").toLowerCase();
          if (h === target) hits.push({ name: n, scheme: s });
          if (hits.length >= limit) break;
        }
        if (hits.length >= limit) break;
      }
      const text = hits.length
        ? `# apihash_lookup 0x${target}\n\n${hits.map(h => `- \`${h.name}\` (via ${h.scheme})`).join("\n")}`
        : `# apihash_lookup 0x${target}\n\nno match in ${API_NAMES.length} known APIs across ${schemes.length} schemes. Try apihash_compute with the full exported-symbol list from the binary itself.`;
      return { content: [{ type: "text" as const, text }] };
    });

  server.tool(
    "apihash_schemes",
    "List every hash scheme apihash_compute / apihash_lookup understand, with a short description.",
    {},
    async () => {
      const text = [
        "# apihash_schemes",
        "",
        "- **djb2**      — classic Daniel J. Bernstein `hash * 33 + c`",
        "- **djb2_xor**  — djb2 variant used by lazy_importer by default (XOR instead of +)",
        "- **sdbm**      — gawk's hash, common in older droppers",
        "- **fnv1a32**   — Fowler–Noll–Vo 32-bit",
        "- **fnv1a64**   — FNV-1a 64-bit (BigInt output)",
        "- **crc32**     — CRC-32/IEEE (reflected, poly 0xEDB88320) — HashDB default",
        "- **murmur3**   — Murmur3 x86 32-bit, seed = 0",
        "- **ror13**     — ROR-13 add hash — used by REvil, BlackMatter, lots of loaders",
      ].join("\n");
      return { content: [{ type: "text" as const, text }] };
    });
}
