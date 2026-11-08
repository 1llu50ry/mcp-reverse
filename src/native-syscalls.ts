// ============================================================
// Windows syscall tables — static maps of (build, name) → SSN.
//
// Based on j00ru/windows-syscalls and hfiref0x/SyscallTables.
// We bake a representative slice of Win10 1909, Win10 21H2 and
// Win11 23H2 numbers so agents can translate direct-syscall
// stubs back to NT API names without hitting a browser.
//
// For comprehensive lookups users should pair this with their
// own pulls; the point here is to decode the common 30-40 calls
// malware embeds (NtAllocateVirtualMemory / NtProtect /
// NtCreateThreadEx / NtWriteVirtualMemory / NtReadFile / ...).
//
// Tools:
//   syscall_name    — number → NT name on a given Windows build
//   syscall_number  — name → number on a given Windows build
//   syscall_builds  — list every bundled build + total entries
// ============================================================

import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// A table is a {name: ssn} map. The three builds have slightly
// different numbers for many calls (that's the point of using a
// table instead of a constant).
type Table = Record<string, number>;

// ---- Win10 21H2 (build 19044) x64 — common NT* calls -----------
const WIN10_21H2: Table = {
  "NtAccessCheck": 0x0000,
  "NtWorkerFactoryWorkerReady": 0x0001,
  "NtAcceptConnectPort": 0x0002,
  "NtMapUserPhysicalPagesScatter": 0x0003,
  "NtWaitForSingleObject": 0x0004,
  "NtCallbackReturn": 0x0005,
  "NtReadFile": 0x0006,
  "NtDeviceIoControlFile": 0x0007,
  "NtWriteFile": 0x0008,
  "NtRemoveIoCompletion": 0x0009,
  "NtReleaseSemaphore": 0x000A,
  "NtReplyWaitReceivePort": 0x000B,
  "NtReplyPort": 0x000C,
  "NtSetInformationThread": 0x000D,
  "NtSetEvent": 0x000E,
  "NtClose": 0x000F,
  "NtQueryObject": 0x0010,
  "NtQueryInformationFile": 0x0011,
  "NtOpenKey": 0x0012,
  "NtEnumerateValueKey": 0x0013,
  "NtFindAtom": 0x0014,
  "NtQueryDefaultLocale": 0x0015,
  "NtAllocateVirtualMemory": 0x0018,
  "NtQueryInformationProcess": 0x0019,
  "NtWaitForMultipleObjects32": 0x001A,
  "NtWriteFileGather": 0x001B,
  "NtSetInformationProcess": 0x001C,
  "NtCreateKey": 0x001D,
  "NtFreeVirtualMemory": 0x001E,
  "NtImpersonateClientOfPort": 0x001F,
  "NtReleaseMutant": 0x0020,
  "NtQueryInformationToken": 0x0021,
  "NtRequestWaitReplyPort": 0x0022,
  "NtQueryVirtualMemory": 0x0023,
  "NtOpenThreadToken": 0x0024,
  "NtQueryPerformanceCounter": 0x0031,
  "NtQuerySystemInformation": 0x0036,
  "NtCreateEvent": 0x0048,
  "NtProtectVirtualMemory": 0x0050,
  "NtQuerySection": 0x0051,
  "NtResumeThread": 0x0052,
  "NtTerminateProcess": 0x002C,
  "NtWriteVirtualMemory": 0x003A,
  "NtReadVirtualMemory": 0x003F,
  "NtOpenProcess": 0x0026,
  "NtOpenThread": 0x0025,
  "NtCreateThreadEx": 0x00C1,
  "NtCreateUserProcess": 0x00C8,
  "NtMapViewOfSection": 0x0028,
  "NtUnmapViewOfSection": 0x002A,
  "NtCreateSection": 0x004A,
  "NtOpenSection": 0x0037,
  "NtQueueApcThread": 0x0045,
  "NtQueueApcThreadEx": 0x00B2,
  "NtDelayExecution": 0x0034,
  "NtSetContextThread": 0x019C,
  "NtGetContextThread": 0x00ED,
  "NtSuspendThread": 0x019E,
};

// ---- Win11 23H2 (build 22631) x64 — same APIs, drifted ---------
// (For brevity we only ship the ones that commonly differ.)
const WIN11_23H2: Table = {
  ...WIN10_21H2,
  "NtAllocateVirtualMemory":   0x0018,  // stable for this call
  "NtProtectVirtualMemory":    0x0050,
  "NtWriteVirtualMemory":      0x003A,
  "NtReadVirtualMemory":       0x003F,
  "NtCreateThreadEx":          0x00C2,  // drifted +1
  "NtCreateUserProcess":       0x00CA,  // drifted +2
  "NtAllocateVirtualMemoryEx": 0x0073,  // only on Win11
  "NtQueryInformationProcess": 0x0019,
  "NtTerminateProcess":        0x002C,
  "NtOpenProcess":             0x0026,
  "NtMapViewOfSectionEx":      0x0109,  // Win11 only
  "NtUnmapViewOfSectionEx":    0x010A,
};

// ---- Win10 1909 (build 18363) x64 — older baseline -------------
const WIN10_1909: Table = {
  ...WIN10_21H2,
  "NtAllocateVirtualMemory":   0x0018,
  "NtProtectVirtualMemory":    0x0050,
  "NtCreateThreadEx":          0x00BC,  // 1909 was earlier
  "NtWriteVirtualMemory":      0x003A,
  "NtReadVirtualMemory":       0x003F,
  "NtCreateUserProcess":       0x00C2,
};

const TABLES: Record<string, Table> = {
  "win10-1909": WIN10_1909,
  "win10-21h2": WIN10_21H2,
  "win11-23h2": WIN11_23H2,
};

type Build = keyof typeof TABLES;

export function registerSyscalls(server: McpServer): void {
  server.tool(
    "syscall_name",
    "Resolve a Windows syscall number (SSN) → NT* API name on a given build. Use when a sample's direct-syscall stub embeds just the number.",
    { build: z.enum(Object.keys(TABLES) as [Build, ...Build[]]).default("win10-21h2"), ssn: z.string() },
    async ({ build, ssn }) => {
      const n = Number(BigInt(ssn));
      const table = TABLES[build];
      const hits = Object.entries(table).filter(([_, v]) => v === n).map(([k]) => k);
      return { content: [{ type: "text" as const, text:
        `# syscall_name ${build} 0x${n.toString(16)}\n\n` +
        (hits.length ? hits.map(h => `- ${h}`).join("\n") : "(no match; try a different build or extend the bundled table)")
      }] };
    });

  server.tool(
    "syscall_number",
    "Look up the SSN for an NT* API on a given Windows build.",
    { build: z.enum(Object.keys(TABLES) as [Build, ...Build[]]).default("win10-21h2"), name: z.string() },
    async ({ build, name }) => {
      const table = TABLES[build];
      const ssn = table[name];
      return { content: [{ type: "text" as const, text:
        `# syscall_number ${build} ${name}\n\n` +
        (ssn !== undefined ? `**0x${ssn.toString(16).padStart(4, "0")}** (${ssn})` : "(not in bundled table)")
      }] };
    });

  server.tool(
    "syscall_builds",
    "List every Windows build this server bundles tables for, with the entry count.",
    {},
    async () => {
      const text = Object.entries(TABLES).map(([k, t]) => `- **${k}** — ${Object.keys(t).length} entries`).join("\n");
      return { content: [{ type: "text" as const, text: `# syscall_builds\n\n${text}` }] };
    });
}
