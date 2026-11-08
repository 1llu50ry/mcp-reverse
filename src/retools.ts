// ============================================================
// RE/DEBUG MCP INTEGRATIONS
//
// Register MCP tools that let a client:
//   - list every supported RE/debug MCP backend and the native CLIs
//     this project knows how to drive (ghidra, ida, x64dbg, cheat
//     engine, frida, radare2, binary ninja, windbg, hopper, rea,
//     vibe-re, superghidra, ...)
//   - get the exact install command, launch command, and Claude /
//     Cursor / Codex MCP config snippet for each
//   - spawn the backend as a managed child process (and later kill
//     or query it)
//   - proxy a request to a running backend's HTTP endpoint (when the
//     backend exposes HTTP, e.g. x64dbg-mcp-server, pyghidra-mcp,
//     superghidra, radare2 r2pipe-mcp)
// ============================================================

import { spawn, type ChildProcess } from "node:child_process";
import { readFile, access } from "node:fs/promises";
import { constants as fsConstants } from "node:fs";
import { join } from "node:path";
import { z } from "zod";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";

// ------------------------------------------------------------
// Types
// ------------------------------------------------------------

export type ReBackendId =
  | "ghidra-mcp"
  | "superghidra-mcp"
  | "ida-pro-mcp-hexrays"
  | "binary-ninja-mcp"
  | "radare2-mcp"
  | "x64dbg-mcp"
  | "windbg-mcp"
  | "cheat-engine-mcp"
  | "frida-mcp"
  | "hopper-mcp"
  | "rea"
  | "jadx-mcp"
  | "angr-mcp"
  | "capstone-mcp"
  | "pcileech-mcp"
  | "memflow-mcp"
  | "scylla-mcp"
  | "dnspy-mcp"
  | "reclass-mcp"
  | "volatility-mcp"
  | "wireshark-mcp"
  | "mitmproxy-mcp"
  | "dotpeek-mcp"
  | "unicorn-mcp"
  | "pyghidra-mcp-gui"
  | "retsync-mcp"
  | "ghidrathon-mcp"
  | "bindiff-mcp"
  | "diaphora-mcp"
  | "qiling-mcp"
  | "unidbg-mcp"
  | "openreality-mcp"
  | "qemu-trace-mcp"
  | "lldb-mcp"
  | "gdb-mcp"
  | "burp-mcp"
  | "yara-mcp"
  | "clrmd-mcp"
  | "ba-sync-mcp"
  | "dolphin-dme-mcp"
  | "cemu-ipc-mcp"
  | "ollydbg-mcp"
  | "aflplusplus-mcp"
  | "honggfuzz-mcp"
  | "libafl-mcp"
  | "winafl-mcp"
  | "v8-inspector-mcp"
  | "cdp-mcp"
  | "idevice-mcp"
  | "adb-mcp"
  | "magisk-mcp"
  | "kdnet-mcp"
  | "gef-mcp"
  | "pwndbg-mcp"
  | "retdec-mcp"
  | "snowman-mcp"
  ;

export interface ReBackend {
  id: ReBackendId;
  name: string;
  kind: "static" | "dynamic" | "both";
  os: ("windows" | "linux" | "macos")[];
  requires: string;
  install: string[];
  launch: {
    cmd: string;
    args: string[];
    cwd?: string;
    env?: Record<string, string>;
    http?: { port: number; path?: string };
  };
  mcpConfig: Record<string, unknown>;
  tags: string[];
  notes: string;
}

interface RunningProc {
  backend: ReBackendId;
  pid: number;
  startedAt: number;
  logTail: string[];
  child: ChildProcess;
}

// ------------------------------------------------------------
// Backend catalog
// ------------------------------------------------------------

const BACKENDS: Record<ReBackendId, ReBackend> = {
  "ghidra-mcp": {
    id: "ghidra-mcp",
    name: "GhidraMCP (LaurieWired)",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Ghidra 11+ with the GhidraMCP extension installed (loads a Jetty HTTP server inside the Ghidra JVM on port 8080 by default).",
    install: [
      "git clone https://github.com/LaurieWired/GhidraMCP",
      "copy GhidraMCP.zip to <ghidra>/Extensions/Ghidra, then File > Install Extensions in the Ghidra GUI",
      "install the Python bridge: `pip install mcp-ghidra`",
    ],
    launch: {
      cmd: "python",
      args: ["-m", "ghidra_mcp"],
      http: { port: 8080, path: "/" },
    },
    mcpConfig: {
      "ghidra-mcp": {
        command: "python",
        args: ["-m", "ghidra_mcp"],
      },
    },
    tags: ["ghidra", "static", "decompile", "xref"],
    notes: "First-generation Ghidra MCP. Ghidra GUI must be running for the plugin to respond.",
  },
  "superghidra-mcp": {
    id: "superghidra-mcp",
    name: "SuperghidraMCP (pyghidra-mcp)",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Python 3.10+, Ghidra 11/12, OpenJDK 21.",
    install: [
      "pip install pyghidra-mcp",
      "set GHIDRA_INSTALL_DIR to the Ghidra install path",
    ],
    launch: {
      cmd: "pyghidra-mcp",
      args: ["--transport", "streamable-http"],
      http: { port: 8765, path: "/mcp" },
    },
    mcpConfig: {
      "superghidra-mcp": {
        command: "pyghidra-mcp",
        args: ["--transport", "stdio"],
        env: { GHIDRA_INSTALL_DIR: "<path-to-ghidra>" },
      },
    },
    tags: ["ghidra", "pyghidra", "chromadb", "semantic-search", "static", "project-wide"],
    notes: "38-tool server; semantic code search over decompiled functions. --gui attaches to a live Ghidra GUI session.",
  },
  "ida-pro-mcp-hexrays": {
    id: "ida-pro-mcp-hexrays",
    name: "Hex-Rays Official IDA MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "IDA Pro 9+.",
    install: [
      "download from https://github.com/HexRaysSA/ida-mcp",
      "place inside IDA's plugins directory per the Hex-Rays blog post",
    ],
    launch: {
      cmd: "ida-mcp",
      args: [],
    },
    mcpConfig: {
      "ida-mcp": {
        command: "ida-mcp",
        args: [],
      },
    },
    tags: ["ida", "hex-rays", "static", "official"],
    notes: "Vendor-supported. Preferred when available.",
  },
  "binary-ninja-mcp": {
    id: "binary-ninja-mcp",
    name: "Binary Ninja MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Binary Ninja (commercial or free). Python 3.10+.",
    install: [
      "pip install binaryninja-mcp",
      "load the Binja plugin via Plugin Manager (search 'MCP')",
    ],
    launch: {
      cmd: "python",
      args: ["-m", "binaryninja_mcp"],
      http: { port: 9009 },
    },
    mcpConfig: {
      "binary-ninja-mcp": {
        command: "python",
        args: ["-m", "binaryninja_mcp"],
      },
    },
    tags: ["binja", "static", "decompile", "hlil"],
    notes: "Exposes HLIL/MLIR/LLIL via MCP. Needs an open BNDB.",
  },
  "radare2-mcp": {
    id: "radare2-mcp",
    name: "radare2 MCP (r2mcp / r2pipe-mcp)",
    kind: "both",
    os: ["windows", "linux", "macos"],
    requires: "radare2 >= 5.9 on PATH. Node 18+ or Python 3.10+.",
    install: [
      "npm install -g r2mcp",
      "OR: pip install r2pipe-mcp",
    ],
    launch: {
      cmd: "r2mcp",
      args: [],
    },
    mcpConfig: {
      "radare2-mcp": {
        command: "r2mcp",
        args: [],
      },
    },
    tags: ["r2", "radare2", "static", "dynamic"],
    notes: "r2 is scriptable, free, and bundled with vibe-re under tools/vendor/vibe-re/tools.",
  },
  "x64dbg-mcp": {
    id: "x64dbg-mcp",
    name: "x64dbg MCP Server (duty1g)",
    kind: "dynamic",
    os: ["windows"],
    requires: "x64dbg (snapshot >= Sep 2024). The plugin DLL from the x64dbg-mcp-server release.",
    install: [
      "download the latest x64dbg-mcp-server release",
      "copy x64dbg-mcp-server.dp64 to <x64dbg>/x64/plugins (and .dp32 under x32)",
      "start x64dbg; the plugin listens on http://127.0.0.1:5566 by default",
    ],
    launch: {
      cmd: "echo",
      args: ["x64dbg plugin -- launch x64dbg itself, plugin boots with it"],
      http: { port: 5566 },
    },
    mcpConfig: {
      "x64dbg-mcp": {
        url: "http://127.0.0.1:5566/mcp",
      },
    },
    tags: ["x64dbg", "dynamic", "debugger", "windows"],
    notes: "SSE for push events; HTTP long-poll via WaitForEvent. Always call GetDebugState before any action.",
  },
  "windbg-mcp": {
    id: "windbg-mcp",
    name: "WinDbg MCP (via dbgeng.dll bridge)",
    kind: "dynamic",
    os: ["windows"],
    requires: "WinDbg (Windows SDK) or WinDbg Preview, Python 3.11+, pywin32.",
    install: [
      "pip install windbg-mcp (community package) or install Microsoft's dbgeng Python bridge",
      "configure symbol server: _NT_SYMBOL_PATH=srv*c:/symbols*https://msdl.microsoft.com/download/symbols",
    ],
    launch: {
      cmd: "windbg-mcp",
      args: [],
    },
    mcpConfig: {
      "windbg-mcp": {
        command: "windbg-mcp",
        args: [],
      },
    },
    tags: ["windbg", "kernel-debug", "dynamic", "windows", "crash-dump"],
    notes: "Primary for KM debugging and crash-dump postmortem. Pair with the `kernel` subagents and the `windows-internals-agent`.",
  },
  "cheat-engine-mcp": {
    id: "cheat-engine-mcp",
    name: "Cheat Engine MCP (Lua bridge)",
    kind: "both",
    os: ["windows", "linux", "macos"],
    requires: "Cheat Engine 7.5+ with the ceserver/ceserver-lua Lua extension.",
    install: [
      "install Cheat Engine 7.5+",
      "install the ceserver-lua MCP bridge plugin (community: github.com/CheatEngineHub/ce-mcp-bridge)",
      "enable Lua console scripting in CE Edit > Settings > Extra",
    ],
    launch: {
      cmd: "ceserver",
      args: ["--mcp"],
      http: { port: 52736 },
    },
    mcpConfig: {
      "cheat-engine-mcp": {
        command: "ceserver",
        args: ["--mcp"],
      },
    },
    tags: ["cheat-engine", "dynamic", "static", "aob", "pointer-scan"],
    notes: "Exposes AoB scan, pointer scan, assembler, Lua eval, process attach, speedhack through MCP tools.",
  },
  "frida-mcp": {
    id: "frida-mcp",
    name: "Frida MCP (frida-mcp-bridge)",
    kind: "dynamic",
    os: ["windows", "linux", "macos"],
    requires: "frida-tools >= 12 on PATH, Python 3.10+.",
    install: [
      "pip install frida-tools",
      "pip install frida-mcp",
    ],
    launch: {
      cmd: "frida-mcp",
      args: [],
    },
    mcpConfig: {
      "frida-mcp": {
        command: "frida-mcp",
        args: [],
      },
    },
    tags: ["frida", "dynamic", "instrumentation", "android", "ios", "javascript"],
    notes: "Attach by pid/name/USB. Exposes Interceptor.attach, Memory.scan, Objective-C/Java bridges through MCP tools.",
  },
  "hopper-mcp": {
    id: "hopper-mcp",
    name: "Hopper Disassembler MCP",
    kind: "static",
    os: ["macos", "linux"],
    requires: "Hopper v4 or v5 (commercial), its Python scripting runtime.",
    install: [
      "Hopper > File > Install Hopper Plugin > hopper-mcp.py",
      "pip install hopper-mcp",
    ],
    launch: {
      cmd: "hopper-mcp",
      args: [],
    },
    mcpConfig: {
      "hopper-mcp": {
        command: "hopper-mcp",
        args: [],
      },
    },
    tags: ["hopper", "static", "arm", "macos", "ios"],
    notes: "Hopper excels on ARM / Mach-O. Preferred backend for iOS and macOS game work.",
  },
  "rea": {
    id: "rea",
    name: "REA (Reverse Engineer Anything)",
    kind: "both",
    os: ["windows", "linux", "macos"],
    requires: "Node.js 18+. For native targets: an existing Hopper, Ghidra, or IDA install.",
    install: [
      "npx rea-agents setup   # interactive setup",
      "npm install -g rea-agents",
    ],
    launch: {
      cmd: "rea",
      args: ["mcp"],
    },
    mcpConfig: {
      rea: {
        command: "npx",
        args: ["-y", "rea-agents@latest", "mcp"],
      },
    },
    tags: ["cross-tool", "electron", "javascript", "dotnet", "native"],
    notes: "Native + JavaScript/Electron + .NET + websites in one MCP. Dispatches to the configured backend (Hopper/Ghidra/IDA).",
  },
  "jadx-mcp": {
    id: "jadx-mcp",
    name: "JADX MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "JADX 1.5+ on PATH, Java 11+.",
    install: [
      "download JADX from https://github.com/skylot/jadx/releases",
      "pip install jadx-mcp",
    ],
    launch: {
      cmd: "jadx-mcp",
      args: [],
    },
    mcpConfig: {
      "jadx-mcp": {
        command: "jadx-mcp",
        args: [],
      },
    },
    tags: ["android", "dex", "apk", "java", "static"],
    notes: "Primary for Android app RE. Pair with the android-researcher agent and the apk-reverse skill.",
  },
  "angr-mcp": {
    id: "angr-mcp",
    name: "angr MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Python 3.10+, angr >= 9.2.",
    install: [
      "pip install angr angr-mcp",
    ],
    launch: {
      cmd: "angr-mcp",
      args: [],
    },
    mcpConfig: {
      "angr-mcp": {
        command: "angr-mcp",
        args: [],
      },
    },
    tags: ["symbolic-execution", "static", "deobfuscation"],
    notes: "Symbolic execution over LLVM IR + VEX IR. Pair with crypto plugins for custom-cipher recovery.",
  },
  "capstone-mcp": {
    id: "capstone-mcp",
    name: "Capstone MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Python 3.10+, capstone >= 5.",
    install: [
      "pip install capstone capstone-mcp",
    ],
    launch: {
      cmd: "capstone-mcp",
      args: [],
    },
    mcpConfig: {
      "capstone-mcp": {
        command: "capstone-mcp",
        args: [],
      },
    },
    tags: ["disassembler", "static", "capstone", "x86", "arm64"],
    notes: "Lightweight disassembler bridge for shellcode / small snippets without loading a full IDE.",
  },
  "pcileech-mcp": {
    id: "pcileech-mcp",
    name: "PCILeech / MemProcFS MCP",
    kind: "dynamic",
    os: ["windows", "linux"],
    requires: "PCILeech FPGA (Screamer, PCIeScreamer, LeetDMA) or software-only (totalmeltdown), MemProcFS >= 5.9, LeechCore driver.",
    install: [
      "download MemProcFS: https://github.com/ufrisk/MemProcFS/releases",
      "pip install memprocfs-mcp",
      "configure your FPGA bitstream (fpga_pciescreamer_wrw.bin)",
    ],
    launch: {
      cmd: "memprocfs-mcp",
      args: ["--device", "FPGA"],
      http: { port: 48666 },
    },
    mcpConfig: {
      "pcileech-mcp": {
        command: "memprocfs-mcp",
        args: ["--device", "FPGA"],
      },
    },
    tags: ["pcileech", "memprocfs", "dma", "fpga", "dynamic", "kernel-memory"],
    notes: "DMA-attack memory R/W. Best vector against kernel-mode anti-cheat (BE, EAC, Vanguard, FACEIT) when target has IOMMU disabled.",
  },
  "memflow-mcp": {
    id: "memflow-mcp",
    name: "Memflow MCP",
    kind: "dynamic",
    os: ["windows", "linux"],
    requires: "Rust toolchain, memflow 0.2+, a memflow connector (qemu/vmware/pcileech/winpmem).",
    install: [
      "cargo install memflow-cli memflow-mcp",
      "memflow init  # pick a connector",
    ],
    launch: {
      cmd: "memflow-mcp",
      args: [],
      http: { port: 48667 },
    },
    mcpConfig: {
      "memflow-mcp": {
        command: "memflow-mcp",
        args: [],
      },
    },
    tags: ["memflow", "dma", "kernel-memory", "rust", "qemu", "vmware", "winpmem"],
    notes: "Rust-based kernel memory introspection framework. Pluggable connectors; good fit for VM-based malware/anti-cheat labs.",
  },
  "scylla-mcp": {
    id: "scylla-mcp",
    name: "Scylla (dump / IAT rebuild) MCP",
    kind: "dynamic",
    os: ["windows"],
    requires: "Scylla >= 0.9, Python 3.10+ for the MCP wrapper.",
    install: [
      "download Scylla: https://github.com/NtQuery/Scylla",
      "pip install scylla-mcp  # community wrapper, drives Scylla CLI",
    ],
    launch: {
      cmd: "scylla-mcp",
      args: [],
    },
    mcpConfig: {
      "scylla-mcp": {
        command: "scylla-mcp",
        args: [],
      },
    },
    tags: ["scylla", "unpacking", "iat-rebuild", "dump", "dynamic", "windows"],
    notes: "Process dumping + IAT rebuilding for unpacking (Themida/VMP/Enigma). Pair with x64dbg at OEP.",
  },
  "dnspy-mcp": {
    id: "dnspy-mcp",
    name: "dnSpyEx MCP",
    kind: "both",
    os: ["windows"],
    requires: ".NET 8 runtime, dnSpyEx with MCP plugin (community).",
    install: [
      "download dnSpyEx: https://github.com/dnSpyEx/dnSpy/releases",
      "drop dnSpy.MCP.dll into Extensions directory next to dnSpy.exe",
    ],
    launch: {
      cmd: "dnSpy.exe",
      args: ["--mcp"],
      http: { port: 48668 },
    },
    mcpConfig: {
      "dnspy-mcp": {
        url: "http://127.0.0.1:48668/mcp",
      },
    },
    tags: ["dnspy", ".net", "mono", "unity", "il", "static", "dynamic", "edit-and-continue"],
    notes: "Primary for Unity/Mono + .NET assemblies. Edit-and-continue + inline C# decompile.",
  },
  "reclass-mcp": {
    id: "reclass-mcp",
    name: "ReClass.NET MCP",
    kind: "dynamic",
    os: ["windows"],
    requires: "ReClass.NET >= 1.2, .NET Framework 4.8.",
    install: [
      "download ReClass.NET: https://github.com/ReClassNET/ReClass.NET",
      "drop ReClass.NET.MCP.dll into Plugins/",
    ],
    launch: {
      cmd: "ReClass.NET.exe",
      args: ["--mcp"],
      http: { port: 48669 },
    },
    mcpConfig: {
      "reclass-mcp": {
        url: "http://127.0.0.1:48669/mcp",
      },
    },
    tags: ["reclass", "class-recovery", "struct-dump", "dynamic", "pointer-chain"],
    notes: "Live class-layout exploration. Export to C/C++/C# headers. Fits UE4/UE5/Unity reversing when offsets drift.",
  },
  "volatility-mcp": {
    id: "volatility-mcp",
    name: "Volatility3 MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Python 3.10+, volatility3 >= 2.5.",
    install: [
      "pip install volatility3 volatility3-mcp",
    ],
    launch: {
      cmd: "volatility3-mcp",
      args: [],
    },
    mcpConfig: {
      "volatility3-mcp": {
        command: "volatility3-mcp",
        args: [],
      },
    },
    tags: ["volatility", "memory-forensics", "static", "crash-dump", "kernel-memory"],
    notes: "Memory forensics across Windows/Linux/macOS dumps. Expose plugins (pslist, modules, malfind, netscan, dumpfiles) over MCP.",
  },
  "wireshark-mcp": {
    id: "wireshark-mcp",
    name: "Wireshark / tshark MCP",
    kind: "dynamic",
    os: ["windows", "linux", "macos"],
    requires: "Wireshark/tshark >= 4.0, Python 3.10+.",
    install: [
      "install wireshark from https://www.wireshark.org/",
      "pip install tshark-mcp",
    ],
    launch: {
      cmd: "tshark-mcp",
      args: [],
    },
    mcpConfig: {
      "tshark-mcp": {
        command: "tshark-mcp",
        args: [],
      },
    },
    tags: ["wireshark", "tshark", "network", "pcap", "dynamic", "dissector"],
    notes: "Network capture + dissection for game protocol RE. Custom Lua dissectors supported.",
  },
  "mitmproxy-mcp": {
    id: "mitmproxy-mcp",
    name: "mitmproxy MCP",
    kind: "dynamic",
    os: ["windows", "linux", "macos"],
    requires: "mitmproxy >= 10, Python 3.11+.",
    install: [
      "pip install mitmproxy mitmproxy-mcp",
    ],
    launch: {
      cmd: "mitmproxy-mcp",
      args: [],
      http: { port: 8080 },
    },
    mcpConfig: {
      "mitmproxy-mcp": {
        command: "mitmproxy-mcp",
        args: [],
      },
    },
    tags: ["mitmproxy", "network", "tls", "proxy", "dynamic", "cert-pin"],
    notes: "TLS MITM for mobile/game clients. Script with Python addons; pair with Frida for cert-pin bypass.",
  },
  "dotpeek-mcp": {
    id: "dotpeek-mcp",
    name: "dotPeek MCP (JetBrains)",
    kind: "static",
    os: ["windows"],
    requires: "dotPeek >= 2023, JetBrains plugin.",
    install: [
      "install dotPeek: https://www.jetbrains.com/decompiler/",
      "add the dotPeek MCP plugin from JetBrains marketplace",
    ],
    launch: {
      cmd: "dotPeek.exe",
      args: ["--mcp"],
      http: { port: 48670 },
    },
    mcpConfig: {
      "dotpeek-mcp": {
        url: "http://127.0.0.1:48670/mcp",
      },
    },
    tags: ["dotpeek", ".net", "jetbrains", "il", "static"],
    notes: "Alternative to dnSpy for .NET decompilation; nicer cross-ref UI.",
  },
  "unicorn-mcp": {
    id: "unicorn-mcp",
    name: "Unicorn Engine MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Python 3.10+, unicorn >= 2.",
    install: [
      "pip install unicorn unicorn-mcp",
    ],
    launch: {
      cmd: "unicorn-mcp",
      args: [],
    },
    mcpConfig: {
      "unicorn-mcp": {
        command: "unicorn-mcp",
        args: [],
      },
    },
    tags: ["unicorn", "emulation", "static", "cpu-emu", "shellcode"],
    notes: "CPU emulator (x86/arm/mips/ppc/sparc/riscv). Run obfuscated code snippets in a sandbox to recover intent.",
  },
  "pyghidra-mcp-gui": {
    id: "pyghidra-mcp-gui",
    name: "pyghidra-mcp --gui (live Ghidra attach)",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Everything superghidra-mcp needs + a GUI session of Ghidra.",
    install: [
      "pip install pyghidra-mcp",
      "set GHIDRA_INSTALL_DIR",
    ],
    launch: {
      cmd: "pyghidra-mcp",
      args: ["--gui", "--transport", "streamable-http", "--project-path", "<project.gpr>"],
      http: { port: 8765, path: "/mcp" },
    },
    mcpConfig: {
      "pyghidra-mcp-gui": {
        command: "pyghidra-mcp",
        args: ["--gui", "--transport", "stdio", "--project-path", "<project.gpr>"],
      },
    },
    tags: ["ghidra", "gui", "live-attach", "pyghidra", "static"],
    notes: "Shares live program state with the Ghidra CodeBrowser -- human + agent collaborating on the same .rep.",
  },
  "retsync-mcp": {
    id: "retsync-mcp",
    name: "ret-sync MCP",
    kind: "both",
    os: ["windows", "linux", "macos"],
    requires: "ret-sync IDA/Ghidra/x64dbg plugins + a debugger session.",
    install: [
      "install ret-sync IDA/Ghidra/x64dbg plugins: https://github.com/bootleg/ret-sync",
      "pip install retsync-mcp",
    ],
    launch: {
      cmd: "retsync-mcp",
      args: [],
      http: { port: 9100 },
    },
    mcpConfig: {
      "retsync-mcp": {
        command: "retsync-mcp",
        args: [],
      },
    },
    tags: ["ret-sync", "live-sync", "ida", "ghidra", "x64dbg", "windbg", "both"],
    notes: "Sync disassembler cursor with a live debugger (IDA <-> x64dbg <-> Ghidra <-> WinDbg). Great during AC driver RE.",
  },
  "ghidrathon-mcp": {
    id: "ghidrathon-mcp",
    name: "Ghidrathon MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Ghidra 11+ + Ghidrathon extension (Python 3 in Ghidra).",
    install: [
      "install Ghidrathon: https://github.com/mandiant/Ghidrathon",
      "pip install ghidrathon-mcp",
    ],
    launch: { cmd: "ghidrathon-mcp", args: [], http: { port: 9108 } },
    mcpConfig: { "ghidrathon-mcp": { command: "ghidrathon-mcp", args: [] } },
    tags: ["ghidra", "ghidrathon", "python3", "static", "scripting"],
    notes: "Modern Python 3 scripting layer for Ghidra from Mandiant.",
  },
  "bindiff-mcp": {
    id: "bindiff-mcp",
    name: "BinDiff MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "BinDiff 8+ (Google), IDA or Ghidra for the source IDBs/GhidraDBs.",
    install: [
      "download BinDiff: https://www.zynamics.com/software.html",
      "pip install bindiff-mcp",
    ],
    launch: { cmd: "bindiff-mcp", args: [] },
    mcpConfig: { "bindiff-mcp": { command: "bindiff-mcp", args: [] } },
    tags: ["bindiff", "diff", "static", "patch-analysis", "offset-migration"],
    notes: "Function-level diff between two builds. Fits game-update offset migration workflow.",
  },
  "diaphora-mcp": {
    id: "diaphora-mcp",
    name: "Diaphora MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "IDA Pro + Diaphora plugin.",
    install: [
      "install Diaphora: https://github.com/joxeankoret/diaphora",
      "pip install diaphora-mcp",
    ],
    launch: { cmd: "diaphora-mcp", args: [] },
    mcpConfig: { "diaphora-mcp": { command: "diaphora-mcp", args: [] } },
    tags: ["diaphora", "diff", "static", "ida"],
    notes: "Open-source alternative to BinDiff. SQLite-backed.",
  },
  "qiling-mcp": {
    id: "qiling-mcp",
    name: "Qiling Framework MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Python 3.10+, qiling >= 1.4.",
    install: ["pip install qiling qiling-mcp"],
    launch: { cmd: "qiling-mcp", args: [] },
    mcpConfig: { "qiling-mcp": { command: "qiling-mcp", args: [] } },
    tags: ["qiling", "emulation", "cross-arch", "firmware", "static"],
    notes: "High-level emulator (built on Unicorn). Great for firmware + IoT + cross-arch shellcode.",
  },
  "unidbg-mcp": {
    id: "unidbg-mcp",
    name: "unidbg MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "JDK 17, unidbg jar, Python 3.10+ for the bridge.",
    install: [
      "clone unidbg: https://github.com/zhkl0228/unidbg",
      "pip install unidbg-mcp",
    ],
    launch: { cmd: "unidbg-mcp", args: [] },
    mcpConfig: { "unidbg-mcp": { command: "unidbg-mcp", args: [] } },
    tags: ["unidbg", "android", "arm64", "emulation", "static"],
    notes: "Emulates Android native libs; great for solving JNI + anti-debug without a real device.",
  },
  "openreality-mcp": {
    id: "openreality-mcp",
    name: "OpenReality / Reko MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Reko decompiler (OpenReality fork) >= 0.11, Mono/.NET 8.",
    install: [
      "download Reko: https://github.com/uxmal/reko",
      "pip install reko-mcp",
    ],
    launch: { cmd: "reko-mcp", args: [] },
    mcpConfig: { "reko-mcp": { command: "reko-mcp", args: [] } },
    tags: ["reko", "decompile", "static", "retro", "cross-arch"],
    notes: "Multi-architecture decompiler (x86, 68k, Z80, SNES, 6502). Fits retro-console game RE.",
  },
  "qemu-trace-mcp": {
    id: "qemu-trace-mcp",
    name: "QEMU + plugin tracing MCP",
    kind: "dynamic",
    os: ["windows", "linux", "macos"],
    requires: "QEMU 8+, TCG plugin SDK, Python 3.10+.",
    install: ["pip install qemu-trace-mcp"],
    launch: { cmd: "qemu-trace-mcp", args: [] },
    mcpConfig: { "qemu-trace-mcp": { command: "qemu-trace-mcp", args: [] } },
    tags: ["qemu", "tcg", "trace", "dynamic", "cross-arch"],
    notes: "Record block-level execution traces across any arch QEMU supports; good for anti-cheat kernel RE in a VM.",
  },
  "lldb-mcp": {
    id: "lldb-mcp",
    name: "LLDB MCP",
    kind: "dynamic",
    os: ["linux", "macos"],
    requires: "LLDB 17+ on PATH, Python 3.10+.",
    install: ["pip install lldb-mcp"],
    launch: { cmd: "lldb-mcp", args: [] },
    mcpConfig: { "lldb-mcp": { command: "lldb-mcp", args: [] } },
    tags: ["lldb", "debugger", "dynamic", "macos", "linux", "ios"],
    notes: "Preferred debugger on macOS / iOS and modern Linux dev builds.",
  },
  "gdb-mcp": {
    id: "gdb-mcp",
    name: "GDB MCP",
    kind: "dynamic",
    os: ["windows", "linux", "macos"],
    requires: "GDB 13+, Python 3.10+.",
    install: ["pip install gdb-mcp"],
    launch: { cmd: "gdb-mcp", args: [] },
    mcpConfig: { "gdb-mcp": { command: "gdb-mcp", args: [] } },
    tags: ["gdb", "debugger", "dynamic", "linux", "emulator"],
    notes: "Primary for Linux / Proton game debug + emulator gdbstub (Cemu, yuzu, Dolphin).",
  },
  "burp-mcp": {
    id: "burp-mcp",
    name: "Burp Suite MCP",
    kind: "dynamic",
    os: ["windows", "linux", "macos"],
    requires: "Burp Suite 2024+, Java 17.",
    install: ["drop the burp-mcp extension JAR into Burp (Extensions tab)"],
    launch: { cmd: "echo", args: ["Burp runs as a GUI; MCP extension exposes its API"], http: { port: 8085 } },
    mcpConfig: { "burp-mcp": { url: "http://127.0.0.1:8085/mcp" } },
    tags: ["burp", "network", "web", "mobile", "proxy", "dynamic"],
    notes: "For game HTTPS/API dissection + mobile client TLS MITM.",
  },
  "yara-mcp": {
    id: "yara-mcp",
    name: "YARA MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Python 3.10+, yara-python >= 4.5.",
    install: ["pip install yara-python yara-mcp"],
    launch: { cmd: "yara-mcp", args: [] },
    mcpConfig: { "yara-mcp": { command: "yara-mcp", args: [] } },
    tags: ["yara", "signature", "static", "detection", "classification"],
    notes: "Scan binaries/dumps with YARA rules; generate rules via the `yara-generator` plugin.",
  },
  "clrmd-mcp": {
    id: "clrmd-mcp",
    name: "ClrMD MCP",
    kind: "dynamic",
    os: ["windows"],
    requires: ".NET 8 runtime, Microsoft.Diagnostics.Runtime (ClrMD) 3+.",
    install: ["dotnet tool install -g clrmd-mcp"],
    launch: { cmd: "clrmd-mcp", args: [] },
    mcpConfig: { "clrmd-mcp": { command: "clrmd-mcp", args: [] } },
    tags: ["clrmd", ".net", "dump", "dynamic", "unity-mono"],
    notes: "Introspect a running .NET / Unity-Mono process or a minidump. Heap walk, thread stacks, GCRoots.",
  },
  "ba-sync-mcp": {
    id: "ba-sync-mcp",
    name: "Binja-Ghidra Sync (bn-ghidra-sync) MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Binary Ninja + Ghidra + bn-ghidra-sync plugin.",
    install: ["pip install bn-ghidra-sync-mcp"],
    launch: { cmd: "bn-ghidra-sync-mcp", args: [], http: { port: 9120 } },
    mcpConfig: { "bn-ghidra-sync-mcp": { command: "bn-ghidra-sync-mcp", args: [] } },
    tags: ["binja", "ghidra", "sync", "static"],
    notes: "Mirrors renames + comments between Binja and Ghidra sessions; useful on a team.",
  },
  "dolphin-dme-mcp": {
    id: "dolphin-dme-mcp",
    name: "Dolphin Memory Engine MCP",
    kind: "dynamic",
    os: ["windows", "linux", "macos"],
    requires: "Dolphin running + Dolphin Memory Engine with the MCP sidecar.",
    install: [
      "download DME: https://github.com/aldelaro5/Dolphin-memory-engine",
      "pip install dme-mcp",
    ],
    launch: { cmd: "dme-mcp", args: [], http: { port: 9121 } },
    mcpConfig: { "dolphin-dme-mcp": { command: "dme-mcp", args: [] } },
    tags: ["dolphin", "dme", "emulator", "gamecube", "wii", "memory-scan"],
    notes: "Live guest-memory R/W of Dolphin (Gamecube / Wii) titles.",
  },
  "cemu-ipc-mcp": {
    id: "cemu-ipc-mcp",
    name: "Cemu IPC MCP",
    kind: "dynamic",
    os: ["windows", "linux"],
    requires: "Cemu 2.x with the IPC extension, Python 3.10+.",
    install: ["pip install cemu-ipc-mcp"],
    launch: { cmd: "cemu-ipc-mcp", args: [], http: { port: 9122 } },
    mcpConfig: { "cemu-ipc-mcp": { command: "cemu-ipc-mcp", args: [] } },
    tags: ["cemu", "emulator", "wii-u", "ipc"],
    notes: "Agent-callable Cemu live state inspection + Lua script invocation.",
  },
  "ollydbg-mcp": {
    id: "ollydbg-mcp",
    name: "OllyDbg MCP (legacy)",
    kind: "dynamic",
    os: ["windows"],
    requires: "OllyDbg 2.01h + the OllyMCP plugin.",
    install: ["drop OllyMCP.dll into <olly>/plugins", "run OllyDbg + attach"],
    launch: { cmd: "echo", args: ["OllyDbg plugin -- host OllyDbg manually"], http: { port: 48671 } },
    mcpConfig: { "ollydbg-mcp": { url: "http://127.0.0.1:48671/mcp" } },
    tags: ["ollydbg", "legacy", "windows", "dynamic", "32-bit"],
    notes: "Classic 32-bit Windows debugger. Still useful for small 32-bit binaries + legacy malware RE.",
  },
  "aflplusplus-mcp": {
    id: "aflplusplus-mcp",
    name: "AFL++ MCP",
    kind: "dynamic",
    os: ["linux", "macos"],
    requires: "AFL++ >= 4.20, Python 3.10+.",
    install: ["apt install afl++ || brew install afl++", "pip install aflplusplus-mcp"],
    launch: { cmd: "aflplusplus-mcp", args: [] },
    mcpConfig: { "aflplusplus-mcp": { command: "aflplusplus-mcp", args: [] } },
    tags: ["aflplusplus", "fuzzer", "coverage", "dynamic", "linux"],
    notes: "State-of-the-art coverage-guided fuzzer. Great for driver + protocol fuzzing on Linux.",
  },
  "honggfuzz-mcp": {
    id: "honggfuzz-mcp",
    name: "honggfuzz MCP",
    kind: "dynamic",
    os: ["linux", "macos", "windows"],
    requires: "honggfuzz >= 2.6, Python 3.10+.",
    install: ["apt install honggfuzz || brew install honggfuzz", "pip install honggfuzz-mcp"],
    launch: { cmd: "honggfuzz-mcp", args: [] },
    mcpConfig: { "honggfuzz-mcp": { command: "honggfuzz-mcp", args: [] } },
    tags: ["honggfuzz", "fuzzer", "coverage", "dynamic"],
    notes: "Fast fork-less fuzzer; particularly good at persistent-mode fuzz.",
  },
  "libafl-mcp": {
    id: "libafl-mcp",
    name: "LibAFL MCP",
    kind: "dynamic",
    os: ["linux", "macos", "windows"],
    requires: "Rust toolchain, LibAFL >= 0.14.",
    install: ["cargo install libafl-mcp"],
    launch: { cmd: "libafl-mcp", args: [] },
    mcpConfig: { "libafl-mcp": { command: "libafl-mcp", args: [] } },
    tags: ["libafl", "fuzzer", "rust", "dynamic", "hybrid"],
    notes: "Composable Rust fuzzer framework. For custom harnesses + exotic targets.",
  },
  "winafl-mcp": {
    id: "winafl-mcp",
    name: "WinAFL MCP",
    kind: "dynamic",
    os: ["windows"],
    requires: "WinAFL (AFL for Windows) + DynamoRIO.",
    install: ["download WinAFL: https://github.com/googleprojectzero/winafl", "pip install winafl-mcp"],
    launch: { cmd: "winafl-mcp", args: [] },
    mcpConfig: { "winafl-mcp": { command: "winafl-mcp", args: [] } },
    tags: ["winafl", "fuzzer", "windows", "dynamic", "dynamoRIO"],
    notes: "Primary fuzzer for Windows binaries. Useful for AC driver + Windows game SDK fuzzing.",
  },
  "v8-inspector-mcp": {
    id: "v8-inspector-mcp",
    name: "V8 Inspector / Chrome DevTools Protocol MCP",
    kind: "dynamic",
    os: ["windows", "linux", "macos"],
    requires: "Node / Chromium / Electron with inspector enabled.",
    install: ["pip install cdp-mcp"],
    launch: { cmd: "cdp-mcp", args: [], http: { port: 9222 } },
    mcpConfig: { "v8-inspector-mcp": { url: "http://127.0.0.1:9222" } },
    tags: ["v8", "cdp", "chrome-devtools", "electron", "node", "dynamic"],
    notes: "Attach to any Electron app (Discord, Slack, Twitch client, VSCode-style apps) via the DevTools Protocol.",
  },
  "cdp-mcp": {
    id: "cdp-mcp",
    name: "Chrome DevTools Protocol MCP",
    kind: "dynamic",
    os: ["windows", "linux", "macos"],
    requires: "Chrome/Chromium with --remote-debugging-port.",
    install: ["pip install cdp-mcp"],
    launch: { cmd: "cdp-mcp", args: [], http: { port: 9222 } },
    mcpConfig: { "cdp-mcp": { command: "cdp-mcp", args: [] } },
    tags: ["cdp", "chrome", "web", "devtools", "dynamic"],
    notes: "Alias for v8-inspector-mcp -- same protocol, different entry point.",
  },
  "idevice-mcp": {
    id: "idevice-mcp",
    name: "libimobiledevice MCP (iOS)",
    kind: "dynamic",
    os: ["linux", "macos", "windows"],
    requires: "libimobiledevice, usbmuxd.",
    install: [
      "brew install libimobiledevice || apt install libimobiledevice-utils",
      "pip install pymobiledevice3 idevice-mcp",
    ],
    launch: { cmd: "idevice-mcp", args: [] },
    mcpConfig: { "idevice-mcp": { command: "idevice-mcp", args: [] } },
    tags: ["ios", "libimobiledevice", "pymobiledevice3", "dynamic"],
    notes: "USB attach to a connected iOS device. Install profiles, pull apps, access MobileBackup, syslog.",
  },
  "adb-mcp": {
    id: "adb-mcp",
    name: "ADB MCP (Android)",
    kind: "dynamic",
    os: ["linux", "macos", "windows"],
    requires: "Android platform-tools on PATH.",
    install: ["pip install adb-mcp"],
    launch: { cmd: "adb-mcp", args: [] },
    mcpConfig: { "adb-mcp": { command: "adb-mcp", args: [] } },
    tags: ["adb", "android", "dynamic"],
    notes: "shell commands, logcat, pm, am, dumpsys, screencap over ADB.",
  },
  "magisk-mcp": {
    id: "magisk-mcp",
    name: "Magisk MCP (Android root)",
    kind: "dynamic",
    os: ["linux", "macos", "windows"],
    requires: "Rooted Android device with Magisk + MagiskSU bridge.",
    install: ["pip install magisk-mcp"],
    launch: { cmd: "magisk-mcp", args: [] },
    mcpConfig: { "magisk-mcp": { command: "magisk-mcp", args: [] } },
    tags: ["magisk", "android", "root", "dynamic"],
    notes: "Root-level ADB. Pair with Zygisk + Frida for anti-cheat bypass on mobile.",
  },
  "kdnet-mcp": {
    id: "kdnet-mcp",
    name: "KDNET MCP (Windows kernel debug over LAN)",
    kind: "dynamic",
    os: ["windows", "linux"],
    requires: "WinDbg (host) + target with kdnet transport.",
    install: ["pip install kdnet-mcp"],
    launch: { cmd: "kdnet-mcp", args: [] },
    mcpConfig: { "kdnet-mcp": { command: "kdnet-mcp", args: [] } },
    tags: ["kdnet", "windbg", "kernel", "dynamic", "network"],
    notes: "Headless kernel debug over LAN. Primary for AC driver RE without a physical COM/firewire cable.",
  },
  "gef-mcp": {
    id: "gef-mcp",
    name: "GEF MCP (GDB + GEF)",
    kind: "dynamic",
    os: ["linux", "macos"],
    requires: "GDB + GEF (hugsy).",
    install: ["pip install gef-mcp", "GEF: see https://github.com/hugsy/gef"],
    launch: { cmd: "gef-mcp", args: [] },
    mcpConfig: { "gef-mcp": { command: "gef-mcp", args: [] } },
    tags: ["gef", "gdb", "dynamic", "exploit"],
    notes: "GDB with modern exploit-development commands. Primary for Linux game + Proton debug.",
  },
  "pwndbg-mcp": {
    id: "pwndbg-mcp",
    name: "pwndbg MCP",
    kind: "dynamic",
    os: ["linux", "macos"],
    requires: "GDB + pwndbg.",
    install: ["pip install pwndbg-mcp", "pwndbg: see https://github.com/pwndbg/pwndbg"],
    launch: { cmd: "pwndbg-mcp", args: [] },
    mcpConfig: { "pwndbg-mcp": { command: "pwndbg-mcp", args: [] } },
    tags: ["pwndbg", "gdb", "dynamic", "exploit", "ctf"],
    notes: "Alternative to GEF; better heap visualisation.",
  },
  "retdec-mcp": {
    id: "retdec-mcp",
    name: "RetDec MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "RetDec >= 5 on PATH.",
    install: ["pip install retdec-mcp"],
    launch: { cmd: "retdec-mcp", args: [] },
    mcpConfig: { "retdec-mcp": { command: "retdec-mcp", args: [] } },
    tags: ["retdec", "decompile", "static", "llvm"],
    notes: "Avast's open-source LLVM-based decompiler. Alternative to Hex-Rays/Ghidra.",
  },
  "snowman-mcp": {
    id: "snowman-mcp",
    name: "Snowman MCP",
    kind: "static",
    os: ["windows", "linux", "macos"],
    requires: "Snowman (nocode decompiler).",
    install: ["pip install snowman-mcp"],
    launch: { cmd: "snowman-mcp", args: [] },
    mcpConfig: { "snowman-mcp": { command: "snowman-mcp", args: [] } },
    tags: ["snowman", "decompile", "static", "x86"],
    notes: "Lightweight C-like decompiler for x86. Good for quick triage.",
  },


  // ----- external tools (ported from ForMCP as catalog, not vendored) -----










};

// ------------------------------------------------------------
// Process registry
// ------------------------------------------------------------

const running = new Map<ReBackendId, RunningProc>();

function pushTail(proc: RunningProc, chunk: string, max = 200) {
  for (const line of chunk.split(/\r?\n/)) {
    if (!line) continue;
    proc.logTail.push(line);
    if (proc.logTail.length > max) proc.logTail.shift();
  }
}

async function pathExists(p: string): Promise<boolean> {
  try {
    await access(p, fsConstants.F_OK);
    return true;
  } catch {
    return false;
  }
}

// ------------------------------------------------------------
// HTTP proxy helper (for backends that expose HTTP)
// ------------------------------------------------------------

async function httpCall(url: string, init?: RequestInit, timeoutMs = 15_000): Promise<{
  status: number;
  headers: Record<string, string>;
  body: string;
}> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const resp = await fetch(url, { ...init, signal: ctrl.signal });
    const body = await resp.text();
    const headers: Record<string, string> = {};
    resp.headers.forEach((v, k) => (headers[k] = v));
    return { status: resp.status, headers, body };
  } finally {
    clearTimeout(timer);
  }
}

// ------------------------------------------------------------
// Register tools onto an McpServer
// ------------------------------------------------------------

export function registerReTools(server: McpServer, projectRoot: string): void {
  // --------------------------------------------------------
  // list_re_backends
  // --------------------------------------------------------
  server.tool(
    "list_re_backends",
    "List every RE / debug MCP backend this project knows how to drive (Ghidra, IDA, Binary Ninja, radare2, x64dbg, WinDbg, Cheat Engine, Frida, Hopper, REA, Vibe-RE, JADX, angr, Capstone). Returns id, kind (static/dynamic/both), supported OS, install hints, launch command, and whether the backend is currently running.",
    {
      kind: z.enum(["static", "dynamic", "both"]).optional().describe("Filter by backend kind."),
      os: z.enum(["windows", "linux", "macos"]).optional().describe("Filter by host OS."),
      tag: z.string().optional().describe("Case-insensitive tag substring filter (e.g. 'android', 'kernel', 'arm')."),
    },
    async ({ kind, os, tag }: { kind?: "static" | "dynamic" | "both"; os?: "windows" | "linux" | "macos"; tag?: string }) => {
      const tagLc = tag?.toLowerCase();
      const rows: string[] = [];
      for (const b of Object.values(BACKENDS)) {
        if (kind && b.kind !== kind) continue;
        if (os && !b.os.includes(os)) continue;
        if (tagLc && !b.tags.some((t) => t.toLowerCase().includes(tagLc))) continue;
        const live = running.get(b.id);
        rows.push(
          `- **${b.id}** (${b.name}) — ${b.kind}, ${b.os.join("/")}` +
            (live ? ` — RUNNING pid ${live.pid}` : "") +
            `\n  tags: ${b.tags.join(", ")}\n  ${b.notes}`
        );
      }
      if (!rows.length) return { content: [{ type: "text" as const, text: "No matching RE backends." }] };
      return {
        content: [{
          type: "text" as const,
          text: `# RE / Debug MCP Backends (${rows.length})\n\n${rows.join("\n")}\n\nUse \`describe_re_backend\` for one, or \`launch_re_backend\` to spawn it, or \`re_mcp_config\` for the Claude/Cursor/Codex config snippet.`,
        }],
      };
    }
  );

  // --------------------------------------------------------
  // describe_re_backend
  // --------------------------------------------------------
  server.tool(
    "describe_re_backend",
    "Full detail for one RE backend: name, OS, requirements, step-by-step install, exact launch command, HTTP endpoint (if any), MCP config snippet, running status.",
    {
      id: z.string().describe("Backend id (see list_re_backends)."),
    },
    async ({ id }: { id: string }) => {
      const b = BACKENDS[id as ReBackendId];
      if (!b) return { content: [{ type: "text" as const, text: `Unknown backend "${id}". Use list_re_backends.` }], isError: true as const };
      const live = running.get(b.id);
      const lines = [
        `# ${b.name} (\`${b.id}\`)`,
        ``,
        `- **Kind:** ${b.kind}`,
        `- **OS:** ${b.os.join(", ")}`,
        `- **Status:** ${live ? `RUNNING (pid ${live.pid}, started ${new Date(live.startedAt).toISOString()})` : "stopped"}`,
        `- **Tags:** ${b.tags.join(", ")}`,
        ``,
        `## Requirements`,
        b.requires,
        ``,
        `## Install`,
        ...b.install.map((s) => `- \`${s}\``),
        ``,
        `## Launch`,
        `\`\`\`shell`,
        `${b.launch.cmd} ${b.launch.args.join(" ")}`,
        `\`\`\``,
      ];
      if (b.launch.cwd) lines.push(`- cwd: \`${b.launch.cwd}\``);
      if (b.launch.http) lines.push(`- HTTP: \`http://127.0.0.1:${b.launch.http.port}${b.launch.http.path ?? ""}\``);
      lines.push(``, `## MCP config snippet`, "```json", JSON.stringify({ mcpServers: b.mcpConfig }, null, 2), "```", ``);
      if (b.notes) lines.push(`## Notes`, b.notes);
      return { content: [{ type: "text" as const, text: lines.join("\n") }] };
    }
  );

  // --------------------------------------------------------
  // re_mcp_config
  // --------------------------------------------------------
  server.tool(
    "re_mcp_config",
    "Emit a ready-to-paste MCP config snippet (Claude Desktop / Claude Code / Cursor / Codex) for one or more RE backends.",
    {
      ids: z.array(z.string()).min(1).describe("Backend ids to include."),
      target: z.enum(["claude-desktop", "claude-code", "cursor", "codex", "generic"]).default("generic"),
    },
    async ({ ids, target }: { ids: string[]; target: "claude-desktop" | "claude-code" | "cursor" | "codex" | "generic" }) => {
      const servers: Record<string, unknown> = {};
      const missing: string[] = [];
      for (const id of ids) {
        const b = BACKENDS[id as ReBackendId];
        if (!b) { missing.push(id); continue; }
        Object.assign(servers, b.mcpConfig);
      }
      if (missing.length) {
        return { content: [{ type: "text" as const, text: `Unknown backend id(s): ${missing.join(", ")}` }], isError: true as const };
      }
      const envelopeKey = target === "cursor" || target === "codex" ? "mcp" : "mcpServers";
      const config = { [envelopeKey]: servers };
      return {
        content: [{
          type: "text" as const,
          text: "```json\n" + JSON.stringify(config, null, 2) + "\n```",
        }],
      };
    }
  );

  // --------------------------------------------------------
  // launch_re_backend
  // --------------------------------------------------------
  server.tool(
    "launch_re_backend",
    "Spawn an RE backend as a managed child process. Captures stdout/stderr tail. Returns pid and HTTP endpoint if the backend declares one. Call stop_re_backend to terminate.",
    {
      id: z.string().describe("Backend id."),
      extraArgs: z.array(z.string()).optional().describe("Additional CLI arguments appended to the configured launch args."),
      env: z.record(z.string(), z.string()).optional().describe("Extra environment variables, merged over process env and backend-declared env."),
      cwdOverride: z.string().optional().describe("Working directory override. Relative to project root."),
    },
    async ({ id, extraArgs = [], env = {}, cwdOverride }: { id: string; extraArgs?: string[]; env?: Record<string, string>; cwdOverride?: string }) => {
      const b = BACKENDS[id as ReBackendId];
      if (!b) return { content: [{ type: "text" as const, text: `Unknown backend "${id}". Use list_re_backends.` }], isError: true as const };
      if (running.has(b.id)) {
        return { content: [{ type: "text" as const, text: `Backend "${id}" is already running with pid ${running.get(b.id)!.pid}.` }], isError: true as const };
      }

      const cwdRaw = cwdOverride ?? b.launch.cwd ?? projectRoot;
      const cwd = cwdRaw.startsWith("/") || /^[A-Za-z]:[\\/]/.test(cwdRaw) ? cwdRaw : join(projectRoot, cwdRaw);
      if (!(await pathExists(cwd))) {
        return { content: [{ type: "text" as const, text: `cwd does not exist: ${cwd}` }], isError: true as const };
      }

      const mergedEnv = { ...process.env, ...b.launch.env, ...env };
      const child = spawn(b.launch.cmd, [...b.launch.args, ...extraArgs], {
        cwd,
        env: mergedEnv,
        stdio: ["ignore", "pipe", "pipe"],
        shell: process.platform === "win32",
      });

      if (!child.pid) {
        return { content: [{ type: "text" as const, text: `Failed to spawn ${b.launch.cmd}. Verify it is installed and on PATH.` }], isError: true as const };
      }

      const proc: RunningProc = {
        backend: b.id,
        pid: child.pid,
        startedAt: Date.now(),
        logTail: [],
        child,
      };
      child.stdout?.on("data", (buf) => pushTail(proc, buf.toString()));
      child.stderr?.on("data", (buf) => pushTail(proc, buf.toString()));
      child.on("exit", (code) => {
        pushTail(proc, `[exit code=${code}]`);
        running.delete(b.id);
      });
      running.set(b.id, proc);

      const lines = [
        `Started \`${b.name}\` (${b.id}) pid=${child.pid}`,
        `cwd=${cwd}`,
        `cmd=${b.launch.cmd} ${[...b.launch.args, ...extraArgs].join(" ")}`,
      ];
      if (b.launch.http) lines.push(`HTTP endpoint: http://127.0.0.1:${b.launch.http.port}${b.launch.http.path ?? ""}`);
      return { content: [{ type: "text" as const, text: lines.join("\n") }] };
    }
  );

  // --------------------------------------------------------
  // stop_re_backend
  // --------------------------------------------------------
  server.tool(
    "stop_re_backend",
    "Terminate a backend started with launch_re_backend. Sends SIGTERM then SIGKILL after the grace period.",
    {
      id: z.string().describe("Backend id."),
      graceMs: z.number().min(0).max(60_000).default(5_000).describe("Grace period before SIGKILL."),
    },
    async ({ id, graceMs }: { id: string; graceMs: number }) => {
      const proc = running.get(id as ReBackendId);
      if (!proc) return { content: [{ type: "text" as const, text: `No running backend "${id}".` }], isError: true as const };
      proc.child.kill("SIGTERM");
      await new Promise<void>((res) => {
        const t = setTimeout(() => {
          try { proc.child.kill("SIGKILL"); } catch { /* already gone */ }
          res();
        }, graceMs);
        proc.child.once("exit", () => { clearTimeout(t); res(); });
      });
      running.delete(id as ReBackendId);
      return { content: [{ type: "text" as const, text: `Stopped ${id} (pid ${proc.pid}).` }] };
    }
  );

  // --------------------------------------------------------
  // re_backend_status
  // --------------------------------------------------------
  server.tool(
    "re_backend_status",
    "Status + recent log output for one or all backends started by launch_re_backend.",
    {
      id: z.string().optional().describe("Backend id. Omit for all."),
      lines: z.number().min(1).max(500).default(50),
    },
    async ({ id, lines }: { id?: string; lines: number }) => {
      const rows: string[] = [];
      const entries = id ? (running.has(id as ReBackendId) ? [[id, running.get(id as ReBackendId)!]] as const : []) : [...running.entries()];
      if (!entries.length) return { content: [{ type: "text" as const, text: id ? `No running backend "${id}".` : "No backends running." }] };
      for (const [bid, proc] of entries) {
        const tail = proc.logTail.slice(-lines).join("\n");
        rows.push(`## ${bid} (pid ${proc.pid}, started ${new Date(proc.startedAt).toISOString()})\n\n\`\`\`\n${tail || "(no output yet)"}\n\`\`\``);
      }
      return { content: [{ type: "text" as const, text: rows.join("\n\n") }] };
    }
  );

  // --------------------------------------------------------
  // re_http_call
  // --------------------------------------------------------
  server.tool(
    "re_http_call",
    "Proxy an HTTP request to a running backend's declared HTTP endpoint (x64dbg-mcp, pyghidra-mcp HTTP, binary-ninja-mcp, radare2 webui, cheat-engine ceserver). Backend must be running or have a static HTTP endpoint declared.",
    {
      id: z.string().describe("Backend id."),
      path: z.string().describe("Path on the backend HTTP server, e.g. '/mcp', '/tool/decompile'."),
      method: z.enum(["GET", "POST", "PUT", "DELETE", "PATCH"]).default("GET"),
      body: z.string().optional().describe("Optional raw request body (JSON string or form-encoded)."),
      headers: z.record(z.string(), z.string()).optional(),
      timeoutMs: z.number().min(500).max(120_000).default(15_000),
    },
    async ({ id, path, method, body, headers, timeoutMs }: { id: string; path: string; method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH"; body?: string; headers?: Record<string, string>; timeoutMs: number }) => {
      const b = BACKENDS[id as ReBackendId];
      if (!b || !b.launch.http) return { content: [{ type: "text" as const, text: `Backend "${id}" has no HTTP endpoint.` }], isError: true as const };
      const url = `http://127.0.0.1:${b.launch.http.port}${path.startsWith("/") ? path : "/" + path}`;
      try {
        const resp = await httpCall(url, { method, body, headers }, timeoutMs);
        const bodyPreview = resp.body.length > 20_000 ? resp.body.slice(0, 20_000) + `\n...[truncated ${resp.body.length - 20_000} bytes]` : resp.body;
        return {
          content: [{
            type: "text" as const,
            text: `${method} ${url}\nstatus=${resp.status}\n\n${bodyPreview}`,
          }],
        };
      } catch (e) {
        const err = e instanceof Error ? e.message : String(e);
        return { content: [{ type: "text" as const, text: `HTTP error contacting ${url}: ${err}` }], isError: true as const };
      }
    }
  );

  // --------------------------------------------------------
  // pick_re_backend
  // --------------------------------------------------------
  server.tool(
    "pick_re_backend",
    "Recommend the best RE backend for a described task (e.g. 'unpack a Themida binary', 'dump UE5 offsets', 'instrument an Android APK', 'decompile a Mach-O'). Ranks by tag match + kind + OS.",
    {
      task: z.string().describe("Natural-language description of what needs to be done."),
      os: z.enum(["windows", "linux", "macos"]).optional(),
      prefer: z.enum(["static", "dynamic", "both"]).optional(),
    },
    async ({ task, os, prefer }: { task: string; os?: "windows" | "linux" | "macos"; prefer?: "static" | "dynamic" | "both" }) => {
      const words = task.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 2);
      const scored: { b: ReBackend; score: number; reasons: string[] }[] = [];
      for (const b of Object.values(BACKENDS)) {
        if (os && !b.os.includes(os)) continue;
        let score = 0;
        const reasons: string[] = [];
        for (const w of words) {
          if (b.id.includes(w)) { score += 4; reasons.push(`id match: ${w}`); }
          if (b.name.toLowerCase().includes(w)) { score += 3; reasons.push(`name match: ${w}`); }
          for (const t of b.tags) if (t.toLowerCase().includes(w)) { score += 2; reasons.push(`tag match: ${t}`); break; }
          if (b.notes.toLowerCase().includes(w)) { score += 1; }
        }
        if (prefer && (b.kind === prefer || b.kind === "both")) score += 2;
        if (score > 0) scored.push({ b, score, reasons });
      }
      scored.sort((a, b) => b.score - a.score);
      if (!scored.length) return { content: [{ type: "text" as const, text: `No backend ranked for task "${task}". Try list_re_backends to browse.` }] };
      const top = scored.slice(0, 5).map(({ b, score, reasons }) => `- **${b.id}** (score ${score}) — ${b.name}\n  reasons: ${[...new Set(reasons)].slice(0, 4).join("; ")}\n  ${b.notes}`);
      return {
        content: [{
          type: "text" as const,
          text: `# Recommended backends for: ${task}\n\n${top.join("\n")}\n\nUse \`describe_re_backend\` for details.`,
        }],
      };
    }
  );

  // --------------------------------------------------------
  // Convenience wrappers for the most common ops
  // --------------------------------------------------------

  server.tool(
    "x64dbg_cmd",
    "Send a text command to a running x64dbg-mcp backend (requires x64dbg running with the plugin on port 5566). Example commands: 'GetDebugState', 'LoadBinary <path>', 'SetBreakpoint 0x401000', 'ReadMemory 0x401000 0x100'.",
    {
      command: z.string().describe("x64dbg command string."),
      params: z.record(z.string(), z.unknown()).optional(),
    },
    async ({ command, params }: { command: string; params?: Record<string, unknown> }) => {
      const b = BACKENDS["x64dbg-mcp"];
      const url = `http://127.0.0.1:${b.launch.http!.port}/tool/${encodeURIComponent(command)}`;
      try {
        const resp = await httpCall(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(params ?? {}),
        });
        return { content: [{ type: "text" as const, text: `x64dbg ${command} -> status=${resp.status}\n\n${resp.body}` }] };
      } catch (e) {
        return { content: [{ type: "text" as const, text: `x64dbg not reachable at ${url}: ${(e as Error).message}` }], isError: true as const };
      }
    }
  );

  server.tool(
    "ghidra_decompile",
    "Decompile a function via a running pyghidra-mcp / superghidra-mcp HTTP endpoint. Backend must be launched first (launch_re_backend id='superghidra-mcp' --transport streamable-http).",
    {
      functionName: z.string().describe("Function name or address (e.g. 'FUN_00401000' or '0x00401000')."),
      programName: z.string().optional().describe("Target program within the Ghidra project."),
    },
    async ({ functionName, programName }: { functionName: string; programName?: string }) => {
      const b = BACKENDS["superghidra-mcp"];
      if (!b.launch.http) return { content: [{ type: "text" as const, text: "superghidra-mcp has no HTTP endpoint declared." }], isError: true as const };
      const url = `http://127.0.0.1:${b.launch.http.port}${b.launch.http.path ?? ""}/tool/decompile`;
      try {
        const resp = await httpCall(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ function: functionName, program: programName }),
        });
        return { content: [{ type: "text" as const, text: `superghidra decompile ${functionName} status=${resp.status}\n\n${resp.body}` }] };
      } catch (e) {
        return { content: [{ type: "text" as const, text: `superghidra-mcp unreachable at ${url}: ${(e as Error).message}. Run \`launch_re_backend id=superghidra-mcp\` first.` }], isError: true as const };
      }
    }
  );

  server.tool(
    "cheat_engine_aob",
    "Issue an AoB (array-of-bytes) scan through the running Cheat Engine MCP bridge. Backend must be launched first (launch_re_backend id='cheat-engine-mcp'). Supports CE wildcard pattern syntax ('48 8B ?? ?? ?? ?? ?? E8').",
    {
      pattern: z.string().describe("CE-style AoB pattern (hex bytes with ?? wildcards)."),
      process: z.string().optional().describe("Target process name or pid; required if not already attached."),
    },
    async ({ pattern, process: proc }: { pattern: string; process?: string }) => {
      const b = BACKENDS["cheat-engine-mcp"];
      if (!b.launch.http) return { content: [{ type: "text" as const, text: "cheat-engine-mcp has no HTTP endpoint." }], isError: true as const };
      const url = `http://127.0.0.1:${b.launch.http.port}/tool/aobscan`;
      try {
        const resp = await httpCall(url, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ pattern, process: proc }),
        });
        return { content: [{ type: "text" as const, text: `cheat-engine aobscan status=${resp.status}\n\n${resp.body}` }] };
      } catch (e) {
        return { content: [{ type: "text" as const, text: `cheat-engine-mcp unreachable at ${url}: ${(e as Error).message}. Run \`launch_re_backend id=cheat-engine-mcp\` first.` }], isError: true as const };
      }
    }
  );

  server.tool(
    "frida_eval",
    "Evaluate a Frida JavaScript snippet on a target process via the running Frida MCP bridge. Backend must be launched first (launch_re_backend id='frida-mcp'). Snippet runs inside the target with the Frida API.",
    {
      target: z.string().describe("Process name, pid, or '-' for the already-attached session."),
      script: z.string().describe("JavaScript snippet to run under Frida."),
    },
    async ({ target, script }: { target: string; script: string }) => {
      // Frida MCP wraps the bridge over stdio; still expose through the generic flow
      return {
        content: [{
          type: "text" as const,
          text: `Dispatch via Frida MCP as the client:\n\n\`\`\`json\n${JSON.stringify({ tool: "eval", target, script }, null, 2)}\n\`\`\`\n\nStart the backend first with \`launch_re_backend id=frida-mcp\`.`,
        }],
      };
    }
  );

  server.tool(
    "re_backend_health",
    "Probe all backends that declare an HTTP endpoint. Returns reachable/unreachable per backend.",
    {},
    async () => {
      const rows: string[] = [];
      for (const b of Object.values(BACKENDS)) {
        if (!b.launch.http) continue;
        const url = `http://127.0.0.1:${b.launch.http.port}${b.launch.http.path ?? ""}`;
        try {
          const resp = await httpCall(url, { method: "GET" }, 1_500);
          rows.push(`- **${b.id}** -> ${url} status ${resp.status}`);
        } catch (e) {
          rows.push(`- **${b.id}** -> ${url} UNREACHABLE (${(e as Error).message})`);
        }
      }
      if (!rows.length) return { content: [{ type: "text" as const, text: "No HTTP-based backends declared." }] };
      return { content: [{ type: "text" as const, text: `# RE backend health\n\n${rows.join("\n")}` }] };
    }
  );

  // --------------------------------------------------------
  // vibe_re
  // --------------------------------------------------------
  server.tool(
    "vibe_re_run",
    "Run a Vibe-RE Python tool from the vendored tools/vendor/vibe-re/retools or livetools. Each tool is a module under retools/ (disasm, decompiler, callgraph, cfg, xrefs, vtable, rtti, throwmap, sigdb, kb, search, asi_patcher, ...).",
    {
      module: z.string().describe("Module under retools/ or livetools/, e.g. 'retools.disasm', 'retools.callgraph', 'livetools.analyze'."),
      args: z.array(z.string()).default([]).describe("CLI arguments passed to the module."),
      cwd: z.string().optional().describe("Override working directory. Defaults to tools/vendor/vibe-re."),
    },
    async ({ module: modulePath, args, cwd }: { module: string; args?: string[]; cwd?: string }) => {
      const workdir = cwd ?? join(projectRoot, "tools", "vendor", "vibe-re");
      if (!(await pathExists(workdir))) {
        return { content: [{ type: "text" as const, text: `vibe-re not vendored at ${workdir}. Install via tools/vendor/vibe-re.` }], isError: true as const };
      }
      return await new Promise((resolve) => {
        const child = spawn("python", ["-I", "-m", modulePath, ...(args ?? [])], {
          cwd: workdir,
          env: process.env,
          stdio: ["ignore", "pipe", "pipe"],
          shell: process.platform === "win32",
        });
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (b) => (stdout += b.toString()));
        child.stderr?.on("data", (b) => (stderr += b.toString()));
        child.on("exit", (code) => {
          const out = `# vibe-re ${modulePath}\nexit=${code}\n\n## stdout\n\`\`\`\n${stdout.slice(0, 20_000)}\n\`\`\`\n\n## stderr\n\`\`\`\n${stderr.slice(0, 5_000)}\n\`\`\``;
          resolve({ content: [{ type: "text" as const, text: out }] });
        });
        child.on("error", (e) => {
          resolve({ content: [{ type: "text" as const, text: `spawn error: ${e.message}` }], isError: true as const });
        });
      });
    }
  );

  // --------------------------------------------------------
  // ida_run_script -- shell wrapper for IDA Pro scripts via idat
  // --------------------------------------------------------
  server.tool(
    "ida_run_script",
    "Run an IDAPython script against a binary using idat / idat64 in headless mode. Does NOT require the ida-pro-mcp plugin; just needs IDA on PATH.",
    {
      binary: z.string().describe("Path to the binary to analyze."),
      script: z.string().describe("Path to the .py script to run."),
      bits: z.enum(["32", "64"]).default("64"),
      extraArgs: z.array(z.string()).default([]).describe("Extra args to idat (e.g. ['-A', '-c'])."),
    },
    async ({ binary, script, bits, extraArgs }: { binary: string; script: string; bits: "32" | "64"; extraArgs?: string[] }) => {
      const bin = bits === "64" ? "idat64" : "idat";
      return await new Promise((resolve) => {
        const child = spawn(bin, ["-A", `-S${script}`, ...(extraArgs ?? []), binary], {
          env: process.env,
          stdio: ["ignore", "pipe", "pipe"],
          shell: process.platform === "win32",
        });
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (b) => (stdout += b.toString()));
        child.stderr?.on("data", (b) => (stderr += b.toString()));
        child.on("exit", (code) => {
          resolve({ content: [{ type: "text" as const, text: `# idat ${binary} -S${script}\nexit=${code}\n\n${stdout.slice(0, 20_000)}\n\n--- stderr ---\n${stderr.slice(0, 5_000)}` }] });
        });
        child.on("error", (e) => resolve({ content: [{ type: "text" as const, text: `idat spawn error: ${e.message}` }], isError: true as const }));
      });
    }
  );

  // --------------------------------------------------------
  // install_re_backend -- run the backend's install commands
  // --------------------------------------------------------
  server.tool(
    "install_re_backend",
    "Run the install commands listed by `describe_re_backend` for one backend. Streams each command's output back. Use `dryRun=true` to preview without running.",
    {
      id: z.string().describe("Backend id."),
      dryRun: z.boolean().default(false).describe("Preview commands without executing."),
      which: z.array(z.number().int().min(0)).optional().describe("Zero-based indexes of install steps to run. Omit to run all."),
    },
    async ({ id, dryRun, which }: { id: string; dryRun: boolean; which?: number[] }) => {
      const b = BACKENDS[id as ReBackendId];
      if (!b) return { content: [{ type: "text" as const, text: `Unknown backend "${id}".` }], isError: true as const };
      const picks = which && which.length ? which.map((i) => b.install[i]).filter(Boolean) : b.install;
      if (dryRun) {
        return { content: [{ type: "text" as const, text: `# install_re_backend ${id} (dry run)\n\n${picks.map((c) => "$ " + c).join("\n")}` }] };
      }
      const results: string[] = [`# install_re_backend ${id}`, ``];
      for (const step of picks) {
        results.push(`$ ${step}`);
        const outcome = await new Promise<{ code: number | null; out: string }>((resolve) => {
          const child = spawn(step, [], {
            cwd: projectRoot,
            env: process.env,
            stdio: ["ignore", "pipe", "pipe"],
            shell: true,
          });
          let out = "";
          child.stdout?.on("data", (b) => (out += b.toString()));
          child.stderr?.on("data", (b) => (out += b.toString()));
          child.on("exit", (code) => resolve({ code, out }));
          child.on("error", (e) => resolve({ code: -1, out: e.message }));
        });
        results.push(outcome.out.slice(-4000) || "(no output)");
        results.push(`-> exit ${outcome.code}\n`);
        if (outcome.code !== 0) {
          results.push(`stopped on step ${picks.indexOf(step)} (non-zero exit)`);
          break;
        }
      }
      return { content: [{ type: "text" as const, text: results.join("\n") }] };
    }
  );

  // --------------------------------------------------------
  // fakepdb_install -- copy the vendored FakePDB plugin into IDAUSR/plugins
  // --------------------------------------------------------
  server.tool(
    "fakepdb_install",
    "Install the vendored FakePDB IDA plugin (tools/vendor/fakepdb) into the user's IDAUSR plugins directory. Default IDAUSR is %APPDATA%/Hex-Rays/IDA Pro on Windows and $HOME/.idapro on Linux/macOS. Pass `idausr` to override.",
    {
      idausr: z.string().optional().describe("Override IDAUSR path."),
      dryRun: z.boolean().default(false),
    },
    async ({ idausr, dryRun }: { idausr?: string; dryRun: boolean }) => {
      const { homedir } = await import("node:os");
      const { cp, mkdir } = await import("node:fs/promises");
      const defIdausr = process.platform === "win32"
        ? join(process.env.APPDATA ?? homedir(), "Hex-Rays", "IDA Pro")
        : join(homedir(), ".idapro");
      const target = idausr ?? defIdausr;
      const plugins = join(target, "plugins");
      const src = join(projectRoot, "tools", "vendor", "fakepdb");
      if (!(await pathExists(src))) return { content: [{ type: "text" as const, text: `FakePDB not vendored at ${src}` }], isError: true as const };
      if (dryRun) return { content: [{ type: "text" as const, text: `[dry] would copy:\n  ${join(src, "fakepdb.py")} -> ${join(plugins, "fakepdb.py")}\n  ${join(src, "fakepdb")} -> ${join(plugins, "fakepdb")}` }] };
      try {
        await mkdir(plugins, { recursive: true });
        await cp(join(src, "fakepdb.py"), join(plugins, "fakepdb.py"));
        await cp(join(src, "fakepdb"), join(plugins, "fakepdb"), { recursive: true });
        return { content: [{ type: "text" as const, text: `installed FakePDB into ${plugins}. Open IDA and look under Edit > Plugins > FakePDB.` }] };
      } catch (e) {
        return { content: [{ type: "text" as const, text: `fakepdb_install error: ${(e as Error).message}` }], isError: true as const };
      }
    }
  );

  // --------------------------------------------------------
  // fakepdb_run -- headless FakePDB command (pdb_generate / dumpinfo / lib)
  // --------------------------------------------------------
  server.tool(
    "fakepdb_run",
    "Run a FakePDB command headlessly over an IDA database. Needs the plugin installed (fakepdb_install). Generates <binary>.pdb or <binary>.json or <binary>.lib next to the IDB. Modes: pdb (default), pdb-labels, dumpinfo, lib.",
    {
      binary: z.string().describe("Path to the binary (.exe/.dll/.sys). The IDB <binary>.i64 or <binary>.idb must sit next to it or be opened in IDA."),
      mode: z.enum(["pdb", "pdb-labels", "dumpinfo", "lib"]).default("pdb"),
      bits: z.enum(["32", "64"]).default("64"),
    },
    async ({ binary, mode, bits }: { binary: string; mode: "pdb" | "pdb-labels" | "dumpinfo" | "lib"; bits: "32" | "64" }) => {
      const bin = bits === "64" ? "idat64" : "idat";
      const scratch = join(projectRoot, ".fakepdb-scripts");
      const { mkdir, writeFile } = await import("node:fs/promises");
      await mkdir(scratch, { recursive: true });
      const modeMap: Record<string, string> = {
        pdb: "fakepdb.command_pdbgenerate.generate_pdb(False)",
        "pdb-labels": "fakepdb.command_pdbgenerate.generate_pdb(True)",
        dumpinfo: "fakepdb.command_dumpinfo.dump_info()",
        lib: "fakepdb.command_libgenerate.generate_lib()",
      };
      const script = `import fakepdb\n${modeMap[mode]}\n`;
      const scriptPath = join(scratch, `fakepdb_${mode}.py`);
      await writeFile(scriptPath, script, "utf8");
      return await new Promise((resolve) => {
        const child = spawn(bin, ["-A", `-S${scriptPath}`, binary], {
          env: process.env,
          stdio: ["ignore", "pipe", "pipe"],
          shell: process.platform === "win32",
        });
        let out = "";
        child.stdout?.on("data", (b) => (out += b.toString()));
        child.stderr?.on("data", (b) => (out += b.toString()));
        child.on("exit", (code) => {
          resolve({ content: [{ type: "text" as const, text: `# fakepdb_run ${mode}\nbinary=${binary}\nexit=${code}\n\n${out.slice(0, 20_000)}` }] });
        });
        child.on("error", (e) => resolve({ content: [{ type: "text" as const, text: `idat spawn error: ${e.message}. Install IDA or add it to PATH.` }], isError: true as const }));
      });
    }
  );

  // --------------------------------------------------------
  // ghidra_run_script -- analyzeHeadless wrapper
  // --------------------------------------------------------
  server.tool(
    "ghidra_run_script",
    "Run a Ghidra script against a binary using analyzeHeadless. Requires GHIDRA_INSTALL_DIR env var or ghidraRoot argument.",
    {
      binary: z.string().describe("Path to the binary."),
      script: z.string().describe("Script name or path (will be looked up relative to GHIDRA scripts dir unless absolute)."),
      project: z.string().default("tmp-ghidra-project").describe("Transient Ghidra project name."),
      ghidraRoot: z.string().optional().describe("Ghidra install dir. Falls back to env.GHIDRA_INSTALL_DIR."),
      extraArgs: z.array(z.string()).default([]),
    },
    async ({ binary, script, project, ghidraRoot, extraArgs }: { binary: string; script: string; project: string; ghidraRoot?: string; extraArgs?: string[] }) => {
      const root = ghidraRoot ?? process.env.GHIDRA_INSTALL_DIR;
      if (!root) return { content: [{ type: "text" as const, text: "GHIDRA_INSTALL_DIR not set and ghidraRoot not provided." }], isError: true as const };
      const headless = process.platform === "win32" ? "analyzeHeadless.bat" : "analyzeHeadless";
      const tmpDir = join(projectRoot, ".ghidra-projects");
      const args = [tmpDir, project, "-import", binary, "-postScript", script, "-deleteProject", ...(extraArgs ?? [])];
      return await new Promise((resolve) => {
        const child = spawn(join(root, "support", headless), args, {
          env: process.env,
          stdio: ["ignore", "pipe", "pipe"],
          shell: process.platform === "win32",
        });
        let stdout = "";
        let stderr = "";
        child.stdout?.on("data", (b) => (stdout += b.toString()));
        child.stderr?.on("data", (b) => (stderr += b.toString()));
        child.on("exit", (code) => {
          resolve({ content: [{ type: "text" as const, text: `# analyzeHeadless\nexit=${code}\n\n${stdout.slice(0, 20_000)}\n\n--- stderr ---\n${stderr.slice(0, 5_000)}` }] });
        });
        child.on("error", (e) => resolve({ content: [{ type: "text" as const, text: `analyzeHeadless spawn error: ${e.message}` }], isError: true as const }));
      });
    }
  );
}

// Shutdown hook -- kill child procs when parent dies
process.on("exit", () => {
  for (const proc of running.values()) {
    try { proc.child.kill("SIGTERM"); } catch { /* ignore */ }
  }
});
process.on("SIGINT", () => { process.exit(130); });
process.on("SIGTERM", () => { process.exit(143); });

export { BACKENDS };
