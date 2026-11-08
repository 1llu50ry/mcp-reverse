import { McpServer, ResourceTemplate } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { randomUUID } from "node:crypto";
import { createServer } from "node:http";
import { z } from "zod";
import { readdir, readFile, stat } from "node:fs/promises";
import { join, resolve } from "path";
import { createReadStream } from "node:fs";
import { createInterface } from "readline";
import { registerReTools } from "./retools.js";
import { registerNativeReTools } from "./native-re.js";
import { registerNativeFormatsTools } from "./native-formats.js";
import { registerAdvancedParsers } from "./native-advanced.js";
import { registerWorkflowTools } from "./workflow-tools.js";
import { registerAgentMesh } from "./agent-mesh.js";
import { registerMcpHub } from "./mcp-hub.js";
import { registerContainerParsers } from "./native-containers.js";
import { registerMetaTools } from "./meta-tools.js";
import { registerCompositeTools } from "./composite-tools.js";
import { registerBm25Search } from "./bm25-search.js";
import { registerAuditAndRate } from "./audit-rate.js";
import { registerDynamicResources } from "./dynamic-resources.js";
import { registerNativeDisasm } from "./native-disasm.js";
import { registerNativeMemory } from "./native-memory.js";
import { registerNativeYara } from "./native-yara.js";
import { registerNativeReclass } from "./native-reclass.js";
import { registerCeserverClient } from "./native-ceserver.js";
import { registerPluginClients } from "./native-tool-clients.js";
import { registerEmulator } from "./native-emulator.js";
import { registerNativeDwarf } from "./native-dwarf.js";
import { registerNativePdb } from "./native-pdb.js";
import { registerSignatureDb } from "./signature-db.js";
import { observabilityHandler, metrics, renderPrometheus } from "./observability.js";
import { registerArm64 } from "./native-arm64.js";
import { registerCacheTools, getCache } from "./decompile-cache.js";
import { registerChunkTools } from "./chunking.js";
import { runRequestMiddleware } from "./http-middleware.js";
import { registerNativeDiff } from "./native-diff.js";
import { registerApiHash } from "./native-apihash.js";
import { registerSyscalls } from "./native-syscalls.js";
import { registerJsDeob } from "./native-jsdeob.js";
import { registerIatRebuild } from "./native-iat-rebuild.js";
import { registerOllvmUndo } from "./native-ollvm-undo.js";
import { registerBitmanip } from "./native-bitmanip.js";
import { registerAsar } from "./native-asar.js";
import { registerGoBinary } from "./native-go-binary.js";
import { registerGguf } from "./native-gguf.js";
import { registerBeam } from "./native-beam.js";
import { registerAuthenticode } from "./native-authenticode.js";
import { registerReaPack } from "./native-rea-pack.js";
import { registerRop } from "./native-rop.js";
import { registerGameEngine } from "./native-gameengine.js";
import { registerSampling } from "./native-sampling.js";
import { registerViz } from "./native-viz.js";

const ROOT = resolve(import.meta.dirname, "..");
const DIRS = {
  skills: join(ROOT, "skills"),
  agents: join(ROOT, "agents"),
  subagents: join(ROOT, "subagents"),
  plugins: join(ROOT, "plugins"),
  prompts: join(ROOT, "prompts"),
} as const;

// ============================================================
// TYPES
// ============================================================

interface ParsedMeta {
  name: string;
  description: string;
  type?: string;
  source?: string;
  topics?: string[];
  model?: string;
  games?: string[];
  engines?: string[];
}

interface ParsedFile {
  meta: ParsedMeta;
  body: string;
}

interface CategorizedFile extends ParsedFile {
  category?: string;
}

interface SkillIndex {
  name: string;
  description: string;
  type: string;
  topics: string[];
  hasSource: boolean;
  searchText: string;
}

// ============================================================
// IN-MEMORY INDEX
// ============================================================

let _index: Map<string, SkillIndex> | null = null;
let _indexTime = 0;
let _indexBuild: Promise<Map<string, SkillIndex>> | null = null;
const INDEX_TTL = 120_000;
const INDEX_CHUNK = 64;

async function buildIndex(): Promise<Map<string, SkillIndex>> {
  // DB-first path: if db/skills.db (or MCP_SKILLS_DB) is present, pull the
  // index from SQLite in one shot. 10,000+ skills get listed in <50 ms
  // instead of walking the filesystem and reading every SKILL.md. The DB
  // writer (scripts/build-db.mjs) is responsible for keeping it current;
  // the server opens it read-only and never writes back.
  const dbMod = await import("./skills-db.js").catch(() => null);
  if (dbMod) {
    const h = await dbMod.getSharedDb(dbMod.defaultDbPath(ROOT));
    if (h) {
      const idx = new Map<string, SkillIndex>();
      // Walk every skill row — a single SELECT reads them all. The hasSource
      // bit is already materialised in the row (source_gz IS NOT NULL).
      let offset = 0;
      const PAGE = 5000;
      while (true) {
        const batch = dbMod.listSkills(h, PAGE, offset);
        if (batch.length === 0) break;
        for (const s of batch) {
          const searchText = [
            s.name, s.description ?? "", ...s.topics,
          ].join(" ").toLowerCase();
          idx.set(s.name, {
            name: s.name,
            description: s.description ?? "",
            type: s.type ?? "unknown",
            topics: s.topics,
            hasSource: s.hasSource,
            searchText,
          });
        }
        offset += batch.length;
        if (batch.length < PAGE) break;
      }
      return idx;
    }
  }

  // Filesystem fallback — same behaviour as before the DB existed.
  const entries = await readdir(DIRS.skills, { withFileTypes: true });
  const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name);
  const idx = new Map<string, SkillIndex>();

  // Bounded concurrency: walk in fixed chunks so open file handles stay flat
  // even on a 4,000+ skill library. The unbounded Promise.all here used to
  // exhaust handles under load and silently drop entries (because safeRead
  // returns null on error, indistinguishable from "file genuinely absent").
  for (let i = 0; i < dirs.length; i += INDEX_CHUNK) {
    const slice = dirs.slice(i, i + INDEX_CHUNK);
    await Promise.all(slice.map(async (name) => {
      const content = await safeRead(join(DIRS.skills, name, "SKILL.md"));
      if (!content) return;
      const parsed = parseFrontmatter(content);
      const hasSource = await fileExists(join(DIRS.skills, name, "source.txt"));
      const topics = parsed.meta.topics ?? [];
      const searchText = [
        name, parsed.meta.name, parsed.meta.description, ...topics,
        ...(parsed.meta.games ?? []), ...(parsed.meta.engines ?? []),
      ].join(" ").toLowerCase();

      idx.set(name, {
        name,
        description: parsed.meta.description,
        type: parsed.meta.type ?? "unknown",
        topics,
        hasSource,
        searchText,
      });
    }));
  }

  return idx;
}

async function getIndex(): Promise<Map<string, SkillIndex>> {
  const now = Date.now();
  if (_index && now - _indexTime < INDEX_TTL) return _index;
  // Single-flight: concurrent callers await the build already running
  // instead of each starting their own (which multiplied handle pressure
  // and could produce different results per caller on the same cold tree).
  if (_indexBuild) return _indexBuild;

  _indexBuild = buildIndex();
  try {
    const idx = await _indexBuild;
    _index = idx;
    _indexTime = Date.now(); // stamp on completion, not start, so TTL counts real freshness
    return idx;
  } finally {
    _indexBuild = null;
  }
}

// Component caches
const _componentCache = new Map<string, { items: CategorizedFile[]; time: number }>();
const COMP_TTL = 60_000;

async function getCachedComponents(dir: string): Promise<CategorizedFile[]> {
  const now = Date.now();
  const cached = _componentCache.get(dir);
  if (cached && now - cached.time < COMP_TTL) return cached.items;
  const items = await listMdFiles(dir);
  _componentCache.set(dir, { items, time: now });
  return items;
}

// ============================================================
// CORE HELPERS
// ============================================================

function parseFrontmatter(content: string): ParsedFile {
  const match = content.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n([\s\S]*)$/);
  if (!match) return { meta: { name: "", description: "" }, body: content };

  const raw = match[1];
  const body = match[2].trim();

  // Allow leading whitespace so nested keys (e.g. `  type:` under `metadata:`) are read.
  // Pre-existing array matcher is already unanchored, so this just brings scalars in line.
  const str = (key: string) => raw.match(new RegExp(`^\\s*${key}:\\s*"?(.+?)"?$`, "m"))?.[1]?.trim();
  const arr = (key: string) => {
    const m = raw.match(new RegExp(`${key}:\\s*\\[([^\\]]*)\\]`));
    return m ? m[1].split(",").map((t) => t.trim().replace(/^['"]|['"]$/g, "")).filter(Boolean) : undefined;
  };

  return {
    meta: {
      name: str("name") ?? "",
      description: str("description") ?? "",
      type: str("type"),
      source: str("source"),
      model: str("model"),
      topics: arr("topics"),
      games: arr("games"),
      engines: arr("engines"),
    },
    body,
  };
}

async function safeRead(path: string): Promise<string | null> {
  try {
    return await readFile(path, "utf-8");
  } catch {
    // Fallback 1: `path.gz` next to the missing file — gunzip on the fly.
    try {
      const { gunzipSync } = await import("node:zlib");
      const buf = await readFile(path + ".gz");
      return gunzipSync(buf).toString("utf-8");
    } catch { /* continue to fallback 2 */ }
    // Fallback 2: content is in the SQLite DB. We only hit this path for
    // the two files we actually store there — skills/<name>/SKILL.md and
    // skills/<name>/source.txt — so a cheap substring check keeps the
    // happy path fast when the DB is absent.
    const m = /[\\/]skills[\\/]([^\\/]+)[\\/](SKILL\.md|source\.txt)$/.exec(path);
    if (m) {
      try {
        const dbMod = await import("./skills-db.js");
        const h = await dbMod.getSharedDb(dbMod.defaultDbPath(ROOT));
        if (h) {
          if (m[2] === "SKILL.md") {
            const row = dbMod.getSkill(h, m[1]);
            if (row) return `---\nname: ${row.name}\ndescription: "${(row.description ?? "").replace(/"/g, '\\"')}"\nmetadata:\n  type: ${row.type ?? "reference"}\n---\n\n${row.body}`;
          } else {
            const text = dbMod.getSkillSource(h, m[1]);
            if (text) return text;
          }
        }
      } catch { /* missing deps or sql error — give up quietly */ }
    }
    return null;
  }
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await stat(path);
    return true;
  } catch {
    // Mirror safeRead's gzip fallback: `path` is considered to exist if
    // `path.gz` is next to it on disk.
    try { await stat(path + ".gz"); return true; } catch { return false; }
  }
}

/**
 * Map a project directory to the SQLite table name. Returns null for
 * directories we don't mirror in the DB (notably `skills` — that one
 * has its own SKILL.md round-trip path through safeRead already).
 */
function dirToTable(dir: string): "plugins" | "agents" | "subagents" | "prompts" | null {
  if (dir === DIRS.plugins)   return "plugins";
  if (dir === DIRS.agents)    return "agents";
  if (dir === DIRS.subagents) return "subagents";
  if (dir === DIRS.prompts)   return "prompts";
  return null;
}

async function listMdFiles(dir: string, category?: string): Promise<CategorizedFile[]> {
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    const results: CategorizedFile[] = [];
    for (const e of entries) {
      if (e.isDirectory()) {
        const sub = await listMdFiles(join(dir, e.name), e.name);
        results.push(...sub);
      } else if (e.name.endsWith(".md")) {
        const content = await safeRead(join(dir, e.name));
        if (content) {
          const parsed = parseFrontmatter(content);
          results.push({ ...parsed, category });
        }
      }
    }
    if (results.length > 0) return results;
    // Fall through to DB when the directory walk produced nothing.
    return (await listMdFromDb(dir)) ?? results;
  } catch {
    // The directory doesn't exist at all — ask the DB directly.
    return (await listMdFromDb(dir)) ?? [];
  }
}

async function listMdFromDb(dir: string): Promise<CategorizedFile[] | null> {
  const table = dirToTable(dir);
  if (!table) return null;
  try {
    const dbMod = await import("./skills-db.js");
    const h = await dbMod.getSharedDb(dbMod.defaultDbPath(ROOT));
    if (!h) return null;
    if (table === "plugins") {
      const rows = dbMod.listPlugins(h);
      const out: CategorizedFile[] = [];
      for (const r of rows) {
        const body = dbMod.getPlugin(h, r.category, r.name);
        if (!body) continue;
        out.push({ ...parseFrontmatter(body.body), category: r.category });
      }
      return out;
    }
    if (table === "prompts") {
      const rows = dbMod.listPrompts(h);
      const out: CategorizedFile[] = [];
      for (const r of rows) {
        const body = dbMod.getPromptBody(h, r.category, r.name);
        if (!body) continue;
        out.push({ ...parseFrontmatter(body), category: r.category });
      }
      return out;
    }
    // agents / subagents (no category)
    const names = dbMod.listAgents(h, table);
    const out: CategorizedFile[] = [];
    for (const n of names) {
      const body = dbMod.getAgentBody(h, table, n);
      if (!body) continue;
      out.push({ ...parseFrontmatter(body) });
    }
    return out;
  } catch { return null; }
}

async function findMdByName(dir: string, name: string): Promise<string | null> {
  const direct = join(dir, `${name}.md`);
  if (await fileExists(direct)) return direct;
  try {
    const entries = await readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      if (e.isDirectory()) {
        const sub = join(dir, e.name, `${name}.md`);
        if (await fileExists(sub)) return sub;
      }
    }
  } catch {}
  return null;
}

/** DB-side alternative: returns the body text directly if present. */
async function readBodyFromDb(dir: string, name: string): Promise<string | null> {
  const table = dirToTable(dir);
  if (!table) return null;
  try {
    const dbMod = await import("./skills-db.js");
    const h = await dbMod.getSharedDb(dbMod.defaultDbPath(ROOT));
    if (!h) return null;
    if (table === "plugins") {
      // The plugins table is keyed by (category, name); scan via the
      // name index to find the right (cat, name) pair.
      for (const row of dbMod.listPlugins(h)) {
        if (row.name === name) {
          const r = dbMod.getPlugin(h, row.category, row.name);
          if (r) return r.body;
        }
      }
      return null;
    }
    if (table === "prompts") {
      for (const row of dbMod.listPrompts(h)) {
        if (row.name === name) {
          return dbMod.getPromptBody(h, row.category, row.name);
        }
      }
      return null;
    }
    return dbMod.getAgentBody(h, table, name);
  } catch { return null; }
}

async function readMdByName(dir: string, name: string): Promise<ParsedFile | null> {
  const path = await findMdByName(dir, name);
  if (path) {
    const content = await safeRead(path);
    if (content) return parseFrontmatter(content);
  }
  // DB fallback — for when the plugins/agents/etc. tree has been
  // reaped and only db/skills.db remains.
  const body = await readBodyFromDb(dir, name);
  if (!body) return null;
  return parseFrontmatter(body);
}

async function readSkill(name: string): Promise<ParsedFile | null> {
  const content = await safeRead(join(DIRS.skills, name, "SKILL.md"));
  return content ? parseFrontmatter(content) : null;
}

function ok(text: string) {
  return { content: [{ type: "text" as const, text }] };
}

function err(text: string) {
  return { content: [{ type: "text" as const, text }], isError: true as const };
}

function notFound(kind: string, name: string) {
  return err(`${kind} "${name}" not found. Use list_${kind.toLowerCase()}s to see available options.`);
}

// ============================================================
// GREP ENGINE -- streaming line search through source.txt
// ============================================================

async function grepFile(filePath: string, pattern: RegExp, maxMatches: number, contextLines: number): Promise<{ line: number; text: string }[]> {
  return new Promise(async (resolve) => {
    const matches: { line: number; text: string }[] = [];
    let lineNum = 0;
    const buffer: string[] = [];

    try {
      // Resolve the live path: prefer the uncompressed source.txt when
      // it exists; otherwise stream through gunzip from source.txt.gz
      // transparently so the greps work in both layouts.
      let readable: NodeJS.ReadableStream;
      if (await fileExists(filePath) && !filePath.endsWith(".gz")) {
        // check if uncompressed exists at the exact path
        try {
          await stat(filePath);
          readable = createReadStream(filePath, { encoding: "utf-8", highWaterMark: 64 * 1024 });
        } catch {
          const { createGunzip } = await import("node:zlib");
          readable = createReadStream(filePath + ".gz", { highWaterMark: 64 * 1024 }).pipe(createGunzip()).setEncoding("utf-8");
        }
      } else {
        const { createGunzip } = await import("node:zlib");
        readable = createReadStream(filePath + ".gz", { highWaterMark: 64 * 1024 }).pipe(createGunzip()).setEncoding("utf-8");
      }
      const rl = createInterface({
        input: readable,
        crlfDelay: Infinity,
      });

      rl.on("line", (line) => {
        lineNum++;
        buffer.push(line);
        if (buffer.length > contextLines * 2 + 1) buffer.shift();

        if (pattern.test(line)) {
          matches.push({ line: lineNum, text: line.trimEnd().slice(0, 200) });
          if (matches.length >= maxMatches) {
            rl.close();
            rl.removeAllListeners();
          }
        }
      });

      rl.on("close", () => resolve(matches));
      rl.on("error", () => resolve(matches));
    } catch {
      resolve(matches);
    }
  });
}

// ============================================================
// FORMATTERS
// ============================================================

function formatSkillCompact(name: string, meta: { description: string; type?: string }, hasSrc: boolean): string {
  const tags = [meta.type ?? "unknown", hasSrc ? "has-source" : "no-source"].join(", ");
  return `- **${name}** [${tags}]: ${meta.description}`;
}

function formatSkillFull(name: string, parsed: ParsedFile, hasSrc: boolean): string {
  const lines = [
    `# ${parsed.meta.name || name}`,
    "",
    `**Description:** ${parsed.meta.description}`,
    `**Type:** ${parsed.meta.type ?? "unknown"}`,
    `**Source:** ${parsed.meta.source ?? "original"}`,
    `**Has source code:** ${hasSrc}`,
  ];
  if (parsed.meta.topics?.length) lines.push(`**Topics:** ${parsed.meta.topics.join(", ")}`);
  if (parsed.meta.games?.length) lines.push(`**Games:** ${parsed.meta.games.join(", ")}`);
  if (parsed.meta.engines?.length) lines.push(`**Engines:** ${parsed.meta.engines.join(", ")}`);
  lines.push("", "---", "", parsed.body);
  return lines.join("\n");
}

function formatComponentList(kind: string, items: CategorizedFile[]): string {
  if (!items.length) return `No ${kind}s found.`;
  const grouped = new Map<string, CategorizedFile[]>();
  for (const item of items) {
    const cat = item.category ?? "uncategorized";
    if (!grouped.has(cat)) grouped.set(cat, []);
    grouped.get(cat)!.push(item);
  }
  const sections: string[] = [`Available ${kind}s (${items.length}):\n`];
  for (const [cat, catItems] of grouped) {
    sections.push(`### ${cat} (${catItems.length})\n${catItems.map((i) => `- **${i.meta.name}**: ${i.meta.description}`).join("\n")}\n`);
  }
  return sections.join("\n");
}

function formatComponent(kind: string, parsed: ParsedFile): string {
  const lines = [`# ${kind}: ${parsed.meta.name}`, "", `**Description:** ${parsed.meta.description}`];
  if (parsed.meta.model) lines.push(`**Model:** ${parsed.meta.model}`);
  lines.push("", "---", "", parsed.body);
  return lines.join("\n");
}

// ============================================================
// SCORED SEARCH
// ============================================================

function scoreSkill(idx: SkillIndex, keywords: string[]): number {
  let score = 0;
  const nameLc = idx.name.toLowerCase();
  for (const kw of keywords) {
    if (nameLc.includes(kw)) score += 5;
    else if (idx.searchText.includes(kw)) score += 2;
  }
  return score;
}

// ============================================================
// SERVER
// ============================================================

// Read version from package.json so serverInfo stays in lockstep with
// package.json instead of being hardcoded (previously stuck at 3.0.0).
const PKG_VERSION = JSON.parse(
  await readFile(join(ROOT, "package.json"), "utf8")
).version as string;

const server = new McpServer({
  name: "mcp-reverse",
  version: PKG_VERSION,
  title: "mcp-reverse: reverse-engineering mega-brain",
}, {
  // Capabilities we actively support. The MCP SDK derives these from
  // registered primitives too, but declaring them explicitly makes the
  // handshake self-descriptive for clients that key feature detection
  // off capabilities rather than trial-and-error.
  // Sampling is a client capability (we consume it via createMessage in
  // decompile_summarize / struct_name_suggest / explain_at_level), so
  // it's not declared here on the server side.
  capabilities: {
    tools:     { listChanged: true },
    resources: { subscribe: false, listChanged: true },
    prompts:   { listChanged: true },
    logging:   {},
  },
  instructions:
    "mcp-reverse exposes 180+ tools for binary RE: Ghidra/IDA/Binja/CE/ReClass/dnSpy/x64dbg bridges, Frida dynamic instrumentation, native PE/ELF/Mach-O/DEX/.NET/Unity/UE/IL2CPP parsers, YARA, FLIRT-light signatures, native x86-64 + ARM64 emulators, agent-mesh (multi-model chat), MCP hub (smart decompile fail-over), content-addressable decompile cache. Prefer the `smart_*` composite tools when uncertain which backend to use. Use `cache_stats` + `chunk_fetch` for large results.",
});

// Wrap server.tool so every registered handler feeds the observability
// counters + latency histogram. Previously only HTTP-middleware wrote to
// metrics; /dashboard's "top tools" and the Prometheus
// mcp_tool_calls_total series were empty by construction. This runs ONCE
// before any registerXxx() so all 200+ handlers get instrumented at once.
{
  // The SDK's method signature is overloaded; the two shapes we actually
  // hit from this file are (name, description, schema, handler) and
  // (name, description, handler) with no schema. We just need the last
  // argument when it's a function.
  const origTool = server.tool.bind(server);
  (server as unknown as { tool: (...a: unknown[]) => unknown }).tool = (...args: unknown[]) => {
    const i = args.findIndex(a => typeof a === "function");
    if (i >= 0) {
      const name = String(args[0] ?? "unknown");
      const orig = args[i] as (...xs: unknown[]) => unknown;
      args[i] = async (...xs: unknown[]) => {
        const t0 = performance.now();
        let ok = true;
        try { return await orig(...xs); }
        catch (e) { ok = false; throw e; }
        finally {
          metrics.toolCall(name, performance.now() - t0, { ok });
        }
      };
    }
    return (origTool as (...a: unknown[]) => unknown)(...args);
  };
}

// ============================================================
// MCP RESOURCES
// ============================================================

server.resource(
  "library-stats",
  "gamehacking://stats",
  { description: "Skill library statistics overview" },
  async () => {
    const idx = await getIndex();
    let withSource = 0;
    let agsCount = 0;
    const types: Record<string, number> = {};

    for (const [name, skill] of idx) {
      if (skill.hasSource) withSource++;
      if (name.startsWith("ags-")) agsCount++;
      types[skill.type] = (types[skill.type] ?? 0) + 1;
    }

    const typeStr = Object.entries(types).sort((a, b) => b[1] - a[1]).map(([k, v]) => `  ${k}: ${v}`).join("\n");

    return {
      contents: [{
        uri: "gamehacking://stats",
        mimeType: "text/markdown",
        text: `# Skill Library Stats\n\n- **Total:** ${idx.size}\n- **Hand-written:** ${idx.size - agsCount}\n- **Archived (ags-):** ${agsCount}\n- **With source:** ${withSource}\n\n**By type:**\n${typeStr}`,
      }],
    };
  }
);

server.resource(
  "agent",
  new ResourceTemplate("gamehacking://agents/{name}", { list: undefined }),
  { description: "Agent definition by name" },
  async (uri, { name }) => {
    const parsed = await readMdByName(DIRS.agents, name as string);
    if (!parsed) return { contents: [{ uri: uri.href, mimeType: "text/plain", text: `Agent "${name}" not found.` }] };
    return { contents: [{ uri: uri.href, mimeType: "text/markdown", text: formatComponent("Agent", parsed) }] };
  }
);

server.resource(
  "subagent",
  new ResourceTemplate("gamehacking://subagents/{name}", { list: undefined }),
  { description: "Subagent definition by name" },
  async (uri, { name }) => {
    const parsed = await readMdByName(DIRS.subagents, name as string);
    if (!parsed) return { contents: [{ uri: uri.href, mimeType: "text/plain", text: `Subagent "${name}" not found.` }] };
    return { contents: [{ uri: uri.href, mimeType: "text/markdown", text: formatComponent("Subagent", parsed) }] };
  }
);

server.resource(
  "plugin",
  new ResourceTemplate("gamehacking://plugins/{name}", { list: undefined }),
  { description: "Plugin definition by name" },
  async (uri, { name }) => {
    const parsed = await readMdByName(DIRS.plugins, name as string);
    if (!parsed) return { contents: [{ uri: uri.href, mimeType: "text/plain", text: `Plugin "${name}" not found.` }] };
    return { contents: [{ uri: uri.href, mimeType: "text/markdown", text: formatComponent("Plugin", parsed) }] };
  }
);

server.resource(
  "skill",
  new ResourceTemplate("gamehacking://skills/{name}", { list: undefined }),
  { description: "Skill SKILL.md content by name" },
  async (uri, { name }) => {
    const n = name as string;
    const skill = await readSkill(n);
    if (!skill) return { contents: [{ uri: uri.href, mimeType: "text/plain", text: `Skill "${n}" not found.` }] };
    const hasSrc = await fileExists(join(DIRS.skills, n, "source.txt"));
    return { contents: [{ uri: uri.href, mimeType: "text/markdown", text: formatSkillFull(n, skill, hasSrc) }] };
  }
);

// ============================================================
// MCP PROMPTS (native)
// ============================================================

server.prompt(
  "analyze-cheat",
  "Full architecture analysis of a cheat project from the skill library",
  { project: z.string().describe("Skill/project name (kebab-case)") },
  async ({ project }) => {
    const skill = await readSkill(project);
    const hasSrc = skill ? await fileExists(join(DIRS.skills, project, "source.txt")) : false;
    const intro = skill ? formatSkillFull(project, skill, hasSrc) : `Project "${project}" not found in library.`;
    return {
      messages: [{
        role: "user",
        content: { type: "text", text: `${intro}\n\nAnalyze this cheat project:\n1. Architecture (internal/external/overlay/DMA/hybrid)\n2. Engine target and version\n3. Memory access method (driver/DMA/hypervisor/direct)\n4. Injection chain\n5. Stealth measures\n6. Detection surface per anti-cheat\n7. Notable techniques worth extracting` },
      }],
    };
  }
);

server.prompt(
  "find-bypass",
  "Research bypass techniques for a specific anti-cheat system",
  { anticheat: z.string().describe("Anti-cheat name: battleye, eac, vanguard, vac, faceit, byfron") },
  async ({ anticheat }) => {
    const idx = await getIndex();
    const kw = anticheat.toLowerCase();
    const relevant: string[] = [];
    for (const [name, skill] of idx) {
      if (skill.searchText.includes(kw)) relevant.push(`- **${name}**: ${skill.description}`);
      if (relevant.length >= 30) break;
    }
    return {
      messages: [{
        role: "user",
        content: { type: "text", text: `# Bypass Research: ${anticheat}\n\nRelevant projects in library (${relevant.length}):\n${relevant.join("\n")}\n\nBased on these projects and your knowledge:\n1. Current detection vectors used by ${anticheat}\n2. Known bypass techniques (kernel, HV, DMA, usermode)\n3. Detection risk assessment per technique\n4. Recommended approach for 2024+\n5. Required tooling and prerequisites` },
      }],
    };
  }
);

server.prompt(
  "reverse-binary",
  "Structured workflow for reversing a game binary",
  {
    game: z.string().describe("Game name"),
    engine: z.string().optional().describe("Engine if known: unreal, unity, source, custom"),
  },
  async ({ game, engine }) => {
    const idx = await getIndex();
    const kws = [game.toLowerCase(), ...(engine ? [engine.toLowerCase()] : [])];
    const relevant: string[] = [];
    for (const [name, skill] of idx) {
      if (kws.some((k) => skill.searchText.includes(k))) {
        relevant.push(`- **${name}**: ${skill.description}`);
        if (relevant.length >= 20) break;
      }
    }
    return {
      messages: [{
        role: "user",
        content: { type: "text", text: `# Reverse Engineering: ${game}${engine ? ` (${engine})` : ""}\n\nRelevant projects:\n${relevant.join("\n")}\n\nProvide a structured RE workflow:\n1. Static analysis setup (IDA/Ghidra config, SDK generation)\n2. Dynamic analysis (debugger attach, bypass anti-debug)\n3. Key structures to find (player, entity list, camera, world)\n4. Offset extraction methodology\n5. Validation and testing approach` },
      }],
    };
  }
);

server.prompt(
  "build-esp",
  "Design an ESP system for a specific game and engine",
  {
    game: z.string().describe("Target game"),
    render_method: z.string().optional().describe("Render method: overlay, internal, dxgi, canvas"),
  },
  async ({ game, render_method }) => ({
    messages: [{
      role: "user",
      content: { type: "text", text: `# ESP System Design: ${game}\nRender method: ${render_method ?? "auto-select"}\n\nDesign a complete ESP system:\n1. Entity scanning (world -> player array -> positions)\n2. World-to-screen projection\n3. Bone-based skeleton ESP\n4. Bounding boxes (2D and 3D)\n5. Health/shield bars\n6. Distance and name labels\n7. Visibility checks\n8. Render pipeline (${render_method ?? "recommend best approach"})\n9. Thread safety (scanner thread vs render thread)\n10. Performance optimization` },
    }],
  })
);

server.prompt(
  "write-driver",
  "Design a kernel driver for game memory access",
  {
    method: z.string().optional().describe("Access method: ioctl, shared-memory, hypervisor, dma"),
  },
  async ({ method }) => ({
    messages: [{
      role: "user",
      content: { type: "text", text: `# Kernel Driver Design\nAccess method: ${method ?? "IOCTL-based"}\n\nDesign a kernel driver for game memory R/W:\n1. Driver entry and device creation\n2. IOCTL dispatch (read/write/get-module)\n3. Process attachment (KeStackAttachProcess vs MmCopyVirtualMemory vs physical)\n4. CR3-based physical memory translation\n5. Stealth loading (manual map, vulnerable driver chain, EFI)\n6. Anti-detection (PiDDB cleanup, MmUnloadedDrivers, BigPool)\n7. Communication channel security\n8. Cleanup and unload` },
    }],
  })
);

server.prompt(
  "compare-projects",
  "Compare two cheat projects side by side",
  {
    project_a: z.string().describe("First project name"),
    project_b: z.string().describe("Second project name"),
  },
  async ({ project_a, project_b }) => {
    const a = await readSkill(project_a);
    const b = await readSkill(project_b);
    const aHas = a ? await fileExists(join(DIRS.skills, project_a, "source.txt")) : false;
    const bHas = b ? await fileExists(join(DIRS.skills, project_b, "source.txt")) : false;
    const aText = a ? formatSkillFull(project_a, a, aHas) : `"${project_a}" not found.`;
    const bText = b ? formatSkillFull(project_b, b, bHas) : `"${project_b}" not found.`;
    return {
      messages: [{
        role: "user",
        content: { type: "text", text: `# Project Comparison\n\n## Project A\n${aText}\n\n## Project B\n${bText}\n\nCompare these projects:\n1. Architecture and design approach\n2. Engine/game targeting\n3. Memory access method\n4. Stealth and anti-detection\n5. Feature completeness\n6. Code quality and maintainability\n7. Which techniques from each are worth adopting` },
      }],
    };
  }
);

// ============================================================
// WORKFLOW TOOLS
// ============================================================

server.tool(
  "research_technique",
  "Research a game hacking technique: finds relevant skills by scored keyword search across the indexed library. Returns consolidated briefing.",
  {
    technique: z.string().describe("Technique to research, e.g. 'DMA memory read', 'EPT hook', 'silent aim', 'driver communication'"),
    detail: z.enum(["concise", "detailed"]).default("concise").describe("Response detail level"),
    max_results: z.number().min(1).max(50).default(10).describe("Max skills to include"),
  },
  async ({ technique, detail, max_results }) => {
    const idx = await getIndex();
    const keywords = technique.toLowerCase().split(/[\s,_-]+/).filter((w) => w.length > 2);
    const scored: Array<{ name: string; score: number; idx: SkillIndex }> = [];

    for (const [name, skill] of idx) {
      const score = scoreSkill(skill, keywords);
      if (score > 0) scored.push({ name, score, idx: skill });
    }

    scored.sort((a, b) => b.score - a.score);
    const top = scored.slice(0, max_results);

    if (!top.length) return err(`No skills found for "${technique}". Try broader keywords.`);

    let output = `# Research: ${technique}\n\nFound ${scored.length} relevant skills (showing top ${top.length}):\n\n`;

    if (detail === "detailed") {
      for (const { name } of top) {
        const parsed = await readSkill(name);
        if (parsed) output += formatSkillFull(name, parsed, scored.find((s) => s.name === name)?.idx.hasSource ?? false) + "\n\n---\n\n";
      }
    } else {
      for (const { name, idx: skill } of top) {
        output += formatSkillCompact(name, { description: skill.description, type: skill.type }, skill.hasSource) + "\n";
      }
    }

    if (scored.length > max_results) {
      output += `\n_${scored.length - max_results} more results. Increase max_results or refine query._`;
    }

    return ok(output);
  }
);

server.tool(
  "analyze_project",
  "Deep-analyze an archived project: reads SKILL.md + source code, classifies technique, provides structured assessment.",
  {
    name: z.string().describe("Skill/project folder name (kebab-case)"),
    focus: z.enum(["architecture", "injection", "stealth", "detection", "all"]).default("all"),
    source_lines: z.number().min(50).max(2000).default(500).describe("Max source lines to include"),
  },
  async ({ name, focus, source_lines }) => {
    const skill = await readSkill(name);
    if (!skill) return notFound("Skill", name);

    const hasSrc = await fileExists(join(DIRS.skills, name, "source.txt"));
    let output = formatSkillFull(name, skill, hasSrc);

    if (hasSrc) {
      const src = await safeRead(join(DIRS.skills, name, "source.txt"));
      if (src) {
        const lines = src.split("\n").slice(0, source_lines);
        output += `\n\n## Source Code (first ${lines.length} lines)\n\n\`\`\`\n${lines.join("\n")}\n\`\`\``;
      }
    }

    const focusMap: Record<string, string> = {
      architecture: "- Architecture type (internal/external/overlay/DMA/EFI/hybrid)\n- Engine target\n- Memory access method\n- Thread model",
      injection: "- Injection technique\n- Loading method\n- Privilege requirements\n- Vulnerable drivers used",
      stealth: "- Hiding techniques\n- Trace cleanup\n- Anti-debug/anti-analysis\n- Detection evasion",
      detection: "- Detection surface per AC (BE/EAC/Vanguard/VAC)\n- Risk rating\n- Detectable artifacts\n- Mitigation options",
      all: "- Full architecture classification\n- Injection and loading chain\n- Stealth measures\n- Detection surface\n- Notable techniques",
    };

    output += `\n\n## Analysis Focus: ${focus}\n\n${focusMap[focus] ?? focusMap.all}`;
    return ok(output);
  }
);

server.tool(
  "get_agent_briefing",
  "Load an agent definition with all available subagents and plugins listed. Returns a ready-to-use system prompt.",
  {
    agent: z.string().describe("Agent name (kebab-case). Use list_agents to see all 75 available agents."),
  },
  async ({ agent }) => {
    const parsed = await readMdByName(DIRS.agents, agent);
    if (!parsed) return notFound("Agent", agent);

    const subagents = await getCachedComponents(DIRS.subagents);
    const plugins = await getCachedComponents(DIRS.plugins);

    let output = formatComponent("Agent", parsed);
    output += "\n\n## Available Subagents\n\n";
    output += subagents.map((s) => `- **${s.meta.name}**: ${s.meta.description}`).join("\n");
    output += "\n\n## Available Plugins\n\n";
    output += plugins.map((p) => `- **${p.meta.name}**: ${p.meta.description}`).join("\n");

    return ok(output);
  }
);

// ============================================================
// GREP / FULL-TEXT SEARCH
// ============================================================

server.tool(
  "grep_sources",
  "Full-text search across all 3,985 source code archives. Streams through source.txt files matching a regex pattern. Use for finding specific offsets, function names, patterns, struct definitions.",
  {
    pattern: z.string().min(2).describe("Regex pattern to search. Examples: '0x447D410', 'ProcessEvent', 'class APlayerController', 'CR3'"),
    case_sensitive: z.boolean().default(false),
    max_files: z.number().min(1).max(100).default(20).describe("Max files to search (stops after this many hits)"),
    max_matches_per_file: z.number().min(1).max(50).default(5).describe("Max matches per file"),
    filter: z.string().optional().describe("Only search skills whose name contains this substring"),
  },
  async ({ pattern, case_sensitive, max_files, max_matches_per_file, filter }) => {
    const idx = await getIndex();
    let regex: RegExp;
    try {
      regex = new RegExp(pattern, case_sensitive ? "" : "i");
    } catch (e) {
      return err(`Invalid regex: ${e}`);
    }

    const results: Array<{ skill: string; matches: { line: number; text: string }[] }> = [];
    let filesSearched = 0;

    for (const [name, skill] of idx) {
      if (!skill.hasSource) continue;
      if (filter && !name.toLowerCase().includes(filter.toLowerCase())) continue;

      const filePath = join(DIRS.skills, name, "source.txt");
      const matches = await grepFile(filePath, regex, max_matches_per_file, 0);

      if (matches.length > 0) {
        results.push({ skill: name, matches });
        if (results.length >= max_files) break;
      }
      filesSearched++;
    }

    if (!results.length) return err(`No matches for "${pattern}" in ${filesSearched} source archives.`);

    let output = `# Grep: \`${pattern}\`\n\nFound in ${results.length} projects (searched ${filesSearched}):\n\n`;
    for (const { skill, matches } of results) {
      output += `## ${skill}\n`;
      for (const m of matches) {
        output += `  L${m.line}: ${m.text}\n`;
      }
      output += "\n";
    }

    return ok(output);
  }
);

// ============================================================
// OFFSET CROSS-REFERENCE
// ============================================================

server.tool(
  "find_offset",
  "Cross-reference a game offset, pattern, or struct name across all archived source code. Finds every project that uses a specific offset value or field name.",
  {
    query: z.string().describe("Offset hex value (0x4F0), field name (BoneMatrix), or pattern (CompSpaceBones)"),
    max_results: z.number().min(1).max(50).default(15),
  },
  async ({ query, max_results }) => {
    const idx = await getIndex();
    let regex: RegExp;
    try {
      regex = new RegExp(query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
    } catch {
      regex = new RegExp(query, "i");
    }

    const results: Array<{ skill: string; matches: { line: number; text: string }[] }> = [];

    for (const [name, skill] of idx) {
      if (!skill.hasSource) continue;
      const filePath = join(DIRS.skills, name, "source.txt");
      const matches = await grepFile(filePath, regex, 3, 0);
      if (matches.length > 0) {
        results.push({ skill: name, matches });
        if (results.length >= max_results) break;
      }
    }

    if (!results.length) return err(`No projects reference "${query}".`);

    let output = `# Offset Cross-Reference: \`${query}\`\n\nFound in ${results.length} projects:\n\n`;
    for (const { skill, matches } of results) {
      output += `### ${skill}\n`;
      for (const m of matches) {
        output += `  L${m.line}: ${m.text}\n`;
      }
      output += "\n";
    }

    return ok(output);
  }
);

// ============================================================
// COMPARE PROJECTS TOOL
// ============================================================

server.tool(
  "compare_projects",
  "Side-by-side comparison of two cheat projects: architecture, techniques, features, detection surface.",
  {
    project_a: z.string().describe("First project name"),
    project_b: z.string().describe("Second project name"),
    include_source: z.boolean().default(false).describe("Include first 200 lines of source from each"),
  },
  async ({ project_a, project_b, include_source }) => {
    const a = await readSkill(project_a);
    const b = await readSkill(project_b);
    if (!a && !b) return err(`Neither "${project_a}" nor "${project_b}" found.`);

    let output = `# Comparison: ${project_a} vs ${project_b}\n\n`;

    const format = async (name: string, skill: ParsedFile | null) => {
      if (!skill) return `## ${name}\n\nNot found in library.\n`;
      const hasSrc = await fileExists(join(DIRS.skills, name, "source.txt"));
      let text = formatSkillFull(name, skill, hasSrc);
      if (include_source && hasSrc) {
        const src = await safeRead(join(DIRS.skills, name, "source.txt"));
        if (src) {
          const lines = src.split("\n").slice(0, 200);
          text += `\n\n### Source Preview\n\`\`\`\n${lines.join("\n")}\n\`\`\``;
        }
      }
      return text;
    };

    output += await format(project_a, a);
    output += "\n\n---\n\n";
    output += await format(project_b, b);

    output += "\n\n---\n\n## Comparison Points\n\n";
    output += "1. Architecture and design approach\n2. Engine/game targeting\n3. Memory access method\n4. Stealth measures\n5. Feature set\n6. Code quality\n7. Techniques worth extracting from each";

    return ok(output);
  }
);

// ============================================================
// FIND SIMILAR
// ============================================================

server.tool(
  "find_similar",
  "Find projects similar to a given one based on topic and description overlap. Great for finding alternative implementations of the same technique.",
  {
    name: z.string().describe("Skill/project name to find similars for"),
    limit: z.number().min(1).max(30).default(10),
  },
  async ({ name, limit }) => {
    const idx = await getIndex();
    const target = idx.get(name);
    if (!target) return notFound("Skill", name);

    const targetWords = new Set(target.searchText.split(/\s+/).filter((w) => w.length > 3));
    const scored: Array<{ name: string; score: number; desc: string }> = [];

    for (const [n, skill] of idx) {
      if (n === name) continue;
      let score = 0;
      const words = skill.searchText.split(/\s+/);
      for (const w of words) {
        if (w.length > 3 && targetWords.has(w)) score++;
      }
      for (const t of target.topics) {
        if (skill.topics.includes(t)) score += 3;
      }
      if (score > 0) scored.push({ name: n, score, desc: skill.description });
    }

    scored.sort((a, b) => b.score - a.score);
    const top = scored.slice(0, limit);

    if (!top.length) return err(`No similar projects found for "${name}".`);

    return ok(`# Similar to: ${name}\n\n${target.description}\n\nFound ${scored.length} similar (top ${top.length}):\n\n${top.map((m) => `- **${m.name}** (overlap:${m.score}): ${m.desc}`).join("\n")}`);
  }
);

// ============================================================
// EXTRACT OFFSETS
// ============================================================

server.tool(
  "extract_offsets",
  "Parse a project's source code and extract all hex offsets (0x...) with surrounding context. Instant offset dump from any cheat.",
  {
    name: z.string().describe("Skill/project name"),
    min_value: z.number().default(0x10).describe("Min offset value to include (filters noise like 0x0, 0x1)"),
    limit: z.number().min(1).max(200).default(50).describe("Max offsets to return"),
  },
  async ({ name, min_value, limit }) => {
    const src = await safeRead(join(DIRS.skills, name, "source.txt"));
    if (!src) return err(`No source.txt for "${name}".`);

    const regex = /\b(0x[0-9A-Fa-f]{2,8})\b/g;
    const seen = new Map<string, string>();
    const lines = src.split("\n");

    for (let i = 0; i < lines.length && seen.size < limit; i++) {
      let match;
      while ((match = regex.exec(lines[i])) !== null) {
        const val = match[1];
        const num = parseInt(val, 16);
        if (num >= min_value && !seen.has(val.toLowerCase())) {
          seen.set(val.toLowerCase(), `L${i + 1}: ${lines[i].trim().slice(0, 150)}`);
        }
      }
    }

    if (!seen.size) return err(`No hex offsets found in "${name}".`);

    let output = `# Offsets: ${name}\n\nExtracted ${seen.size} unique offsets:\n\n`;
    for (const [offset, context] of seen) {
      output += `- \`${offset}\` -- ${context}\n`;
    }

    return ok(output);
  }
);

// ============================================================
// SEARCH BY GAME / ENGINE
// ============================================================

server.tool(
  "search_by_game",
  "Find all skills/projects targeting a specific game. Searches name, description, topics, and games metadata.",
  {
    game: z.string().describe("Game name: cs2, valorant, fortnite, apex, pubg, rust, eft, r6, overwatch, genshin, roblox, minecraft, cod, league, dayz"),
    has_source: z.boolean().optional(),
    limit: z.number().min(1).max(200).default(30),
  },
  async ({ game, has_source, limit }) => {
    const idx = await getIndex();
    const kw = game.toLowerCase();
    const aliases: Record<string, string[]> = {
      cs2: ["cs2", "csgo", "counter-strike", "counterstrike", "cstrike"],
      valorant: ["valorant", "vanguard", "riot"],
      fortnite: ["fortnite", "fn", "fortnitegame"],
      apex: ["apex", "apex-legends", "apexlegends"],
      pubg: ["pubg", "playerunknown", "battlegrounds"],
      rust: ["rust-game", "rustgame", "facepunch"],
      eft: ["eft", "tarkov", "escape-from-tarkov"],
      r6: ["r6", "rainbow-six", "siege", "rainbow6"],
      overwatch: ["overwatch", "ow2"],
      genshin: ["genshin", "hoyoverse", "mihoyo"],
      roblox: ["roblox", "byfron"],
      cod: ["cod", "call-of-duty", "warzone", "modern-warfare"],
      league: ["league", "lol", "league-of-legends"],
      dayz: ["dayz", "day-z"],
      minecraft: ["minecraft", "mc-"],
    };

    const keywords = aliases[kw] ?? [kw];
    const matches: Array<{ name: string; desc: string }> = [];

    for (const [name, skill] of idx) {
      if (has_source !== undefined && skill.hasSource !== has_source) continue;
      if (keywords.some((k) => skill.searchText.includes(k))) {
        matches.push({ name, desc: skill.description });
        if (matches.length >= limit) break;
      }
    }

    if (!matches.length) return err(`No projects found for game "${game}".`);

    return ok(`# Game: ${game}\n\nFound ${matches.length} projects:\n\n${matches.map((m) => `- **${m.name}**: ${m.desc}`).join("\n")}`);
  }
);

server.tool(
  "search_by_engine",
  "Find all skills/projects targeting a specific game engine.",
  {
    engine: z.string().describe("Engine: unreal, unity, source, cryengine, frostbite, godot, idtech"),
    has_source: z.boolean().optional(),
    limit: z.number().min(1).max(200).default(30),
  },
  async ({ engine, has_source, limit }) => {
    const idx = await getIndex();
    const kw = engine.toLowerCase();
    const aliases: Record<string, string[]> = {
      unreal: ["unreal", "ue4", "ue5", "uobject", "gobjects", "gnames", "processevent", "uworld"],
      unity: ["unity", "il2cpp", "mono", "gameobject", "unityengine"],
      source: ["source-engine", "source2", "valve", "netvar", "clientclass", "convar"],
      cryengine: ["cryengine", "lumberyard"],
      frostbite: ["frostbite", "dice"],
      godot: ["godot"],
      idtech: ["idtech", "id-tech", "quake"],
    };

    const keywords = aliases[kw] ?? [kw];
    const matches: Array<{ name: string; desc: string }> = [];

    for (const [name, skill] of idx) {
      if (has_source !== undefined && skill.hasSource !== has_source) continue;
      if (keywords.some((k) => skill.searchText.includes(k))) {
        matches.push({ name, desc: skill.description });
        if (matches.length >= limit) break;
      }
    }

    if (!matches.length) return err(`No projects found for engine "${engine}".`);

    return ok(`# Engine: ${engine}\n\nFound ${matches.length} projects:\n\n${matches.map((m) => `- **${m.name}**: ${m.desc}`).join("\n")}`);
  }
);

// ============================================================
// FILE TREE
// ============================================================

server.tool(
  "get_file_tree",
  "Parse a project's source.txt and show its file/directory tree structure (without file contents). Quick project structure overview.",
  {
    name: z.string().describe("Skill/project name"),
    max_entries: z.number().min(10).max(500).default(100).describe("Max tree entries to show"),
  },
  async ({ name, max_entries }) => {
    const src = await safeRead(join(DIRS.skills, name, "source.txt"));
    if (!src) return err(`No source.txt for "${name}".`);

    const paths: string[] = [];
    const dirSet = new Set<string>();
    let match: RegExpExecArray | null;

    // Pattern A (primary) — the format source.txt actually uses: a
    // "Source Tree:" marker followed by a fenced block containing a
    // Unicode box-drawing listing. Example:
    //   Source Tree:
    //   ```txt
    //   project-root
    //   ├── README.md
    //   ├── src
    //   │   ├── main.cpp
    //   └── utils.hpp
    //   ```
    // Depth is derived from the 4-column indent prefix; a line is a
    // directory when the NEXT line is deeper.
    const treeMarker = /Source Tree:\s*\r?\n+```[^\n]*\r?\n([\s\S]*?)\r?\n```/i;
    const treeMatch = src.match(treeMarker);
    if (treeMatch) {
      const block = treeMatch[1];
      const lines = block.split(/\r?\n/);
      // Capture the leading indent (spaces + box-drawing filler like "│   ")
      // and the entry name. 4 columns per depth level is the standard tree(1) output.
      const treeLine = /^([\s│├└─]*?)[├└]──\s*(.+?)\s*$/;
      type Entry = { depth: number; name: string; parentPath: string };
      const stack: string[] = [];
      // Push the root (first non-blank, non-tree line) if present.
      let rootPath = "";
      for (const ln of lines) {
        if (!ln.trim()) continue;
        if (treeLine.test(ln)) break;
        rootPath = ln.trim();
        break;
      }
      if (rootPath) stack.push(rootPath);

      const entries: Entry[] = [];
      for (const ln of lines) {
        const m = ln.match(treeLine);
        if (!m) continue;
        const indent = m[1];
        // Count depth by taking 4 columns per level; the "├──" marker itself
        // is 4 cols at the current depth so the prefix is always `depth * 4`.
        const depth = Math.floor(indent.length / 4) + (rootPath ? 1 : 0);
        const nm = m[2].trim();
        // Trim trailing comment/annotation after whitespace (`name   # note`)
        const nameClean = nm.replace(/\s{2,}.*$/, "").replace(/\/+$/, "");
        // Maintain parent-path stack by truncating to `depth`
        while (stack.length > depth) stack.pop();
        const parentPath = stack.join("/");
        entries.push({ depth, name: nameClean, parentPath });
        // Tentatively push this entry; we'll pop it if the next line isn't deeper.
        stack.push(nameClean);
      }
      // Classify: an entry is a directory iff ANOTHER entry has a deeper
      // depth AND follows it before the depth drops back.
      for (let i = 0; i < entries.length && paths.length < max_entries; i++) {
        const e = entries[i];
        const full = e.parentPath ? `${e.parentPath}/${e.name}` : e.name;
        let isDir = false;
        for (let j = i + 1; j < entries.length; j++) {
          if (entries[j].depth > e.depth) { isDir = true; break; }
          if (entries[j].depth <= e.depth) break;
        }
        if (isDir) dirSet.add(full);
        else paths.push(full);
      }
    }

    // Pattern B (fallback) — explicit "File:" / "PATH:" markers with === rules.
    if (!paths.length) {
      const filePathRegex = /^={3,}\s*(?:File|PATH):\s*(.+?)(?:\s*={3,})?$/gim;
      while ((match = filePathRegex.exec(src)) !== null) {
        paths.push(match[1].trim());
        if (paths.length >= max_entries) break;
      }
    }

    // Pattern C (fallback) — explicit `// file:` / `# path:` / `; source:` labels.
    // Note: no bare `- name.ext` fallback — that previously matched prose
    // bullets (e.g. `- http://processhacker.sourceforge.net`) and returned
    // confident wrong results.
    if (!paths.length) {
      const extRegex = /^(?:\/\/|#|;)\s*(?:file|path|source):\s*(.+)/gim;
      while ((match = extRegex.exec(src)) !== null) {
        paths.push(match[1].trim());
        if (paths.length >= max_entries) break;
      }
    }

    if (!paths.length) return err(`Could not extract file tree from "${name}". Source may not use a recognised layout.`);

    // Fallback dir enumeration from path segments (patterns B/C don't yield
    // explicit directories).
    if (!dirSet.size) {
      for (const p of paths) {
        const parts = p.split(/[/\\]/);
        for (let i = 1; i < parts.length; i++) dirSet.add(parts.slice(0, i).join("/"));
      }
    }

    return ok(`# File Tree: ${name}\n\n${paths.length} files, ${dirSet.size} directories:\n\n\`\`\`\n${paths.join("\n")}\n\`\`\``);
  }
);

// ============================================================
// FIND FUNCTION
// ============================================================

server.tool(
  "find_function",
  "Search for a function definition/declaration across all source archives. Matches C/C++ function signatures, class methods, NTSTATUS routines, etc.",
  {
    function_name: z.string().min(2).describe("Function name to find. Examples: 'DriverEntry', 'ProcessEvent', 'WorldToScreen', 'GetBoneMatrix'"),
    max_results: z.number().min(1).max(30).default(10),
  },
  async ({ function_name, max_results }) => {
    const idx = await getIndex();
    const escaped = function_name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(`(?:^|\\s|\\*|>)${escaped}\\s*\\(`, "i");

    const results: Array<{ skill: string; matches: { line: number; text: string }[] }> = [];

    for (const [name, skill] of idx) {
      if (!skill.hasSource) continue;
      const filePath = join(DIRS.skills, name, "source.txt");
      const matches = await grepFile(filePath, regex, 3, 0);
      if (matches.length > 0) {
        results.push({ skill: name, matches });
        if (results.length >= max_results) break;
      }
    }

    if (!results.length) return err(`No definitions found for "${function_name}".`);

    let output = `# Function: ${function_name}\n\nFound in ${results.length} projects:\n\n`;
    for (const { skill, matches } of results) {
      output += `### ${skill}\n`;
      for (const m of matches) {
        output += `  L${m.line}: ${m.text}\n`;
      }
      output += "\n";
    }

    return ok(output);
  }
);

// ============================================================
// EXPORT OFFSETS
// ============================================================

server.tool(
  "export_offsets",
  "Collect all hex offsets for a specific game across all skills and export as a C++ header. Aggregates offsets from every project targeting that game.",
  {
    game: z.string().describe("Game name: cs2, valorant, fortnite, apex, etc."),
    max_projects: z.number().min(1).max(50).default(15).describe("Max projects to scan"),
  },
  async ({ game, max_projects }) => {
    const idx = await getIndex();
    const kw = game.toLowerCase();
    const gameProjects: string[] = [];

    for (const [name, skill] of idx) {
      if (!skill.hasSource) continue;
      if (skill.searchText.includes(kw)) {
        gameProjects.push(name);
        if (gameProjects.length >= max_projects) break;
      }
    }

    if (!gameProjects.length) return err(`No projects with source code found for "${game}".`);

    const allOffsets = new Map<string, { value: string; contexts: string[] }>();
    const offsetRegex = /\b(\w+)\s*[=:]\s*(0x[0-9A-Fa-f]{3,8})\b/g;

    for (const proj of gameProjects) {
      const src = await safeRead(join(DIRS.skills, proj, "source.txt"));
      if (!src) continue;
      const lines = src.split("\n");
      for (const line of lines) {
        let match;
        while ((match = offsetRegex.exec(line)) !== null) {
          const name = match[1];
          const value = match[2];
          const key = `${name}=${value}`.toLowerCase();
          if (!allOffsets.has(key)) {
            allOffsets.set(key, { value: `${name} = ${value}`, contexts: [] });
          }
          const entry = allOffsets.get(key)!;
          if (!entry.contexts.includes(proj)) entry.contexts.push(proj);
        }
      }
    }

    if (!allOffsets.size) return err(`No offsets extracted for "${game}" from ${gameProjects.length} projects.`);

    const sorted = [...allOffsets.values()].sort((a, b) => b.contexts.length - a.contexts.length);

    let header = `// ${game.toUpperCase()} offsets -- aggregated from ${gameProjects.length} projects\n`;
    header += `// Generated by mcp-reverse\n`;
    header += `// Offsets found in multiple projects are more likely current\n\n`;
    header += `#pragma once\n\nnamespace ${game.replace(/[^a-zA-Z0-9]/g, "_")}_offsets {\n\n`;

    for (const entry of sorted.slice(0, 100)) {
      const refs = entry.contexts.length > 1 ? ` // found in ${entry.contexts.length} projects` : "";
      header += `    constexpr auto ${entry.value};${refs}\n`;
    }

    header += `\n} // namespace ${game.replace(/[^a-zA-Z0-9]/g, "_")}_offsets\n`;

    return ok(`# Exported Offsets: ${game}\n\nScanned ${gameProjects.length} projects, found ${allOffsets.size} unique offset assignments.\n\n\`\`\`cpp\n${header}\`\`\``);
  }
);

// ============================================================
// SKILL CHANGELOG (offset diff between two game projects)
// ============================================================

server.tool(
  "skill_changelog",
  "Compare offsets between two projects targeting the same game. Shows which offsets changed, were added, or removed. Useful for tracking game updates.",
  {
    project_old: z.string().describe("Older project name"),
    project_new: z.string().describe("Newer project name"),
  },
  async ({ project_old, project_new }) => {
    const extractOffsets = async (name: string): Promise<Map<string, string>> => {
      const src = await safeRead(join(DIRS.skills, name, "source.txt"));
      if (!src) return new Map();
      const offsets = new Map<string, string>();
      const regex = /\b(\w+)\s*[=:]\s*(0x[0-9A-Fa-f]{3,8})\b/g;
      for (const line of src.split("\n")) {
        let match;
        while ((match = regex.exec(line)) !== null) {
          offsets.set(match[1].toLowerCase(), match[2]);
        }
      }
      return offsets;
    };

    const oldOff = await extractOffsets(project_old);
    const newOff = await extractOffsets(project_new);

    if (!oldOff.size && !newOff.size) return err(`No offsets found in either project.`);

    const changed: string[] = [];
    const added: string[] = [];
    const removed: string[] = [];

    for (const [name, val] of newOff) {
      const oldVal = oldOff.get(name);
      if (!oldVal) {
        added.push(`+ ${name} = ${val}`);
      } else if (oldVal !== val) {
        changed.push(`~ ${name}: ${oldVal} -> ${val}`);
      }
    }

    for (const [name, val] of oldOff) {
      if (!newOff.has(name)) {
        removed.push(`- ${name} = ${val}`);
      }
    }

    let output = `# Offset Changelog: ${project_old} -> ${project_new}\n\n`;
    output += `Old: ${oldOff.size} offsets | New: ${newOff.size} offsets\n\n`;

    if (changed.length) output += `## Changed (${changed.length})\n\`\`\`\n${changed.join("\n")}\n\`\`\`\n\n`;
    if (added.length) output += `## Added (${added.length})\n\`\`\`\n${added.join("\n")}\n\`\`\`\n\n`;
    if (removed.length) output += `## Removed (${removed.length})\n\`\`\`\n${removed.join("\n")}\n\`\`\`\n\n`;

    if (!changed.length && !added.length && !removed.length) output += "No offset differences found.\n";

    return ok(output);
  }
);

// ============================================================
// ADDITIONAL NATIVE PROMPTS
// ============================================================

server.prompt(
  "build-aimbot",
  "Design an aimbot system for a specific game",
  {
    game: z.string().describe("Target game"),
    type: z.string().optional().describe("Aimbot type: rage, legit, silent, psilent"),
  },
  async ({ game, type }) => ({
    messages: [{
      role: "user",
      content: { type: "text", text: `# Aimbot Design: ${game}\nType: ${type ?? "legit + rage modes"}\n\nDesign a complete aimbot:\n1. Target selection (FOV circle, distance weight, visibility)\n2. Bone targeting (head/neck/chest, configurable)\n3. Aim smoothing (linear, bezier, humanized)\n4. Recoil compensation (pattern-based vs real-time read)\n5. Silent aim (server-side angle override)\n6. Backtracking (tick-based position history)\n7. Prediction (velocity extrapolation for moving targets)\n8. Trigger conditions (key hold, FOV threshold, visibility)\n9. Anti-detection (mouse input simulation, jitter, deadzone)\n10. Configuration (sensitivity, FOV, bone priority, smooth factor)` },
    }],
  })
);

server.prompt(
  "build-triggerbot",
  "Design a triggerbot with color/pixel or crosshair-based detection",
  {
    game: z.string().describe("Target game"),
    method: z.string().optional().describe("Detection: color, crosshair, trace, memory"),
  },
  async ({ game, method }) => ({
    messages: [{
      role: "user",
      content: { type: "text", text: `# Triggerbot Design: ${game}\nMethod: ${method ?? "color + memory hybrid"}\n\nDesign a triggerbot:\n1. Screen capture method (DXGI duplication, BitBlt, GPU readback)\n2. Target detection (HSV color range, crosshair entity ID, ray trace)\n3. FOV region (circular scan from center)\n4. Reaction delay (humanized random range)\n5. Cooldown between shots\n6. Bone filtering (head-only, body, any)\n7. Confidence threshold (pixel count ratio)\n8. Input method (SendInput, driver mouse, hardware mouse)\n9. Anti-detection (randomized delays, movement patterns)\n10. Performance (scan rate, threading model)` },
    }],
  })
);

server.prompt(
  "write-injector",
  "Design a DLL injector with specified injection technique",
  {
    technique: z.string().optional().describe("Injection: manual-map, reflective, apc, thread-hijack, efi"),
  },
  async ({ technique }) => ({
    messages: [{
      role: "user",
      content: { type: "text", text: `# DLL Injector Design\nTechnique: ${technique ?? "manual map"}\n\nDesign a complete injector:\n1. Process discovery and handle acquisition\n2. PE parsing (headers, sections, imports, relocations, TLS)\n3. Memory allocation in target process\n4. Section mapping with correct protections\n5. Import resolution (LoadLibrary/GetProcAddress or manual)\n6. Relocation fixups (delta-based)\n7. TLS callback execution\n8. Entry point invocation (DllMain or custom)\n9. Header erasure and cleanup\n10. Exception handler registration\n11. Stealth considerations (no LoadLibrary trace, PEB cleanup)\n12. Error handling and rollback` },
    }],
  })
);

server.prompt(
  "spoof-hardware",
  "Design an HWID spoofing system",
  {
    target_ac: z.string().optional().describe("Anti-cheat to evade: battleye, eac, vanguard, ricochet"),
  },
  async ({ target_ac }) => ({
    messages: [{
      role: "user",
      content: { type: "text", text: `# HWID Spoofing Design${target_ac ? `\nTarget AC: ${target_ac}` : ""}\n\nDesign a comprehensive HWID spoofer:\n1. Disk serial (SMART data, StorPort miniport hook, SCSI inquiry)\n2. NIC MAC address (NDIS filter driver, registry)\n3. SMBIOS/DMI (physical memory patch or EFI runtime)\n4. GPU serial (registry + driver IOCTL)\n5. Windows product ID / install ID (registry)\n6. TPM endorsement key\n7. Monitor EDID serial\n8. USB device serials\n9. CPU serial / CPUID\n10. Registry cleanup (past HWID traces)\n11. Persistence across reboots\n12. Detection vectors per anti-cheat${target_ac ? ` (focus on ${target_ac})` : ""}` },
    }],
  })
);

server.prompt(
  "bypass-battleye",
  "Research and design BattlEye bypass strategies",
  {},
  async () => {
    const idx = await getIndex();
    const relevant: string[] = [];
    for (const [name, skill] of idx) {
      if (skill.searchText.includes("battleye") || skill.searchText.includes("be_") || name.includes("battleye")) {
        relevant.push(`- **${name}**: ${skill.description}`);
        if (relevant.length >= 20) break;
      }
    }
    return {
      messages: [{
        role: "user",
        content: { type: "text", text: `# BattlEye Bypass Research\n\nProjects in library:\n${relevant.join("\n")}\n\nAnalyze BattlEye and provide bypass strategies:\n1. BEService/BEClient/BEDaisy architecture\n2. Kernel driver (BEDaisy.sys) detection methods\n3. User-mode module scanning and integrity checks\n4. Memory scanning patterns and timing\n5. Heartbeat/packet encryption\n6. Known bypass vectors (DMA, HV, EFI, driver)\n7. Detection timeline (what gets caught, when)\n8. Current recommended approach` },
      }],
    };
  }
);

server.prompt(
  "bypass-eac",
  "Research and design Easy Anti-Cheat bypass strategies",
  {},
  async () => {
    const idx = await getIndex();
    const relevant: string[] = [];
    for (const [name, skill] of idx) {
      if (skill.searchText.includes("eac") || skill.searchText.includes("easy anti") || skill.searchText.includes("easyanticheat")) {
        relevant.push(`- **${name}**: ${skill.description}`);
        if (relevant.length >= 20) break;
      }
    }
    return {
      messages: [{
        role: "user",
        content: { type: "text", text: `# EAC Bypass Research\n\nProjects in library:\n${relevant.join("\n")}\n\nAnalyze Easy Anti-Cheat and provide bypass strategies:\n1. EAC architecture (service, driver, user-mode module)\n2. Kernel-level detection (driver verification, memory scanning)\n3. User-mode integrity checks (module whitelist, CRC)\n4. System call monitoring\n5. Hypervisor detection\n6. DMA detection improvements\n7. Known bypass vectors\n8. Current recommended approach` },
      }],
    };
  }
);

server.prompt(
  "bypass-vanguard",
  "Research and design Vanguard (Valorant) bypass strategies",
  {},
  async () => {
    const idx = await getIndex();
    const relevant: string[] = [];
    for (const [name, skill] of idx) {
      if (skill.searchText.includes("vanguard") || skill.searchText.includes("vgk") || skill.searchText.includes("valorant")) {
        relevant.push(`- **${name}**: ${skill.description}`);
        if (relevant.length >= 20) break;
      }
    }
    return {
      messages: [{
        role: "user",
        content: { type: "text", text: `# Vanguard Bypass Research\n\nProjects in library:\n${relevant.join("\n")}\n\nAnalyze Riot Vanguard and provide bypass strategies:\n1. vgk.sys kernel driver architecture\n2. Boot-time loading and SecureBoot enforcement\n3. HWID collection and banning system\n4. Hypervisor detection methods\n5. DMA/FPGA detection\n6. UEFI NVRAM scanning\n7. Module integrity verification\n8. Known bypass vectors (HV, EFI, DMA)\n9. Current recommended approach` },
      }],
    };
  }
);

server.prompt(
  "implement-backtrack",
  "Design a backtracking/lag compensation system",
  {
    game: z.string().describe("Target game"),
    engine: z.string().optional().describe("Engine: unreal, source, unity"),
  },
  async ({ game, engine }) => ({
    messages: [{
      role: "user",
      content: { type: "text", text: `# Backtracking System: ${game}${engine ? ` (${engine})` : ""}\n\nDesign a complete backtracking system:\n1. Tick/timestamp-based position recording\n2. Circular buffer per entity (configurable window: 50-200ms)\n3. Interpolation between recorded positions\n4. Best record selection (closest to crosshair or oldest valid)\n5. Latency compensation (local vs server tick delta)\n6. Integration with aimbot (bone position override)\n7. Choke cycle exploitation (if applicable)\n8. Visual representation (backtrack skeleton/ghost)\n9. Validity checks (max time window, distance sanity)\n10. Anti-detection (realistic tick manipulation)` },
    }],
  })
);

server.prompt(
  "implement-autowall",
  "Design a wall penetration calculation system",
  {
    game: z.string().describe("Target game"),
  },
  async ({ game }) => ({
    messages: [{
      role: "user",
      content: { type: "text", text: `# Autowall System: ${game}\n\nDesign a wall penetration calculation system:\n1. Ray tracing from source to target\n2. Material/surface type detection (metal, wood, concrete, etc.)\n3. Penetration depth calculation per material\n4. Damage falloff through walls\n5. Multi-wall penetration (recursive trace)\n6. Weapon penetration power values\n7. Minimum damage threshold (configurable)\n8. Integration with aimbot (skip unpenetrable targets)\n9. Performance optimization (cache traces, limit depth)\n10. Visual feedback (penetration indicator, damage preview)` },
    }],
  })
);

// ============================================================
// SKILL TOOLS -- direct access
// ============================================================

server.tool("list_skills", "List skills with optional filtering. Uses in-memory index for fast lookup.", {
  filter: z.string().optional().describe("Filter by name substring (case-insensitive)"),
  type: z.string().optional().describe("Filter by type: 'reference', 'redirect', etc."),
  has_source: z.boolean().optional().describe("Filter to only skills with/without source.txt"),
  limit: z.number().min(1).max(500).default(50),
}, async ({ filter, type, has_source, limit }) => {
  const idx = await getIndex();
  let results: SkillIndex[] = [...idx.values()];

  if (filter) {
    const lc = filter.toLowerCase();
    results = results.filter((s) => s.name.toLowerCase().includes(lc));
  }
  if (type) results = results.filter((s) => s.type === type);
  if (has_source !== undefined) results = results.filter((s) => s.hasSource === has_source);

  const sliced = results.slice(0, limit);
  const text = `Found ${results.length} skills${results.length > limit ? ` (showing first ${limit})` : ""}:\n\n${sliced.map((s) => formatSkillCompact(s.name, { description: s.description, type: s.type }, s.hasSource)).join("\n")}`;

  return ok(text);
});

server.tool("read_skill", "Read a skill's SKILL.md content with full metadata.", {
  name: z.string().describe("Skill folder name (kebab-case)"),
}, async ({ name }) => {
  const skill = await readSkill(name);
  if (!skill) return notFound("Skill", name);
  const hasSrc = await fileExists(join(DIRS.skills, name, "source.txt"));
  return ok(formatSkillFull(name, skill, hasSrc));
});

server.tool("read_source", "Read a project's source code snapshot with pagination.", {
  name: z.string().describe("Skill folder name"),
  offset: z.number().min(0).default(0).describe("Start line (0-based)"),
  limit: z.number().min(1).max(2000).default(200).describe("Max lines"),
}, async ({ name, offset, limit }) => {
  const content = await safeRead(join(DIRS.skills, name, "source.txt"));
  if (!content) return err(`No source.txt for "${name}".`);

  const lines = content.split("\n");
  const slice = lines.slice(offset, offset + limit);

  return ok(`Source: ${name} (lines ${offset}-${offset + slice.length} of ${lines.length})\n\n${slice.join("\n")}${offset + limit < lines.length ? `\n\n_${lines.length - offset - limit} more lines. Use offset=${offset + limit} to continue._` : ""}`);
});

server.tool("search_skills", "Scored keyword search across the indexed skill library (name + description + topics + games + engines).", {
  query: z.string().min(2).describe("Search query. Examples: 'kdmapper', 'DMA', 'valorant aimbot'"),
  has_source: z.boolean().optional().describe("Filter to skills with/without source code"),
  limit: z.number().min(1).max(100).default(20),
}, async ({ query, has_source, limit }) => {
  const idx = await getIndex();
  const keywords = query.toLowerCase().split(/[\s,]+/).filter((w) => w.length >= 2);
  const matches: Array<{ name: string; desc: string; score: number }> = [];

  for (const [, skill] of idx) {
    if (has_source !== undefined && skill.hasSource !== has_source) continue;
    const score = scoreSkill(skill, keywords);
    if (score > 0) matches.push({ name: skill.name, desc: skill.description, score });
  }

  matches.sort((a, b) => b.score - a.score);
  const top = matches.slice(0, limit);

  if (!top.length) return err(`No skills matching "${query}".`);

  return ok(`Found ${matches.length} skills for "${query}" (top ${top.length}):\n\n${top.map((m) => `- **${m.name}** (score:${m.score}): ${m.desc}`).join("\n")}${matches.length > limit ? `\n\n_${matches.length - limit} more. Increase limit or refine._` : ""}`);
});

server.tool("skill_stats", "Library statistics from the in-memory index.", {}, async () => {
  const idx = await getIndex();
  let withSource = 0;
  let agsCount = 0;
  const types: Record<string, number> = {};
  const topicCount: Record<string, number> = {};

  for (const [name, skill] of idx) {
    if (skill.hasSource) withSource++;
    if (name.startsWith("ags-")) agsCount++;
    types[skill.type] = (types[skill.type] ?? 0) + 1;
    for (const t of skill.topics) {
      topicCount[t] = (topicCount[t] ?? 0) + 1;
    }
  }

  const typeStr = Object.entries(types).sort((a, b) => b[1] - a[1]).map(([k, v]) => `  ${k}: ${v}`).join("\n");
  const topTopics = Object.entries(topicCount).sort((a, b) => b[1] - a[1]).slice(0, 20).map(([k, v]) => `  ${k}: ${v}`).join("\n");

  return ok(`# Skill Library Stats\n\n- **Total:** ${idx.size}\n- **Hand-written:** ${idx.size - agsCount}\n- **Archived (ags-):** ${agsCount}\n- **With source:** ${withSource}\n\n**By type:**\n${typeStr}\n\n**Top 20 topics:**\n${topTopics}`);
});

// ============================================================
// COMPONENT TOOLS
// ============================================================

const componentTools = [
  { singular: "agent", plural: "agents", dir: DIRS.agents },
  { singular: "subagent", plural: "subagents", dir: DIRS.subagents },
  { singular: "plugin", plural: "plugins", dir: DIRS.plugins },
  { singular: "prompt", plural: "prompts", dir: DIRS.prompts },
] as const;

for (const { singular, plural, dir } of componentTools) {
  server.tool(
    `list_${plural}`,
    `List all available ${plural} grouped by category.`,
    {
      category: z.string().optional().describe("Filter by category/subdirectory name"),
    },
    async ({ category }: { category?: string }) => {
      let items = await getCachedComponents(dir);
      if (category) {
        const lc = category.toLowerCase();
        items = items.filter((i) => i.category?.toLowerCase() === lc);
      }
      return ok(formatComponentList(singular, items));
    }
  );

  server.tool(
    `read_${singular}`,
    `Read a ${singular}'s full definition and system prompt.`,
    {
      name: z.string().describe(`${singular} name (without .md extension). Use list_${plural} to see available options.`),
    },
    async ({ name }: { name: string }) => {
      const parsed = await readMdByName(dir, name);
      if (!parsed) return notFound(singular.charAt(0).toUpperCase() + singular.slice(1), name);
      return ok(formatComponent(singular.charAt(0).toUpperCase() + singular.slice(1), parsed));
    }
  );
}

// ============================================================
// RE / DEBUG MCP INTEGRATIONS
// ============================================================
// Register bridges and launchers for Ghidra, IDA Pro, Binary Ninja,
// radare2, x64dbg, WinDbg, Cheat Engine, Frida, Hopper, REA,
// Vibe-RE, JADX, angr, Capstone, PCILeech, Memflow, Scylla, dnSpy,
// ReClass, Volatility, Wireshark, mitmproxy, dotPeek, Unicorn,
// pyghidra-mcp --gui, ret-sync. See src/retools.ts.
registerReTools(server, ROOT);

// Native TypeScript RE tools -- PE parse, AoB scan, entropy,
// strings, hash-ID, signature maker, file summary. Always
// available (no external deps). See src/native-re.ts.
registerNativeReTools(server);

// Native TypeScript binary-format parsers -- ELF, Mach-O (fat +
// thin), DEX, WebAssembly, plus a format-identify magic sniffer
// that recognises PE, ELF, Mach-O, DEX, WASM, ZIP/APK/JAR, 7-Zip,
// gzip, zstd, LZ4, PDF, scripts, Switch NSO/NCA, Xbox 360 XEX,
// PS4/PS5 FSELF. See src/native-formats.ts.
registerNativeFormatsTools(server);

// Advanced native parsers -- Minidump, PDB70 (RSDS), Rich Header,
// C++ demangler (MSVC + Itanium), Unity AssetBundle, UE4/UE5 .pak,
// IL2CPP global-metadata.dat, Switch NSO. See src/native-advanced.ts.
registerAdvancedParsers(server);

// Workflow tools -- offset_diff, offset_merge, cross-build
// signature validator, AC risk matrix, cheat-sheet generator.
// See src/workflow-tools.ts.
registerWorkflowTools(server);

// Agent Mesh -- lets several MCP clients (Claude, ChatGPT via
// Codex, Cursor, custom agents) share a workspace through this
// server: register, DM + channel broadcast, task hand-off,
// adversarial voting, shared KV knowledge-base, named locks.
// Persistence: JSON files under <project>/.agent-mesh/ (or
// MCP_AGENT_MESH_DIR). See src/agent-mesh.ts.
await registerAgentMesh(server, ROOT);

// MCP Hub -- aggregate multiple backend MCP servers. Our server
// becomes a CLIENT to other MCPs (ghidra-mcp, ida-pro-mcp,
// x64dbg-mcp, binja-mcp) and re-exposes their tools via
// `hub_call`. `smart_decompile` dispatches to the first available
// decompiler backend; `hub_consensus_call` fans out across
// backends. See src/mcp-hub.ts.
registerMcpHub(server);

// Native container parsers -- ZIP / APK (+signing block), .NET
// CLR header + metadata root, Windows catalog PKCS#7 sniff.
registerContainerParsers(server);

// Repo-wide meta tools -- fs_sandbox_status, wiki_link_check,
// training_jsonl_export, symsrv_download, pattern_mine,
// mesh_orchestrate.
registerMetaTools(server, ROOT);

// Composite tools -- analyze_binary (one-shot deep triage),
// pe_debug_dir, compare_binaries.
registerCompositeTools(server);

// BM25 full-text search over the skill library (10-min TTL
// cached inverted index; ~1 sec cold build on 4,200 skills).
registerBm25Search(server, ROOT);

// Audit log + rate limiter (opt-in).
registerAuditAndRate(server, ROOT);

// MCP Resource templates for URI-addressable skill/plugin/agent
// content: gamehacking://skills/{name}, gamehacking://ags/{name}/source,
// gamehacking://plugins/{category}/{name}, etc.
registerDynamicResources(server, ROOT);

// Native x86-64 mini-disassembler (prologue/epilogue coverage).
registerNativeDisasm(server);

// Native "mega-brain" absorption of previously-hub-only backends:
//   memory_put/get/search/list/delete/prune/export/stats
//     — replaces local-memory-mcp + ai-memory + TencentDB-Agent-Memory
//       client role; shared JSON persistence under <project>/.memory/
//   yara_scan / yara_parse — in-process YARA-light engine
//   reclass_parse / reclass_to_cpp — ReClass.NET project → C++ header
//   ce_attach / ce_aob_scan / ce_pointer_scan / ce_read_memory /
//     ce_write_memory / ce_lua / ce_status — ceserver HTTP client
await registerNativeMemory(server, ROOT);
registerNativeYara(server);
registerNativeReclass(server);
registerCeserverClient(server);

// Clients for the host-side plugins under plugins-side/ (Ghidra, IDA,
// ReClass.NET, dnSpy, ILSpy, x64dbg, Binary Ninja). Each plugin runs
// inside its host tool and exposes a small HTTP MCP surface; the
// clients registered here (ghidra_* / ida_* / reclass_*_live / dnspy_*
// / ilspy_* / x64dbg_* / binja_* / bridge_health_all) call it over
// localhost. See plugins-side/README.md for install instructions.
registerPluginClients(server);

// Wave 2 (dynamic analysis + symbols + observability):
//   emu_run / emu_decrypt_xor — tiny built-in x86-64 emulator for
//     string-decrypt loops and small decrypt stubs (no external deps)
//   dwarf_parse — native DWARF v4/v5 compile-unit + subprogram walker
//   pdb_info    — native MSF/PDB superblock + Info + DBI module list
//   sig_list / sig_match / sig_make — FLIRT-light signature db
//     (signatures/common.json ships with the project; extend via sig_make)
registerEmulator(server);
registerNativeDwarf(server);
registerNativePdb(server);
registerSignatureDb(server, ROOT);

// Wave 3 (platform + distribution):
//   emu_arm64_run   — native AArch64 emulator for iOS/Android loops
//   cache_stats / cache_clear — content-addressable decompile cache
//   chunk_fetch / chunk_list — paging through large tool results
registerArm64(server);
registerCacheTools(server, ROOT);
registerChunkTools(server, ROOT);
// Warm the cache singleton so .stats() in telemetry works even before
// the first wrap() call.
getCache(ROOT);

// Wave 4 (RE-ops upgrades):
//   bindiff — function-level fingerprint diff with equal/shifted/modified
//   rop_find / rop_chain — gadget search + packed-chain builder (x86-64 & aarch64)
//   unity_il2cpp_metadata / unreal_fnames / godot_pck — engine metadata
//   decompile_summarize / struct_name_suggest / explain_at_level — MCP sampling
//   viz_call_graph / viz_cfg — SVG graph rendering
registerNativeDiff(server);

// Native ports from ForMCP projects (no vendor):
//   apihash_*  — lazy_importer / hashdb-ida / hashdb-ghidra schemes
//   syscall_*  — Windows syscall tables (win10-1909 / 21h2, win11-23h2)
//   js_deob_*  — javascript-deobfuscator (hex literals + string arrays)
//   iat_rebuild_* — PyIATRebuild / Import-Handler
//   ollvm_*    — de-ollvm / VMAttack flatten detector
//   bits_*     — reversingBits cheatsheet ops
registerApiHash(server);
registerSyscalls(server);
registerJsDeob(server);
registerIatRebuild(server);
registerOllvmUndo(server);
registerBitmanip(server);

// Artifact-type coverage parity: Electron ASAR, Go BuildInfo,
// GGUF / safetensors model artifacts, Erlang BEAM, PE Authenticode
// signers, PyInstaller CArchive, HAR captures, SQLite inspect,
// ELF notes, Apple IPS crashes.
registerAsar(server);
registerGoBinary(server);
registerGguf(server);
registerBeam(server);
registerAuthenticode(server);
registerReaPack(server);
registerRop(server);
registerGameEngine(server);
registerSampling(server);
registerViz(server);

// SQLite-backed skills store: ships a single db/skills.db alongside
// dist/, replacing the 19 GiB on-disk tree with a ~20 MiB queryable
// file. `db_search` is FTS5 (bm25 ranking) over every skill name +
// description + body in one indexed sweep.
server.tool(
  "db_search",
  "Full-text search over the SQLite skills DB (FTS5 + bm25). Returns up to `limit` hits ranked by relevance. Falls back to the legacy filesystem index when db/skills.db is absent.",
  { query: z.string().min(1), limit: z.number().min(1).max(200).default(20) },
  async ({ query, limit }: { query: string; limit: number }) => {
    try {
      const dbMod = await import("./skills-db.js");
      const h = await dbMod.getSharedDb(dbMod.defaultDbPath(ROOT));
      if (!h) return { content: [{ type: "text" as const, text: "# db_search\n\nNo db/skills.db present. Build it with `node scripts/build-db.mjs` or set MCP_SKILLS_DB." }] };
      const hits = dbMod.searchSkills(h, query, limit);
      const text = [
        `# db_search \`${query}\``,
        `**hits:** ${hits.length}`,
        ``,
        ...hits.map(hit => `- \`${hit.name}\` — ${hit.description ?? ""} _bm25=${hit.rank.toFixed(2)}_\n  ${hit.snippet.replace(/\s+/g, " ").trim()}`),
      ].join("\n");
      return { content: [{ type: "text" as const, text }] };
    } catch (e) {
      return { content: [{ type: "text" as const, text: `db_search error: ${(e as Error).message}` }], isError: true as const };
    }
  },
);

server.tool(
  "db_stats",
  "Show the SQLite skills DB counts, build timestamp, and whether source blobs are embedded.",
  {},
  async () => {
    try {
      const dbMod = await import("./skills-db.js");
      const p = dbMod.defaultDbPath(ROOT);
      const h = await dbMod.getSharedDb(p);
      if (!h) return { content: [{ type: "text" as const, text: `# db_stats\n\nNo DB at \`${p}\`. Build with: \`node scripts/build-db.mjs\`` }] };
      const s = dbMod.stats(h);
      return { content: [{ type: "text" as const, text:
        `# db_stats\n\n**path:** \`${p}\`\n\n` +
        Object.entries(s).map(([k, v]) => `- ${k}: **${v}**`).join("\n")
      }] };
    } catch (e) {
      return { content: [{ type: "text" as const, text: `db_stats error: ${(e as Error).message}` }], isError: true as const };
    }
  },
);

// ============================================================
// MAIN
// ============================================================

async function main() {
  const mode = process.env.MCP_TRANSPORT ?? "stdio";
  if (mode === "http" || mode === "sse" || mode === "streamable-http") {
    const port = Number(process.env.MCP_HTTP_PORT ?? 7777);
    const host = process.env.MCP_HTTP_HOST ?? "127.0.0.1";
    // Optional bearer-token auth for the HTTP transport. Set MCP_AUTH_TOKEN
    // to require `Authorization: Bearer <token>` on /mcp (and the HTTP
    // JSON-RPC path). /healthz is always open so a load balancer can poll
    // without credentials; /metrics is gated when auth is on so running
    // tool counts and uptime aren't leaked to unauth'd probes.
    const AUTH_TOKEN = process.env.MCP_AUTH_TOKEN ?? "";
    const authRequired = AUTH_TOKEN.length > 0;
    const checkAuth = (req: import("node:http").IncomingMessage): boolean => {
      if (!authRequired) return true;
      const h = req.headers.authorization;
      if (!h || typeof h !== "string") return false;
      if (!h.startsWith("Bearer ")) return false;
      const got = h.slice("Bearer ".length).trim();
      // Constant-time compare to avoid trivial timing leaks on the token.
      if (got.length !== AUTH_TOKEN.length) return false;
      let diff = 0;
      for (let i = 0; i < got.length; i++) diff |= got.charCodeAt(i) ^ AUTH_TOKEN.charCodeAt(i);
      return diff === 0;
    };
    const transports = new Map<string, StreamableHTTPServerTransport>();
    const httpServer = createServer(async (req, res) => {
      // Per-request middleware: trace-id (X-Trace-Id), optional per-user
      // rate limit (MCP_RATE_LIMIT_PER_USER=1), structured access log.
      // The middleware already writes a 429 response when it rejects, so
      // we stop here on `rejected`.
      const mw = runRequestMiddleware(req, res);
      if (mw.rejected) return;
      // Normalise the request URL once so query strings, fragments, and
      // trailing slashes can't bypass the route-equality checks that gate
      // the auth call (CodeQL js/user-controlled-bypass-of-security-check).
      // Equality comparisons downstream use `pathname` only.
      const pathname = (() => {
        try { return new URL(req.url ?? "/", "http://localhost").pathname.replace(/\/+$/, "") || "/"; }
        catch { return "/"; }
      })();
      // /healthz: readiness probe — always open
      if (req.method === "GET" && pathname === "/healthz") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ status: "ok", pid: process.pid, uptime: process.uptime(), version: PKG_VERSION, auth: authRequired ? "on" : "off" }));
        return;
      }
      // /metrics: Prometheus-style — gated when auth is on. Combines
      // the process gauges (RSS / heap / uptime / active_transports)
      // with the per-tool counters + latency histograms + bridge_up
      // gauges that live in src/observability.ts.
      if (req.method === "GET" && pathname === "/metrics") {
        if (!checkAuth(req)) {
          res.writeHead(401, { "content-type": "text/plain; charset=utf-8", "www-authenticate": "Bearer" });
          res.end("unauthorized");
          return;
        }
        const mu = process.memoryUsage();
        const processLines = [
          `# HELP mcp_gamehacking_rss_bytes Process RSS`,
          `# TYPE mcp_gamehacking_rss_bytes gauge`,
          `mcp_gamehacking_rss_bytes ${mu.rss}`,
          `# HELP mcp_gamehacking_heap_used_bytes V8 heap used`,
          `# TYPE mcp_gamehacking_heap_used_bytes gauge`,
          `mcp_gamehacking_heap_used_bytes ${mu.heapUsed}`,
          `# HELP mcp_gamehacking_active_transports Active HTTP MCP sessions`,
          `# TYPE mcp_gamehacking_active_transports gauge`,
          `mcp_gamehacking_active_transports ${transports.size}`,
        ].join("\n") + "\n";
        res.writeHead(200, { "content-type": "text/plain; version=0.0.4" });
        res.end(processLines + renderPrometheus());
        return;
      }
      // /dashboard + /_dashboard.json: handled by the observability
      // module. Returns true when it answered so we can bail; false
      // means the request wasn't for one of its routes.
      if (observabilityHandler(req, res)) return;
      // MCP endpoint: use streamable HTTP transport. Gated when auth is on.
      // Uses the normalised `pathname` (strips query / fragment / trailing /)
      // so no `/mcp?x=` or `/mcp/` form can bypass the auth gate.
      if (pathname === "/mcp") {
        if (!checkAuth(req)) {
          res.writeHead(401, { "content-type": "text/plain; charset=utf-8", "www-authenticate": "Bearer" });
          res.end("unauthorized");
          return;
        }
        try {
          const sessionId = (req.headers["mcp-session-id"] as string | undefined) ?? randomUUID();
          let transport = transports.get(sessionId);
          if (!transport) {
            transport = new StreamableHTTPServerTransport({ sessionIdGenerator: () => sessionId });
            transports.set(sessionId, transport);
            await server.connect(transport);
            transport.onclose = () => transports.delete(sessionId);
          }
          await transport.handleRequest(req, res);
          return;
        } catch (e) {
          // CodeQL js/xss-through-exception: exception messages can be
          // influenced by request content. Serve the error body as
          // text/plain so no HTML interpretation can happen, and strip
          // any carriage returns / newlines just in case a message
          // contains header-injection bait.
          const msg = (e as Error).message.replace(/[\r\n]+/g, " ");
          res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
          res.end(`transport error: ${msg}`);
          return;
        }
      }
      res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
      res.end("not found. endpoints: /mcp, /healthz, /metrics");
    });
    httpServer.listen(port, host, () => {
      console.error(`[mcp-reverse] HTTP transport on http://${host}:${port}/mcp (health: /healthz, metrics: /metrics, dashboard: /dashboard)`);
    });
  } else {
    const transport = new StdioServerTransport();
    await server.connect(transport);
  }
}

main().catch(console.error);
