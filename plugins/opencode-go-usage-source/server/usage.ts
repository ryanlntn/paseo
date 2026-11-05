import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { z } from "zod";
import {
  hashAccountKey,
  unavailable,
  type UsageAccount,
  toneFromUsedPct,
  windowFromUsedPct,
  type UsageReport,
} from "@getpaseo/plugin/server/usage";
import type { Input } from "../shared/input.js";

const authSchema = z
  .object({
    "opencode-go": z
      .object({ type: z.literal("api"), key: z.string().min(1) })
      .passthrough()
      .optional(),
  })
  .passthrough();
const credentialValueSchema = z
  .object({ type: z.literal("key"), key: z.string().min(1) })
  .passthrough();
const credentialRowSchema = z.object({ value: z.string() });
const expiredKeySchema = z.object({ error: z.object({ code: z.literal("api_key_expired") }) });
const windowSchema = z.object({
  status: z.enum(["ok", "rate-limited"]),
  percent: z.number().finite(),
  resetsAt: z.iso.datetime(),
});
const responseSchema = z.object({
  usage: z.object({ rolling: windowSchema, weekly: windowSchema, monthly: windowSchema }),
});

function authPath(env: NodeJS.ProcessEnv = process.env): string {
  return join(
    env.XDG_DATA_HOME || join(env.HOME || homedir(), ".local", "share"),
    "opencode",
    "auth.json",
  );
}

// @types/node@20 predates the node:sqlite typings; declare the slice we use.
interface CredentialDatabase {
  prepare(sql: string): { all(...params: unknown[]): unknown[] };
  close(): void;
}
interface NodeSqliteModule {
  DatabaseSync: new (path: string, options?: { readOnly?: boolean }) => CredentialDatabase;
}

// OpenCode 2.x keeps credentials in opencode.db beside the 1.x auth.json. The active row wins,
// then the newest; `active` is NULL on rows OpenCode never toggled.
async function readDatabaseKey(path: string): Promise<string | null> {
  // Held in a variable so TypeScript skips module resolution: @types/node@20 has no
  // node:sqlite typings yet, while the runtime (Node 22+ / Electron) provides it.
  const sqliteSpecifier: string = "node:sqlite";
  let sqlite: NodeSqliteModule;
  try {
    sqlite = (await import(sqliteSpecifier)) as unknown as NodeSqliteModule;
  } catch {
    return null; // runtime without node:sqlite
  }
  if (!existsSync(path)) return null;
  let db: CredentialDatabase | undefined;
  try {
    db = new sqlite.DatabaseSync(path, { readOnly: true });
    const rows = db
      .prepare(
        "SELECT value FROM credential WHERE integration_id = ? ORDER BY COALESCE(active, 0) != 0 DESC, time_updated DESC",
      )
      .all("opencode-go");
    for (const row of rows) {
      const parsed = credentialRowSchema.safeParse(row);
      if (!parsed.success) continue;
      try {
        const value = credentialValueSchema.safeParse(JSON.parse(parsed.data.value));
        if (value.success) return value.data.key;
      } catch {
        // skip a malformed credential value
      }
    }
    return null;
  } catch {
    return null;
  } finally {
    db?.close();
  }
}

/** `path` names auth.json; its directory also holds OpenCode 2.x's opencode.db. */
export async function readDefaultKey(path = authPath()): Promise<string | null> {
  const databaseKey = await readDatabaseKey(join(dirname(path), "opencode.db"));
  if (databaseKey) return databaseKey;
  try {
    const auth = authSchema.parse(JSON.parse(await readFile(path, "utf8")));
    return auth["opencode-go"]?.key ?? null;
  } catch {
    return null;
  }
}

async function isExpiredKey(response: Response): Promise<boolean> {
  try {
    return expiredKeySchema.safeParse(await response.json()).success;
  } catch {
    return false;
  }
}

export async function discover(path = authPath()): Promise<UsageAccount[]> {
  return (await readDefaultKey(path)) ? [{ key: hashAccountKey(path), input: { path } }] : [];
}

export async function fetchUsage(
  input: Input,
  fetchApi: typeof fetch = fetch,
): Promise<UsageReport> {
  const apiKey = await readDefaultKey(input.path);
  if (!apiKey) throw new Error("OpenCode Go login store no longer exists");
  const response = await fetchApi("https://opencode.ai/zen/go/v1/usage", {
    headers: { Authorization: `Bearer ${apiKey}`, Accept: "application/json" },
    signal: AbortSignal.timeout(15_000),
  });
  // Signing in again reuses the expired key, so the remedy is a new key from the console.
  if (response.status === 401 && (await isExpiredKey(response)))
    return unavailable({
      kind: "no_quota",
      detail:
        "OpenCode Go API key expired. Create a new key in OpenCode Console, then run opencode auth login.",
    });
  if (response.status === 401 || response.status === 403)
    return unavailable({ kind: "rejected", status: response.status, refreshedBy: "opencode" });
  if (!response.ok) throw new Error(`OpenCode Go usage API returned ${response.status}`);
  const data = responseSchema.parse(await response.json());
  const windows = (
    [
      // The rolling window's length is not reported, so its percent stands without a name.
      ["rolling", "Rolling", "", data.usage.rolling],
      ["weekly", "Weekly", "wk", data.usage.weekly],
      ["monthly", "Monthly", "mo", data.usage.monthly],
    ] as const
  ).map(([id, label, shortLabel, value]) =>
    windowFromUsedPct({
      id,
      label,
      shortLabel,
      utilizationPct: value.percent,
      resetsAt: value.resetsAt,
      tone: toneFromUsedPct(value.percent),
    }),
  );
  return { status: "available", planLabel: "Go", windows };
}
