import type { UsageInput } from "../shared/input.js";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { z } from "zod";
import {
  toneFromUsedPct,
  usedPctOf,
  unavailable,
  windowFromUsedPct,
  type UsageAccount,
  type UsageReport,
  type UsageBalance,
  type UsageScope,
  type UsageWindow,
} from "@getpaseo/plugin/server/usage";

const ApiNumberSchema = z.coerce.number().finite();
const ApiNullableNumberSchema = z.preprocess(
  (value) => (value == null ? null : value),
  ApiNumberSchema.nullable(),
);
function toIsoStringOrNull(timestampMs: number): string | null {
  const date = new Date(timestampMs);
  return Number.isFinite(date.getTime()) ? date.toISOString() : null;
}

// Cursor desktop stores auth in VS Code's ItemTable (state.vscdb). Modern builds keep
// the access token as a plain JWT string under `cursorAuth/accessToken`; older builds
// kept a JSON blob under `cursorAuthStatus`. Read it with node:sqlite so we don't
// depend on a `sqlite3` CLI, which isn't installed by default on Windows (or on many
// Linux hosts) — a missing binary silently rendered Cursor usage unavailable.
// Headless hosts (VPS, cursor-agent only) have no desktop db; their session lives in
// ~/.config/cursor/auth.json instead.
const CURSOR_ACCESS_TOKEN_KEY = "cursorAuth/accessToken";
const CURSOR_LEGACY_AUTH_KEY = "cursorAuthStatus";

// @types/node@20 predates the node:sqlite typings; declare the slice we use.
interface CursorStateStatement {
  get(...params: unknown[]): Record<string, unknown> | undefined;
}
interface CursorStateDatabase {
  prepare(sql: string): CursorStateStatement;
  close(): void;
}
interface NodeSqliteModule {
  DatabaseSync: new (path: string, options?: { readOnly?: boolean }) => CursorStateDatabase;
}

const CursorBillingCycleTimestampSchema = z.preprocess(
  (value) => (typeof value === "string" || typeof value === "number" ? value : null),
  z.union([z.string(), z.number()]).nullable(),
);

const CursorUsageResponseSchema = z.object({
  planUsage: z
    .object({
      totalSpend: ApiNullableNumberSchema,
      includedSpend: ApiNullableNumberSchema,
      bonusSpend: ApiNullableNumberSchema,
      remaining: ApiNullableNumberSchema,
      limit: ApiNullableNumberSchema,
      totalPercentUsed: ApiNullableNumberSchema,
      autoPercentUsed: ApiNullableNumberSchema,
      apiPercentUsed: ApiNullableNumberSchema,
    })
    .nullish(),
  billingCycleStart: CursorBillingCycleTimestampSchema,
  billingCycleEnd: CursorBillingCycleTimestampSchema,
});

const CursorAuthStatusSchema = z.object({
  accessToken: z.string().optional(),
});

type CursorUsageResponse = z.infer<typeof CursorUsageResponseSchema>;

function parseCursorBillingCycleTimestamp(
  value: CursorUsageResponse["billingCycleStart"],
): string | null {
  if (value === null) return null;

  const raw = String(value).trim();
  if (!raw) return null;

  const numeric = Number(raw);
  if (Number.isFinite(numeric)) {
    const timestampMs = Math.abs(numeric) < 10_000_000_000 ? numeric * 1000 : numeric;
    return toIsoStringOrNull(timestampMs);
  }

  return toIsoStringOrNull(new Date(raw).getTime());
}

function centsToDollars(value: number | null): number | null {
  return value === null ? null : value / 100;
}

function readItemTableValue(db: CursorStateDatabase, key: string): string | null {
  const row = db.prepare("SELECT value FROM ItemTable WHERE key = ?").get(key);
  const value = row?.["value"];
  if (typeof value === "string") return value;
  if (value instanceof Uint8Array) return Buffer.from(value).toString("utf8");
  return null;
}

function cursorTokenFromDb(db: CursorStateDatabase): string | null {
  const modern = readItemTableValue(db, CURSOR_ACCESS_TOKEN_KEY)?.trim();
  if (modern) return modern;

  const legacy = readItemTableValue(db, CURSOR_LEGACY_AUTH_KEY);
  if (legacy) {
    try {
      const parsed = CursorAuthStatusSchema.parse(JSON.parse(legacy));
      if (parsed.accessToken) return parsed.accessToken;
    } catch {
      // ignore a malformed legacy blob
    }
  }
  return null;
}

async function readCursorTokenFromSqlite(path: string): Promise<string | null> {
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
  let db: CursorStateDatabase | undefined;
  try {
    db = new sqlite.DatabaseSync(path, { readOnly: true });
    return cursorTokenFromDb(db);
  } catch {
    return null;
  } finally {
    db?.close();
  }
}

// cursor-agent's macOS Keychain item: service `${domain}-access-token`, account `${domain}-user`.
const CURSOR_AGENT_KEYCHAIN_SERVICE = "cursor-access-token";
const CURSOR_AGENT_KEYCHAIN_ACCOUNT = "cursor-user";
const KEYCHAIN_TIMEOUT_MS = 5_000;
const execFileAsync = promisify(execFile);

/** Runs `security` with these arguments; resolves to trimmed stdout, or null on failure. */
export type SecurityCommandRunner = (args: string[]) => Promise<string | null>;

async function runSecurityCommand(args: string[]): Promise<string | null> {
  try {
    const { stdout } = await execFileAsync("security", args, { timeout: KEYCHAIN_TIMEOUT_MS });
    return stdout.trim() || null;
  } catch {
    return null;
  }
}

async function readCursorTokenFromKeychain(
  service: string,
  runSecurity: SecurityCommandRunner,
): Promise<string | null> {
  const token = await runSecurity([
    "find-generic-password",
    "-a",
    CURSOR_AGENT_KEYCHAIN_ACCOUNT,
    "-s",
    service,
    "-w",
  ]);
  return token?.trim() || null;
}

async function readCursorTokenFromAuthJson(path: string): Promise<string | null> {
  if (!existsSync(path)) return null;
  try {
    const parsed = CursorAuthStatusSchema.parse(JSON.parse(await readFile(path, "utf8")));
    return parsed.accessToken?.trim() || null;
  } catch {
    return null;
  }
}

export async function fetchUsage(
  input: UsageInput,
  fetchApi: typeof fetch = fetch,
  runSecurity: SecurityCommandRunner = runSecurityCommand,
): Promise<UsageReport> {
  const token = await readToken(input, runSecurity);
  if (!token) throw new Error("Cursor login store no longer exists");

  const res = await fetchApi(
    "https://api2.cursor.sh/aiserver.v1.DashboardService/GetCurrentPeriodUsage",
    {
      signal: AbortSignal.timeout(15_000),
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
        "Connect-Protocol-Version": "1",
      },
      body: JSON.stringify({}),
    },
  );

  if (res.status === 401 || res.status === 403)
    return unavailable({ kind: "rejected", status: res.status });
  if (!res.ok) throw new Error(`Cursor usage API returned ${res.status}`);

  const resp = CursorUsageResponseSchema.parse(await res.json());
  const billingCycleEnd = parseCursorBillingCycleTimestamp(resp.billingCycleEnd);
  const windows: UsageWindow[] = [];
  const balances: UsageBalance[] = [];
  if (resp.planUsage) {
    // Total spend includes bonus credits; returned percentages measure quota usage.
    for (const [id, label, usedPct] of [
      ["plan_usage", "Total", resp.planUsage.totalPercentUsed],
      ["cursor_usage", "Cursor", resp.planUsage.autoPercentUsed],
      ["third_party_usage", "Third Party", resp.planUsage.apiPercentUsed],
    ] as const) {
      if (usedPct === null) continue;
      windows.push(
        windowFromUsedPct({
          id,
          label,
          utilizationPct: usedPct,
          resetsAt: billingCycleEnd,
          summary: id === "plan_usage",
          tone: toneFromUsedPct(usedPct),
        }),
      );
    }
  }
  if (resp.planUsage && windows.length === 0) {
    const totalSpend = centsToDollars(resp.planUsage.totalSpend);
    const remaining = centsToDollars(resp.planUsage.remaining);
    const limit = centsToDollars(resp.planUsage.limit);
    balances.push({
      id: "plan_usage",
      label: "Plan usage",
      used: totalSpend,
      remaining,
      limit,
      unit: "usd",
      resetsAt: billingCycleEnd,
      tone: toneFromUsedPct(usedPctOf(totalSpend, limit)),
    });
  }

  return {
    status: "available",
    planLabel: undefined,
    windows,
    balances,
    details: [],
  };
}

async function readToken(
  input: UsageInput,
  runSecurity: SecurityCommandRunner = runSecurityCommand,
): Promise<string | undefined> {
  switch (input.store) {
    case "env":
      return process.env[input.locator];
    case "sqlite":
      return (await readCursorTokenFromSqlite(input.locator)) ?? undefined;
    case "file":
      return (await readCursorTokenFromAuthJson(input.locator)) ?? undefined;
    case "keychain":
      return (await readCursorTokenFromKeychain(input.locator, runSecurity)) ?? undefined;
  }
}

const CursorIdentitySchema = z.object({ sub: z.string().min(1) });

function cursorAccount(token: string, input: UsageInput): UsageAccount {
  const parts = token.split(".");
  if (parts.length === 3) {
    try {
      const payload: unknown = JSON.parse(Buffer.from(parts[1]!, "base64url").toString("utf8"));
      const identity = CursorIdentitySchema.safeParse(payload);
      if (identity.success) {
        const key = createHash("sha256").update(identity.data.sub).digest("hex");
        return { key: `account-${key}`, input };
      }
    } catch {
      // Non-JWT logins still have a usage card, isolated to their credential store.
    }
  }
  const key = createHash("sha256").update(JSON.stringify(input)).digest("hex");
  return { key: `store-${key}`, input };
}

export async function discover(): Promise<UsageAccount[]> {
  const home = homedir();
  const candidates: UsageInput[] = ["CURSOR_ACCESS_TOKEN", "CURSOR_TOKEN"].map((locator) => ({
    store: "env",
    locator,
  }));
  if (process.env.APPDATA)
    candidates.push({
      store: "sqlite",
      locator: join(process.env.APPDATA, "Cursor", "User", "globalStorage", "state.vscdb"),
    });
  candidates.push(
    ...[
      join(
        home,
        "Library",
        "Application Support",
        "Cursor",
        "User",
        "globalStorage",
        "state.vscdb",
      ),
      join(home, ".config", "Cursor", "User", "globalStorage", "state.vscdb"),
    ].map((locator) => ({ store: "sqlite" as const, locator })),
    { store: "file", locator: join(home, ".config", "cursor", "auth.json") },
  );
  for (const input of candidates) {
    const token = await readToken(input);
    if (token) return [cursorAccount(token, input)];
  }
  return [];
}

// Account identity joins global and session logins without merging different users.
export async function discoverSession(
  scope: Extract<UsageScope, { kind: "session" }>,
  platform: NodeJS.Platform = process.platform,
  runSecurity: SecurityCommandRunner = runSecurityCommand,
): Promise<UsageAccount[]> {
  if (scope.provider !== "cursor") return [];
  const input = cursorAgentStore(scope.env, platform);
  if (!input) return [];
  const token = await readToken(input, runSecurity);
  return token ? [cursorAccount(token, input)] : [];
}

// Mirrors cursor-agent's credential store. Env credentials win over the stored login and
// can't be named by an input. AGENT_CLI_CREDENTIAL_STORE picks "file" or "memory"; by
// default macOS keeps the login in the Keychain and other platforms in auth.json.
function cursorAgentStore(
  env: Record<string, string>,
  platform: NodeJS.Platform,
): UsageInput | null {
  if (env.CURSOR_API_KEY || env.CURSOR_AUTH_TOKEN) return null;
  const store = env.AGENT_CLI_CREDENTIAL_STORE;
  if (store === "memory") return null;
  if (platform === "darwin" && store !== "file")
    return { store: "keychain", locator: CURSOR_AGENT_KEYCHAIN_SERVICE };
  const home = env.HOME || env.USERPROFILE || homedir();
  let locator: string;
  if (platform === "win32")
    locator = join(env.APPDATA || join(home, "AppData", "Roaming"), "Cursor", "auth.json");
  else if (platform === "darwin") locator = join(home, ".cursor", "auth.json");
  else locator = join(env.XDG_CONFIG_HOME || join(home, ".config"), "cursor", "auth.json");
  return { store: "file", locator };
}
