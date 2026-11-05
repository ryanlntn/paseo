import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, test } from "vitest";
import { discover, fetchUsage } from "./usage.js";

import { inputSchema } from "../shared/input.js";

// node:sqlite has no @types/node@20 typings; require it with a narrow local type.
const testRequire = createRequire(import.meta.url);
interface TestSqliteDb {
  exec(sql: string): void;
  prepare(sql: string): { run(...params: unknown[]): void };
  close(): void;
}

interface CredentialRow {
  id: string;
  integrationId: string;
  value: unknown;
  active: number | null;
  timeUpdated: number;
}

// Mirrors OpenCode 2.x's `credential` table in opencode.db.
function writeOpencodeDb(directory: string, rows: CredentialRow[]): string {
  const { DatabaseSync } = testRequire("node:sqlite") as {
    DatabaseSync: new (path: string) => TestSqliteDb;
  };
  const path = join(directory, "opencode.db");
  const db = new DatabaseSync(path);
  db.exec(
    "CREATE TABLE IF NOT EXISTS credential (id text PRIMARY KEY, integration_id text, label text NOT NULL, value text NOT NULL, connector_id text, method_id text, active integer, time_created integer NOT NULL, time_updated integer NOT NULL)",
  );
  const insert = db.prepare(
    "INSERT INTO credential (id, integration_id, label, value, active, time_created, time_updated) VALUES (?, ?, 'API key', ?, ?, ?, ?)",
  );
  for (const row of rows)
    insert.run(
      row.id,
      row.integrationId,
      JSON.stringify(row.value),
      row.active,
      row.timeUpdated,
      row.timeUpdated,
    );
  db.close();
  return path;
}

function goKey(id: string, key: string, timeUpdated: number, active: number | null = null) {
  return { id, integrationId: "opencode-go", value: { type: "key", key }, active, timeUpdated };
}

async function requestedKey(path: string): Promise<string | null> {
  let authorization: string | null = null;
  await fetchUsage({ path }, (async (_url: string | URL | Request, init?: RequestInit) => {
    authorization = new Headers(init?.headers).get("Authorization");
    return Response.json(upstreamResponse);
  }) as typeof fetch);
  return authorization;
}

let fixtureDirectory: string;
let fixturePath: string;
beforeEach(async () => {
  fixtureDirectory = await mkdtemp(join(tmpdir(), "go-default-"));
  fixturePath = join(fixtureDirectory, "auth.json");
  await writeFile(
    fixturePath,
    JSON.stringify({ "opencode-go": { type: "api", key: "fixture-secret" } }),
  );
});
afterEach(async () => {
  await rm(fixtureDirectory, { recursive: true, force: true });
});

test("discovery input rejects an explicit API key", () => {
  expect(inputSchema.safeParse({ apiKey: "unused" }).success).toBe(false);
  expect(() => inputSchema.parse({})).toThrow();
});

const upstreamResponse = {
  usage: {
    rolling: { status: "ok", percent: 21, resetsAt: "2026-09-26T20:00:00.000Z" },
    weekly: { status: "ok", percent: 42, resetsAt: "2026-09-28T00:00:00.000Z" },
    monthly: { status: "rate-limited", percent: 100, resetsAt: "2026-10-01T00:00:00.000Z" },
  },
};

test("discovers and fetches the default key from read-only auth.json", async () => {
  const directory = await mkdtemp(join(tmpdir(), "paseo-go-usage-"));
  const path = join(directory, "auth.json");
  const content = JSON.stringify({ "opencode-go": { type: "api", key: "fixture-key" } });
  try {
    await writeFile(path, content);
    expect(await discover(path)).toEqual([
      { key: expect.stringMatching(/^[a-f0-9]{64}$/), input: { path } },
    ]);
    const requests: Array<{ url: string; authorization: string | null }> = [];
    const fetchApi = async (url: string | URL | Request, init?: RequestInit) => {
      requests.push({
        url: String(url),
        authorization: new Headers(init?.headers).get("Authorization"),
      });
      return Response.json(upstreamResponse);
    };
    const report = await fetchUsage({ path }, fetchApi as typeof fetch);
    expect(requests).toEqual([
      { url: "https://opencode.ai/zen/go/v1/usage", authorization: "Bearer fixture-key" },
    ]);
    expect(report.status).toBe("available");
    expect(report.windows.map((window) => [window.id, window.usedPct, window.resetsAt])).toEqual([
      ["rolling", 21, "2026-09-26T20:00:00.000Z"],
      ["weekly", 42, "2026-09-28T00:00:00.000Z"],
      ["monthly", 100, "2026-10-01T00:00:00.000Z"],
    ]);
    // The rolling window's length is not reported, so its percent stands without a name.
    expect(report.windows.map((window) => window.shortLabel)).toEqual(["", "wk", "mo"]);
    // The current upstream endpoint returns windows only; do not invent balances.
    expect(report.balances).toBeUndefined();
    expect(await readFile(path, "utf8")).toBe(content);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("omits default discovery when auth.json lacks an OpenCode Go API key", async () => {
  const directory = await mkdtemp(join(tmpdir(), "paseo-go-usage-"));
  const path = join(directory, "auth.json");
  try {
    await writeFile(path, JSON.stringify({ openai: { type: "oauth", access: "other-token" } }));
    expect(await discover(path)).toEqual([]);
    await expect(
      fetchUsage({ path }, async () => {
        throw new Error("must not fetch");
      }),
    ).rejects.toThrow("login store no longer exists");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test.each([401, 403])("maps HTTP %i to unavailable", async (status) => {
  const report = await fetchUsage(
    { path: fixturePath },
    async () => new Response(null, { status }),
  );
  expect(report).toEqual({
    status: "unavailable",
    problem: { kind: "rejected", status, refreshedBy: "opencode" },
  });
});

test.each(["missing file", "unrelated file"])("discovers no accounts for %s", async (scenario) => {
  const path = join(fixtureDirectory, "missing.json");
  if (scenario === "unrelated file") await writeFile(path, "{}");
  expect(await discover(path)).toEqual([]);
});

describe("OpenCode 2.x credential database", () => {
  test("discovers the Go key from opencode.db under the same account key as auth.json", async () => {
    const before = await discover(fixturePath);
    await rm(fixturePath);
    const dbPath = writeOpencodeDb(fixtureDirectory, [goKey("cred_go", "db-key", 10)]);
    const content = await readFile(dbPath);
    expect(await discover(fixturePath)).toEqual(before);
    expect(await requestedKey(fixturePath)).toBe("Bearer db-key");
    expect(await readFile(dbPath)).toEqual(content);
  });

  test("prefers the database over auth.json", async () => {
    writeOpencodeDb(fixtureDirectory, [goKey("cred_go", "db-key", 10)]);
    expect(await requestedKey(fixturePath)).toBe("Bearer db-key");
  });

  test("picks the most recently updated Go key when none is active", async () => {
    writeOpencodeDb(fixtureDirectory, [
      goKey("cred_old", "old-key", 10),
      goKey("cred_new", "new-key", 30),
      { ...goKey("cred_other", "other-key", 50), integrationId: "opencode" },
    ]);
    expect(await requestedKey(fixturePath)).toBe("Bearer new-key");
  });

  test("prefers an active Go key over a newer inactive one", async () => {
    writeOpencodeDb(fixtureDirectory, [
      goKey("cred_active", "active-key", 10, 1),
      goKey("cred_newer", "newer-key", 30),
    ]);
    expect(await requestedKey(fixturePath)).toBe("Bearer active-key");
  });

  test("skips a Go row that holds no API key", async () => {
    writeOpencodeDb(fixtureDirectory, [
      goKey("cred_old", "old-key", 10),
      { ...goKey("cred_oauth", "", 30), value: { type: "oauth", access: "token" } },
    ]);
    expect(await requestedKey(fixturePath)).toBe("Bearer old-key");
  });

  test("falls back to auth.json when the database has no Go key", async () => {
    writeOpencodeDb(fixtureDirectory, [
      { ...goKey("cred_other", "other-key", 50), integrationId: "opencode" },
    ]);
    expect(await requestedKey(fixturePath)).toBe("Bearer fixture-secret");
  });

  test("falls back to auth.json when the database is not a credential store", async () => {
    await writeFile(join(fixtureDirectory, "opencode.db"), "not a database");
    expect(await requestedKey(fixturePath)).toBe("Bearer fixture-secret");
  });
});

test("tells the user to replace an expired API key instead of signing in again", async () => {
  const body = {
    error: {
      code: "api_key_expired",
      message: "This API key has expired. Create a new API key in OpenCode Console.",
    },
  };
  const report = await fetchUsage({ path: fixturePath }, async () =>
    Response.json(body, { status: 401 }),
  );
  expect(report).toEqual({
    status: "unavailable",
    problem: {
      kind: "no_quota",
      detail:
        "OpenCode Go API key expired. Create a new key in OpenCode Console, then run opencode auth login.",
    },
  });
});

test("keeps the refresh remedy for a 401 that is not an expired key", async () => {
  const report = await fetchUsage({ path: fixturePath }, async () =>
    Response.json({ error: { code: "invalid_api_key" } }, { status: 401 }),
  );
  expect(report).toEqual({
    status: "unavailable",
    problem: { kind: "rejected", status: 401, refreshedBy: "opencode" },
  });
});
