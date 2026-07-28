import { spawnSync, type SpawnSyncReturns } from "node:child_process";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { describe, expect, test } from "bun:test";

const testPosix = process.platform === "win32" ? test.skip : test;
const entrypoint = join(
  import.meta.dir,
  "..",
  "..",
  "..",
  "docker",
  "entrypoint.sh",
);

async function runEntrypoint(
  args: readonly string[],
  overrides: Record<string, string> = {},
): Promise<SpawnSyncReturns<string>> {
  const root = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-container-entrypoint-")),
  );

  try {
    await writeFile(
      join(root, "codex-security"),
      "#!/bin/sh\nprintf '%s\\n' \"$@\"\n",
      { mode: 0o755 },
    );

    return spawnSync("sh", [entrypoint, ...args], {
      encoding: "utf8",
      env: {
        ...process.env,
        GH_TOKEN: "",
        GITHUB_TOKEN: "",
        PATH: `${root}${delimiter}${process.env["PATH"] ?? ""}`,
        ...overrides,
      },
      timeout: 10_000,
    });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("customer container entrypoint", () => {
  testPosix(
    "preserves CSV scan arguments and selects the supported Linux sandbox",
    async () => {
      const result = await runEntrypoint([
        "bulk-scan",
        "/input/repositories.csv",
        "--output-dir",
        "/output",
        "--workers",
        "2",
      ]);

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout).toBe(
        [
          "bulk-scan",
          "/input/repositories.csv",
          "--output-dir",
          "/output",
          "--workers",
          "2",
          "--codex",
          "features.use_legacy_landlock=true",
          "",
        ].join("\n"),
      );
    },
  );

  testPosix(
    "preserves bulk-scan help without injecting scan configuration",
    async () => {
      const result = await runEntrypoint(["bulk-scan", "--help"]);

      expect(result.status).toBe(0);
      expect(result.stderr).toBe("");
      expect(result.stdout).toBe("bulk-scan\n--help\n");
    },
  );

  testPosix(
    "rejects interactive discovery before starting the CLI",
    async () => {
      const result = await runEntrypoint(["bulk-scan"]);

      expect(result.status).toBe(2);
      expect(result.stdout).toBe("");
      expect(result.stderr).toBe(
        "codex-security: bulk-scan requires a repository CSV; interactive discovery is not supported in this image.\n",
      );
    },
  );

  testPosix("does not change non-scan commands", async () => {
    const result = await runEntrypoint(["--version"]);

    expect(result.status).toBe(0);
    expect(result.stderr).toBe("");
    expect(result.stdout).toBe("--version\n");
  });
});
