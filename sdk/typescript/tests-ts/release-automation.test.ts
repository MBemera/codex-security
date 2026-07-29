import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, expect, test } from "bun:test";

type ReleaseMetadata = Record<string, unknown>;

type ReleaseAutomation = {
  releaseVersion: (packageJson: ReleaseMetadata) => string;
  verifyPublishedRelease: (
    metadata: ReleaseMetadata,
    archive: Uint8Array,
    expected: { version: string; gitHead: string },
  ) => {
    version: string;
    gitHead: string;
    integrity: string;
    sha256: string;
  };
  verifyGitHubRelease: (
    release: ReleaseMetadata,
    archive: Uint8Array,
    expectedTag: string,
    assetName: string,
  ) => { tag: string; asset: string; digest: string };
};

const { releaseVersion, verifyPublishedRelease, verifyGitHubRelease } =
  (await import(
    new URL("../scripts/release-automation.mjs", import.meta.url).href
  )) as ReleaseAutomation;

const releaseCommit = "1e03c89ad22d2df5ae65b146be1483b3608572a9";
const archive = Buffer.from("verified codex security release artifact");
const integrity =
  "sha512-" + createHash("sha512").update(archive).digest("base64");
const digest = "sha256:" + createHash("sha256").update(archive).digest("hex");
const githubReleaseWorkflow = readFileSync(
  new URL(
    "../../../.github/workflows/node-github-release.yml",
    import.meta.url,
  ),
  "utf8",
);
const releaseLabelsWorkflow = readFileSync(
  new URL(
    "../../../.github/workflows/node-release-labels.yml",
    import.meta.url,
  ),
  "utf8",
);

function publishedMetadata(): ReleaseMetadata {
  return {
    name: "@openai/codex-security",
    version: "0.1.2",
    gitHead: releaseCommit,
    "dist.integrity": integrity,
    "dist.attestations": {
      provenance: {
        predicateType: "https://slsa.dev/provenance/v1",
      },
    },
  };
}

function githubRelease(): ReleaseMetadata {
  return {
    tag_name: "npm-v0.1.2",
    draft: false,
    prerelease: false,
    assets: [{ name: "openai-codex-security-0.1.2.tgz", digest }],
  };
}

describe("stable npm release versions", () => {
  test("accepts the official stable package and version", () => {
    expect(
      releaseVersion({
        name: "@openai/codex-security",
        version: "0.1.2",
      }),
    ).toBe("0.1.2");
  });

  test("rejects another package", () => {
    expect(() =>
      releaseVersion({ name: "codex-security", version: "0.1.2" }),
    ).toThrow("Release package must be @openai/codex-security.");
  });

  test.each(["0.1.2-beta.1", "01.1.2", "0.1", "latest", ""])(
    "rejects unstable or malformed version %s",
    (version) => {
      expect(() =>
        releaseVersion({ name: "@openai/codex-security", version }),
      ).toThrow("Release package must have a stable X.Y.Z version.");
    },
  );
});

describe("published npm release verification", () => {
  test("verifies source commit, tarball integrity, and SLSA provenance", () => {
    expect(
      verifyPublishedRelease(publishedMetadata(), archive, {
        version: "0.1.2",
        gitHead: releaseCommit,
      }),
    ).toEqual({
      version: "0.1.2",
      gitHead: releaseCommit,
      integrity,
      sha256: digest.slice("sha256:".length),
    });
  });

  test("supports nested public npm metadata", () => {
    expect(
      verifyPublishedRelease(
        {
          name: "@openai/codex-security",
          version: "0.1.2",
          gitHead: releaseCommit,
          dist: {
            integrity,
            attestations: {
              provenance: {
                predicateType: "https://slsa.dev/provenance/v1",
              },
            },
          },
        },
        archive,
        { version: "0.1.2", gitHead: releaseCommit },
      ).integrity,
    ).toBe(integrity);
  });

  test("rejects a different published version", () => {
    expect(() =>
      verifyPublishedRelease(publishedMetadata(), archive, {
        version: "0.1.3",
        gitHead: releaseCommit,
      }),
    ).toThrow("Published npm package must match the release version.");
  });

  test("rejects a missing or mismatched release commit", () => {
    expect(() =>
      verifyPublishedRelease(
        { ...publishedMetadata(), gitHead: undefined },
        archive,
        { version: "0.1.2", gitHead: releaseCommit },
      ),
    ).toThrow("npm package gitHead must match release commit");
  });

  test("rejects a tarball that differs from the published npm artifact", () => {
    expect(() =>
      verifyPublishedRelease(
        publishedMetadata(),
        Buffer.from("different release artifact"),
        { version: "0.1.2", gitHead: releaseCommit },
      ),
    ).toThrow(
      "Published npm integrity must match the verified release artifact.",
    );
  });

  test("rejects missing or unexpected provenance", () => {
    expect(() =>
      verifyPublishedRelease(
        { ...publishedMetadata(), "dist.attestations": undefined },
        archive,
        { version: "0.1.2", gitHead: releaseCommit },
      ),
    ).toThrow("Published npm package must have SLSA v1 provenance.");
  });
});

describe("idempotent GitHub release verification", () => {
  test("accepts the already-published exact verified release asset", () => {
    expect(
      verifyGitHubRelease(
        githubRelease(),
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
      ),
    ).toEqual({
      tag: "npm-v0.1.2",
      asset: "openai-codex-security-0.1.2.tgz",
      digest,
    });
  });

  test("rejects a GitHub release for another tag", () => {
    expect(() =>
      verifyGitHubRelease(
        { ...githubRelease(), tag_name: "npm-v0.1.1" },
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
      ),
    ).toThrow("Existing GitHub Release must match the release tag.");
  });

  test("rejects a draft or prerelease", () => {
    expect(() =>
      verifyGitHubRelease(
        { ...githubRelease(), draft: true },
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
      ),
    ).toThrow("Existing GitHub Release must be published and stable.");
  });

  test("rejects a missing or different GitHub release artifact", () => {
    expect(() =>
      verifyGitHubRelease(
        {
          ...githubRelease(),
          assets: [
            {
              name: "openai-codex-security-0.1.2.tgz",
              digest: "sha256:incorrect",
            },
          ],
        },
        archive,
        "npm-v0.1.2",
        "openai-codex-security-0.1.2.tgz",
      ),
    ).toThrow(
      "Existing GitHub Release asset must match the verified npm artifact.",
    );
  });
});

describe("GitHub release workflow safeguards", () => {
  test("does not force a historical backfill to become the latest release", () => {
    expect(githubReleaseWorkflow).toContain("--generate-notes");
    expect(githubReleaseWorkflow).not.toMatch(/^\s*--latest(?:=true)?\s*$/mu);
  });

  test("reconciles the previous category after a pull request title changes", () => {
    expect(releaseLabelsWorkflow).toContain(
      "PR_PREVIOUS_TITLE: ${{ github.event.changes.title.from }}",
    );
    expect(releaseLabelsWorkflow).toContain(
      'previous_label="$(release_note_label "$PR_PREVIOUS_TITLE")"',
    );
    expect(releaseLabelsWorkflow).toContain(
      'if [[ -n "$previous_label" && "$previous_label" != "$label" ]]; then',
    );
    expect(releaseLabelsWorkflow).toContain("gh api --method DELETE");
  });
});
