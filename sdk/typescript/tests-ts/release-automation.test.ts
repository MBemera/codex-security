import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "bun:test";

type ReleaseMetadata = Record<string, unknown>;

type ReleaseAutomation = {
  releaseVersion: (packageJson: ReleaseMetadata) => string;
  releaseTagVersion: (
    refType: string,
    ref: string,
    refName: string,
    packageJson: ReleaseMetadata,
  ) => string;
  compareReleaseVersions: (left: string, right: string) => -1 | 0 | 1;
  requireReleaseIncrease: (version: string, previousVersion: string) => string;
  releaseHistory: (
    tag: string,
    history: {
      registryVersions: string[];
      githubReleaseTags: string[];
      reachableTags: string[];
    },
  ) => { previousTag: string | null; makeLatest: boolean };
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
  verifySignatureAudit: (
    report: ReleaseMetadata,
    archive: Uint8Array,
    expected: {
      version: string;
      gitHead: string;
      repository: string;
      runId: string;
    },
  ) => {
    version: string;
    gitHead: string;
    repository: string;
    runId: string;
    sha512: string;
  };
  verifyGitHubRelease: (
    release: ReleaseMetadata,
    archive: Uint8Array,
    expectedTag: string,
    assetName: string,
  ) => { tag: string; asset: string; digest: string };
};

const automationScript = new URL(
  "../scripts/release-automation.mjs",
  import.meta.url,
);
const {
  releaseVersion,
  releaseTagVersion,
  compareReleaseVersions,
  requireReleaseIncrease,
  releaseHistory,
  verifyPublishedRelease,
  verifySignatureAudit,
  verifyGitHubRelease,
} = (await import(automationScript.href)) as ReleaseAutomation;

const releaseCommit = "1e03c89ad22d2df5ae65b146be1483b3608572a9";
const releaseRun = "30481596229";
const releaseRepository = "openai/codex-security";
const archive = Buffer.from("verified codex security release artifact");
const integrity =
  "sha512-" + createHash("sha512").update(archive).digest("base64");
const sha512 = createHash("sha512").update(archive).digest("hex");
const digest = "sha256:" + createHash("sha256").update(archive).digest("hex");
const protectedReleaseWorkflow = readFileSync(
  new URL("../../../.github/workflows/node-release.yml", import.meta.url),
  "utf8",
);
const releaseCutWorkflow = readFileSync(
  new URL("../../../.github/workflows/node-release-cut.yml", import.meta.url),
  "utf8",
);
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

type SignatureAuditFixture = {
  name?: string;
  version?: string;
  registry?: string;
  invalid?: unknown[];
  missing?: unknown[];
  includeVerified?: boolean;
  includeProvenance?: boolean;
  includeBundle?: boolean;
  subjectName?: string;
  subjectDigest?: string;
  repository?: string;
  workflowPath?: string;
  workflowRef?: string;
  sourceCommit?: string;
  runId?: string;
  builder?: string;
};

function signatureAudit(options: SignatureAuditFixture = {}): ReleaseMetadata {
  const version = options.version ?? "0.1.2";
  const repository = options.repository ?? releaseRepository;
  const releaseRef = options.workflowRef ?? `refs/tags/npm-v${version}`;
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [
      {
        name:
          options.subjectName ?? `pkg:npm/%40openai/codex-security@${version}`,
        digest: { sha512: options.subjectDigest ?? sha512 },
      },
    ],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        externalParameters: {
          workflow: {
            repository: `https://github.com/${repository}`,
            ref: releaseRef,
            path: options.workflowPath ?? ".github/workflows/node-release.yml",
          },
        },
        resolvedDependencies: [
          {
            uri: `git+https://github.com/${repository}@${releaseRef}`,
            digest: { gitCommit: options.sourceCommit ?? releaseCommit },
          },
        ],
      },
      runDetails: {
        builder: {
          id:
            options.builder ??
            "https://github.com/actions/runner/github-hosted",
        },
        metadata: {
          invocationId:
            `https://github.com/${repository}/actions/runs/` +
            `${options.runId ?? releaseRun}/attempts/1`,
        },
      },
    },
  };

  return {
    invalid: options.invalid ?? [],
    missing: options.missing ?? [],
    verified:
      options.includeVerified === false
        ? []
        : [
            {
              name: options.name ?? "@openai/codex-security",
              version,
              registry: options.registry ?? "https://registry.npmjs.org/",
              attestations:
                options.includeProvenance === false
                  ? {}
                  : {
                      provenance: {
                        predicateType: "https://slsa.dev/provenance/v1",
                      },
                    },
              attestationBundles:
                options.includeBundle === false
                  ? []
                  : [
                      {
                        predicateType: "https://slsa.dev/provenance/v1",
                        bundle: {
                          dsseEnvelope: {
                            payload: Buffer.from(
                              JSON.stringify(statement),
                            ).toString("base64"),
                          },
                        },
                      },
                    ],
            },
          ],
  };
}

function signatureExpected() {
  return {
    version: "0.1.2",
    gitHead: releaseCommit,
    repository: releaseRepository,
    runId: releaseRun,
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

describe("protected Git release refs", () => {
  const packageJson = {
    name: "@openai/codex-security",
    version: "0.1.2",
  };

  test("accepts the exact stable Git tag and package", () => {
    expect(
      releaseTagVersion(
        "tag",
        "refs/tags/npm-v0.1.2",
        "npm-v0.1.2",
        packageJson,
      ),
    ).toBe("0.1.2");
  });

  test("rejects a release-shaped branch", () => {
    expect(() =>
      releaseTagVersion(
        "branch",
        "refs/heads/npm-v0.1.2",
        "npm-v0.1.2",
        packageJson,
      ),
    ).toThrow("npm releases must be dispatched from a real Git tag.");
  });

  test("rejects a mismatched full Git ref", () => {
    expect(() =>
      releaseTagVersion(
        "tag",
        "refs/tags/npm-v0.1.3",
        "npm-v0.1.2",
        packageJson,
      ),
    ).toThrow("npm releases must be dispatched from a real Git tag.");
  });

  test("rejects an unstable release tag", () => {
    expect(() =>
      releaseTagVersion(
        "tag",
        "refs/tags/npm-v0.1.2-beta.1",
        "npm-v0.1.2-beta.1",
        packageJson,
      ),
    ).toThrow("Release tags must identify a stable npm-vX.Y.Z version.");
  });

  test("rejects a Git tag for a different package version", () => {
    expect(() =>
      releaseTagVersion(
        "tag",
        "refs/tags/npm-v0.1.3",
        "npm-v0.1.3",
        packageJson,
      ),
    ).toThrow("npm release tag must match the stable package version.");
  });
});

describe("monotonic stable release versions", () => {
  test("compares semantic version components numerically", () => {
    expect(compareReleaseVersions("0.1.10", "0.1.9")).toBe(1);
    expect(compareReleaseVersions("1.0.0", "0.99.99")).toBe(1);
    expect(compareReleaseVersions("0.1.2", "0.1.2")).toBe(0);
    expect(compareReleaseVersions("0.1.2", "0.1.3")).toBe(-1);
  });

  test("compares components without unsafe JavaScript number rounding", () => {
    expect(
      compareReleaseVersions("9007199254740993.0.0", "9007199254740992.0.0"),
    ).toBe(1);
  });

  test("accepts a strictly increasing release", () => {
    expect(requireReleaseIncrease("0.1.3", "0.1.2")).toBe("0.1.3");
  });

  test("rejects a downgrade or repeated release", () => {
    expect(() => requireReleaseIncrease("0.1.1", "0.1.2")).toThrow(
      "Release version must be greater than the previous stable version.",
    );
    expect(() => requireReleaseIncrease("0.1.2", "0.1.2")).toThrow(
      "Release version must be greater than the previous stable version.",
    );
  });

  test("rejects malformed and prerelease versions", () => {
    expect(() => compareReleaseVersions("0.1.3-beta.1", "0.1.2")).toThrow(
      "Release versions must use stable X.Y.Z versions.",
    );
  });
});

describe("published GitHub and npm release history", () => {
  test("marks the first verified GitHub release as latest", () => {
    expect(
      releaseHistory("npm-v0.1.2", {
        registryVersions: ["0.1.0", "0.1.1", "0.1.2"],
        githubReleaseTags: [],
        reachableTags: ["npm-v0.1.1", "npm-v0.1.0"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.1", makeLatest: true });
  });

  test("never marks a historical backfill as latest", () => {
    expect(
      releaseHistory("npm-v0.1.2", {
        registryVersions: ["0.1.1", "0.1.2", "0.1.3"],
        githubReleaseTags: ["npm-v0.1.3"],
        reachableTags: ["npm-v0.1.1"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.1", makeLatest: false });
  });

  test("starts notes from the newest actually published version", () => {
    expect(
      releaseHistory("npm-v0.1.4", {
        registryVersions: ["0.1.1", "0.1.2", "0.1.4"],
        githubReleaseTags: ["npm-v0.1.2"],
        reachableTags: ["npm-v0.1.3", "npm-v0.1.2", "npm-v0.1.1"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.2", makeLatest: true });
  });

  test("compares published versions numerically rather than lexically", () => {
    expect(
      releaseHistory("npm-v0.1.11", {
        registryVersions: ["0.1.9", "0.1.10", "0.1.11"],
        githubReleaseTags: ["npm-v0.1.9", "npm-v0.1.10"],
        reachableTags: ["npm-v0.1.9", "npm-v0.1.10"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.10", makeLatest: true });
  });

  test("ignores unrelated, unstable, and unreachable release tags", () => {
    expect(
      releaseHistory("npm-v0.1.2", {
        registryVersions: ["0.1.1", "0.1.2", "0.1.3-beta.1"],
        githubReleaseTags: ["container-v99.0.0", "npm-v0.1.3-beta.1"],
        reachableTags: ["container-v99.0.0", "npm-v0.1.3-beta.1", "npm-v0.1.1"],
      }),
    ).toEqual({ previousTag: "npm-v0.1.1", makeLatest: true });
  });

  test("rejects invalid release history inputs", () => {
    expect(() =>
      releaseHistory("0.1.2", {
        registryVersions: [],
        githubReleaseTags: [],
        reachableTags: [],
      }),
    ).toThrow("Release tags must identify a stable npm-vX.Y.Z version.");
  });
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

describe("cryptographically verified npm provenance", () => {
  test("binds the verified bundle to the exact archive, source, and run", () => {
    expect(
      verifySignatureAudit(signatureAudit(), archive, signatureExpected()),
    ).toEqual({
      version: "0.1.2",
      gitHead: releaseCommit,
      repository: releaseRepository,
      runId: releaseRun,
      sha512,
    });
  });

  test("rejects invalid or missing registry signatures", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ invalid: [{ name: "@openai/codex-security" }] }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("npm registry signatures and attestations must verify.");
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ missing: [{ name: "@openai/codex-security" }] }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("npm registry signatures and attestations must verify.");
  });

  test("requires the exact published package in the verified audit", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ includeVerified: false }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "The published package must have a cryptographically verified attestation.",
    );
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ name: "@openai/codex" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "The published package must have a cryptographically verified attestation.",
    );
  });

  test("requires the signed public npm registry and SLSA bundle", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ registry: "https://registry.example/" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("Verified provenance must come from the public npm registry.");
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ includeProvenance: false }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("The verified npm package must have SLSA v1 provenance.");
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ includeBundle: false }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("The verified SLSA provenance bundle is missing.");
  });

  test("rejects provenance for a different package subject or archive", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ subjectName: "pkg:npm/another-package@0.1.2" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the exact published tarball.",
    );
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ subjectDigest: "incorrect" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the exact published tarball.",
    );
  });

  test("rejects another repository, workflow, or release tag", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ repository: "attacker/codex-security" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the protected release workflow.",
    );
    expect(() =>
      verifySignatureAudit(
        signatureAudit({
          workflowPath: ".github/workflows/untrusted-release.yml",
        }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the protected release workflow.",
    );
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ workflowRef: "refs/heads/npm-v0.1.2" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the protected release workflow.",
    );
  });

  test("rejects a source commit outside the protected release", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({
          sourceCommit: "0000000000000000000000000000000000000000",
        }),
        archive,
        signatureExpected(),
      ),
    ).toThrow("npm package gitHead must match release commit");
  });

  test("rejects provenance from another release run or builder", () => {
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ runId: "12345" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must identify the successful release run.",
    );
    expect(() =>
      verifySignatureAudit(
        signatureAudit({ builder: "https://example.com/untrusted-runner" }),
        archive,
        signatureExpected(),
      ),
    ).toThrow(
      "Verified SLSA provenance must use a GitHub-hosted release runner.",
    );
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
  test("requires a real tag for protected npm publication", () => {
    expect(protectedReleaseWorkflow).toContain("release-tag");
    expect(protectedReleaseWorkflow).toContain('"$GITHUB_REF_TYPE"');
    expect(protectedReleaseWorkflow).toContain('"$GITHUB_REF"');
  });

  test("restricts release cuts to main and increasing stable versions", () => {
    expect(releaseCutWorkflow).toContain(
      'if [[ "$GITHUB_REF" != "refs/heads/main" ]]; then',
    );
    expect(releaseCutWorkflow).toContain(
      'git merge-base --is-ancestor "$GITHUB_SHA" origin/main',
    );
    expect(releaseCutWorkflow).toContain("require-increase");
  });

  test("explicitly prevents historical releases becoming latest", () => {
    expect(githubReleaseWorkflow).toContain("--generate-notes");
    expect(githubReleaseWorkflow).toContain('--latest="$MAKE_LATEST"');
    expect(githubReleaseWorkflow).toContain("release-history");
  });

  test("generates notes only from a previously published release", () => {
    expect(githubReleaseWorkflow).toContain(
      "npm view @openai/codex-security versions",
    );
    expect(githubReleaseWorkflow).toContain(
      "steps.history.outputs.previous-tag",
    );
    expect(githubReleaseWorkflow).toContain(
      'release_args+=(--notes-start-tag "$PREVIOUS_TAG")',
    );
  });

  test("recovers a public npm tarball after release artifacts expire", () => {
    expect(githubReleaseWorkflow).toContain("if ! gh run download");
    expect(githubReleaseWorkflow).toContain(
      'npm pack "@openai/codex-security@$RELEASE_VERSION"',
    );
    expect(githubReleaseWorkflow).toContain("--ignore-scripts");
  });

  test("cryptographically verifies the exact npm provenance bundle", () => {
    expect(githubReleaseWorkflow).toContain("npm audit signatures");
    expect(githubReleaseWorkflow).toContain("--include-attestations");
    expect(githubReleaseWorkflow).toContain("verify-provenance");
  });

  test("serializes label reconciliation and reads the current PR title", () => {
    expect(releaseLabelsWorkflow).toContain(
      "group: node-release-labels-${{ github.event.pull_request.number }}",
    );
    expect(releaseLabelsWorkflow).toContain(
      'gh api "repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER"',
    );
    expect(releaseLabelsWorkflow).toContain(
      'label="$(release_note_label "$current_title")"',
    );
    expect(releaseLabelsWorkflow).toContain(
      "enhancement | bug | documentation | skip-release-notes)",
    );
    expect(releaseLabelsWorkflow).toContain("gh api --method DELETE");
    expect(releaseLabelsWorkflow).toContain("return 0");
  });

  test("documents JSON stdin for every verification command", () => {
    const result = spawnSync(
      "node",
      [fileURLToPath(automationScript), "unknown"],
      { encoding: "utf8", timeout: 10_000 },
    );
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("package metadata JSON from stdin");
    expect(result.stderr).toContain("signature audit JSON from stdin");
    expect(result.stderr).toContain("GitHub release JSON from stdin");
  });
});
