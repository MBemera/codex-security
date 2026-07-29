import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";
import { assertExpectedGitHead } from "./package-provenance.mjs";

const packageName = "@openai/codex-security";
const stableVersion = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const provenancePredicate = "https://slsa.dev/provenance/v1";
const publicNpmRegistry = "https://registry.npmjs.org/";

function stableReleaseTagVersion(tag) {
  if (typeof tag !== "string" || !tag.startsWith("npm-v")) {
    throw new Error("Release tags must identify a stable npm-vX.Y.Z version.");
  }

  const version = tag.slice("npm-v".length);
  if (!stableVersion.test(version)) {
    throw new Error("Release tags must identify a stable npm-vX.Y.Z version.");
  }
  return version;
}

export function releaseVersion(packageJson) {
  if (packageJson?.name !== packageName) {
    throw new Error("Release package must be @openai/codex-security.");
  }
  if (
    typeof packageJson.version !== "string" ||
    !stableVersion.test(packageJson.version)
  ) {
    throw new Error("Release package must have a stable X.Y.Z version.");
  }
  return packageJson.version;
}

export function releaseTagVersion(refType, ref, refName, packageJson) {
  if (refType !== "tag" || ref !== `refs/tags/${refName}`) {
    throw new Error("npm releases must be dispatched from a real Git tag.");
  }

  const tagVersion = stableReleaseTagVersion(refName);
  const packageVersion = releaseVersion(packageJson);
  if (tagVersion !== packageVersion) {
    throw new Error("npm release tag must match the stable package version.");
  }

  return packageVersion;
}

export function compareReleaseVersions(left, right) {
  if (!stableVersion.test(left) || !stableVersion.test(right)) {
    throw new Error("Release versions must use stable X.Y.Z versions.");
  }

  const leftParts = left.split(".").map(BigInt);
  const rightParts = right.split(".").map(BigInt);
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] > rightParts[index]) return 1;
    if (leftParts[index] < rightParts[index]) return -1;
  }
  return 0;
}

export function requireReleaseIncrease(version, previousVersion) {
  if (compareReleaseVersions(version, previousVersion) <= 0) {
    throw new Error(
      "Release version must be greater than the previous stable version.",
    );
  }
  return version;
}

export function releaseHistory(tag, history) {
  const version = stableReleaseTagVersion(tag);
  if (
    !Array.isArray(history?.registryVersions) ||
    !Array.isArray(history.githubReleaseTags) ||
    !Array.isArray(history.reachableTags)
  ) {
    throw new Error(
      "Release history must contain published and reachable tags.",
    );
  }

  const publishedVersions = new Set(
    history.registryVersions.filter(
      (candidate) =>
        typeof candidate === "string" && stableVersion.test(candidate),
    ),
  );
  const publishedGitHubTags = new Set(
    history.githubReleaseTags.filter(
      (candidate) =>
        typeof candidate === "string" &&
        candidate.startsWith("npm-v") &&
        stableVersion.test(candidate.slice("npm-v".length)),
    ),
  );

  let previousTag = null;
  for (const candidate of history.reachableTags) {
    if (
      typeof candidate !== "string" ||
      !candidate.startsWith("npm-v") ||
      !stableVersion.test(candidate.slice("npm-v".length))
    ) {
      continue;
    }

    const candidateVersion = candidate.slice("npm-v".length);
    if (
      compareReleaseVersions(candidateVersion, version) >= 0 ||
      (!publishedVersions.has(candidateVersion) &&
        !publishedGitHubTags.has(candidate))
    ) {
      continue;
    }

    if (
      previousTag === null ||
      compareReleaseVersions(
        candidateVersion,
        previousTag.slice("npm-v".length),
      ) > 0
    ) {
      previousTag = candidate;
    }
  }

  const makeLatest = Array.from(publishedGitHubTags).every(
    (candidate) =>
      compareReleaseVersions(version, candidate.slice("npm-v".length)) > 0,
  );

  return { previousTag, makeLatest };
}

export function verifyPublishedRelease(metadata, archive, expected) {
  const version = releaseVersion(metadata);
  if (version !== expected.version) {
    throw new Error("Published npm package must match the release version.");
  }

  assertExpectedGitHead(metadata, expected.gitHead);

  const integrity = metadata["dist.integrity"] ?? metadata.dist?.integrity;
  const expectedIntegrity =
    "sha512-" + createHash("sha512").update(archive).digest("base64");
  if (integrity !== expectedIntegrity) {
    throw new Error(
      "Published npm integrity must match the verified release artifact.",
    );
  }

  const attestations =
    metadata["dist.attestations"] ?? metadata.dist?.attestations;
  if (attestations?.provenance?.predicateType !== provenancePredicate) {
    throw new Error("Published npm package must have SLSA v1 provenance.");
  }

  return {
    version,
    gitHead: expected.gitHead,
    integrity: expectedIntegrity,
    sha256: createHash("sha256").update(archive).digest("hex"),
  };
}

export function verifySignatureAudit(report, archive, expected) {
  if (
    !Array.isArray(report?.invalid) ||
    !Array.isArray(report.missing) ||
    !Array.isArray(report.verified) ||
    report.invalid.length !== 0 ||
    report.missing.length !== 0
  ) {
    throw new Error("npm registry signatures and attestations must verify.");
  }

  const version = releaseVersion({
    name: packageName,
    version: expected.version,
  });
  const verified = report.verified.find(
    (candidate) =>
      candidate?.name === packageName && candidate.version === version,
  );
  if (verified === undefined) {
    throw new Error(
      "The published package must have a cryptographically verified attestation.",
    );
  }

  let registry;
  try {
    registry = new URL(verified.registry).href;
  } catch {
    throw new Error(
      "Verified provenance must come from the public npm registry.",
    );
  }
  if (registry !== publicNpmRegistry) {
    throw new Error(
      "Verified provenance must come from the public npm registry.",
    );
  }

  if (
    verified.attestations?.provenance?.predicateType !== provenancePredicate
  ) {
    throw new Error("The verified npm package must have SLSA v1 provenance.");
  }

  const provenance = verified.attestationBundles?.find(
    (candidate) => candidate?.predicateType === provenancePredicate,
  );
  const encodedStatement = provenance?.bundle?.dsseEnvelope?.payload;
  if (typeof encodedStatement !== "string") {
    throw new Error("The verified SLSA provenance bundle is missing.");
  }

  let statement;
  try {
    statement = JSON.parse(
      Buffer.from(encodedStatement, "base64").toString("utf8"),
    );
  } catch {
    throw new Error("The verified SLSA provenance statement is invalid.");
  }
  if (
    statement?._type !== "https://in-toto.io/Statement/v1" ||
    statement.predicateType !== provenancePredicate
  ) {
    throw new Error("The verified SLSA provenance statement is invalid.");
  }

  const sha512 = createHash("sha512").update(archive).digest("hex");
  const expectedSubject = `pkg:npm/%40openai/codex-security@${version}`;
  if (
    !Array.isArray(statement.subject) ||
    !statement.subject.some(
      (subject) =>
        subject?.name === expectedSubject && subject.digest?.sha512 === sha512,
    )
  ) {
    throw new Error(
      "Verified SLSA provenance must identify the exact published tarball.",
    );
  }

  if (
    typeof expected.repository !== "string" ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/u.test(expected.repository)
  ) {
    throw new Error("Verified provenance requires an exact GitHub repository.");
  }
  const repository = `https://github.com/${expected.repository}`;
  const releaseRef = `refs/tags/npm-v${version}`;
  const build = statement.predicate?.buildDefinition;
  const workflow = build?.externalParameters?.workflow;
  if (
    workflow?.repository !== repository ||
    workflow.ref !== releaseRef ||
    workflow.path !== ".github/workflows/node-release.yml"
  ) {
    throw new Error(
      "Verified SLSA provenance must identify the protected release workflow.",
    );
  }

  const sourceUri = `git+${repository}@${releaseRef}`;
  const source = build.resolvedDependencies?.find(
    (dependency) => dependency?.uri === sourceUri,
  );
  if (source === undefined) {
    throw new Error(
      "Verified SLSA provenance must identify the exact release source.",
    );
  }
  assertExpectedGitHead(
    { gitHead: source.digest?.gitCommit },
    expected.gitHead,
  );

  const runId = String(expected.runId);
  if (!/^[1-9][0-9]*$/u.test(runId)) {
    throw new Error(
      "Verified provenance requires a valid release workflow run.",
    );
  }
  const invocation = statement.predicate?.runDetails?.metadata?.invocationId;
  if (
    typeof invocation !== "string" ||
    !invocation.startsWith(`${repository}/actions/runs/${runId}/attempts/`)
  ) {
    throw new Error(
      "Verified SLSA provenance must identify the successful release run.",
    );
  }

  if (
    statement.predicate?.runDetails?.builder?.id !==
    "https://github.com/actions/runner/github-hosted"
  ) {
    throw new Error(
      "Verified SLSA provenance must use a GitHub-hosted release runner.",
    );
  }

  return {
    version,
    gitHead: expected.gitHead,
    repository: expected.repository,
    runId,
    sha512,
  };
}

export function verifyGitHubRelease(release, archive, expectedTag, assetName) {
  if (release?.tag_name !== expectedTag) {
    throw new Error("Existing GitHub Release must match the release tag.");
  }
  if (release.draft !== false || release.prerelease !== false) {
    throw new Error("Existing GitHub Release must be published and stable.");
  }

  const expectedDigest =
    "sha256:" + createHash("sha256").update(archive).digest("hex");
  const asset = Array.isArray(release.assets)
    ? release.assets.find((candidate) => candidate.name === assetName)
    : undefined;
  if (asset?.digest !== expectedDigest) {
    throw new Error(
      "Existing GitHub Release asset must match the verified npm artifact.",
    );
  }

  return {
    tag: expectedTag,
    asset: assetName,
    digest: expectedDigest,
  };
}

function main() {
  const command = process.argv[2];

  if (command === "version" && process.argv.length === 4) {
    const packageJson = JSON.parse(readFileSync(process.argv[3], "utf8"));
    console.log(releaseVersion(packageJson));
    return;
  }

  if (command === "release-tag" && process.argv.length === 7) {
    const packageJson = JSON.parse(readFileSync(process.argv[6], "utf8"));
    console.log(
      releaseTagVersion(
        process.argv[3],
        process.argv[4],
        process.argv[5],
        packageJson,
      ),
    );
    return;
  }

  if (command === "require-increase" && process.argv.length === 5) {
    console.log(requireReleaseIncrease(process.argv[3], process.argv[4]));
    return;
  }

  if (command === "release-history" && process.argv.length === 4) {
    const registryVersions = JSON.parse(
      process.env.CODEX_SECURITY_PUBLISHED_NPM_VERSIONS ?? "[]",
    );
    const githubReleaseTags = (
      process.env.CODEX_SECURITY_PUBLISHED_GITHUB_TAGS ?? ""
    )
      .split("\n")
      .filter(Boolean);
    const reachableTags = (
      process.env.CODEX_SECURITY_REACHABLE_RELEASE_TAGS ?? ""
    )
      .split("\n")
      .filter(Boolean);
    console.log(
      JSON.stringify(
        releaseHistory(process.argv[3], {
          registryVersions,
          githubReleaseTags,
          reachableTags,
        }),
      ),
    );
    return;
  }

  if (command === "verify-publication" && process.argv.length === 6) {
    const metadata = JSON.parse(readFileSync(0, "utf8"));
    const archive = readFileSync(process.argv[3]);
    const verified = verifyPublishedRelease(metadata, archive, {
      version: process.argv[4],
      gitHead: process.argv[5],
    });
    console.log(JSON.stringify(verified));
    return;
  }

  if (command === "verify-provenance" && process.argv.length === 8) {
    const report = JSON.parse(readFileSync(0, "utf8"));
    const archive = readFileSync(process.argv[3]);
    const verified = verifySignatureAudit(report, archive, {
      version: process.argv[4],
      gitHead: process.argv[5],
      repository: process.argv[6],
      runId: process.argv[7],
    });
    console.log(JSON.stringify(verified));
    return;
  }

  if (command === "verify-github-release" && process.argv.length === 5) {
    const release = JSON.parse(readFileSync(0, "utf8"));
    const archivePath = process.argv[3];
    const archive = readFileSync(archivePath);
    const verified = verifyGitHubRelease(
      release,
      archive,
      process.argv[4],
      basename(archivePath),
    );
    console.log(JSON.stringify(verified));
    return;
  }

  throw new Error(
    "Usage: release-automation.mjs version <package.json>, " +
      "release-tag <ref-type> <ref> <ref-name> <package.json>, " +
      "require-increase <version> <previous-version>, " +
      "release-history <tag>, " +
      "verify-publication <archive> <version> <git-head> " +
      "(package metadata JSON from stdin), " +
      "verify-provenance <archive> <version> <git-head> <repository> <run-id> " +
      "(signature audit JSON from stdin), or " +
      "verify-github-release <archive> <tag> " +
      "(GitHub release JSON from stdin).",
  );
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main();
}
