import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { pathToFileURL } from "node:url";
import { assertExpectedGitHead } from "./package-provenance.mjs";

const packageName = "@openai/codex-security";
const stableVersion = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u;
const provenancePredicate = "https://slsa.dev/provenance/v1";

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
      "verify-publication <archive> <version> <git-head>, or " +
      "verify-github-release <archive> <tag>.",
  );
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  main();
}
