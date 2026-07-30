# Contributing

Thanks for helping improve Codex Security. We welcome bug reports, feature
requests, documentation corrections, and feedback from open-source
maintainers.

See the
[Codex Security documentation](https://developers.openai.com/codex/security)
for setup and the
[`@openai/codex-security` npm package](https://www.npmjs.com/package/@openai/codex-security)
for releases.

## How this repository works

Codex Security is developed in OpenAI's canonical repository and published
here through a one-way mirror. We can't import pull requests from this
repository into the canonical source.

Start by searching
[existing issues](https://github.com/openai/codex-security/issues). If you
don't find a match, open an issue that explains what you want to change and
why. Maintainers review issues as time allows and can carry accepted changes
into the canonical source.

For changes maintained only in this public repository, a maintainer may
invite a focused pull request. Please start with an issue so we can confirm
the change belongs here.

## Support for open-source projects

If you maintain an open-source project, we want to hear where Codex Security
can help. We'll try to support your project as our time and capacity allow.

[Open an issue](https://github.com/openai/codex-security/issues/new) and tell
us:

- The repository and your role in the project.
- What you are trying to do.
- Your CLI or SDK version and operating system.
- What happened, what you expected, and how to reproduce it safely.
- A small example or redacted logs, if they help.

Support is best effort. We can't promise product access, free usage, a
response by a particular date, a completed scan, or a fix. Scan only
repositories you trust and either own or have explicit permission to assess.

## Report a bug

Check existing issues first. Include your CLI or SDK version, operating
system, steps to reproduce the problem, and what you expected to happen.

Before posting, remove API keys, access tokens, private code, customer data,
and security findings.

## Suggest a feature or improve the documentation

Open an issue that describes the problem and the workflow you want to
support. Documentation corrections and small, safe examples are welcome.
Maintainers can carry accepted changes into the canonical source.

## Report a security issue

Do not post vulnerabilities, exploit details, credentials, or sensitive scan
results in public issues or pull requests. Report security issues in Codex
Security privately as described in [SECURITY.md](SECURITY.md).

If a scan finds a vulnerability in another project, report it to that
project's maintainers through their security policy.

## Community expectations

Be respectful and give other contributors the context they need. Do not
share material you do not have permission to disclose.

## Dependency and release maintenance

Maintainers update package dependencies and the committed lockfile in the
canonical repository. The public release workflow installs that locked
dependency graph, tests the package, and publishes a verified artifact with
npm provenance. GitHub Actions dependencies are maintained separately in this
repository.
