# Codex Security

`@openai/codex-security` is a CLI and TypeScript SDK for finding, validating, and fixing security vulnerabilities in your code. Scan repositories, review changes, track findings over time, and run security checks in CI.

**[Documentation](http://learn.chatgpt.com/docs/security/cli)**

## Quick start

Requires Node.js 22 or later, Python 3.10 or later, and access to Codex Security.

```bash
npm install @openai/codex-security
npx codex-security login
npx codex-security scan .
```

For CI, set `OPENAI_API_KEY` instead of signing in.

If both a ChatGPT sign-in and an API key are available, interactive scans ask
which credential to use. CI and other noninteractive scans keep the existing
API-key precedence. Select a credential explicitly when needed:

```bash
npx codex-security scan . --auth chatgpt
npx codex-security scan . --auth api-key
```

To make your ChatGPT sign-in the automatic default, unset any configured API
keys:

```bash
unset OPENAI_API_KEY CODEX_API_KEY
```

Scan history is stored in the Codex Security workbench state directory. If that
directory cannot be written, set `CODEX_SECURITY_STATE_DIR` to a writable
directory outside the repository.

## TypeScript SDK

```ts
import { CodexSecurity } from "@openai/codex-security";

const security = new CodexSecurity();
const result = await security.run(".");

console.log(result.reportPath);
await security.close();
```

## Containerized bulk scans

Create `repositories.csv` with one full, immutable Git commit per repository:

```csv
id,repository,revision
payments,https://github.com/example/payments.git,0123456789abcdef0123456789abcdef01234567
```

Once the approved image has been published, prepare private results and
authentication directories, sign in, and run the supplied Docker Compose
configuration:

```bash
mkdir -p results state
chmod 700 results state
export CODEX_SECURITY_USER="$(id -u):$(id -g)"
export CODEX_SECURITY_IMAGE=ghcr.io/openai/codex-security:0.1.1
docker compose pull codex-security
docker compose run --rm codex-security login --device-auth
docker compose run --rm codex-security
```

Reports and resumable scan results are written to `results/`; the reusable
device login remains in `state/`. For unattended scans, set `OPENAI_API_KEY`
or `CODEX_API_KEY` instead. Set `GH_TOKEN` or `GITHUB_TOKEN` for private
GitHub repositories.

On Ubuntu hosts that restrict unprivileged user namespaces, an administrator
can install the optional, narrowly scoped AppArmor profile once:

```bash
sudo install -m 0644 docker/codex-security.apparmor /etc/apparmor.d/codex-security-container
sudo apparmor_parser -r -W /etc/apparmor.d/codex-security-container
docker compose -f compose.yaml -f compose.apparmor.yaml run --rm codex-security
```

The override preserves the nonroot user, dropped capabilities, no-new-privileges,
and hardened seccomp policy. Other Docker hosts do not need the profile or
override.

For installation, authentication, scan options, and CI setup, see the [official documentation](http://learn.chatgpt.com/docs/security/cli).
