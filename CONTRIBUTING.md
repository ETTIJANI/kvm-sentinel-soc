# Contributing to KVM-Sentinel-SOC

## Development Setup

1. Fork and clone the repository
2. Install pre-commit hooks: `pre-commit install` (optional)
3. Create a feature branch: `git checkout -b feature/your-feature`

## Commit Message Convention

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `style` | Formatting, no code change |
| `refactor` | Code change, no new feature or fix |
| `perf` | Performance improvement |
| `test` | Adding or fixing tests |
| `chore` | Build process, tooling, dependencies |

### Scopes

| Scope | Area |
|---|---|
| `deploy` | deploy-lab.sh |
| `cloud-init` | Cloud-init templates |
| `honeypot` | vm1-honeypot stack |
| `soc` | vm2-soc stack |
| `agent` | Python agents |
| `controller` | Host controller |
| `nixos` | NixOS configuration |
| `docs` | Documentation |

### Examples

```
feat(deploy): add readiness beacon on port 9999
fix(promtail): remove invalid target_config field
docs(readme): restructure for onboarding
chore(git): add .gitignore for NixOS artifacts
```

## Pull Request Process

1. Update documentation for any changed behavior
2. Add tests for new functionality where applicable
3. Ensure all scripts pass `bash -n`
4. Ensure all Python passes `py_compile`
5. Ensure compose files pass `docker compose config -q`
6. Request review from at least one maintainer

## Code Standards

- Shell scripts: `bash -n` must pass, use `set -euo pipefail`
- Python: type hints on all functions, no `as any` or `@ts-ignore` equivalents
- YAML: validate with `yamllint` or `docker compose config`
- Markdown: wrap at 100 characters, use fenced code blocks with language tags
