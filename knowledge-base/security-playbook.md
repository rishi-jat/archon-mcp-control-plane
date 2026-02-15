# ARCHON Security Playbook

> Knowledge base document for Archestra's Knowledge Graph (GraphRAG).
> Provides security policy rules used by the orchestrator during risk correlation and decision-making.

---

## 1. Vulnerability Response SLAs

| Severity | Response Time | Resolution Time | Escalation |
|----------|--------------|-----------------|------------|
| **CRITICAL** | 1 hour | 24 hours | Immediate — page on-call engineer |
| **HIGH** | 4 hours | 72 hours | Notify security team lead |
| **MEDIUM** | 24 hours | 2 weeks | Add to sprint backlog |
| **LOW** | 1 week | Next release cycle | Track in issue |

## 2. Dependency Vulnerability Policies

### 2.1 Automatic Blocking
The following conditions should **block deployment** and trigger an immediate security issue:

- Any dependency with a CVSS score ≥ 9.0
- Any dependency with a known active exploit (CISA KEV catalog)
- Any dependency that is abandoned (no release in > 2 years) AND has a known CVE

### 2.2 Upgrade Guidance
- **Pin versions** in production manifests (`==` for pip, exact version for npm).
- **Use lock files** always (`package-lock.json`, `Pipfile.lock`, `go.sum`).
- **Automated checks**: Run dependency scans on every PR and on a weekly schedule.
- **Transitive dependencies**: If a transitive dependency has a CRITICAL CVE and the direct dependency hasn't patched it within 7 days, consider switching to an alternative.

### 2.3 Ecosystem-Specific Rules

#### Python / pip
- Prefer `pip-audit` for local scanning.
- Check `safety-db` for additional coverage beyond NVD.
- Pin all transitive deps using `pip-compile`.

#### Node.js / npm
- Run `npm audit` on every CI build.
- Use `--audit-level=high` to fail builds on HIGH+ findings.
- Be wary of packages with < 100 weekly downloads or < 1 year of history.

#### Go
- Use `govulncheck` for targeted vulnerability detection.
- Go's module system reduces typosquatting risk, but verify module paths.

#### Rust / Cargo
- Use `cargo-audit` for vulnerability checking.
- Rust's safety guarantees reduce memory corruption risk but don't eliminate logic bugs.

## 3. Secret Exposure Policies

### 3.1 Confirmed Secret Exposure
When a real credential is found in source code:

1. **Immediately rotate** the credential.
2. **Create a CRITICAL security issue** with the ARCHON actions server.
3. **Audit access logs** for the exposed credential's service.
4. **Check git history** — the credential may exist in older commits even if removed from HEAD.
5. **Consider BFG Repo-Cleaner** or `git filter-branch` to purge from history if the repo is public.

### 3.2 False Positive Handling
Common false positives from secret scanners:

- Test fixtures with dummy API keys (e.g., `sk_test_...`)
- Example configuration files with placeholder values
- Documentation showing credential formats
- Base64-encoded non-secret data that triggers high entropy detection

**Policy:** If a finding is in a path matching `test/`, `spec/`, `fixtures/`, `examples/`, `docs/`, or the filename contains `example`, `sample`, or `template`, downgrade its severity by one level.

### 3.3 Prevention
- Use `.gitignore` to prevent committing `.env`, `*.pem`, `*.key` files.
- Use pre-commit hooks (e.g., `detect-secrets`, `trufflehog`) to catch secrets before they enter the repo.
- Store secrets in a vault (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault) and reference them by name — never by value.

## 4. Commit Pattern Risk Rules

### 4.1 High-Risk Commit Patterns
| Pattern | Risk Signal |
|---------|-------------|
| Large commit (>500 lines) touching infrastructure files | Configuration takeover risk |
| Off-hours commit (midnight–6am author local time) to sensitive files | Possible compromised account |
| Commit with message "fix" or "update" touching auth/security code | Backdoor insertion risk |
| Revert of a security patch | Regression of a known fix |
| First-time contributor modifying CI/CD pipeline | Supply-chain injection risk |

### 4.2 Mitigation
- Require code review for ALL commits touching: `Dockerfile`, `*.yml` (CI), `*.tf`, `*.env`, auth modules.
- Enable branch protection on `main`/`master` with required reviews.
- Use signed commits for infrastructure changes.

## 5. PR Review Policies

### 5.1 Mandatory Review
PRs touching the following MUST have at least 1 approving review:

- Any file in `.github/workflows/`
- Any Dockerfile or docker-compose file
- Any Terraform/Kubernetes manifest
- Any file containing "auth", "security", "token", "secret", "password" in its path

### 5.2 Stale PR Policy
- PRs open > 7 days without review: Flag as **MEDIUM** risk.
- PRs open > 14 days: Flag as **HIGH** risk — likely indicates process breakdown.
- PRs open > 30 days: Recommend closing and re-opening when ready.

### 5.3 Size Limits
- PRs > 500 lines changed: Recommend splitting.
- PRs > 1500 lines changed: Flag as **HIGH** risk — review quality degrades with size.

## 6. Repository Health Standards

### 6.1 Minimum Requirements
Every production repository MUST have:

- [ ] README with setup instructions
- [ ] LICENSE file
- [ ] CI/CD pipeline (GitHub Actions, GitLab CI, Jenkins, etc.)
- [ ] Dependency manifest with lock file
- [ ] SECURITY.md or security policy
- [ ] CODEOWNERS file for sensitive paths
- [ ] Branch protection on default branch

### 6.2 Health Score Thresholds

| Grade | Score Range | Action |
|-------|------------|--------|
| A | 90-100 | No action needed |
| B | 75-89 | Monitor, address recommendations when convenient |
| C | 50-74 | Create improvement issue, block new feature work until addressed |
| D | 25-49 | Escalate to engineering leadership |
| F | 0-24 | Consider repository archival or major remediation sprint |

---

*This playbook is maintained as part of the ARCHON knowledge base and is loaded into Archestra's Knowledge Graph for RAG-powered decision support.*
