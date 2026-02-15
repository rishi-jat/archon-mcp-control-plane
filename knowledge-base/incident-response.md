# ARCHON Incident Response Procedures

> Knowledge base document for Archestra's Knowledge Graph (GraphRAG).
> Defines standard procedures the orchestrator follows when a risk threshold is breached.

---

## 1. Incident Classification

### 1.1 Severity Levels

| Level | Definition | Examples |
|-------|-----------|----------|
| **SEV-1 (Critical)** | Active exploitation or imminent breach risk | Leaked production API key in public repo, CRITICAL RCE CVE in deployed dependency |
| **SEV-2 (High)** | Significant vulnerability requiring prompt action | HIGH CVEs with known PoC, suspicious commit patterns on auth code |
| **SEV-3 (Medium)** | Moderate risk with no evidence of exploitation | MEDIUM CVEs, stale PRs on sensitive files, health score degradation |
| **SEV-4 (Low)** | Minor issues, informational findings | LOW CVEs, minor policy violations, improvement suggestions |

### 1.2 Classification Rules

When multiple signals are present, use the **highest applicable severity** with these escalation multipliers:

- **Compounding signals**: If ≥ 2 independent signals point to the same risk area, escalate by one level
- **Velocity**: If findings increased by > 50% since last assessment, escalate by one level
- **Public exposure**: If the repository is public AND the finding involves credentials, always classify as SEV-1

## 2. Response Procedures

### 2.1 SEV-1 Response

**Time to respond: < 1 hour**

```
┌──────────────────────────────────────────┐
│  1. Create CRITICAL security issue       │
│  2. Generate full security report        │
│  3. Log incident in action audit         │
│  4. Generate operational report          │
│  5. If secret exposure:                  │
│     - Note affected service in issue     │
│     - List rotation steps               │
│     - Flag all PRs touching same files  │
└──────────────────────────────────────────┘
```

**ARCHON Actions:**
1. Call `create_security_issue` with severity=critical
2. Call `generate_security_report` with all findings
3. Call `generate_operational_report` for full context
4. Call `log_action` for each action taken

### 2.2 SEV-2 Response

**Time to respond: < 4 hours**

```
┌──────────────────────────────────────────┐
│  1. Create incident tracking issue       │
│  2. Generate security report             │
│  3. Log incident in action audit         │
│  4. If ambiguous: delegate to            │
│     analysis sub-agent for assessment    │
└──────────────────────────────────────────┘
```

**ARCHON Actions:**
1. Call `create_incident_issue` with severity=high
2. Call `generate_security_report` if CVEs are involved
3. Call `log_action` for each action
4. If uncertainty > 30%: delegate to `agent__analysis` via A2A

### 2.3 SEV-3 Response

**Time to respond: < 24 hours**

```
┌──────────────────────────────────────────┐
│  1. Generate operational report          │
│  2. Log findings in action audit         │
│  3. Note recommendations for next cycle  │
└──────────────────────────────────────────┘
```

**ARCHON Actions:**
1. Call `generate_operational_report` with all signal data
2. Call `log_action` with severity=warning

### 2.4 SEV-4 Response

**Time to respond: < 1 week**

```
┌──────────────────────────────────────────┐
│  1. Log findings in action audit         │
│  2. Include in next scheduled report     │
└──────────────────────────────────────────┘
```

**ARCHON Actions:**
1. Call `log_action` with severity=info

## 3. Escalation Procedures

### 3.1 When to Escalate

| Trigger | Action |
|---------|--------|
| SEV-1 finding confirmed | Immediate — create issue and report |
| SEV-2 finding unresolved for > 72 hours | Escalate to SEV-1 |
| ≥ 5 SEV-3 findings in single assessment | Escalate to SEV-2 |
| Health score drops below 25 (Grade F) | Escalate to SEV-2 |
| Same CVE found in > 3 repositories | Organizational escalation — flag as systemic |

### 3.2 Delegation to Analysis Sub-Agent

Use A2A delegation to `agent__analysis` when:

1. **Conflicting signals**: Commit patterns look suspicious but security scan is clean
2. **Borderline severity**: Findings hover between two severity levels
3. **Complex dependency chains**: Transitive vulnerability where direct dep is unaffected
4. **Ecosystem expertise needed**: Language-specific risk assessment (e.g., npm supply-chain)

**Delegation format:**
```json
{
  "question": "Specific question for the analysis agent",
  "repository": "owner/repo",
  "signals": {
    "commit_analysis": { ... },
    "pr_analysis": { ... },
    "health_score": { ... },
    "dependency_scan": { ... },
    "secret_scan": { ... }
  }
}
```

## 4. Post-Incident Review

After a SEV-1 or SEV-2 incident is resolved:

### 4.1 Data to Collect
- Timeline of detection to resolution
- Which signals triggered the alert
- False positive rate for this type of finding
- Whether the analysis sub-agent was used and its accuracy

### 4.2 Playbook Updates
- If a new pattern was identified, add it to the security playbook
- If a false positive pattern was confirmed, add it to the exclusion list
- If response time SLA was missed, investigate root cause

## 5. Communication Templates

### 5.1 Security Issue Body Template
```markdown
## 🛡️ Security Finding — {SEVERITY}

**Detected by:** ARCHON automated security scan
**Severity:** {CRITICAL|HIGH|MEDIUM|LOW}
**CVE(s):** {list or N/A}

### Finding Details
{detailed description}

### Affected Components
- {component 1}
- {component 2}

### Recommended Actions
1. {action 1}
2. {action 2}

### References
- {link 1}
- {link 2}

---
*This issue was automatically created by ARCHON. Review and prioritize accordingly.*
```

### 5.2 Incident Issue Body Template
```markdown
## 🚨 Operational Incident — {SEVERITY}

**Detected by:** ARCHON pattern analysis
**Severity:** {CRITICAL|HIGH|MEDIUM|LOW}
**Detection Time:** {ISO 8601 timestamp}

### Incident Summary
{summary paragraph}

### Affected Components
- {component 1}
- {component 2}

### Evidence
{supporting signal data}

### Required Actions
- [ ] {action 1}
- [ ] {action 2}
- [ ] {action 3}

### Timeline
| Time | Event |
|------|-------|
| {T+0} | Anomaly detected by ARCHON |
| {T+?} | Response initiated |

---
*This issue was automatically created by ARCHON. Track resolution using the checkboxes above.*
```

## 6. Continuous Improvement

ARCHON should track these metrics over time:

| Metric | Target | Purpose |
|--------|--------|---------|
| Mean Time to Detect (MTTD) | < 5 minutes | How fast signals are processed |
| Mean Time to Alert (MTTA) | < 10 minutes | How fast issues/reports are created |
| False Positive Rate | < 20% | Accuracy of detection |
| Signal Correlation Accuracy | > 80% | Quality of cross-signal analysis |
| Delegation Accuracy | > 85% | How often sub-agent classification matches final outcome |

---

*This procedure document is maintained as part of the ARCHON knowledge base and is loaded into Archestra's Knowledge Graph for context-aware incident response.*
