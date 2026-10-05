# SentinelAudit

**SentinelAudit is an autonomous AI security engineer that continuously learns about emerging threats and safely hardens an isolated codebase.**

It separates threat intelligence from the protected source code into three security domains:

```text
Internet
   │
   ▼
┌──────────────────────┐
│ ONLINE               │
│ Threat Intelligence  │
│ Gemma + live sources │
└──────────┬───────────┘
           │ one-way
           ▼
┌──────────────────────┐
│ GUARD                │
│ Validate + sanitize  │
│ enforce boundary     │
└──────────┬───────────┘
           │ one-way
           ▼
┌──────────────────────┐
│ OFFLINE              │
│ Local Gemma          │
│ Codebase + tools     │
└──────────────────────┘
```

## How it works

1. **Online** monitors live security intelligence such as NVD/CVE, OSV, GitHub Advisories, CISA KEV, EPSS, security research and selected web/social sources.
2. Online Gemma correlates new threats and produces a **signed Threat Intelligence Package**.
3. **Guard** validates the package, checks its schema/integrity, and blocks injection or unexpected payloads.
4. **Offline** Gemma receives only validated intelligence and investigates the protected Python repository.
5. The Offline agent reproduces the issue, patches the code, runs tests/security checks, and re-audits the repository.
6. A successful fix is committed; failed attempts are rolled back.

## Why SentinelAudit?

Traditional scanners usually report vulnerabilities. SentinelAudit is designed to **discover, reproduce, fix, validate and continuously adapt** to new threats while keeping the protected codebase isolated from the internet.

### MVP

- **Target:** Python repositories
- **Online AI:** Gemma with internet access and current threat intelligence
- **Offline AI:** local Gemma runtime on the isolated machine
- **Guard:** software-enforced one-way transfer for the prototype
- **Autonomy:** automatic patch → test → re-audit → commit/rollback
- **Demo:** deliberately vulnerable Python application

> The prototype uses software-enforced one-way isolation. A production deployment can replace this with a physically enforced data diode and a genuinely air-gapped offline environment.

## Example flow

```text
New vulnerability discovered
        ↓
Online Gemma understands the attack
        ↓
Threat Intelligence Package
        ↓
Guard validates / rejects malicious content
        ↓
Offline Gemma checks the codebase
        ↓
Exploit reproduction
        ↓
Patch generation + application
        ↓
Tests + security checks
        ↓
Re-audit
        ↓
PASS → commit    FAIL → rollback
```

## Repository structure

```text
sentinelaudit/
├── online/          # Threat intelligence + Online Gemma agent
├── guard/           # One-way boundary and package validation
├── offline/         # Local Gemma agent + code modification
├── demo-target/     # Deliberately vulnerable Python application
├── shared/          # Schemas, signing, common utilities
├── tests/           # Unit, integration and security tests
└── README.md
```

## Team

| Member | Responsibility |
|---|---|
| **Sidak** | Online threat detection and intelligence pipeline |
| **Lavanya** | Guard and security boundary |
| **Ojas** | Offline AI/repository agent |
| **Himalaya** | Offline sandbox, testing and validation |

## Open Source

SentinelAudit is released under the **MIT License**.

