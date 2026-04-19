# routines-hub Roadmap

Tracking the path to **SonarQube + Snyk parity** across code quality, dependency health, and database quality — executed as Linear-native auto-routines.

## Current state (2026-04-19)

17 detectors + 1 groomer shipped. Tier A covered: every detector produces **skill-grade Linear issues** (Rating A–E, Clean Code attribute mapping, per-severity breakdown, top offenders table, remediation playbook with code, historical trend delta, effort estimate in SQALE-style hours, references).

| Detector | Signature | Cadence | Quality Dimension | Clean Code Attribute |
|---|---|---|---|---|
| W2 ci-red | `[ci-red:<repo>]` | near-real-time | Reliability | Responsible |
| W5 npm-audit | `[cve:<id>]` | daily | Security | Responsible |
| W6 semgrep | `[semgrep:<repo>]` | daily | Security | Responsible |
| W7 dead-code | `[dead-code:<repo>]` | daily | Maintainability | Adaptable (Focused) |
| W8 code-health | `[code-health:<repo>]` | daily | Maintainability | Adaptable (Modular) |
| W9 duplication | `[dupes:<repo>]` | daily | Maintainability | Adaptable (Distinct) |
| W10 outdated-majors | `[deps:majors:<repo>]` | daily | Maintainability | Responsible |
| W11 verify-gap | `[verify-gap:<parent>]` | daily | Reliability | Intentional (Complete) |
| W12 discipline | `[discipline:<repo>]` | daily | Maintainability | Consistent |
| W13 secrets-history | `[secrets-history:<repo>]` | daily | Security | Responsible |
| W14 stale-branches | `[stale-branches:<repo>]` | daily | Maintainability | Consistent |
| W15 stale-prs | `[stale-prs:<repo>]` | daily | Maintainability | Intentional (Complete) |
| W20 deploy-drift | `[deploy-drift:<repo>]` | daily | Reliability | Responsible |
| W21 agent-zombies | `[agent-zombies]` | daily | Maintainability | Intentional (Complete) |
| W22 icloud-dupes | `[icloud-dupes:<repo>]` | daily | Maintainability | Consistent |
| W23 complexity | `[complexity:<repo>]` | weekly (Mon) | Maintainability | Intentional + Adaptable |
| W26 license-compliance | `[license:<repo>]` | weekly (Mon) | — | Responsible (Lawful) |
| W27 malicious-packages | `[malicious-packages:<repo>]` | daily | Security | Responsible (Trustworthy) |

All signatures have matching `gonePolicy` heartbeat rules in `scripts/groomers/linear-scrub.mjs` (3d default) so issues auto-close when the underlying signal clears.

## What's still missing vs SonarQube + Snyk

### Tier B — Enrichment of existing detectors

- **W5 npm-audit: CVSS / EPSS / CISA KEV enrichment.** Current output shows CVE count only. Upgrade to show per-CVE CVSS v3 score, EPSS probability (prob of exploitation within 30d), and CISA KEV (Known Exploited Vulnerabilities) flag. Changes `onNew` description only; no new scan tool.
- **W6 semgrep: CWE/OWASP mapping + Security Hotspot vs Vulnerability split.** SonarQube distinguishes "definite vulnerability" from "needs human review" (hotspot). Semgrep rule metadata already has CWE/OWASP tags — surface them in the issue table and split findings into two tables (Vulnerabilities / Hotspots).
- **Tier D depth upgrade:** every pre-W20 detector's `onNew` description is a simple table. Lift all 12 to the skill-grade template used by W20–W27 (8 mandatory sections, Clean Code attribute mapping, Rating A–E, SQALE effort estimate).

### Tier C — Database quality (zero-to-one)

No existing detector touches Postgres. Biggest single gap. Each new detector needs DB access in CI — simplest path: Azure Database for PostgreSQL + managed-identity OIDC federation from GitHub Actions, or short-lived connection string secret per-repo.

- **W28 db-schema-quality** — queries `pg_class`, `pg_indexes`, `pg_stat_user_tables`, `information_schema.table_constraints`, `pg_policy`. Detects: tables without PK, RLS gaps on HIPAA-flagged schemas, missing indexes on FK columns, duplicate/redundant indexes, dead-tuple ratio needing VACUUM, unused indexes (`idx_scan = 0`), large unpartitioned tables, missing NOT NULL on semantically-required columns, bloat estimation. One rolling issue per database. Maps to **Reliability + Maintainability**, Clean Code attribute **Adaptable (Tested, Modular)**.
- **W29 db-query-performance** — reads `pg_stat_statements` for top-20 slowest queries by mean exec time. Flags any with mean > 500ms. Runs `EXPLAIN (FORMAT JSON)` on each and analyzes for missing indexes, sequential scans on large tables, nested-loop bombs. Maps to **Reliability**, Clean Code **Intentional (Efficient)**.
- **W30 db-migration-safety** — on every PR that touches `migrations/` or `drizzle/`, static-analyze the migration files for risky patterns: `DROP COLUMN` (data loss), `ALTER COLUMN TYPE` with non-trivial cast (data coercion risk), `CREATE INDEX` without `CONCURRENTLY` (table-lock), missing transaction wrapping on multi-statement migrations, backward-incompatible schema changes without feature-flag guard. This one is **PR-scoped**, not daily — fires as a GitHub Action check on PR open/update. Maps to **Reliability + Security**, Clean Code **Responsible (Lawful for HIPAA retention compliance)**.

### Tier E — Quality Gate (PR-blocking)

A composite action `.github/actions/routines-quality-gate/` that runs on every PR to the fleet and fails the check when:

- New code introduces any **Bug** or **Vulnerability** (runs W6 semgrep on diff only)
- New code test coverage **< 80%** (requires Tier F-1 coverage detector to exist first)
- New code duplication **> 3%** (runs W9 jscpd on diff only)
- Repo-wide **Security rating** no longer A (W5 + W6 + W13 + W27 composite)
- Repo-wide **Reliability rating** drops below C (W2 + W8 composite)

Based on [SonarQube's Sonar way for AI Code](https://docs.sonarsource.com/sonarqube-cloud/ai-features/). Uses the same skill-grade output rendered as a PR comment + check-run annotation.

### Tier F — `/audit` skill deep rewrite

The existing `~/.claude/skills/audit/` skill today runs Tier 2 audit (functional/security/quality/supply-chain/compliance) mostly via direct tool calls. Rewrite it to:

1. Pull **every current Linear issue** for the repo under the Ops team (query by `project IN (Security Hygiene, Prod Health, Code Health, Dependencies)` and `gitBranchName LIKE '%<repo>%'`)
2. Call the **existing detectors** directly via `node scripts/detectors/<name>.mjs` locally (no GH Actions round-trip)
3. Synthesize a **single comprehensive audit report** grouped by:
   - Executive Summary (ratings per Clean Code attribute, pass/fail quality gate verdict)
   - Security (W5 + W6 + W13 + W27 — all CVE/semgrep/secrets/malware findings merged)
   - Reliability (W2 + W8 + W29 — CI state + file-size + slow queries)
   - Maintainability (W7 + W9 + W12 + W23 — dead code + dupes + discipline + complexity)
   - Responsibility (W26 license + compliance labels)
4. Emit a **rich Markdown report** plus a PR-ready summary comment. Henry can invoke `/audit <repo>` and get a single skill-grade document.

This is what the user meant by *"it's running a full on skill for the audits"* — each individual detector is the daily/automatic version; the skill is the on-demand deep-dive synthesis.

### Tier G — Coverage detector (unlocks Tier E quality gate)

- **W31 test-coverage** — runs each repo's test suite with coverage enabled (`vitest --coverage`, `jest --coverage`, `pytest --cov`), parses lcov/cobertura output, computes per-file and new-code coverage. Flags files <50% overall and new files with 0%. Target thresholds: 80% overall, 95% on new code per Sonar way for AI. Maps to **Reliability**, Clean Code **Adaptable (Tested)**.

Runs per-repo in a weekly matrix (coverage runs are slow — daily would bill too many CI minutes).

## Dependency graph for next builds

```
  Tier A (shipped) ──────────────────────────────┐
                                                 │
  Tier B enrichment (onNew rewrites) ────────────┤
                                                 ▼
  Tier D depth upgrade (older detectors) ──►  Tier E quality gate
                                                 ▲
  Tier G coverage ─────────────────────────────┘ ▲
                                                   │
  Tier C database (W28/W29) ────► Tier C-PR (W30) ─┘
                                                   │
  Tier F /audit skill rewrite  ◄─ needs Tier B + D done
```

Suggested order: **Tier B** (fastest wins, no new tools), then **Tier G** (unlocks quality gate), then **Tier C** (biggest net-new value), then **Tier E** + **Tier F** + **Tier D** in parallel.

## Output depth contract (mandatory for every detector)

Every `onNew` issue description must contain these 8 sections in order:

1. **Header metadata** (repo, scan date, tool version, file/package/function count)
2. **Quality Rating** table with per-dimension A–E rating, violation count, trend column
3. **Findings by Severity** (Blocker / High / Medium / Low / Info with counts + rule description)
4. **Top N Offenders** (specific file:line or package@version with severity + Clean Code attribute per row)
5. **Findings by Software Quality** (which of Security / Reliability / Maintainability is primary + secondary)
6. **Remediation Playbook** (per-category fix recipes with before/after code snippets, per-fix effort estimate in minutes)
7. **Historical Trend** (first scan OR delta from prior run via embedded `<!-- routines-hub:<kind>:metrics JSON -->` block)
8. **References** (canonical docs: SonarQube rule page, OWASP/CWE ID, Snyk advisory, vendor docs)

Plus a footer with signature, cadence, and G1 auto-close TTL.

`onMatch` heartbeat must render delta ("was N, now M, Δ±K") when prior metrics parseable, plain count otherwise. Never hard-fails.

## Shared output helpers wanted

Several detectors now independently implement: severity-ladder scoring, rating A-E computation, prior-metrics comment parsing, table rendering. Candidate for a shared `lib/skill-grade.mjs` helper — defer until 3+ more Tier B/D detectors written (premature abstraction risk before then).

## References

- [SonarQube Clean Code definition](https://docs.sonarsource.com/sonarqube-server/latest/core-concepts/clean-code/definition/)
- [SonarQube Quality Gates](https://docs.sonarsource.com/sonarqube-server/quality-standards-administration/managing-quality-gates/introduction-to-quality-gates)
- [SonarQube code metrics](https://docs.sonarsource.com/sonarqube-server/latest/user-guide/code-metrics/metrics-definition/)
- [Snyk OSS license policy](https://docs.snyk.io/scan-with-snyk/snyk-open-source/licenses)
- [OSV Schema](https://ossf.github.io/osv-schema/)
- [SQALE method](https://en.wikipedia.org/wiki/SQALE) — technical debt estimation basis for effort-hours.
