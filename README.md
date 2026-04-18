# routines-hub

Linear-native routine automation for WakeWell / 5D Smiles.

**One rule:** Linear is the source of truth. Detectors write signals to the `Ops` team; groomers keep it clean. No separate dashboard. No parallel ticketing. Open Linear → switch view → see what needs attention.

---

## The Loop

```
Detectors (cron + event)  →  Linear Ops team  →  /queue (pick)  →  /ship (close)
                              ↑
                       Groomers (daily)
```

- **Detectors** find signals (CI red, CVE, failed deploy, stale verification) and create Linear issues.
- **Groomers** close issues when signals resolve, dedup, flag stale.
- **Initiators** (`/queue`, `/start-task`) pick highest-priority work across all teams.

---

## Linear Ops Team

Team key: **OPS**. 1-week cycles enabled.

| Project | ID | What lives here |
|---|---|---|
| **Security Hygiene** | `4c076596…` | CVEs, Semgrep findings, secret rotations |
| **Prod Health** | `2c019878…` | Sentry errors, CI-red, failed deploys, smoke test fails |
| **Linear Ground Truth** | `dd7bfb4d…` | Verification gaps from existing projects |
| **Code Health** | `02b00026…` | Dead code, file-size creep, god-node growth |
| **Dependencies** | `8586da5c…` | Outdated majors, Dependabot batches |

Labels: `routine`, `cve`, `verify-gap`, `bug-prod`, `ci-red`, `compliance`, `auto-close`, `evidence-gap`.

Full ID config: [`config/linear.json`](config/linear.json).

---

## Detectors (writers)

| ID | Name | Trigger | Writes to | Signature prefix |
|---|---|---|---|---|
| W2 | CI-red-on-main | `workflow_run: failure` on main | Prod Health | `[ci-red:<repo>]` |
| W5 | npm audit | daily cron 14:00 UTC | Security Hygiene | `[cve:<id>:<repo>]` |

### Coming next (scaffolded but not yet enabled)

| ID | Name | Trigger | Writes to |
|---|---|---|---|
| W1 | Sentry new error class | webhook | Prod Health |
| W3 | Nightly smoke test | cron 02:00 UTC | Prod Health |
| W4 | Azure App Insights exceptions | daily query | Prod Health |
| W6 | Semgrep HIPAA/secrets | PR gate + weekly full scan | Security Hygiene |
| W7 | Expiring secrets (60d/30d/14d) | weekly | Security Hygiene |
| W8 | Code health weekly scan | Fri 18:00 UTC | Code Health |
| W9 | Failed deploy | Azure Monitor alert | Prod Health |
| W10 | Outdated majors monthly | 1st of month | Dependencies |
| W11 | Linear Ground Truth Verifier | Sun 22:00 UTC | Linear Ground Truth |

---

## Groomers

| ID | Name | Schedule | Does |
|---|---|---|---|
| G1 | Daily Linear Scrub | 13:00 UTC | (1) auto-close issues whose PR merged, (2) comment on "In Progress" >14d, (3) dedup by signature |

---

## Signature-based dedup

Every auto-created issue has a title prefix like `[kind:identifier]`:

- `[ci-red:sleep_test_scheduler]` — one at a time per repo
- `[cve:GHSA-abc-123:sleep_test_scheduler]` — per-CVE per-repo
- `[verify-gap:WAK-123]` — per parent Linear issue

When a detector fires, it searches for an open issue with that prefix. If found → posts comment. If not → creates. When the signal resolves, the groomer closes it.

This prevents issue-pollution and keeps Linear readable.

---

## Setup

### 1. GitHub secrets (repo: `Wakewell-Sleep-Solutions/routines-hub`)

- `LINEAR_API_KEY` — Linear personal API key with write access to Ops team
- `REPO_READ_TOKEN` — PAT with `repo` scope (for cross-repo checkout in detector-npm-audit)

### 2. Enable detector in target repos

For each repo (sleep_test_scheduler, WakewellWeb, etc.):

1. Copy [`examples/caller-ci-red.yml`](examples/caller-ci-red.yml) to `.github/workflows/routines-ci-red.yml`
2. Edit the `workflows: [...]` list to match the repo's actual CI workflow names
3. Add `LINEAR_API_KEY` to that repo's secrets (or use org-level secret)

### 3. Local testing

```bash
# Smoke test the helper library
infisical run --env=dev --path=/shared -- node scripts/lib/linear.mjs --test

# Dry-run the groomer against real Linear (will post comments)
infisical run --env=dev --path=/shared -- node scripts/groomers/linear-scrub.mjs
```

---

## Why this architecture

**Linear absorbs everything — no duplicate dashboard.** Linear already has:
- Cycles for cadence
- Priorities for triage
- Labels for routing
- Saved views for Monday-morning surface
- Mobile access
- API for writes
- `/queue` + `/start-task` for initiation

Building an Obsidian dashboard on top would duplicate all of it. This hub keeps concerns separate: Linear = queue, code = truth, routines = glue.

**Ops team insulates product teams.** WAK / 5DS / SHR stay human-curated (features, bugs Henry triaged). Ops is where machine-generated signals land.

**Signature dedup beats perfect dedup logic.** Any detector can be retried, re-deployed, or re-run without creating issue spam.

---

## Tracking issue

[OPS-1 — Build routines-hub: Linear-native ops automation](https://linear.app/wakewellnow/issue/OPS-1/build-routines-hub-linear-native-ops-automation)
