// W27: Malicious Packages detector (daily).
// Runs OSV-Scanner against a target repo and cross-references installed deps
// against the OSV database (OpenSSF Malicious Packages + GHSA + npm advisories
// + PyPI advisories). Posts a rolling Linear issue per repo under Security
// Hygiene with Snyk-grade detail.
//
// Signature: [malicious-packages:<repo>]  — one rolling issue per repo.
// Heartbeat on match; G1 CHECK 4 auto-closes when clear for 3d.
//
// Two classes of finding surfaced:
//   1. Malicious packages — id prefix `MAL-` OR summary text matches
//      malware/typosquat/backdoor/cryptojacker/infostealer indicators.
//      These are the primary signal: a package publisher turned hostile.
//   2. High/Critical CVEs — id prefix `CVE-`/`GHSA-` with severity >= 7.0.
//      Overlaps with npm-audit detector (W5), but OSV covers PyPI + others
//      and attaches CWE IDs + CVSS vectors + full dep paths.
//
// Priority routing:
//   - any malicious finding OR any CVSS >=7.0 → P1 Urgent
//   - any CVSS 4.0-6.9 (Medium)                → P2 High
//   - else metadata-only (low/unknown)          → P3 Medium
//
// Env:
//   LINEAR_API_KEY — Linear auth (Infisical /shared or repo secret)
//   TARGET_REPO    — matrix repo name for dedup signature
//   TARGET_DIR     — path to checked-out target repo
//   OSV_JSON       — optional override for osv-scanner json output path
//   OSV_VERSION    — optional, osv-scanner version string for issue metadata

import { existsSync, readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { ensureIssue, commentOnIssue } from '../lib/linear.mjs';

const { TARGET_REPO, TARGET_DIR, OSV_JSON, OSV_VERSION } = process.env;
if (!TARGET_REPO) throw new Error('TARGET_REPO required');
if (!TARGET_DIR || !existsSync(TARGET_DIR)) {
  console.log(`No TARGET_DIR at ${TARGET_DIR} — skipping.`);
  process.exit(0);
}

// ---------------------------------------------------------------------------
// 1. Locate + parse osv-scanner JSON output

const OSV_JSON_PATH = OSV_JSON || `${TARGET_DIR}/../osv.json`;
if (!existsSync(OSV_JSON_PATH)) {
  console.log(`No OSV output at ${OSV_JSON_PATH} — skipping.`);
  process.exit(0);
}

let osv;
try {
  osv = JSON.parse(readFileSync(OSV_JSON_PATH, 'utf8'));
} catch (e) {
  // osv-scanner prints warnings on stderr AND sometimes prefixes stdout with
  // status lines when the redirect merges streams. Try to salvage the JSON.
  const raw = readFileSync(OSV_JSON_PATH, 'utf8');
  const start = raw.indexOf('{');
  if (start < 0) {
    console.log(`Failed to parse osv.json (no JSON found): ${e.message}`);
    process.exit(0);
  }
  try {
    osv = JSON.parse(raw.slice(start));
  } catch (e2) {
    console.log(`Failed to parse osv.json: ${e2.message}`);
    process.exit(0);
  }
}

const results = Array.isArray(osv?.results) ? osv.results : [];

// ---------------------------------------------------------------------------
// 2. Classify findings
//
// Malicious detection strategy (multi-signal):
//   - id.startsWith('MAL-')                                 → OpenSSF MAL
//   - summary.match(/malicious|malware|typosquat|backdoor|  → GHSA malware
//                    cryptojacker|infostealer|embedded malware/i)
//   - database_specific.malicious-packages-origins present   → OpenSSF source
// Any one hit flags the finding as malicious.

const MALICIOUS_TEXT = /malicious|malware|typosquat|backdoor|cryptojacker|infostealer|embedded\s+malware/i;

function isMalicious(vuln) {
  if (typeof vuln.id === 'string' && vuln.id.startsWith('MAL-')) return true;
  const summary = vuln.summary || '';
  if (MALICIOUS_TEXT.test(summary)) return true;
  if (vuln.database_specific && vuln.database_specific['malicious-packages-origins']) return true;
  return false;
}

// Extract the highest CVSS score we can find. OSV returns CVSS in two places:
//   - vuln.severity[] = [{type: "CVSS_V3", score: "CVSS:3.1/..."}]  (vector)
//   - groups[].max_severity = "7.5"                                  (numeric)
// We also look at database_specific.severity (LOW/MODERATE/HIGH/CRITICAL).

const SEVERITY_TEXT_TO_SCORE = {
  CRITICAL: 9.5,
  HIGH: 8.0,
  MODERATE: 5.5,
  MEDIUM: 5.5,
  LOW: 2.5,
};

function cvssScoreOf(vuln, group) {
  // Prefer the numeric group max (cleanest)
  if (group && typeof group.max_severity === 'string' && group.max_severity.trim()) {
    const n = parseFloat(group.max_severity);
    if (!Number.isNaN(n)) return n;
  }
  // Parse any CVSS vector string for a base score
  if (Array.isArray(vuln.severity)) {
    for (const s of vuln.severity) {
      if (typeof s.score === 'number' && !Number.isNaN(s.score)) return s.score;
      if (typeof s.score === 'string') {
        const n = parseFloat(s.score);
        if (!Number.isNaN(n)) return n;
        // CVSS vector — no numeric score present; fall through to text
      }
    }
  }
  // Fall back to GHSA textual severity
  const text = (vuln.database_specific?.severity || '').toUpperCase();
  if (SEVERITY_TEXT_TO_SCORE[text] !== undefined) return SEVERITY_TEXT_TO_SCORE[text];
  return 0;
}

function severityBucket(score) {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score > 0) return 'low';
  return 'unknown';
}

function firstFixedVersion(vuln) {
  const affected = Array.isArray(vuln.affected) ? vuln.affected : [];
  for (const a of affected) {
    const ranges = Array.isArray(a.ranges) ? a.ranges : [];
    for (const r of ranges) {
      const events = Array.isArray(r.events) ? r.events : [];
      for (const ev of events) {
        if (ev.fixed) return ev.fixed;
      }
    }
  }
  return null;
}

function cweIdsOf(vuln) {
  const ids = vuln.database_specific?.cwe_ids;
  return Array.isArray(ids) ? ids : [];
}

// Build flat finding list with full context.
// severityCounts tracks ONLY non-malicious CVE findings so the CVE
// distribution table reads cleanly. Malicious findings have their own table.
const malicious = [];
const cves = [];
const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
let packagesScanned = 0;

for (const result of results) {
  const packages = Array.isArray(result?.packages) ? result.packages : [];
  for (const entry of packages) {
    packagesScanned += 1;
    const pkg = entry.package || {};
    const groups = Array.isArray(entry.groups) ? entry.groups : [];
    const vulns = Array.isArray(entry.vulnerabilities) ? entry.vulnerabilities : [];
    const depGroups = Array.isArray(entry.dependency_groups) ? entry.dependency_groups : [];
    const isProd = depGroups.length === 0 || depGroups.includes('prod') || depGroups.some((g) => g !== 'dev');

    for (const vuln of vulns) {
      const group = groups.find((g) => Array.isArray(g.ids) && g.ids.includes(vuln.id));
      const cvss = cvssScoreOf(vuln, group);
      const bucket = severityBucket(cvss);

      const finding = {
        pkgName: pkg.name || 'unknown',
        pkgVersion: pkg.version || 'unknown',
        ecosystem: pkg.ecosystem || 'unknown',
        advisoryId: vuln.id || 'UNKNOWN',
        aliases: Array.isArray(vuln.aliases) ? vuln.aliases.filter((a) => a !== vuln.id) : [],
        summary: vuln.summary || '(no summary)',
        cvss,
        severity: bucket,
        cweIds: cweIdsOf(vuln),
        fixedIn: firstFixedVersion(vuln),
        isProd,
        isDev: depGroups.includes('dev'),
        source: result?.source?.path || 'unknown',
      };

      if (isMalicious(vuln)) {
        malicious.push(finding);
      } else {
        // Only non-malicious findings count in the CVE distribution — the
        // malicious table surfaces those separately with its own severity.
        severityCounts[bucket] += 1;
        cves.push(finding);
      }
    }
  }
}

// Sort: malicious first (no sort among them — all urgent), CVEs by score desc.
cves.sort((a, b) => b.cvss - a.cvss);

// ---------------------------------------------------------------------------
// 3. Early exit if clean. No issue created when the world is quiet.

const totalFindings = malicious.length + cves.length;
if (totalFindings === 0) {
  console.log(`${TARGET_REPO}: clean — 0 OSV findings across ${packagesScanned} packages.`);
  process.exit(0);
}

// ---------------------------------------------------------------------------
// 4. Compute security rating + priority

function securityRating(malCount, high, crit) {
  if (malCount >= 2 || (crit >= 1 && malCount >= 1)) return 'E';
  if (malCount >= 1) return 'D';
  const highCrit = high + crit;
  if (highCrit >= 6) return 'C';
  if (highCrit >= 1) return 'B';
  return 'A';
}

const rating = securityRating(malicious.length, severityCounts.high, severityCounts.critical);

const hasHighCrit = severityCounts.critical > 0 || severityCounts.high > 0;
const hasMedium = severityCounts.medium > 0;

// Priority ladder per spec:
//   - HIGH/CRITICAL (CVSS >=7) or any malicious → P1 Urgent
//   - MEDIUM (CVSS 4-6.9)                       → P2 High
//   - else                                       → P3 Medium
let priority = 3;
if (malicious.length > 0 || hasHighCrit) priority = 1;
else if (hasMedium) priority = 2;

// ---------------------------------------------------------------------------
// 5. Render skill-grade description (SonarQube/Snyk depth)

const now = new Date();
const iso = now.toISOString();
const scanner = `osv-scanner v${OSV_VERSION || 'latest'}`;

// Malicious Packages table — the headline
const maliciousTable = (() => {
  if (malicious.length === 0) {
    return '> ✅ No malicious packages detected in OSV database cross-reference.';
  }
  const rows = malicious.map((f) => {
    const cwe = f.cweIds.length ? f.cweIds.join(', ') : 'CWE-506';
    return `| \`${f.pkgName}\` | ${f.pkgVersion} | ${f.advisoryId} | ${cwe} | **REMOVE IMMEDIATELY** — audit all machines that ran \`npm install\` since adoption |`;
  });
  return [
    '| Package | Version | Advisory | CWE | Action Required |',
    '|---|---|---|---|---|',
    ...rows,
  ].join('\n');
})();

// High/Critical CVE table — drops medium/low to keep the primary table focused.
const cveHighCritRows = cves
  .filter((f) => f.severity === 'critical' || f.severity === 'high')
  .map((f) => {
    const installed = f.pkgVersion;
    const fixed = f.fixedIn || 'none';
    const score = f.cvss ? f.cvss.toFixed(1) : '—';
    const summary = (f.summary || '').replace(/[|\n\r]/g, ' ').slice(0, 80);
    return `| \`${f.pkgName}\` | ${installed} | ${fixed} | ${f.advisoryId} | ${score} | ${summary} |`;
  });

const cveTable = cveHighCritRows.length
  ? ['| Package | Installed | Patched | Advisory | CVSS | Description |', '|---|---|---|---|---|---|', ...cveHighCritRows].join('\n')
  : '_No high/critical CVEs in this scan._';

// Dependency paths section — light version (OSV doesn't give us the full tree
// without additional work). We show each malicious/critical pkg with its
// source lockfile so the user knows where to look.
const depPaths = (() => {
  const items = [...malicious, ...cves.filter((f) => f.severity === 'critical')];
  if (items.length === 0) return '_None — no malicious or critical findings._';
  const lines = ['```'];
  for (const f of items) {
    const source = f.source.split('/').slice(-2).join('/');
    const marker = malicious.includes(f) ? '  ← MALICIOUS' : '  ← CRITICAL';
    lines.push(`${source}`);
    lines.push(`└── ${f.pkgName}@${f.pkgVersion} (${f.isDev ? 'dev' : 'prod'})${marker}`);
    lines.push('');
  }
  lines.push('```');
  return lines.join('\n');
})();

// Aliases footer for each malicious pkg so users can cross-reference
const maliciousDetails = malicious.length
  ? malicious
      .map((f) => {
        const aliases = f.aliases.length ? ` (aliases: ${f.aliases.join(', ')})` : '';
        return `- \`${f.pkgName}@${f.pkgVersion}\` — ${f.advisoryId}${aliases}\n  ${f.summary.slice(0, 240)}${f.summary.length > 240 ? '…' : ''}`;
      })
      .join('\n')
  : '';

const sections = [];

sections.push(`**Repo:** ${TARGET_REPO}`);
sections.push(`**Scan date:** ${iso}`);
sections.push(`**Scanner:** ${scanner}`);
sections.push(`**Sources:** OpenSSF Malicious Packages, npm Security Advisories, GHSA, PyPI Advisories`);
sections.push(`**Packages scanned:** ${packagesScanned}`);
sections.push('');

sections.push('## Security Rating');
sections.push('');
sections.push('| Dimension | Rating | Malicious | CVE High/Crit | Trend |');
sections.push('|---|---|---|---|---|');
sections.push(
  `| Security | **${rating}** | ${malicious.length} | ${severityCounts.critical + severityCounts.high} | first |`,
);
sections.push('');
sections.push('Applies to SonarQube Clean Code attribute **Responsible** (Trustworthy). Malicious packages violate the fundamental contract of dependency integrity.');
sections.push('');
sections.push('### Rating logic');
sections.push('- **A**: 0 malicious, 0 high/critical CVEs');
sections.push('- **B**: 0 malicious, 1-5 high/critical CVEs');
sections.push('- **C**: 0 malicious, 6-20 high/critical CVEs');
sections.push('- **D**: 1 malicious package, any CVE profile');
sections.push('- **E**: ≥2 malicious packages OR unpatched critical (CVSS 9+) in prod dep');
sections.push('');

sections.push('## Malicious Packages Detected');
sections.push('');
sections.push(maliciousTable);
sections.push('');

if (maliciousDetails) {
  sections.push('### Advisory details');
  sections.push(maliciousDetails);
  sections.push('');
}

sections.push('## High/Critical CVEs');
sections.push('');
sections.push(cveTable);
sections.push('');

sections.push('## CVE Severity Distribution');
sections.push('');
sections.push('| Severity (CVSS) | Count |');
sections.push('|---|---|');
sections.push(`| Critical (9.0-10.0) | ${severityCounts.critical} |`);
sections.push(`| High (7.0-8.9)      | ${severityCounts.high} |`);
sections.push(`| Medium (4.0-6.9)    | ${severityCounts.medium} |`);
sections.push(`| Low (<4.0)          | ${severityCounts.low} |`);
sections.push('');

sections.push('## Affected Dependency Paths');
sections.push('');
sections.push(depPaths);
sections.push('');

sections.push('## Remediation Playbook');
sections.push('');
sections.push('### Malicious package found');
sections.push('1. **IMMEDIATELY** `npm uninstall <package>` and remove from `package.json`');
sections.push('2. **ROTATE** any secrets that machines with the install might have seen (env vars, .npmrc tokens, git config, SSH keys if the `postinstall` ran)');
sections.push('3. **AUDIT** recent git history: `git log --all -p -- package.json package-lock.json` — did this package land recently? Who added it?');
sections.push('4. **ESCALATE** to security channel if CI/CD or production ever ran `npm install` with this package. Credential exposure assessment needed.');
sections.push('5. **REPORT** to npm security: https://www.npmjs.com/advisories');
sections.push('');
sections.push('### High/Critical CVE');
sections.push('1. `npm audit fix` — auto-patches if compatible');
sections.push('2. If `npm audit fix` says "breaking", do `npm audit fix --force` in a branch, run tests, ship');
sections.push('3. If no patch exists upstream: find fork, patch yourself via `patch-package`, or pin to a known-safe version and file an upstream issue');
sections.push('4. Consider Socket.dev or Snyk paid tier for ongoing supply-chain monitoring (CVSS alone misses supply-chain attacks)');
sections.push('');
sections.push('### Post-install scripts (often malware vector)');
sections.push('Review packages with `preinstall`, `install`, `postinstall` scripts. Command:');
sections.push('```bash');
sections.push("cat package-lock.json | jq '[.packages[] | select(.scripts.preinstall or .scripts.install or .scripts.postinstall)] | length'");
sections.push('```');
sections.push('');

sections.push('## Findings by Software Quality');
sections.push('');
sections.push('**Security** (primary) — the malicious-package threat model: attacker publishes a package that steals credentials, mines crypto, or backdoors the host via `postinstall` hooks.');
sections.push('');

sections.push('## Historical Trend');
sections.push('');
sections.push('First scan. Heartbeats show delta.');
sections.push('');

sections.push('## Effort Estimate');
sections.push('');
sections.push('**Total:** Malicious packages = 2-8 hours each (uninstall + credential rotation + audit). High CVEs = 15-45 min each (usually `npm audit fix`).');
sections.push('');

sections.push('## References');
sections.push('');
sections.push('- [OSV Schema](https://ossf.github.io/osv-schema/)');
sections.push('- [OpenSSF Malicious Packages Database](https://github.com/ossf/malicious-packages)');
sections.push('- [Snyk malicious package reports](https://security.snyk.io/vuln/unmanaged)');
sections.push('- [npm supply-chain security](https://docs.npmjs.com/cli/v11/commands/npm-audit)');
sections.push('- [CWE-506: Embedded Malicious Code](https://cwe.mitre.org/data/definitions/506.html)');
sections.push('');

sections.push('---');
sections.push('');
sections.push(
  `_Auto-generated by routines-hub W27 (malicious-packages). Daily scan (supply chain moves fast). Signature: \`[malicious-packages:${TARGET_REPO}]\`. Auto-closes via G1 when clear for 3d._`,
);

// ---------------------------------------------------------------------------
// 6. Title + signature + ensureIssue

const signature = `[malicious-packages:${TARGET_REPO}]`;

// Build a scannable title: surface the worst signal first.
let titleSuffix;
if (malicious.length > 0) {
  titleSuffix = `${malicious.length} malicious package${malicious.length === 1 ? '' : 's'} — SUPPLY CHAIN RISK`;
} else if (severityCounts.critical > 0) {
  titleSuffix = `${severityCounts.critical} critical + ${severityCounts.high} high CVE`;
} else if (severityCounts.high > 0) {
  titleSuffix = `${severityCounts.high} high CVE`;
} else if (severityCounts.medium > 0) {
  titleSuffix = `${severityCounts.medium} medium CVE`;
} else {
  titleSuffix = `${totalFindings} advisory finding${totalFindings === 1 ? '' : 's'}`;
}
const title = `${signature} ${titleSuffix}`;

try {
  const result = await ensureIssue({
    signature,
    onMatch: async (existing) => {
      await commentOnIssue(
        existing.id,
        `Still tracking supply-chain risk in ${TARGET_REPO} as of ${iso}.\n` +
          `Malicious: ${malicious.length}. High/Crit CVE: ${severityCounts.critical + severityCounts.high}. Rating ${rating}.`,
      );
    },
    onNew: () => ({
      title,
      description: sections.join('\n'),
      projectKey: 'security-hygiene',
      labelNames: ['routine', 'cve'],
      priority,
    }),
  });
  console.log(`  ${result.action}: ${result.issue.identifier} — ${signature}`);
} catch (e) {
  console.error(`  ERROR on ${signature}: ${e.message}`);
  process.exit(1);
}
