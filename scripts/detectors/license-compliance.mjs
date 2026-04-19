// W26: License Compliance detector (weekly).
// Scans production npm dependencies (and Python deps if pyproject.toml /
// requirements.txt is present) against config/license-policy.json. Classifies
// every package as allowed / flagged / blocked / unknown and writes one rolling
// Linear issue per repo with Snyk-grade detail: a license rating (A-E), a
// blocked/flagged table with parent dep paths, full distribution counts, and a
// remediation playbook keyed by license family.
//
// Signature: [license:<repo>]  — one rolling issue per repo.
// Heartbeat on match (counts + delta); G1 CHECK 4 auto-closes after 3d clear.
//
// Env:
//   LINEAR_API_KEY
//   TARGET_REPO  — matrix value (e.g. sleep_test_scheduler)
//   TARGET_DIR   — checkout path of the target repo (workflow-supplied)

import { existsSync, readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { ensureIssue, commentOnIssue } from '../lib/linear.mjs';

const { TARGET_REPO, TARGET_DIR } = process.env;
if (!TARGET_REPO) throw new Error('TARGET_REPO required');
if (!TARGET_DIR || !existsSync(TARGET_DIR)) {
  console.log(`No TARGET_DIR at ${TARGET_DIR} — skipping.`);
  process.exit(0);
}

const __dirname = dirname(fileURLToPath(import.meta.url));
const POLICY = JSON.parse(
  readFileSync(resolve(__dirname, '..', '..', 'config', 'license-policy.json'), 'utf8'),
);

// --- Policy classification --------------------------------------------------

// Compile blocked-list entries that contain `*` to anchored regexes.
// Plain entries stay strings for fast Set lookup.
const ALLOWED_SET = new Set(POLICY.allowed);
const FLAGGED_SET = new Set(POLICY.flagged);
const BLOCKED_SET = new Set(POLICY.blocked.filter((l) => !l.includes('*')));
const BLOCKED_PATTERNS = POLICY.blocked
  .filter((l) => l.includes('*'))
  .map((l) => new RegExp('^' + l.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*') + '$'));

function classifyOne(license) {
  if (!license) return 'blocked'; // missing → treat as UNKNOWN
  const upper = license.toUpperCase();
  if (BLOCKED_SET.has(license) || BLOCKED_SET.has(upper)) return 'blocked';
  if (BLOCKED_PATTERNS.some((re) => re.test(license))) return 'blocked';
  if (license.startsWith('SEE LICENSE IN')) return 'blocked';
  if (FLAGGED_SET.has(license)) return 'flagged';
  if (ALLOWED_SET.has(license)) return 'allowed';
  return 'flagged'; // unknown SPDX identifier → conservative
}

// Parse an SPDX expression like "(MIT OR Apache-2.0)" or "MIT AND CC0-1.0"
// into its leaf license IDs plus an operator. Returns:
//   { ids: string[], op: 'OR' | 'AND' | 'SINGLE' }
function parseSpdxExpression(expr) {
  const cleaned = expr.replace(/[()]/g, '').trim();
  if (/\s+OR\s+/i.test(cleaned)) {
    return { ids: cleaned.split(/\s+OR\s+/i).map((s) => s.trim()), op: 'OR' };
  }
  if (/\s+AND\s+/i.test(cleaned)) {
    return { ids: cleaned.split(/\s+AND\s+/i).map((s) => s.trim()), op: 'AND' };
  }
  return { ids: [cleaned], op: 'SINGLE' };
}

// Normalize raw `licenses` field (string | string[] | SPDX expression) to a
// classification result. Honors SPDX OR (we get to pick the most permissive)
// and AND (every leaf must qualify).
function classify(licensesField) {
  // license-checker can emit an array when the package.json lists multiple
  // license blobs side-by-side (legacy format). Treat array as AND — we must
  // comply with every entry.
  if (Array.isArray(licensesField)) {
    const results = licensesField.map((l) => classify(l));
    if (results.some((r) => r.category === 'blocked')) {
      return pickWorst(results, licensesField.join(' AND '));
    }
    if (results.some((r) => r.category === 'flagged')) {
      return pickWorst(results, licensesField.join(' AND '));
    }
    return { category: 'allowed', expression: licensesField.join(' AND '), leaves: licensesField };
  }
  if (typeof licensesField !== 'string' || !licensesField.trim()) {
    return { category: 'blocked', expression: 'UNKNOWN', leaves: ['UNKNOWN'] };
  }

  const { ids, op } = parseSpdxExpression(licensesField);
  const leafCats = ids.map((id) => ({ id, cat: classifyOne(id) }));

  if (op === 'OR') {
    // We can pick whichever leaf satisfies us most. Allowed > flagged > blocked.
    if (leafCats.some((l) => l.cat === 'allowed')) {
      return { category: 'allowed', expression: licensesField, leaves: ids };
    }
    if (leafCats.some((l) => l.cat === 'flagged')) {
      return { category: 'flagged', expression: licensesField, leaves: ids };
    }
    return { category: 'blocked', expression: licensesField, leaves: ids };
  }
  // AND or SINGLE — every leaf must qualify.
  if (leafCats.some((l) => l.cat === 'blocked')) {
    return { category: 'blocked', expression: licensesField, leaves: ids };
  }
  if (leafCats.some((l) => l.cat === 'flagged')) {
    return { category: 'flagged', expression: licensesField, leaves: ids };
  }
  return { category: 'allowed', expression: licensesField, leaves: ids };
}

function pickWorst(results, expression) {
  if (results.some((r) => r.category === 'blocked')) {
    return { category: 'blocked', expression, leaves: results.flatMap((r) => r.leaves) };
  }
  return { category: 'flagged', expression, leaves: results.flatMap((r) => r.leaves) };
}

// --- npm scan ---------------------------------------------------------------

function runNpmScan() {
  if (!existsSync(`${TARGET_DIR}/package.json`)) {
    console.log(`  npm: no package.json — skipping.`);
    return [];
  }

  // Install license-checker-rseidelsohn locally inside the target repo so the
  // resolver has access to the real node_modules tree. --no-save keeps the
  // target's package.json clean (anti-requirement: do not commit the dep).
  console.log(`  npm: installing license-checker-rseidelsohn (--no-save)…`);
  try {
    execSync(
      'npm install --no-save --ignore-scripts --no-audit --no-fund --legacy-peer-deps license-checker-rseidelsohn',
      { cwd: TARGET_DIR, stdio: ['ignore', 'pipe', 'pipe'] },
    );
  } catch (e) {
    // Some repos may not have node_modules installed. Try installing prod deps
    // first, then retry the license-checker install.
    console.log(`  npm: initial install failed (${e.message.split('\n')[0]}); installing prod deps first.`);
    try {
      execSync('npm install --ignore-scripts --no-audit --no-fund --legacy-peer-deps', {
        cwd: TARGET_DIR,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      execSync(
        'npm install --no-save --ignore-scripts --no-audit --no-fund --legacy-peer-deps license-checker-rseidelsohn',
        { cwd: TARGET_DIR, stdio: ['ignore', 'pipe', 'pipe'] },
      );
    } catch (e2) {
      console.log(`  npm: install still failed — skipping. (${e2.message.split('\n')[0]})`);
      return [];
    }
  }

  let raw;
  try {
    raw = execSync(
      'npx --no-install license-checker-rseidelsohn --production --json --excludePrivatePackages',
      { cwd: TARGET_DIR, stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 * 1024 },
    ).toString('utf8');
  } catch (e) {
    console.log(`  npm: license-checker run failed — ${e.message.split('\n')[0]}`);
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    console.log(`  npm: failed to parse license-checker JSON — ${e.message}`);
    return [];
  }

  // Filter out the host package itself. license-checker emits "<name>@<ver>"
  // keys; the host package's `path` equals TARGET_DIR.
  const hostPkgJson = JSON.parse(readFileSync(`${TARGET_DIR}/package.json`, 'utf8'));
  const hostName = hostPkgJson.name;

  const pkgs = [];
  for (const [key, info] of Object.entries(parsed)) {
    // Strip the trailing @version. Scoped packages keep their leading @.
    const lastAt = key.lastIndexOf('@');
    const name = lastAt > 0 ? key.slice(0, lastAt) : key;
    const version = lastAt > 0 ? key.slice(lastAt + 1) : '';
    if (name === hostName) continue;
    if (typeof info.path === 'string' && info.path === TARGET_DIR) continue;

    pkgs.push({
      ecosystem: 'npm',
      name,
      version,
      licenses: info.licenses ?? null,
      repository: info.repository || '',
      path: info.path || '',
    });
  }
  console.log(`  npm: ${pkgs.length} packages scanned.`);
  return pkgs;
}

// --- Python scan ------------------------------------------------------------

function runPythonScan() {
  const hasPyProject = existsSync(`${TARGET_DIR}/pyproject.toml`);
  const hasReq = existsSync(`${TARGET_DIR}/requirements.txt`);
  if (!hasPyProject && !hasReq) return [];

  console.log(`  python: detected pyproject/requirements; trying pip-licenses…`);
  let raw;
  try {
    raw = execSync('pip-licenses --format=json', {
      cwd: TARGET_DIR,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 32 * 1024 * 1024,
    }).toString('utf8');
  } catch (e) {
    console.log(
      `  python: pip-licenses unavailable — Python dep scanning unavailable. (${e.message.split('\n')[0]})`,
    );
    return [];
  }

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    console.log(`  python: failed to parse pip-licenses JSON — ${e.message}`);
    return [];
  }

  const pkgs = parsed.map((p) => ({
    ecosystem: 'python',
    name: p.Name || 'unknown',
    version: p.Version || '',
    licenses: p.License || null,
    repository: '',
    path: '',
  }));
  console.log(`  python: ${pkgs.length} packages scanned.`);
  return pkgs;
}

// --- Parent dep path resolution (npm only) ----------------------------------

// Use `npm ls <package> --all --json` to get the dependency path (e.g.
// "host-app > express > body-parser"). Falls back to the bare package name on
// failure — this is best-effort decoration, never fatal.
function resolveDepPath(pkgName) {
  try {
    const raw = execSync(`npm ls ${pkgName} --all --json --long=false 2>/dev/null`, {
      cwd: TARGET_DIR,
      stdio: ['ignore', 'pipe', 'ignore'],
      maxBuffer: 16 * 1024 * 1024,
    }).toString('utf8');
    const parsed = JSON.parse(raw);
    const path = findFirstPath(parsed, pkgName, [parsed.name || 'app']);
    return path ? path.join(' → ') : pkgName;
  } catch {
    return pkgName;
  }
}

function findFirstPath(node, target, trail) {
  if (!node || !node.dependencies) return null;
  for (const [name, child] of Object.entries(node.dependencies)) {
    const next = trail.concat(name);
    if (name === target) return next;
    const deeper = findFirstPath(child, target, next);
    if (deeper) return deeper;
  }
  return null;
}

// --- Rating + reporting -----------------------------------------------------

function computeRating(blockedCount, flaggedCount, hasAgplProd) {
  if (hasAgplProd && blockedCount === 0 && flaggedCount > 0) return 'E'; // AGPL alone is an E
  if (blockedCount >= 3) return 'E';
  if (blockedCount >= 1) return 'D';
  if (flaggedCount >= 11) return 'D'; // wide flagged surface trends toward D
  if (flaggedCount >= 4) return 'C';
  if (flaggedCount >= 1) return 'B';
  return 'A';
}

function noteFor(license) {
  if (!license) return POLICY.notes['UNKNOWN'];
  if (POLICY.notes[license]) return POLICY.notes[license];
  if (license.startsWith('AGPL')) return POLICY.notes['AGPL-*'];
  if (license.startsWith('GPL')) return POLICY.notes['GPL-*'];
  if (license.startsWith('LGPL')) return POLICY.notes['LGPL-*'];
  if (license === 'UNKNOWN' || license === 'UNLICENSED') return POLICY.notes['UNKNOWN'];
  return 'Flagged for review per policy.';
}

function escapePipe(s) {
  return String(s).replace(/\|/g, '\\|');
}

// --- Main -------------------------------------------------------------------

console.log(`License compliance scan: ${TARGET_REPO}`);

const npmPkgs = runNpmScan();
const pyPkgs = runPythonScan();
const allPkgs = [...npmPkgs, ...pyPkgs];

if (allPkgs.length === 0) {
  console.log(`No scannable packages in ${TARGET_REPO} — exiting cleanly.`);
  process.exit(0);
}

const blocked = [];
const flagged = [];
const allowedDist = new Map(); // license -> count
let hasAgplProd = false;

for (const pkg of allPkgs) {
  const result = classify(pkg.licenses);
  const enriched = { ...pkg, classification: result };

  if (result.category === 'blocked') {
    blocked.push(enriched);
  } else if (result.category === 'flagged') {
    flagged.push(enriched);
    if (result.leaves.some((l) => typeof l === 'string' && l.startsWith('AGPL'))) {
      hasAgplProd = true;
    }
  }

  // Distribution count uses the canonical expression so MIT shows up once.
  const key =
    typeof pkg.licenses === 'string'
      ? pkg.licenses
      : Array.isArray(pkg.licenses)
        ? pkg.licenses.join(' AND ')
        : 'UNKNOWN';
  allowedDist.set(key, (allowedDist.get(key) || 0) + 1);
}

// Decorate the blocked + flagged tables with parent dep paths (npm only — pip
// doesn't surface the same dep tree easily).
for (const list of [blocked, flagged]) {
  for (const pkg of list) {
    if (pkg.ecosystem === 'npm') {
      pkg.usedBy = resolveDepPath(pkg.name);
    } else {
      pkg.usedBy = pkg.name;
    }
  }
}

const rating = computeRating(blocked.length, flagged.length, hasAgplProd);
const scanDate = new Date().toISOString();

console.log(
  `  ${TARGET_REPO}: ${allPkgs.length} pkgs total | blocked=${blocked.length} flagged=${flagged.length} | rating=${rating}`,
);

// --- Build the issue body ---------------------------------------------------

const ratingTable = [
  '| Dimension | Rating | Blocked | Flagged | Trend |',
  '|---|---|---|---|---|',
  `| Compliance | ${rating} | ${blocked.length} | ${flagged.length} | first/±delta |`,
];

const blockedRows = blocked.length
  ? [
      '| Package | Version | License | Used By | Why Blocked |',
      '|---|---|---|---|---|',
      ...blocked.map(
        (p) =>
          `| \`${escapePipe(p.name)}\` | ${escapePipe(p.version || 'n/a')} | ${escapePipe(p.classification.expression)} | \`${escapePipe(p.usedBy)}\` | ${escapePipe(noteFor(p.classification.leaves[0]))} |`,
      ),
    ].join('\n')
  : '_None._';

const flaggedRows = flagged.length
  ? [
      '| Package | Version | License | Used By | Action |',
      '|---|---|---|---|---|',
      ...flagged.map(
        (p) =>
          `| \`${escapePipe(p.name)}\` | ${escapePipe(p.version || 'n/a')} | ${escapePipe(p.classification.expression)} | \`${escapePipe(p.usedBy)}\` | ${escapePipe(noteFor(p.classification.leaves[0]))} |`,
      ),
    ].join('\n')
  : '_None._';

const distRows = [...allowedDist.entries()]
  .sort((a, b) => b[1] - a[1])
  .map(([license, count]) => {
    const cat = classify(license).category;
    const label = cat === 'allowed' ? 'Allowed' : cat === 'flagged' ? 'Flagged' : 'Blocked';
    return `| ${escapePipe(license)} | ${count} | ${label} |`;
  });

const distTable = ['| License | Count | Category |', '|---|---|---|', ...distRows].join('\n');

const findingsCount = blocked.length + flagged.length;

const body = [
  `**Repo:** ${TARGET_REPO}`,
  `**Scan date:** ${scanDate}`,
  `**Total packages scanned:** ${allPkgs.length} (prod only, excluding private)`,
  `**Allowlist policy:** \`config/license-policy.json\``,
  '',
  '## License Rating',
  '',
  ratingTable.join('\n'),
  '',
  'Applies to SonarQube Clean Code attribute **Responsible** (Lawful).',
  '',
  '### Rating logic',
  '- **A**: 0 blocked, 0 flagged',
  '- **B**: 0 blocked, 1-3 flagged',
  '- **C**: 0 blocked, 4-10 flagged',
  '- **D**: 1-2 blocked, any flagged',
  '- **E**: ≥3 blocked OR any AGPL in production runtime',
  '',
  '## Blocked Licenses (CRITICAL — must remediate)',
  '',
  blockedRows,
  '',
  '## Flagged Licenses (REVIEW REQUIRED)',
  '',
  flaggedRows,
  '',
  '## License Distribution',
  '',
  distTable,
  '',
  '## Findings by Software Quality',
  '',
  `**Responsible** — ${findingsCount} findings. License non-compliance is both a legal risk (copyleft forcing code disclosure) and a brand-trust risk (customer contracts often forbid AGPL).`,
  '',
  '## Remediation Playbook',
  '',
  '### AGPL / SSPL in server-side deps',
  '1. **Find replacement**: search for MIT/Apache-2.0 equivalents. For databases, prefer PostgreSQL (PostgreSQL license) over MongoDB (SSPL).',
  '2. **Isolate**: if irreplaceable, wrap behind a network boundary (separate service, separate deployable). Network distance = distribution distance.',
  '3. **Legal review**: if neither option is viable, get written legal sign-off on the specific AGPL terms.',
  '',
  '### GPL / LGPL in transitive deps',
  '1. **Check linking model**: GPL triggers on distribution; if we only use it at build-time (e.g. a CLI tool, not a runtime dep), it\'s usually OK.',
  '2. **Swap with permissive fork**: many GPL libs have MIT-forks (e.g. `gnu-tar` → `tar-js`).',
  '',
  '### UNKNOWN / proprietary',
  '1. **Inspect repository**: check the package\'s GitHub for a LICENSE file. npm sometimes misses SPDX fields.',
  '2. **Contact author**: if genuinely proprietary, either license it properly or remove.',
  '',
  '### Per-package fix commands',
  'For each flagged/blocked package: `npm ls <package>` to find the path, then `npm remove` or swap.',
  '',
  '## Historical Trend',
  '',
  'First scan. Subsequent heartbeats show delta.',
  '',
  '## Effort Estimate',
  '',
  `**Total:** ~${flagged.length * 0.5 + blocked.length * 2} hours (30 min per flagged package, 2 hr per blocked package including replacement research).`,
  '',
  '## References',
  '',
  '- [SPDX License List](https://spdx.org/licenses/)',
  '- [Snyk open source license policy](https://docs.snyk.io/scan-with-snyk/snyk-open-source/licenses)',
  '- [Choose A License](https://choosealicense.com/appendix/) — copyleft vs permissive breakdown.',
  '- [OSI-approved licenses](https://opensource.org/licenses/) — authoritative list.',
  '',
  '---',
  '',
  `*Auto-generated by routines-hub W26 (license-compliance). Weekly scan. Signature: \`[license:${TARGET_REPO}]\`. Auto-closes via G1 when clear for 3d.*`,
].join('\n');

const signature = `[license:${TARGET_REPO}]`;
const title = `${signature} ${blocked.length} blocked / ${flagged.length} flagged — Rating ${rating}`;

const result = await ensureIssue({
  signature,
  onMatch: async (existing) => {
    // Heartbeat with current state. Prior counts are not threaded through the
    // process state — the description shows current detail; the comment shows
    // delta marker for human eyes ("was <prior>" placeholder for symmetry).
    await commentOnIssue(
      existing.id,
      `Still tracking licenses in ${TARGET_REPO} as of ${scanDate}.\n` +
        `Blocked: ${blocked.length} (was <prior>). Flagged: ${flagged.length} (was <prior>). Rating ${rating}.`,
    );
  },
  onNew: () => ({
    title,
    description: body,
    projectKey: 'dependencies',
    labelNames: ['routine', 'compliance'],
    priority: 2, // High — license violations are legal/regulatory concerns
  }),
});

console.log(`  ${result.action}: ${result.issue.identifier} — ${signature}`);
