// W5: npm audit detector.
// Parses the JSON output of `npm audit --json --audit-level=high` and writes
// one Linear issue per High/Critical advisory in the Security Hygiene project.
//
// Signature: [cve:<id>:<repo>]  (one issue per advisory per repo)
//
// Env:
//   LINEAR_API_KEY, TARGET_REPO, AUDIT_JSON

import { readFileSync, existsSync } from 'node:fs';
import { ensureIssue, commentOnIssue } from '../lib/linear.mjs';

const { TARGET_REPO, AUDIT_JSON } = process.env;

if (!TARGET_REPO) throw new Error('TARGET_REPO required');
if (!AUDIT_JSON || !existsSync(AUDIT_JSON)) {
  console.log(`No audit.json at ${AUDIT_JSON} — skipping.`);
  process.exit(0);
}

const raw = readFileSync(AUDIT_JSON, 'utf8');
let audit;
try {
  audit = JSON.parse(raw);
} catch (e) {
  console.log(`Failed to parse audit.json: ${e.message}`);
  process.exit(0);
}

// npm 7+ format: { vulnerabilities: { <pkg>: { severity, via: [{source, name, title, url}] } } }
const vulns = audit.vulnerabilities || {};

const advisoriesByCveId = new Map();

for (const [pkg, info] of Object.entries(vulns)) {
  if (!['high', 'critical'].includes(info.severity)) continue;

  const sources = Array.isArray(info.via) ? info.via.filter((v) => typeof v === 'object') : [];
  for (const src of sources) {
    const id = src.source || src.url || src.name;
    if (!id) continue;
    const key = `${id}`;
    if (!advisoriesByCveId.has(key)) {
      advisoriesByCveId.set(key, {
        source: src.source,
        name: src.name || pkg,
        title: src.title || 'Unknown vulnerability',
        url: src.url || '',
        severity: info.severity,
        pkg,
      });
    }
  }
}

if (advisoriesByCveId.size === 0) {
  console.log(`No High/Critical advisories for ${TARGET_REPO}.`);
  process.exit(0);
}

console.log(`Found ${advisoriesByCveId.size} High/Critical advisories in ${TARGET_REPO}.`);

const priorityBySeverity = { critical: 1, high: 2 };

for (const [id, adv] of advisoriesByCveId) {
  const signature = `[cve:${id}:${TARGET_REPO}]`;
  const title = `${signature} ${adv.name} — ${adv.title}`;
  const body = [
    `**Repo:** ${TARGET_REPO}`,
    `**Package:** ${adv.pkg}`,
    `**Advisory:** ${adv.title}`,
    `**Severity:** ${adv.severity}`,
    `**Source:** ${adv.url || adv.source || 'n/a'}`,
    '',
    `Detected by scheduled npm audit. Auto-closes when advisory no longer appears.`,
    '',
    `Fix: \`npm audit fix\` in \`${TARGET_REPO}\`, test, open PR.`,
  ].join('\n');

  try {
    const result = await ensureIssue({
      signature,
      onMatch: async (existing) => {
        await commentOnIssue(
          existing.id,
          `Still present in ${TARGET_REPO} as of ${new Date().toISOString()}.`,
        );
      },
      onNew: () => ({
        title,
        description: body,
        projectKey: 'security-hygiene',
        labelNames: ['routine', 'cve', 'compliance'],
        priority: priorityBySeverity[adv.severity] || 2,
      }),
    });
    console.log(`  ${result.action}: ${result.issue.identifier} — ${signature}`);
  } catch (e) {
    console.error(`  ERROR on ${signature}: ${e.message}`);
  }
}
