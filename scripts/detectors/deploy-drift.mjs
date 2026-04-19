// W20: Deploy drift detector (daily).
// For each repo, reads the running commit SHA from its prod /healthz endpoint
// and compares against the default branch's HEAD on GitHub. If they diverge,
// opens (or heartbeats) one rolling Linear issue per repo.
//
// Why this matters: OPS-119 (2026-04-19) was only found because a human noticed
// main CI timing out on deploys that were actually succeeding. A W20 detector
// catches drift between GitHub's reported status and the running commit within
// one cron cycle.
//
// Signature: [deploy-drift:<repo>]  — one rolling issue per repo.
// Dedup: ensureIssue → startsWith title match + open-state filter. Heartbeat
//        comment on match; G1 CHECK 4 auto-closes after 3d of silence.

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { ensureIssue, commentOnIssue } from '../lib/linear.mjs';

const { TARGET_REPO, GITHUB_TOKEN } = process.env;
if (!TARGET_REPO) throw new Error('TARGET_REPO required');
if (!GITHUB_TOKEN) throw new Error('GITHUB_TOKEN required (repo read scope)');

const OWNER = 'Wakewell-Sleep-Solutions';
const FETCH_TIMEOUT_MS = 10_000;

const __dirname = dirname(fileURLToPath(import.meta.url));
const ENDPOINTS = JSON.parse(
  readFileSync(resolve(__dirname, '..', '..', 'config', 'deploy-endpoints.json'), 'utf8'),
);

const endpoint = ENDPOINTS[TARGET_REPO];
if (!endpoint) {
  console.log(`${TARGET_REPO}: no deploy endpoint configured — skipping.`);
  process.exit(0);
}

// --- GitHub: default branch HEAD SHA -------------------------------------
async function gh(query, variables = {}) {
  const res = await fetch('https://api.github.com/graphql', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ query, variables }),
  });
  const json = await res.json();
  if (json.errors) throw new Error(`GitHub GraphQL error: ${JSON.stringify(json.errors)}`);
  return json.data;
}

const ghData = await gh(
  `query DefaultBranchHead($owner: String!, $name: String!) {
    repository(owner: $owner, name: $name) {
      defaultBranchRef { target { oid } }
    }
  }`,
  { owner: OWNER, name: TARGET_REPO },
);

const mainSha = ghData.repository?.defaultBranchRef?.target?.oid;
if (!mainSha) {
  console.log(`${TARGET_REPO}: default branch HEAD not found on GitHub — skipping.`);
  process.exit(0);
}

// --- Health endpoint: running SHA ----------------------------------------
async function fetchWithTimeout(url, ms) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  try {
    return await fetch(url, { signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// Minimal JSONPath: supports "$.a" and "$.a.b.c". No arrays, no filters.
function extractByPath(obj, path) {
  if (typeof path !== 'string' || !path.startsWith('$.')) return undefined;
  const parts = path.slice(2).split('.').filter(Boolean);
  let cur = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = cur[p];
  }
  return cur;
}

let healthRes;
try {
  healthRes = await fetchWithTimeout(endpoint.url, FETCH_TIMEOUT_MS);
} catch (e) {
  console.log(`${TARGET_REPO}: health fetch failed (${endpoint.url}): ${e.message} — skipping.`);
  process.exit(0);
}

if (!healthRes.ok) {
  console.log(`${TARGET_REPO}: health endpoint returned HTTP ${healthRes.status} — skipping.`);
  process.exit(0);
}

let healthJson;
try {
  healthJson = await healthRes.json();
} catch (e) {
  console.log(`${TARGET_REPO}: health response not JSON: ${e.message} — skipping.`);
  process.exit(0);
}

const deployedShaRaw = extractByPath(healthJson, endpoint.shaJsonPath);
if (typeof deployedShaRaw !== 'string' || deployedShaRaw.length < 7) {
  console.log(
    `${TARGET_REPO}: could not extract SHA at path ${endpoint.shaJsonPath} — skipping.`,
  );
  process.exit(0);
}

const deployedSha = deployedShaRaw.toLowerCase();
const mainShaLower = mainSha.toLowerCase();

if (deployedSha === mainShaLower) {
  console.log(`${TARGET_REPO}: no drift (deployed=main=${mainShaLower.slice(0, 7)}).`);
  process.exit(0);
}

// --- Drift detected: open or heartbeat the rolling issue ------------------
const mainShort = mainShaLower.slice(0, 7);
const deployedShort = deployedSha.slice(0, 7);
const signature = `[deploy-drift:${TARGET_REPO}]`;
const title = `${signature} main HEAD ${mainShort} not deployed — running ${deployedShort}`;

const checkedAt = new Date().toISOString();
const sections = [
  '| Field | Value |',
  '|---|---|',
  `| Repo | \`${TARGET_REPO}\` |`,
  `| Main SHA | \`${mainShaLower}\` |`,
  `| Deployed SHA | \`${deployedSha}\` |`,
  `| Endpoint URL | ${endpoint.url} |`,
  `| Checked At | ${checkedAt} |`,
  '',
  '### Remediation',
  '1. Check the last CI run on main — did the deploy job actually succeed, or did it fail silently while marking the job green?',
  '2. Trigger a manual deploy from the latest main commit and watch for the running SHA to update.',
  '3. Verify a slot swap or staging deployment didn\'t stick to a stale commit — inspect Azure deployment slots if applicable.',
  '',
  '---',
  `_Auto-generated by routines-hub W20 (deploy-drift). Daily scan. Signature: \`${signature}\`. Auto-closes via G1 when deployed SHA matches main for 3d._`,
];

const result = await ensureIssue({
  signature,
  onMatch: async (existing) => {
    await commentOnIssue(
      existing.id,
      `Still drifting in \`${TARGET_REPO}\` as of ${checkedAt}. ` +
        `Deployed \`${deployedShort}\`, main \`${mainShort}\`.`,
    );
  },
  onNew: () => ({
    title,
    description: sections.join('\n'),
    projectKey: 'prod-health',
    labelNames: ['routine', 'bug-prod'],
    priority: 2, // High — drift means the prod truth diverges from our source of truth
  }),
});

console.log(`  ${result.action}: ${result.issue.identifier} — ${signature}`);
process.exit(0);
