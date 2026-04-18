// W8: Code Health detector (daily).
// Three signals per repo:
//   1. Files > 300 LOC (violates our AI-native 300-line rule)
//   2. Graphify god nodes (degree ≥200)
//   3. Graphify orphans (degree == 0)
//
// Posts ONE rolling Linear issue per repo. Signature:
//   [code-health:<repo>]
//
// The daily run posts a "Still present" heartbeat when an existing issue is
// matched, so G1 CHECK 4 auto-closes the issue once signals clear.
// Only creates an issue when at least ONE signal is non-trivial.

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, extname, relative } from 'node:path';
import { ensureIssue, commentOnIssue } from '../lib/linear.mjs';

const { TARGET_REPO, TARGET_DIR } = process.env;
if (!TARGET_REPO) throw new Error('TARGET_REPO required');
if (!TARGET_DIR || !existsSync(TARGET_DIR)) {
  console.log(`No TARGET_DIR at ${TARGET_DIR} — skipping.`);
  process.exit(0);
}

const LOC_THRESHOLD = 300;
const GOD_NODE_DEGREE = 200;

const CODE_EXTS = new Set([
  '.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py',
]);
const SKIP_DIRS = new Set([
  'node_modules', 'dist', 'build', '.next', '.nuxt', '.cache',
  '.git', 'coverage', '__pycache__', '.venv', 'venv',
  'graphify-out', '.claude-flow',
]);

// ---------- Signal 1: oversized files ----------
function walkCodeFiles(dir, out = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const ent of entries) {
    if (ent.name.startsWith('.') && ent.name !== '.github') continue;
    const full = join(dir, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIRS.has(ent.name)) continue;
      walkCodeFiles(full, out);
    } else if (ent.isFile() && CODE_EXTS.has(extname(ent.name))) {
      out.push(full);
    }
  }
  return out;
}

function countLines(path) {
  try {
    return readFileSync(path, 'utf8').split('\n').length;
  } catch { return 0; }
}

console.log(`Scanning ${TARGET_REPO}…`);
const allFiles = walkCodeFiles(TARGET_DIR);
const oversized = [];
for (const f of allFiles) {
  const loc = countLines(f);
  if (loc >= LOC_THRESHOLD) {
    oversized.push({ path: relative(TARGET_DIR, f), loc });
  }
}
oversized.sort((a, b) => b.loc - a.loc);
const topOversized = oversized.slice(0, 10);

// ---------- Signal 2 + 3: graphify god nodes + orphans (if available) ----------
const graphPath = join(TARGET_DIR, 'graphify-out', 'graph.json');
let godNodes = [];
let orphanCount = 0;
let totalNodes = 0;
let totalEdges = 0;
if (existsSync(graphPath)) {
  try {
    const graph = JSON.parse(readFileSync(graphPath, 'utf8'));
    const nodes = graph.nodes || [];
    const edges = graph.edges || graph.links || [];
    totalNodes = nodes.length;
    totalEdges = edges.length;

    // Compute degree per node
    const degree = new Map();
    for (const e of edges) {
      const s = typeof e.source === 'object' ? e.source.id : e.source;
      const t = typeof e.target === 'object' ? e.target.id : e.target;
      degree.set(s, (degree.get(s) || 0) + 1);
      degree.set(t, (degree.get(t) || 0) + 1);
    }

    // God nodes: degree ≥ threshold
    const nodesById = new Map(nodes.map((n) => [n.id, n]));
    const gods = [];
    for (const [id, deg] of degree.entries()) {
      if (deg >= GOD_NODE_DEGREE) {
        const n = nodesById.get(id) || { id };
        gods.push({
          name: n.label || n.name || id,
          path: n.path || n.file || '',
          degree: deg,
        });
      }
    }
    gods.sort((a, b) => b.degree - a.degree);
    godNodes = gods.slice(0, 10);

    // Orphans: nodes with degree 0 that look like source code (not test, not config)
    for (const n of nodes) {
      const d = degree.get(n.id) || 0;
      if (d !== 0) continue;
      const p = n.path || n.file || '';
      if (!p || /\btest|spec|\.d\.ts|config|node_modules/i.test(p)) continue;
      orphanCount++;
    }
  } catch (e) {
    console.log(`  (graphify parse failed: ${e.message})`);
  }
}

// ---------- Decide whether to post ----------
const nonTrivial =
  oversized.length >= 5 ||
  godNodes.length >= 1 ||
  orphanCount >= 10;

if (!nonTrivial) {
  console.log(`  Healthy: ${oversized.length} oversized, ${godNodes.length} god, ${orphanCount} orphan — no issue.`);
  process.exit(0);
}

// ---------- Build Linear issue ----------
const signature = `[code-health:${TARGET_REPO}]`;
const title = `${signature} ${oversized.length} oversized, ${godNodes.length} god nodes, ${orphanCount} orphans`;

const sections = [`**Repo:** ${TARGET_REPO}`];

if (totalNodes > 0) {
  sections.push(`**Graphify:** ${totalNodes} nodes, ${totalEdges} edges`);
}

sections.push('');

if (oversized.length > 0) {
  sections.push(`### Files ≥${LOC_THRESHOLD} LOC (top 10 of ${oversized.length})`);
  sections.push('');
  sections.push('| File | LOC |');
  sections.push('|---|---|');
  for (const f of topOversized) sections.push(`| \`${f.path}\` | ${f.loc} |`);
  sections.push('');
}

if (godNodes.length > 0) {
  sections.push(`### God nodes (degree ≥${GOD_NODE_DEGREE})`);
  sections.push('');
  sections.push('| Symbol | Path | Edges |');
  sections.push('|---|---|---|');
  for (const g of godNodes) {
    sections.push(`| \`${g.name}\` | \`${g.path}\` | ${g.degree} |`);
  }
  sections.push('');
  sections.push('_Do not extend god nodes — create domain repos and wire through them._');
  sections.push('');
}

if (orphanCount > 0) {
  sections.push(`### Orphans`);
  sections.push(`${orphanCount} source files have zero in-edges (no one imports them).`);
  sections.push('Review candidates for deletion via `knip` / `ts-prune` / manual audit.');
  sections.push('');
}

sections.push('---');
sections.push('_Auto-generated by routines-hub W8 (code-health). Daily scan; one rolling issue per repo. Auto-closes via G1 when signals clear._');

try {
  const result = await ensureIssue({
    signature,
    onMatch: async (existing) => {
      await commentOnIssue(
        existing.id,
        `Still present in ${TARGET_REPO} as of ${new Date().toISOString()}.\n` +
          `Current counts: **${oversized.length} oversized**, **${godNodes.length} god node${godNodes.length === 1 ? '' : 's'}**, **${orphanCount} orphan${orphanCount === 1 ? '' : 's'}**.`,
      );
    },
    onNew: () => ({
      title,
      description: sections.join('\n'),
      projectKey: 'code-health',
      labelNames: ['routine'],
      priority: 4, // Low — this is slow-burn tech debt, not urgent
    }),
  });
  console.log(`  ${result.action}: ${result.issue.identifier} — ${signature}`);
} catch (e) {
  console.error(`  ERROR on ${signature}: ${e.message}`);
  process.exit(1);
}
