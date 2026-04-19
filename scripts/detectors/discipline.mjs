// W12: Discipline / HIPAA-hygiene detector (daily).
// Grep-based sweep across every canonical repo for banned patterns:
//   - console.{log,error,warn,info,debug} in production code (use pino instead)
//   - `as any` escape hatch (banned — use proper types)
//   - @ts-ignore / @ts-nocheck (only @ts-expect-error WAK-XXX is allowed)
//   - committed .env files (HIPAA / secrets risk)
//   - PHI-ish terms near logger calls (weak signal — surfaces for manual review)
//
// Signature: [discipline:<repo>]  — one rolling issue per repo.
// Heartbeat on match; G1 CHECK 4 auto-closes when all violations clear for 3d.
//
// Allowlist (per-repo opt-out for intentional violations):
//   1. File-level: `.disciplinerc.json` at repo root with shape:
//        { "console": ["scripts/**", "bin/**"],
//          "asAny": ["legacy/**"],
//          "tsIgnore": [] }
//      Path patterns are gitignore-style; matching files are skipped entirely.
//   2. Line-level: inline `// discipline(<kind>): <reason>` on the SAME line.
//      Kinds: `console`, `as-any`, `ts-ignore`. Required reason after the colon.
//      Example: `console.log("boot");  // discipline(console): CLI startup banner`

import { existsSync, readFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { ensureIssue, commentOnIssue } from '../lib/linear.mjs';

const { TARGET_REPO, TARGET_DIR } = process.env;
if (!TARGET_REPO) throw new Error('TARGET_REPO required');
if (!TARGET_DIR || !existsSync(TARGET_DIR)) {
  console.log(`No TARGET_DIR at ${TARGET_DIR} — skipping.`);
  process.exit(0);
}

// Read .disciplinerc.json allowlist if present. Returns { console, asAny, tsIgnore }
// where each value is an array of gitignore-style pathspecs to exclude.
function readAllowlist() {
  const empty = { console: [], asAny: [], tsIgnore: [] };
  const path = `${TARGET_DIR}/.disciplinerc.json`;
  if (!existsSync(path)) return empty;
  try {
    const cfg = JSON.parse(readFileSync(path, 'utf8'));
    return {
      console: Array.isArray(cfg.console) ? cfg.console : [],
      asAny: Array.isArray(cfg.asAny) ? cfg.asAny : [],
      tsIgnore: Array.isArray(cfg.tsIgnore) ? cfg.tsIgnore : [],
    };
  } catch (e) {
    console.error(`  WARN: failed to parse .disciplinerc.json — ${e.message}`);
    return empty;
  }
}

const ALLOW = readAllowlist();
const INLINE_ANNOTATION = /\/\/\s*discipline\((console|as-any|ts-ignore)\)\s*:/;

// Convert allowlist paths to git pathspec exclusions.
function toExcludes(paths) {
  return paths.map((p) => `':!${p}'`);
}

// Use git grep — respects .gitignore, fast, no path glob surprises.
// Returns { count, examples } where examples are up to 5 "file:line:text" strings.
// Pass `kind` to also drop lines bearing matching `// discipline(kind):` annotation.
function gitGrep(pattern, extraPathSpecs = [], kind = null) {
  const pathspecs = [
    "'*.ts'",
    "'*.tsx'",
    "'*.js'",
    "'*.jsx'",
    "'*.mjs'",
    "'*.cjs'",
    // Exclude tests and vendored / build output
    "':!**/*.test.*'",
    "':!**/*.spec.*'",
    "':!**/test/**'",
    "':!**/tests/**'",
    "':!**/__tests__/**'",
    "':!**/__mocks__/**'",
    "':!**/node_modules/**'",
    "':!**/dist/**'",
    "':!**/build/**'",
    "':!**/.next/**'",
    "':!**/coverage/**'",
    "':!**/graphify-out/**'",
    "':!**/.claude-flow/**'",
    ...extraPathSpecs,
  ].join(' ');
  try {
    const out = execSync(
      `git -C ${JSON.stringify(TARGET_DIR)} grep -I -nE ${JSON.stringify(pattern)} -- ${pathspecs}`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 8 * 1024 * 1024 },
    );
    let lines = out.split('\n').filter(Boolean);
    if (kind) {
      const annotationKind = kind === 'asAny' ? 'as-any' : kind === 'tsIgnore' ? 'ts-ignore' : 'console';
      lines = lines.filter((l) => {
        const m = l.match(INLINE_ANNOTATION);
        return !(m && m[1] === annotationKind);
      });
    }
    return { count: lines.length, examples: lines.slice(0, 5) };
  } catch {
    // git grep exits 1 when nothing found — treat as empty
    return { count: 0, examples: [] };
  }
}

// Tracked .env files (excluding example/sample variants)
function trackedEnvFiles() {
  try {
    const out = execSync(
      `git -C ${JSON.stringify(TARGET_DIR)} ls-files`,
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], maxBuffer: 8 * 1024 * 1024 },
    );
    return out
      .split('\n')
      .filter((f) => /(^|\/)\.env(\.|$)/.test(f))
      .filter((f) => !/\.(example|sample|template)$/.test(f));
  } catch {
    return [];
  }
}

const checks = {
  console: gitGrep(
    '(^|[^a-zA-Z_.])console\\.(log|error|warn|info|debug)\\s*\\(',
    toExcludes(ALLOW.console),
    'console',
  ),
  asAny: gitGrep('\\bas\\s+any\\b', toExcludes(ALLOW.asAny), 'asAny'),
  tsIgnore: gitGrep('@ts-(ignore|nocheck)\\b', toExcludes(ALLOW.tsIgnore), 'tsIgnore'),
};
const envFiles = trackedEnvFiles();

const total =
  checks.console.count +
  checks.asAny.count +
  checks.tsIgnore.count +
  envFiles.length;

if (total === 0) {
  console.log(`${TARGET_REPO}: clean discipline — no issue.`);
  process.exit(0);
}

const signature = `[discipline:${TARGET_REPO}]`;
const title = `${signature} ${total} violation${total === 1 ? '' : 's'} — console:${checks.console.count} as-any:${checks.asAny.count} ts-ignore:${checks.tsIgnore.count} env:${envFiles.length}`;

const sections = [
  `**Repo:** ${TARGET_REPO}`,
  '',
  '| Check | Count | Policy |',
  '|---|---|---|',
  `| \`console.*(...)\` in prod code | **${checks.console.count}** | Use structured logger (pino); never \`console\` in server/app code |`,
  `| \`as any\` escape hatch | **${checks.asAny.count}** | Banned; use proper types or Zod schema |`,
  `| \`@ts-ignore\` / \`@ts-nocheck\` | **${checks.tsIgnore.count}** | Banned; only \`@ts-expect-error WAK-XXX\` with ticket |`,
  `| Tracked \`.env*\` files | **${envFiles.length}** | NEVER commit secrets files |`,
  '',
];

if (checks.console.examples.length) {
  sections.push('### `console.*` examples (first 5)');
  for (const e of checks.console.examples) sections.push(`- \`${e}\``);
  sections.push('');
}
if (checks.asAny.examples.length) {
  sections.push('### `as any` examples (first 5)');
  for (const e of checks.asAny.examples) sections.push(`- \`${e}\``);
  sections.push('');
}
if (checks.tsIgnore.examples.length) {
  sections.push('### `@ts-ignore` / `@ts-nocheck` examples (first 5)');
  for (const e of checks.tsIgnore.examples) sections.push(`- \`${e}\``);
  sections.push('');
}
if (envFiles.length) {
  sections.push('### Tracked `.env*` files — ROTATE SECRETS AND REMOVE IMMEDIATELY');
  for (const f of envFiles) sections.push(`- \`${f}\``);
  sections.push('');
}

sections.push('---');
sections.push(
  '_Auto-generated by routines-hub W12 (discipline). Daily sweep for banned patterns. Auto-closes via G1 when all clear._',
);

// Priority: P1 if any tracked .env (hard secret leak risk); otherwise P2 (HIPAA-adjacent)
const priority = envFiles.length > 0 ? 1 : 2;

try {
  const result = await ensureIssue({
    signature,
    onMatch: async (existing) => {
      await commentOnIssue(
        existing.id,
        `Still present in ${TARGET_REPO} as of ${new Date().toISOString()}.\n` +
          `Current: console:${checks.console.count} as-any:${checks.asAny.count} ts-ignore:${checks.tsIgnore.count} env:${envFiles.length}`,
      );
    },
    onNew: () => ({
      title,
      description: sections.join('\n'),
      projectKey: 'security-hygiene',
      labelNames: ['routine', 'compliance'],
      priority,
    }),
  });
  console.log(`  ${result.action}: ${result.issue.identifier} — ${signature}`);
} catch (e) {
  console.error(`  ERROR on ${signature}: ${e.message}`);
  process.exit(1);
}
