// W11: Linear Ground Truth Verifier
//
// For each open "In Progress" or "In Review" Linear issue that has
// acceptance-criteria checkboxes in its description, search the canonical
// GitHub repos via the code-search API for evidence of implementation.
// Post a verification comment on the issue, and create sub-issues in
// Ops/Linear Ground Truth for any AC without evidence (`verify-gap` label).
//
// Signature: the per-gap sub-issue prefix is `[verify-gap:<parent-issue-id>]`
// so dedup prevents duplicate gaps across runs.
//
// Env:
//   LINEAR_API_KEY   (required)
//   GITHUB_TOKEN     (required — code search against private repos)
//   DRY_RUN          (optional: "true" → log only)

import {
  CONFIG,
  ensureIssue,
  commentOnIssue,
} from '../lib/linear.mjs';

const LINEAR_API = 'https://api.linear.app/graphql';
const GITHUB_API = 'https://api.github.com';
const LINEAR_TOKEN = process.env.LINEAR_API_KEY;
const GH_TOKEN = process.env.GITHUB_TOKEN;
const DRY_RUN = String(process.env.DRY_RUN || '').toLowerCase() === 'true';

const CANONICAL_REPOS = [
  'sleep_test_scheduler',
  'WakewellWeb',
  'wakewell-hq',
  '5dsmiles-dashboard',
  'treatment-hub',
  'aria-slack-bot',
];

if (!LINEAR_TOKEN) throw new Error('LINEAR_API_KEY required');
if (!GH_TOKEN) throw new Error('GITHUB_TOKEN required');

async function linearGql(query, variables = {}) {
  const res = await fetch(LINEAR_API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: LINEAR_TOKEN },
    body: JSON.stringify({ query, variables }),
  });
  const json = await res.json();
  if (json.errors) throw new Error(`Linear: ${JSON.stringify(json.errors)}`);
  return json.data;
}

// Fetch in-progress issues across all teams (skip Ops — we don't verify ourselves)
async function fetchCandidateIssues() {
  const query = `
    query Candidates {
      issues(
        filter: {
          state: { type: { in: ["started"] } }
          team: { key: { nin: ["OPS"] } }
        }
        first: 50
      ) {
        nodes {
          id
          identifier
          title
          description
          url
          updatedAt
          team { key }
        }
      }
    }`;
  const data = await linearGql(query);
  return data.issues.nodes;
}

// Parse acceptance criteria from a Linear issue description.
// Handles three shapes in order of preference:
//   1. Checkbox bullets `- [ ] …` or `- [x] …` (explicit checked state)
//   2. Regular bullets `- …` / `* …` under a relevant section heading
//   3. (Fallback) top-level bullets if none of the above match
function parseACs(description) {
  if (!description) return [];
  const acs = [];

  // 1. Checkbox bullets
  const cb = /^[ \t]*[-*][ \t]+\[(\s|x|X)\][ \t]+(.+?)$/gm;
  let m;
  while ((m = cb.exec(description)) !== null) {
    acs.push({ checked: /[xX]/.test(m[1]), text: m[2].trim(), kind: 'checkbox' });
  }
  if (acs.length > 0) return acs;

  // 2. Bullets inside an AC-ish section (Acceptance Criteria / Deliverable /
  //    Requirements / Tasks / Goal / Checklist)
  const section = /^#{2,3}[ \t]+(Acceptance Criteria|Deliverable|Deliverables|Requirements|Tasks|Goal|Checklist|Criteria|Scope)\b[^\n]*\n([\s\S]*?)(?=^#{1,3}[ \t]|\Z)/gim;
  while ((m = section.exec(description)) !== null) {
    const body = m[2];
    const bullet = /^[ \t]*[-*][ \t]+(.+?)$/gm;
    let b;
    while ((b = bullet.exec(body)) !== null) {
      acs.push({ checked: false, text: b[1].trim(), kind: 'section-bullet' });
    }
  }
  if (acs.length > 0) return acs.slice(0, 12);

  // 3. Fallback: first ≤10 top-level bullets anywhere. Skip lines that look
  //    like sentence fragments or code references.
  const fallback = /^[ \t]*[-*][ \t]+(.{10,})$/gm;
  let count = 0;
  while ((m = fallback.exec(description)) !== null && count < 10) {
    const text = m[1].trim();
    // Skip code-only or file-path-only lines
    if (/^[`_]/.test(text)) continue;
    acs.push({ checked: false, text, kind: 'fallback-bullet' });
    count++;
  }
  return acs;
}

// Extract searchable keywords from an AC. Prefer specific identifiers over
// generic nouns — we want signal, not noise.
const COMMON_STOPS = new Set([
  // grammar
  'the', 'and', 'with', 'from', 'that', 'this', 'when', 'must', 'should', 'able', 'before', 'after',
  // too-generic nouns that match everywhere in a healthcare+TS codebase
  'user', 'users', 'data', 'page', 'form', 'service', 'services', 'server', 'client', 'api',
  'endpoint', 'endpoints', 'test', 'tests', 'build', 'report', 'file', 'files',
  'format', 'validation', 'validator', 'check', 'handler', 'route', 'routes',
  'admin', 'mapping', 'table', 'logs', 'value', 'error', 'errors', 'passes',
  'allow', 'existing', 'primary', 'secondary', 'list', 'index', 'content',
  'entity', 'flow', 'flows', 'regressions', 'real',
]);

function extractKeywords(acText) {
  const kw = new Set();

  // Quoted strings (single, double, backtick)
  const quoted = acText.match(/['"`]([^'"`]+)['"`]/g) || [];
  for (const q of quoted) kw.add(q.slice(1, -1));

  // File paths — grab `foo/bar.ext`
  const paths = acText.match(/[a-zA-Z_][\w-]*\/[\w/.-]+\.(ts|tsx|js|jsx|mjs|py|md|sql|json)/g) || [];
  for (const p of paths) kw.add(p);

  // camelCase / PascalCase identifiers (≥ 4 chars)
  const ids = acText.match(/\b[A-Z][a-zA-Z0-9]{3,}|[a-z][a-zA-Z]*[A-Z][a-zA-Z0-9]+\b/g) || [];
  for (const i of ids) kw.add(i);

  // snake_case identifiers
  const snake = acText.match(/\b[a-z]+(?:_[a-z0-9]+)+\b/g) || [];
  for (const s of snake) kw.add(s);

  // Domain-looking emails
  const emails = acText.match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || [];
  for (const e of emails) kw.add(e.split('@')[0]);

  // Drop stopwords + very short tokens
  const filtered = Array.from(kw).filter(
    (k) => k.length >= 4 && !COMMON_STOPS.has(k.toLowerCase()),
  );

  // If still empty, take significant 5+ char words (non-stopword)
  if (filtered.length === 0) {
    const nouns = acText.toLowerCase().match(/\b[a-z]{6,}\b/g) || [];
    for (const n of nouns) if (!COMMON_STOPS.has(n)) filtered.push(n);
  }

  // De-dupe case-insensitively, cap to 3 to stay inside GitHub rate limit
  const seen = new Set();
  const out = [];
  for (const k of filtered) {
    const key = k.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(k);
    if (out.length >= 3) break;
  }
  return out;
}

// GitHub code search against the Wakewell-Sleep-Solutions org.
// Returns count + up to 3 file:line snippets.
async function searchGitHub(keyword) {
  const q = encodeURIComponent(`org:Wakewell-Sleep-Solutions "${keyword}"`);
  const url = `${GITHUB_API}/search/code?q=${q}&per_page=3`;
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${GH_TOKEN}`,
      Accept: 'application/vnd.github+json',
    },
  });
  if (!res.ok) {
    return { total: 0, snippets: [], error: `HTTP ${res.status}` };
  }
  const json = await res.json();
  return {
    total: json.total_count || 0,
    snippets: (json.items || []).map((it) => ({
      repo: it.repository?.name,
      path: it.path,
      url: it.html_url,
    })),
  };
}

function verdictFor(matches) {
  if (matches.length === 0) return 'NOT_FOUND';
  // Require at least one SPECIFIC keyword match (≤200 hits = specific; >200 = too generic)
  const specificHits = matches.filter((m) => m.result.total > 0 && m.result.total <= 200);
  const anySpecific = specificHits.length > 0;
  const allKeywordsMatched = matches.every((m) => m.result.total > 0);
  if (allKeywordsMatched && anySpecific) return 'VERIFIED';
  if (anySpecific) return 'PARTIAL';
  if (matches.some((m) => m.result.total > 0)) return 'PARTIAL'; // only generic matches
  return 'NOT_FOUND';
}

const EMOJI = { VERIFIED: '✅', PARTIAL: '⚠️', NOT_FOUND: '❌', ALREADY_CHECKED: '✔️' };

function formatReport(issue, results) {
  const lines = [`## Ground Truth Verification — ${new Date().toISOString().slice(0, 10)}`, ''];
  const counts = { VERIFIED: 0, PARTIAL: 0, NOT_FOUND: 0, ALREADY_CHECKED: 0 };

  for (const r of results) {
    counts[r.verdict]++;
    lines.push(`${EMOJI[r.verdict]} **${r.verdict}** — ${r.ac.text}`);
    if (r.verdict === 'ALREADY_CHECKED') {
      lines.push('   (marked complete in description)');
    } else {
      for (const m of r.matches) {
        if (m.result.total > 0) {
          const top = m.result.snippets[0];
          lines.push(`   - \`${m.keyword}\`: ${m.result.total} hits${top ? ` (e.g. ${top.repo}/${top.path})` : ''}`);
        } else {
          lines.push(`   - \`${m.keyword}\`: no hits`);
        }
      }
    }
    lines.push('');
  }

  const total = results.length;
  const done = counts.VERIFIED + counts.ALREADY_CHECKED;
  lines.push(`**Score:** ${done}/${total} criteria verified`);
  if (counts.NOT_FOUND > 0) {
    lines.push(`**Recommendation:** ${counts.NOT_FOUND} criteria missing. Sub-issues created in Ops/Linear Ground Truth.`);
  } else if (counts.PARTIAL > 0) {
    lines.push(`**Recommendation:** ${counts.PARTIAL} criteria partial — review for completeness.`);
  } else if (counts.VERIFIED === total) {
    lines.push(`**Recommendation:** All criteria verified. Move to Done?`);
  }
  lines.push('');
  lines.push('_Auto-generated by routines-hub ground-truth verifier (W11). Keyword-based heuristic — review before acting._');
  return lines.join('\n');
}

async function run() {
  console.log(`DRY_RUN=${DRY_RUN}`);
  const issues = await fetchCandidateIssues();
  console.log(`Found ${issues.length} "In Progress" candidate issues`);

  let processed = 0;
  let verified = 0;
  let gapsCreated = 0;

  for (const issue of issues) {
    const acs = parseACs(issue.description);
    if (acs.length === 0) {
      // No parseable ACs — skip
      continue;
    }

    console.log(`\n[${issue.identifier}] ${issue.title} — ${acs.length} AC(s)`);

    const results = [];
    for (const ac of acs) {
      if (ac.checked) {
        results.push({ ac, verdict: 'ALREADY_CHECKED', matches: [] });
        continue;
      }

      const keywords = extractKeywords(ac.text);
      if (keywords.length === 0) {
        results.push({ ac, verdict: 'NOT_FOUND', matches: [] });
        continue;
      }

      const matches = [];
      for (const kw of keywords) {
        const result = await searchGitHub(kw);
        matches.push({ keyword: kw, result });
        // Respect GitHub's 30 req/min code-search rate limit
        await new Promise((r) => setTimeout(r, 2200));
      }

      const verdict = verdictFor(matches);
      results.push({ ac, verdict, matches });
    }

    const verdicts = results.map((r) => r.verdict);
    const allVerified = verdicts.every((v) => v === 'VERIFIED' || v === 'ALREADY_CHECKED');
    const hasGaps = verdicts.includes('NOT_FOUND');

    if (allVerified) verified++;
    processed++;

    const body = formatReport(issue, results);
    if (DRY_RUN) {
      console.log('  DRY_RUN — would post:\n' + body.split('\n').map((l) => '    ' + l).join('\n'));
      continue;
    }

    try {
      await commentOnIssue(issue.id, body);
    } catch (e) {
      console.error(`  Failed to comment on ${issue.identifier}: ${e.message}`);
    }

    // Create gap sub-issue(s) in Ops for each NOT_FOUND AC
    for (const r of results) {
      if (r.verdict !== 'NOT_FOUND') continue;
      const sig = `[verify-gap:${issue.identifier}:${r.ac.text.slice(0, 40).replace(/[^a-z0-9]+/gi, '-').toLowerCase()}]`;
      const title = `${sig} Missing evidence — ${r.ac.text.slice(0, 100)}`;
      try {
        const out = await ensureIssue({
          signature: sig,
          onMatch: async () => {
            // Already open — don't double-create; the verifier's weekly comment is enough
          },
          onNew: () => ({
            title,
            description: [
              `Parent issue: [${issue.identifier}](${issue.url})`,
              '',
              `**Missing acceptance criterion:** ${r.ac.text}`,
              '',
              `Ground Truth Verifier found no code evidence for this AC.`,
              `Searched keywords: ${r.matches.map((m) => '`' + m.keyword + '`').join(', ')}`,
              '',
              `If this is actually implemented, add the keywords to the AC text so next scan can find it.`,
              `If not implemented, use this issue to scope + ship it.`,
            ].join('\n'),
            projectKey: 'linear-ground-truth',
            labelNames: ['routine', 'verify-gap'],
            priority: 3,
          }),
        });
        if (out.action === 'created') gapsCreated++;
      } catch (e) {
        console.error(`  Failed to create gap issue: ${e.message}`);
      }
    }
  }

  console.log(`\n=== Summary ===`);
  console.log(`Processed:   ${processed}`);
  console.log(`Verified:    ${verified}`);
  console.log(`Gaps created: ${gapsCreated}`);
}

run().catch((e) => {
  console.error('Ground Truth failed:', e);
  process.exit(1);
});
