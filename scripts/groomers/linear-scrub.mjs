// Daily Linear Scrub (G1).
// Four checks:
//   1. Auto-close "In Progress" issues whose linked PR is merged
//   2. Comment on stale "In Progress" (>14d no update)
//   3. Dedup by signature prefix — close duplicates, keep the oldest
//   4. Close-on-signal-gone — close auto-generated issues whose underlying
//      signal has aged past its detector cadence. All auto-detectors run
//      daily, so the policy is uniform (3d without a "Still present" heartbeat):
//        [cve:*]         — W5 npm audit
//        [code-health:*] — W8 code health
//        [deps:majors:*] — W10 outdated majors
//        [semgrep:*]     — W6 semgrep
//        [dead-code:*]   — W7 knip
//        [dupes:*]       — W9 jscpd
//        [discipline:*]  — W12 discipline
//      Legacy datestamped signatures ([foo:repo:YYYY-MM] or YYYY-Www) close
//      once the stamped period is 14d+ old — lets old issues retire cleanly.
//
// Env:
//   LINEAR_API_KEY (required)
//   GITHUB_TOKEN   (optional, for PR-merged check)
//   DRY_RUN=1      (optional, log actions without mutating)
//
// Posts a summary JSON so a downstream Slack/Obsidian step can consume it.

import {
  CONFIG,
  commentOnIssue,
  moveIssueToState,
} from '../lib/linear.mjs';

const API = 'https://api.linear.app/graphql';
const TOKEN = process.env.LINEAR_API_KEY;
const GH_TOKEN = process.env.GITHUB_TOKEN;
const DRY_RUN = process.env.DRY_RUN === '1' || process.env.DRY_RUN === 'true';

async function gql(query, variables) {
  const res = await fetch(API, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: TOKEN },
    body: JSON.stringify({ query, variables }),
  });
  const json = await res.json();
  if (json.errors) throw new Error(JSON.stringify(json.errors));
  return json.data;
}

// Fetch all "In Progress" + "In Review" issues across all teams with attachments
async function fetchActiveIssues() {
  const query = `
    query ActiveIssues {
      issues(
        filter: { state: { type: { in: ["started"] } } }
        first: 100
        orderBy: updatedAt
      ) {
        nodes {
          id
          identifier
          title
          url
          updatedAt
          team { key }
          state { type name }
          attachments { nodes { url title sourceType } }
        }
      }
    }`;
  const data = await gql(query);
  return data.issues.nodes;
}

// Given a PR URL, ask GitHub if it's merged
async function isPrMerged(prUrl) {
  if (!GH_TOKEN) return null;
  const m = prUrl.match(/github\.com\/([^/]+)\/([^/]+)\/pull\/(\d+)/);
  if (!m) return null;
  const [, owner, repo, number] = m;
  try {
    const res = await fetch(
      `https://api.github.com/repos/${owner}/${repo}/pulls/${number}`,
      { headers: { Authorization: `Bearer ${GH_TOKEN}`, Accept: 'application/vnd.github+json' } },
    );
    if (!res.ok) return null;
    const pr = await res.json();
    return { merged: pr.merged === true, merged_at: pr.merged_at, url: prUrl };
  } catch {
    return null;
  }
}

const SIGNATURE_RE = /^(\[[a-z][a-z0-9-]*:[^\]]+\])/;
const STILL_PRESENT_RE = /^Still present in /m;

// Fetch comments for a single issue (used to check heartbeat freshness).
async function fetchIssueComments(issueId) {
  const query = `
    query IssueComments($id: String!) {
      issue(id: $id) {
        comments(first: 50) {
          nodes { id body createdAt }
        }
      }
    }`;
  const data = await gql(query, { id: issueId });
  return data?.issue?.comments?.nodes || [];
}

// Parse week (YYYY-Www) or month (YYYY-MM) stamp from a signature.
// Returns a Date anchored at the start of that period, or null if no stamp.
function parseDateStamp(sig) {
  const weekMatch = sig.match(/:(\d{4})-W(\d{1,2})\]/);
  if (weekMatch) {
    const y = Number(weekMatch[1]);
    const w = Number(weekMatch[2]);
    // ISO week 1 = week with the first Thursday of the year.
    // Good-enough approximation: Jan 1 + (w-1)*7 days.
    const jan1 = new Date(Date.UTC(y, 0, 1));
    return new Date(jan1.getTime() + (w - 1) * 7 * 86400000);
  }
  const monthMatch = sig.match(/:(\d{4})-(\d{2})\]/);
  if (monthMatch) {
    const y = Number(monthMatch[1]);
    const m = Number(monthMatch[2]);
    return new Date(Date.UTC(y, m - 1, 1));
  }
  return null;
}

// Policy map for close-on-signal-gone. Returns null for signatures we don't groom.
//
// All auto-routines now run daily, so the default heartbeat threshold is 3d.
// Datestamped legacy signatures (e.g. [code-health:repo:2026-W15]) retire
// 14d after the stamped period via the datestamp fallback.
function gonePolicy(sig) {
  const hasDateStamp =
    /:(\d{4})-W\d{1,2}\]/.test(sig) || /:(\d{4})-\d{2}\]/.test(sig);

  if (sig.startsWith('[cve:')) {
    return {
      kind: 'heartbeat',
      days: 3,
      note: 'CVE not detected in recent daily scans',
    };
  }
  if (sig.startsWith('[code-health:')) {
    if (hasDateStamp) {
      return {
        kind: 'datestamp',
        days: 14,
        note: 'Legacy dated code-health snapshot retired',
      };
    }
    return {
      kind: 'heartbeat',
      days: 3,
      note: 'Code-health signals cleared in recent daily scans',
    };
  }
  if (sig.startsWith('[deps:majors:')) {
    if (hasDateStamp) {
      return {
        kind: 'datestamp',
        days: 14,
        note: 'Legacy dated outdated-majors snapshot retired',
      };
    }
    return {
      kind: 'heartbeat',
      days: 3,
      note: 'All major updates landed (no recent detection)',
    };
  }
  if (sig.startsWith('[semgrep:')) {
    return {
      kind: 'heartbeat',
      days: 3,
      note: 'Semgrep findings cleared in recent daily scans',
    };
  }
  if (sig.startsWith('[dead-code:')) {
    return {
      kind: 'heartbeat',
      days: 3,
      note: 'Dead-code items cleared in recent daily scans',
    };
  }
  if (sig.startsWith('[dupes:')) {
    return {
      kind: 'heartbeat',
      days: 3,
      note: 'Code duplication dropped below threshold',
    };
  }
  if (sig.startsWith('[discipline:')) {
    return {
      kind: 'heartbeat',
      days: 3,
      note: 'Discipline violations cleared in recent daily scans',
    };
  }
  return null;
}

async function run() {
  const summary = {
    checked: 0,
    closed_merged_pr: [],
    stale_commented: [],
    duplicates_closed: [],
    closed_signal_gone: [],
    errors: [],
    dry_run: DRY_RUN,
  };

  const active = await fetchActiveIssues();
  summary.checked = active.length;

  // CHECK 1: Auto-close when PR merged
  for (const issue of active) {
    const prAttachments = (issue.attachments?.nodes || []).filter((a) =>
      /github\.com\/.+\/pull\/\d+/.test(a.url || ''),
    );
    for (const pr of prAttachments) {
      const status = await isPrMerged(pr.url);
      if (status?.merged) {
        try {
          if (!DRY_RUN) {
            await commentOnIssue(
              issue.id,
              `Auto-closed by groomer-linear-scrub — linked PR merged: ${pr.url}\nAt: ${status.merged_at}`,
            );
            await moveIssueToState(issue.id, 'done');
          }
          summary.closed_merged_pr.push({ id: issue.identifier, pr: pr.url });
          console.log(`${DRY_RUN ? 'DRY-RUN ' : ''}CLOSED ${issue.identifier} (merged ${pr.url})`);
        } catch (e) {
          summary.errors.push({ id: issue.identifier, error: e.message });
        }
        break;
      }
    }
  }

  // CHECK 2: Stale "In Progress" (>14d no update)
  const staleThreshold = Date.now() - 14 * 24 * 60 * 60 * 1000;
  for (const issue of active) {
    const updated = new Date(issue.updatedAt).getTime();
    if (updated > staleThreshold) continue;
    // Skip issues we just closed in check 1
    if (summary.closed_merged_pr.find((x) => x.id === issue.identifier)) continue;
    try {
      const days = Math.floor((Date.now() - updated) / 86400000);
      if (!DRY_RUN) {
        await commentOnIssue(
          issue.id,
          `🕸️ Auto-stale check: no update in **${days} days**.\n\nReclaim, demote to Backlog, or archive?`,
        );
      }
      summary.stale_commented.push({ id: issue.identifier, days });
      console.log(`${DRY_RUN ? 'DRY-RUN ' : ''}STALE ${issue.identifier} (${days}d)`);
    } catch (e) {
      summary.errors.push({ id: issue.identifier, error: e.message });
    }
  }

  // CHECK 3: Signature-prefix dedup across Ops team
  const query = `
    query OpsOpen {
      issues(
        filter: {
          team: { id: { eq: "${CONFIG.team.id}" } }
          state: { type: { nin: ["completed", "canceled"] } }
        }
        first: 200
        orderBy: createdAt
      ) {
        nodes { id identifier title url createdAt }
      }
    }`;
  const opsData = await gql(query);
  const opsIssues = opsData.issues.nodes;

  const bySignature = new Map();
  for (const issue of opsIssues) {
    const m = issue.title.match(SIGNATURE_RE);
    if (!m) continue;
    const sig = m[1];
    if (!bySignature.has(sig)) bySignature.set(sig, []);
    bySignature.get(sig).push(issue);
  }

  for (const [sig, issues] of bySignature) {
    if (issues.length < 2) continue;
    // Keep oldest, close the rest
    const sorted = [...issues].sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
    const keep = sorted[0];
    for (const dup of sorted.slice(1)) {
      try {
        if (!DRY_RUN) {
          await commentOnIssue(
            dup.id,
            `Duplicate of ${keep.identifier} (${keep.url}) — auto-closed by groomer.`,
          );
          await moveIssueToState(dup.id, 'duplicate');
        }
        summary.duplicates_closed.push({ closed: dup.identifier, kept: keep.identifier, sig });
        console.log(`${DRY_RUN ? 'DRY-RUN ' : ''}DEDUP ${dup.identifier} → kept ${keep.identifier}`);
      } catch (e) {
        summary.errors.push({ id: dup.identifier, error: e.message });
      }
    }
  }

  // CHECK 4: Close-on-signal-gone for auto-generated signatures
  const now = Date.now();
  const alreadyClosedIds = new Set([
    ...summary.closed_merged_pr.map((x) => x.id),
    ...summary.duplicates_closed.map((x) => x.closed),
  ]);

  for (const issue of opsIssues) {
    if (alreadyClosedIds.has(issue.identifier)) continue;
    const m = issue.title.match(SIGNATURE_RE);
    if (!m) continue;
    const sig = m[1];
    const policy = gonePolicy(sig);
    if (!policy) continue;

    let referenceTime;
    let referenceSource;
    if (policy.kind === 'datestamp') {
      const stamped = parseDateStamp(sig);
      if (stamped) {
        referenceTime = stamped.getTime();
        referenceSource = `signature datestamp ${stamped.toISOString().slice(0, 10)}`;
      } else {
        referenceTime = new Date(issue.createdAt).getTime();
        referenceSource = `issue createdAt ${issue.createdAt}`;
      }
    } else {
      // heartbeat: look for "Still present in ..." comments from detector re-runs
      let comments;
      try {
        comments = await fetchIssueComments(issue.id);
      } catch (e) {
        summary.errors.push({ id: issue.identifier, error: `fetch comments: ${e.message}` });
        continue;
      }
      const heartbeats = comments.filter((c) => STILL_PRESENT_RE.test(c.body));
      if (heartbeats.length > 0) {
        const latest = heartbeats
          .map((c) => new Date(c.createdAt).getTime())
          .sort((a, b) => b - a)[0];
        referenceTime = latest;
        referenceSource = `latest heartbeat ${new Date(latest).toISOString()}`;
      } else {
        referenceTime = new Date(issue.createdAt).getTime();
        referenceSource = `issue createdAt ${issue.createdAt} (no heartbeats recorded)`;
      }
    }

    const ageDays = Math.floor((now - referenceTime) / 86400000);
    if (ageDays < policy.days) continue;

    try {
      if (!DRY_RUN) {
        await commentOnIssue(
          issue.id,
          `Auto-closed by groomer-linear-scrub — ${policy.note}.\n\nReference: ${referenceSource} (${ageDays}d ago, threshold ${policy.days}d).`,
        );
        await moveIssueToState(issue.id, 'done');
      }
      summary.closed_signal_gone.push({
        id: issue.identifier,
        sig,
        kind: policy.kind,
        age_days: ageDays,
        threshold_days: policy.days,
      });
      console.log(
        `${DRY_RUN ? 'DRY-RUN ' : ''}SIGNAL-GONE ${issue.identifier} (${sig}, ${ageDays}d ≥ ${policy.days}d)`,
      );
    } catch (e) {
      summary.errors.push({ id: issue.identifier, error: e.message });
    }
  }

  console.log('\n=== Summary ===');
  console.log(JSON.stringify(summary, null, 2));
}

run().catch((e) => {
  console.error('Groomer failed:', e);
  process.exit(1);
});
