// Daily Linear Scrub (G1).
// Three checks:
//   1. Auto-close "In Progress" issues whose linked PR is merged
//   2. Comment on stale "In Progress" (>14d no update)
//   3. Dedup by signature prefix — close duplicates, keep the oldest
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

async function run() {
  const summary = {
    checked: 0,
    closed_merged_pr: [],
    stale_commented: [],
    duplicates_closed: [],
    errors: [],
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
          await commentOnIssue(
            issue.id,
            `Auto-closed by groomer-linear-scrub — linked PR merged: ${pr.url}\nAt: ${status.merged_at}`,
          );
          await moveIssueToState(issue.id, 'done');
          summary.closed_merged_pr.push({ id: issue.identifier, pr: pr.url });
          console.log(`CLOSED ${issue.identifier} (merged ${pr.url})`);
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
      await commentOnIssue(
        issue.id,
        `🕸️ Auto-stale check: no update in **${days} days**.\n\nReclaim, demote to Backlog, or archive?`,
      );
      summary.stale_commented.push({ id: issue.identifier, days });
      console.log(`STALE ${issue.identifier} (${days}d)`);
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
        await commentOnIssue(
          dup.id,
          `Duplicate of ${keep.identifier} (${keep.url}) — auto-closed by groomer.`,
        );
        await moveIssueToState(dup.id, 'duplicate');
        summary.duplicates_closed.push({ closed: dup.identifier, kept: keep.identifier, sig });
        console.log(`DEDUP ${dup.identifier} → kept ${keep.identifier}`);
      } catch (e) {
        summary.errors.push({ id: dup.identifier, error: e.message });
      }
    }
  }

  console.log('\n=== Summary ===');
  console.log(JSON.stringify(summary, null, 2));
}

run().catch((e) => {
  console.error('Groomer failed:', e);
  process.exit(1);
});
