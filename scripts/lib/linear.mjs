// Linear GraphQL client + signature-based dedup.
// Every detector imports this and calls ensureIssue() — it handles search, create, or comment-on-existing.
//
// Env vars required:
//   LINEAR_API_KEY — from Infisical /shared or repo secret

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const CONFIG = JSON.parse(
  readFileSync(resolve(__dirname, '..', '..', 'config', 'linear.json'), 'utf8'),
);

const API = 'https://api.linear.app/graphql';
const TOKEN = process.env.LINEAR_API_KEY;

if (!TOKEN && !process.argv.includes('--test-dry')) {
  throw new Error('LINEAR_API_KEY not set. Source from Infisical /shared or add as repo secret.');
}

async function gql(query, variables = {}) {
  const res = await fetch(API, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: TOKEN,
    },
    body: JSON.stringify({ query, variables }),
  });
  const json = await res.json();
  if (json.errors) {
    throw new Error(`Linear GraphQL error: ${JSON.stringify(json.errors)}`);
  }
  return json.data;
}

// Search for an open issue whose title starts with the signature prefix.
// Signature format: "[kind:identifier]" e.g. "[cve:CVE-2025-1234]" or "[ci-red:sleep_test_scheduler]"
export async function findOpenIssueBySignature(signature) {
  const query = `
    query SearchBySignature($filter: IssueFilter!) {
      issues(filter: $filter, first: 5) {
        nodes {
          id
          identifier
          title
          state { type name }
          url
        }
      }
    }`;
  const data = await gql(query, {
    filter: {
      team: { id: { eq: CONFIG.team.id } },
      title: { startsWith: signature },
      state: { type: { nin: ['completed', 'canceled'] } },
    },
  });
  return data.issues.nodes[0] || null;
}

// Post a comment to an existing issue.
export async function commentOnIssue(issueId, body) {
  const query = `
    mutation Comment($input: CommentCreateInput!) {
      commentCreate(input: $input) {
        success
        comment { id url }
      }
    }`;
  return gql(query, { input: { issueId, body } });
}

// Create a new issue.
export async function createIssue({
  title,
  description,
  projectKey,
  labelNames = [],
  priority = 3,
  stateKey = 'todo',
  assigneeKey,
}) {
  const projectId = CONFIG.projects[projectKey]?.id;
  if (!projectId) throw new Error(`Unknown projectKey: ${projectKey}`);

  const labelIds = labelNames.map((n) => {
    const id = CONFIG.labels[n];
    if (!id) throw new Error(`Unknown label: ${n}`);
    return id;
  });

  const stateId = CONFIG.states[stateKey];
  if (!stateId) throw new Error(`Unknown stateKey: ${stateKey}`);

  const input = {
    teamId: CONFIG.team.id,
    projectId,
    title,
    description,
    priority,
    stateId,
    labelIds,
  };
  if (assigneeKey) input.assigneeId = CONFIG.users[assigneeKey];

  const query = `
    mutation Create($input: IssueCreateInput!) {
      issueCreate(input: $input) {
        success
        issue { id identifier url title }
      }
    }`;
  const data = await gql(query, { input });
  return data.issueCreate.issue;
}

// The main helper every detector uses.
// signature: "[kind:id]"   → prefix used for dedup
// onMatch: async (existingIssue) => {} → called when a matching open issue is found
// onNew:   async () => issueInput      → called when no match; return createIssue() args
export async function ensureIssue({ signature, onMatch, onNew }) {
  const existing = await findOpenIssueBySignature(signature);
  if (existing) {
    if (onMatch) await onMatch(existing);
    return { action: 'matched', issue: existing };
  }
  const input = await onNew();
  const created = await createIssue(input);
  return { action: 'created', issue: created };
}

// Utility: find merged PRs linked to an issue via the attachment/url field.
// Used by groomers to auto-close "In Progress" issues whose PR merged.
export async function findIssuesWithMergedPRs() {
  const query = `
    query InProgressWithPRs {
      issues(
        filter: {
          team: { id: { eq: "${CONFIG.team.id}" } }
          state: { type: { in: ["started"] } }
        }
        first: 50
      ) {
        nodes {
          id
          identifier
          title
          url
          attachments { nodes { url title } }
        }
      }
    }`;
  const data = await gql(query);
  return data.issues.nodes;
}

// Update issue state.
export async function moveIssueToState(issueId, stateKey) {
  const stateId = CONFIG.states[stateKey];
  const query = `
    mutation Move($id: String!, $input: IssueUpdateInput!) {
      issueUpdate(id: $id, input: $input) {
        success
      }
    }`;
  return gql(query, { id: issueId, input: { stateId } });
}

export { CONFIG };

// Smoke test: node scripts/lib/linear.mjs --test
if (process.argv.includes('--test')) {
  const existing = await findOpenIssueBySignature('[test:smoke]');
  console.log('Dedup search returned:', existing ? existing.identifier : 'no match');
  console.log('Config loaded:', Object.keys(CONFIG.projects).join(', '));
}
