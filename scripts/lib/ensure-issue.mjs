// Called by the create-linear-issue-dedup composite action.
// Reads env (SIGNATURE, TITLE, BODY, PROJECT, LABELS, PRIORITY), calls ensureIssue, emits GH Action outputs.

import { appendFileSync } from 'node:fs';
import { ensureIssue, commentOnIssue } from './linear.mjs';

const {
  SIGNATURE,
  TITLE,
  BODY,
  PROJECT,
  LABELS = 'routine',
  PRIORITY = '3',
  GITHUB_OUTPUT,
} = process.env;

if (!SIGNATURE || !TITLE || !BODY || !PROJECT) {
  throw new Error('Missing required env: SIGNATURE, TITLE, BODY, PROJECT');
}

if (!TITLE.startsWith(SIGNATURE)) {
  throw new Error(`TITLE must start with SIGNATURE ('${SIGNATURE}'). Got: '${TITLE}'`);
}

const labelNames = LABELS.split(',').map((s) => s.trim()).filter(Boolean);
const priority = Number.parseInt(PRIORITY, 10);

const result = await ensureIssue({
  signature: SIGNATURE,
  onMatch: async (existing) => {
    const stamp = new Date().toISOString();
    await commentOnIssue(
      existing.id,
      `**Recurrence detected — ${stamp}**\n\n${BODY}`,
    );
    console.log(`Matched existing issue ${existing.identifier} (${existing.url}) — posted comment.`);
  },
  onNew: () => ({
    title: TITLE,
    description: BODY,
    projectKey: PROJECT,
    labelNames,
    priority,
  }),
});

const action = result.action;
const identifier = result.issue.identifier;
const url = result.issue.url;

console.log(`${action.toUpperCase()}: ${identifier} — ${url}`);

if (GITHUB_OUTPUT) {
  appendFileSync(GITHUB_OUTPUT, `action=${action}\n`);
  appendFileSync(GITHUB_OUTPUT, `identifier=${identifier}\n`);
  appendFileSync(GITHUB_OUTPUT, `url=${url}\n`);
}
