// Resolve any open Linear issue matching a signature (move to Done).
// Used by detectors to auto-close issues when the underlying signal goes green.
//
// Env:
//   LINEAR_API_KEY
//   SIGNATURE        — e.g. '[ci-red:sleep_test_scheduler]'
//   RESOLVED_BY      — URL/context describing what resolved it

import {
  findOpenIssueBySignature,
  commentOnIssue,
  moveIssueToState,
} from './linear.mjs';

const { SIGNATURE, RESOLVED_BY = '(unknown)' } = process.env;

if (!SIGNATURE) throw new Error('SIGNATURE required');

const issue = await findOpenIssueBySignature(SIGNATURE);

if (!issue) {
  console.log(`No open issue matching ${SIGNATURE} — nothing to close.`);
  process.exit(0);
}

await commentOnIssue(
  issue.id,
  `Signal resolved — auto-closed by routines-hub.\n\nResolved by: ${RESOLVED_BY}\nAt: ${new Date().toISOString()}`,
);
await moveIssueToState(issue.id, 'done');

console.log(`Closed ${issue.identifier} — ${issue.url}`);
