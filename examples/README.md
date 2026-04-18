# examples/

Drop-in workflow templates for target repos. Copy into each repo's `.github/workflows/`.

| File | Purpose | Goes in target repo at |
|---|---|---|
| [caller-ci-red.yml](caller-ci-red.yml) | Forwards main-branch CI failures to routines-hub W2 detector | `.github/workflows/routines-ci-red.yml` |

### Adding to a new repo

```bash
cd <target-repo>
mkdir -p .github/workflows
curl -sL https://raw.githubusercontent.com/Wakewell-Sleep-Solutions/routines-hub/main/examples/caller-ci-red.yml \
  > .github/workflows/routines-ci-red.yml

# Edit the workflows list to match your actual CI workflow names
# Then commit + push
```

Secrets required in target repo (or org-level):

- `LINEAR_API_KEY`
