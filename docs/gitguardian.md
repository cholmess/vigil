# GitGuardian and CI

This repo uses **intentional placeholder strings** in tests, examples, and attack fixtures (e.g. `sk_live_...`, `AKIA...`) so that:

- **canari-forensics** pattern tests still match (Stripe/AWS-style regex).
- **BreakPoint** and **Canari** still classify and block/redact them in demos.

These are not real secrets. To avoid GitGuardian CI failures we rely on path exclusions.

## Repo config (`.gitguardian.yaml`)

In the repo root, `.gitguardian.yaml` is in **version 2** format and excludes:

- `tests/**`
- `examples/**`
- `src/vigil/attacks/**`
- `**/*.bp.json`

The [GitGuardian docs](https://docs.gitguardian.com/secrets-detection/customize-detection/exclusion-rules) state that the GitHub App and ggshield honor this file when `version: 2` is set.

## If CI still fails

Some GitGuardian setups use **only** workspace-level (Dashboard) settings. If CI keeps reporting secrets on those paths:

1. Open **GitGuardian Dashboard** → your workspace → **Secrets detection** (or **Policies**).
2. Add **path exclusions** (or “ignored paths”) with the same patterns as above:
   - `tests/**`
   - `examples/**`
   - `src/vigil/attacks/**`
   - `**/*.bp.json`
3. Save and re-run the failing workflow.

After that, scans should ignore those paths and CI should pass.
