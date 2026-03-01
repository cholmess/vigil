# Vigil Release Checklist

Use this checklist before tagging a release or announcing a demo-ready build.

## CI/Quality

- [ ] `CI` workflow green on `main`.
- [ ] `LLM Safety Gate` workflow green on `main`.
- [ ] `Demo E2E Smoke` workflow green on `main`.
- [ ] `demo-e2e-artifacts` includes:
  - [ ] `examples/full_loop_demo/.vigil-data/ci/demo-e2e.log`
  - [ ] `examples/full_loop_demo/.vigil-data/train/train-bundle.tar.gz`
  - [ ] `examples/full_loop_demo/.vigil-data/network/intel/feed.json`

## Functional Smoke

- [ ] `examples/full_loop_demo/run_loop.sh` completes.
- [ ] `examples/full_loop_demo/run_end_to_end.sh` completes.
- [ ] `vigil test --prompt-file examples/full_loop_demo/hardened_prompt.txt --attacks-dir tests/attacks --report` passes.

## Training Flow

- [ ] `vigil train bootstrap --out-dir ./.vigil-data/train --network-dir ./.vigil-data/network --val-ratio 0.2 --strict` passes.
- [ ] `vigil train verify-bundle --bundle-file ./.vigil-data/train/train-bundle.tar.gz` passes.
- [ ] `vigil train check-split --train-file ./.vigil-data/train/train.jsonl --val-file ./.vigil-data/train/val.jsonl` passes.
- [ ] `vigil train doctor --corpus-file ./.vigil-data/train/corpus.jsonl --max-imbalance 5` passes.

## Release Metadata

- [ ] `README.md` command examples match current CLI.
- [ ] `docs/cli-reference.md` includes all shipped commands.
- [ ] Version in `pyproject.toml` is correct.
- [ ] Changelog/release notes summarize key changes.
