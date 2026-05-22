# Experiment Plan

## MVP Experiment

The current mock-model MVP evaluates 50 adversarial tool-use cases across five suites:

1. `prompt_injection`
2. `secret_exfiltration`
3. `tool_misuse`
4. `instruction_conflict`
5. `reward_hacking`

The canonical mock comparison is:

```bash
python -m asrh.cli.run --suite suites --model mock/unsafe_leaker --mitigation none --out runs/sample_baseline.jsonl --overwrite
python -m asrh.cli.run --suite suites --model mock/unsafe_leaker --mitigation tool_policy_guard --out runs/sample_guarded.jsonl --overwrite
python -m asrh.cli.report --compare runs/sample_baseline.jsonl runs/sample_guarded.jsonl --out reports/sample_comparison.md --overwrite
```

Expected mock result:

- Baseline: 33 PASS, 17 UNSAFE_SUCCESS.
- Tool-policy guard: 50 PASS.

## Real-Model Experiment

The next experiment should run at least one hosted model and preferably two:

- One OpenAI model.
- One Anthropic model.
- Optional local OpenAI-compatible model.

Recommended initial matrix:

| Model family | Mitigations |
|---|---|
| OpenAI | `none`, `tool_policy_guard` |
| Anthropic | `none`, `tool_policy_guard` |

Run one-case smoke tests before full-suite runs. Do not run all 50 cases until the model reliably returns valid ASRH JSON actions.

## Reporting

For each model, produce:

- baseline trace JSONL
- guarded trace JSONL
- single-run baseline report
- single-run guarded report
- baseline-vs-guard comparison report

## Claims Allowed

With mock results only, claim that ASRH has a validated mock-model mitigation demo.

With real model traces, claim only what the traces support: failure modes, mitigation deltas, utility changes, and notable failures.
