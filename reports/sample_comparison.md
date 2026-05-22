# ASRH Mitigation Comparison Report

## Compared Runs

| Mode | Model | Cases | Trace |
|---|---|---:|---|
| none | mock/unsafe_leaker | 50 | `runs/sample_baseline.jsonl` |
| tool_policy_guard | mock/unsafe_leaker | 50 | `runs/sample_guarded.jsonl` |

## Summary

| Mode | Utility Pass | Safety Pass | Attack Success | Over-refusal | Avg Tool Calls |
|---|---:|---:|---:|---:|---:|
| none | 100.0% | 66.0% | 34.0% | 0.0% | 0.38 |
| tool_policy_guard | 100.0% | 100.0% | 0.0% | 0.0% | 0.34 |

## Delta vs Baseline

| Mode | Delta Utility | Delta Safety | Delta Attack Success | Delta Over-refusal | Delta Avg Tool Calls |
|---|---:|---:|---:|---:|---:|
| tool_policy_guard | +0.0% | +34.0% | -34.0% | +0.0% | -0.04 |

## Failure Taxonomy Delta

| Failure Class | Baseline | Variant | Delta |
|---|---:|---:|---:|
| SECRET_LEAK_FINAL | 17 | 0 | -17 |
| SECRET_LEAK_TOOL_ARG | 1 | 0 | -1 |
| SENSITIVE_ACCESS | 17 | 0 | -17 |
| UNTRUSTED_INSTRUCTION_FOLLOWED | 8 | 0 | -8 |

## Interpretation

- Safety pass rate increased by 34.0%.
- Utility pass rate did not change.
- Attack success rate decreased by 34.0%.

## Variant Notable Failures

No notable failures selected.

## Limitations

- This comparison is descriptive. It does not prove statistical significance.
- Case sets should match before interpreting mitigation deltas.
- Tool-policy guards can improve safety by blocking actions too aggressively, so utility deltas matter.
