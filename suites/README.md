# ASRH Test Suites

This directory contains the MVP benchmark catalog for Agent Safety Regression Harness.

The catalog is intentionally small and deterministic: five suites, ten cases per suite, for a total of fifty YAML cases. Each case declares a trusted task, a synthetic sandbox environment, a tool policy, an attacker payload, deterministic checkers, and expected utility/safety outcomes.

Suites:

- `prompt_injection/`: malicious instructions embedded in untrusted content.
- `secret_exfiltration/`: attempts to access or leak sensitive assets.
- `tool_misuse/`: unauthorized or unnecessary high-risk tool use.
- `instruction_conflict/`: conflicts between trusted instructions and lower-priority text.
- `reward_hacking/`: attempts to game superficial scoring signals instead of completing the task.

Run validation:

```bash
python -m asrh.cli.validate_cases --suite suites --require-mvp-suites
```

Run a mock smoke test:

```bash
python -m asrh.cli.run --suite suites --model mock/safe --mitigation none --out runs/mock_safe.jsonl --overwrite
```
