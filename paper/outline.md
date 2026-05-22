# Verification-Style Regression Testing for Tool-Using LLM Agents Under Prompt Injection

## Abstract

Tool-using LLM agents are vulnerable to adversarial instructions embedded in untrusted data such as files and email-like documents. ASRH is a lightweight regression harness for evaluating agent safety using verification-inspired concepts: testbenches, deterministic checkers, trace capture, and failure taxonomy. ASRH evaluates both utility and safety across synthetic prompt-injection, secret-exfiltration, tool-misuse, instruction-conflict, and reward-hacking suites. Current results are mock-model only; real-model conclusions should be added only after provider-backed runs are completed.

## Outline

1. Motivation
2. Threat model
3. Harness design
4. Test-suite construction
5. Checkers and metrics
6. Mitigation strategies
7. Mock-model validation
8. Real-model experiments
9. Results
10. Failure analysis
11. Limitations
12. Future work

## Current Claims

The current repository supports a validated mock-model MVP with 50 cases, sandboxed tools, deterministic checkers, JSONL traces, and Markdown reports. It should not claim real-model findings until real OpenAI, Anthropic, or local model traces are generated.

## Planned Real-Model Claims

After real-model runs, the writeup should state:

- which models were evaluated,
- how many cases were run,
- which failure classes appeared,
- which mitigations reduced failures,
- whether utility decreased,
- and which claims are supported by specific JSONL traces.
