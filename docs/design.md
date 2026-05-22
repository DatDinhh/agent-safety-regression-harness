# ASRH Design

ASRH is a verification-style regression harness for evaluating whether tool-using LLM agents preserve safety constraints under adversarial conditions.

## Core Architecture

The system follows a trace-first flow:

```text
YAML test case
-> case loader and validator
-> sandbox environment builder
-> sandboxed tool registry
-> agent runner
-> deterministic checkers
-> JSONL traces
-> Markdown reports
```

## System Under Test

The system under test is a tool-using LLM agent. The agent receives a trusted user task and may call simulated tools such as `read_file`, `list_files`, `write_file`, `send_email`, and `run_shell`.

The tools are not real operating-system, network, or email tools. They are controlled sandbox actions that produce traceable outputs and policy decisions.

## Verification Mapping

| Verification Concept | ASRH Equivalent |
|---|---|
| Device under test | Tool-using LLM agent |
| Testbench | Synthetic sandbox environment |
| Stimulus | YAML test case |
| Assertions | Deterministic checkers |
| Waveform / trace | JSONL run trace |
| Regression suite | Five adversarial test suites |
| Failure taxonomy | Structured checker failure classes |

## Module Responsibilities

- `asrh.cases`: schema, loading, discovery, and validation for YAML cases.
- `asrh.envs`: sandbox state, in-memory file system, email box, memory store, and policy decisions.
- `asrh.tools`: tool definitions and registry wrappers around the sandbox.
- `asrh.agents`: JSON-action agent loop and prompt builders.
- `asrh.models`: mock, OpenAI, Anthropic, and local OpenAI-compatible clients.
- `asrh.mitigations`: prompt and code-policy mitigation strategies.
- `asrh.checkers`: deterministic utility and safety checkers.
- `asrh.runner`: case and suite execution, trace creation, and JSONL writing.
- `asrh.report`: report summaries, tables, and Markdown rendering.
- `asrh.cli`: command-line entry points for running, validating, listing, and reporting.

## Current Status

This repository includes a validated mock-model MVP with 50 YAML cases, passing unit tests, sample JSONL traces, and sample Markdown reports. The `asrh.models` package is present so the next step is to run provider-backed one-case smoke tests and then full real-model comparisons.
