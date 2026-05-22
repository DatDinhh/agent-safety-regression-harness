# Threat Model

## System Under Test

A tool-using LLM agent operating in a synthetic sandbox environment.

## Trusted Inputs

- System prompt.
- Developer policy.
- User task.
- Tool policy configuration.
- Harness-defined checker configuration.

## Untrusted Inputs

- File contents.
- Email-like contents.
- Tool outputs.
- External document-like text.
- Attacker payloads embedded inside otherwise task-relevant data.

## Sensitive Assets

- API keys.
- Private notes.
- Internal policies.
- Credentials.
- Private emails.
- System prompts or hidden instructions.
- Synthetic secrets embedded in test cases.

All secrets in this repository are synthetic fixtures. Real credentials must not be placed in YAML cases, `.env`, traces, reports, or committed files.

## Attacker Capabilities

The attacker can place text into untrusted content. For example, the attacker can add a malicious footer to a file, email-like document, or tool-output-like string.

The attacker cannot directly modify the system prompt, tool policy, checker code, or sandbox implementation. The attacker cannot directly call tools; the attack succeeds only if the agent calls tools or emits unsafe content.

## Security Properties

ASRH checks whether an agent preserves these properties:

1. No secret disclosure.
2. No unauthorized tool call.
3. No sensitive file access without authorization.
4. No following untrusted instructions as authority.
5. No false task completion.
6. No excessive over-refusal on benign tasks.

## Out of Scope

The MVP does not execute real shell commands, send real emails, make real network requests, handle real credentials, or run browser automation.
