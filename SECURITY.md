# Security Policy

f5-veil is a safety-critical tool. A defect can cause customer-identifying
data to be sent to a third-party AI service. Security reports are taken
seriously.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: oldgrowthcreations@gmail.com
Subject prefix: `[f5-veil SECURITY]`

Acknowledgement target: within 72 hours.

## In Scope

- Identifiers that pass through the obfuscator without being redacted.
- Cryptographic weaknesses in the answer-file encryption.
- Cases where the de-obfuscator restores incorrect values or fails to
  restore values introduced by an AI in its output.
- Cases where the leak detector misses known-bad patterns it claims to
  cover.
- Information disclosure via logs, error messages, stack traces, or
  transcripts.
- Passphrase or key-material exposure through process listings,
  environment variables, or shell history.

## Out of Scope

- Identifiers introduced by an AI in its output that were never in the
  original configuration — the de-obfuscator can only restore what was
  obfuscated.
- Misuse against configurations the tool was not designed to handle
  (non-F5 configs, partial / corrupted UCS archives, etc.).
- Social engineering of the engineer running the tool.

## Disclaimer

The leak detector is a safety net, not a guarantee. Always review the
sanitized output before sending it to any third-party AI service.
