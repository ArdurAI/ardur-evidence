# Security Policy

This file is the public reporting policy for Ardur.

## Supported versions

The latest tagged release (v0.1.0+) and the default branch are supported
for security fixes.

## Reporting a vulnerability

Do not open a public issue for an active vulnerability.

Report security issues privately via one of:

- **Preferred:** [GitHub Security Advisory](https://github.com/ArdurAI/ardur-evidence/security/advisories/new) — creates a private advisory thread that the maintainer will triage.
- **Fallback:** email `gnani.nutakki@gmail.com` if the advisory path is not available or not working for you.

Both channels land in the same inbox; the advisory path is preferred because it carries better history and coordination tooling for the fix.

Include:

- affected version or commit
- reproduction steps
- expected impact
- whether the issue can cause out-of-scope action, forged evidence, or unsafe
  overclaiming

## What counts as a security issue

Examples include:

- out-of-scope tool or resource execution
- delegation scope widening
- forged, replayed, stripped, or tampered receipts
- verifier bypasses that turn missing evidence into false success
- downgrade attacks on governance tiers
- secret leakage through official artifacts or evidence bundles

## Scope reminders

Ardur is a runtime governance and evidence layer. Some gaps are documented
openly in `docs/known-limitations.md`. Those documented boundaries may still be
important product risks even when they are not implementation bugs.

## Security posture

For the actual product security model, see:

- `docs/security-model.md`
- `docs/known-limitations.md`
