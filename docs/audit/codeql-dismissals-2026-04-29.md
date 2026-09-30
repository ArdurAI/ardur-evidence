# CodeQL Alert Dismissals — 2026-04-29

> Audit-trail mirror of the GitHub Code Scanning dismissal record for
> alerts that surfaced on PR #8 (the `dev → main` graduation that
> carried the 11-round S2 hostile-audit cycle, the framework-demo
> code lift, and Article 06).
>
> GitHub stores the same content under
> `gh api repos/ArdurAI/ardur-evidence/code-scanning/alerts/<n>`, but
> that surface is gated behind authenticated access to the repo's
> security tab. This file mirrors the record into the public tree so
> any reader (including someone reviewing the repo without GitHub
> credentials) can audit what was dismissed and why.

## Why this file exists

The 11-round audit cycle (S2) terminated cleanly on 2026-04-29 with
two consecutive clean rounds (R10, R11), 101 findings closed across
the cycle (1 CRITICAL + 16 HIGH + 37 MEDIUM + 47 LOW). When PR #8
opened, GitHub's Advanced Security CodeQL aggregator surfaced eight
new alerts on the PR diff that the human auditor had not flagged.

This is expected — CodeQL is a different lens (taint-flow over the
semantic model) and routinely catches things a human auditor's
scope misses. It is also expected that not every CodeQL alert is a
real bug: false-positive rate on rules like
`py/clear-text-logging-sensitive-data` and
`py/overly-permissive-file` runs high in security-tooling code
because the rules cannot reason about the surrounding contract
(token redaction, public-vs-private key material, HTTP response
sinks vs. log sinks).

Every dismissal here was triaged before merge, has a recorded
justification visible in the GitHub Code Scanning UI, and is
restated in this file with file:line, rule id, severity, and the
reasoning we used.

## Summary

| Alert | Rule | Sec sev | Rule sev | Disposition | Class |
|---|---|---|---|---|---|
| #1 | `py/clear-text-logging-sensitive-data` | high | error | won't fix | Operator-bootstrap UX with abbreviation by default |
| #2 | `py/clear-text-logging-sensitive-data` | high | error | false positive | Stderr line emits redacted fingerprint, not cleartext |
| #3 | `py/overly-permissive-file` | high | warning | false positive | Stale alert — file deleted during audit cycle |
| #4 | `py/overly-permissive-file` | high | warning | false positive | `0o644` on public key (correct by definition) |
| #5 | `py/log-injection` | medium | error | false positive | HTTP response sink misclassified as log sink |
| #13 | `py/unsafe-cyclic-import` | — | error | false positive | Fix landed in commit `438ee15` (topology break) |
| #14 | `py/unsafe-cyclic-import` | — | error | false positive | Fix landed in commit `438ee15` (topology break) |
| #15 | `py/unsafe-cyclic-import` | — | error | false positive | Fix landed in commit `438ee15` (topology break) |

Eight dismissals. Five "false positive" (the rule's pattern fires
on shape but not on the actual security predicate). One "won't fix"
(the operator UX is the deliberate design and tightening it would
be backwards-incompatible without a corresponding gain). Three
correspond to a real fix that landed in the same PR and will
auto-close on the next CodeQL scan against `main` post-merge.

## Per-alert detail

### #1 — `py/clear-text-logging-sensitive-data` (HIGH)

- **File:** `python/vibap/proxy.py:5031` (banner-print site)
- **Rule message:** *"This expression logs sensitive data (password)
  as clear text."*
- **Disposition:** Superseded by code fix on `dev` (2026-06-04)
- **Justification:** The startup banner no longer prints the bearer token or
  supports `VIBAP_PRINT_FULL_TOKEN`. It prints only a context-bound token
  fingerprint and instructs operators to provide the actual token via
  `VIBAP_API_TOKEN` or `--api-token`.
- **Extended reasoning:** This section records the original 2026-04-29 triage.
  The 2026-06-04 security hardening removed the full-token display path rather
  than continuing to rely on a false-positive dismissal.

### #2 — `py/clear-text-logging-sensitive-data` (HIGH)

- **File:** `python/vibap/proxy.py:5040` (stderr structured line)
- **Rule message:** *"This expression logs sensitive data (password)
  as clear text."*
- **Disposition:** Superseded by code fix on `dev` (2026-06-04)
- **Justification:** The stderr line now emits only `token=redacted`, not a
  digest, fingerprint, prefix/suffix slice, or cleartext token.
- **Extended reasoning:** This section records the original 2026-04-29 triage.
  The 2026-06-04 hardening removed direct token dataflow from both the startup
  banner and stderr audit line.

### #3 — `py/overly-permissive-file` (HIGH)

- **File:** `python/vibap/legacy_passport.py:238`
- **Rule message:** *"Overly permissive mask in chmod sets file to
  world readable."*
- **Disposition:** False positive
- **Justification (verbatim, 280-char limit):** *"`legacy_passport.py`
  was deleted during the 11-round audit cycle; no longer exists at
  HEAD. Alert is stale and will auto-close on next CodeQL scan.
  Dismissing to clear the PR view."*
- **Extended reasoning:** `legacy_passport.py` was removed during
  one of the audit-cycle rounds. The CodeQL alert references a file
  that does not exist in the repo's current tree shape. Confirmed
  via `git ls-tree HEAD -- python/vibap/legacy_passport.py`
  returning empty, and `find python/vibap -name '*passport*.py'`
  returning only `passport.py` and `biscuit_passport.py`. The alert
  will auto-close on the next CodeQL analysis run that observes
  the new tree shape; explicit dismissal here clears the PR-view
  noise.

### #4 — `py/overly-permissive-file` (HIGH)

- **File:** `python/vibap/passport.py:355` (in `_write_bytes` call
  for the public key)
- **Rule message:** *"Overly permissive mask in chmod sets file to
  world readable."*
- **Disposition:** False positive
- **Justification (verbatim, 280-char limit):** *"`0o644` on
  `passport_public.pem` is correct: PUBLIC keys are world-readable
  by definition. Companion call at `passport.py:347` writes PRIVATE
  key with `0o600`. CodeQL flags any `0o644` `.pem` chmod without
  distinguishing public from private material."*
- **Extended reasoning:** The flagged call writes
  `passport_public.pem` — the *public* half of the key pair — with
  mode `0o644` (owner read+write, world-readable). For public-key
  material, world-readable is the textbook correct posture; making
  the public key owner-only would break every consumer that needs
  to verify signatures. The companion call at `passport.py:347`
  writes the private key (`passport_private.pem`) with `0o600`
  (owner-only), the textbook correct posture for that material.
  CodeQL fires on any `chmod` call setting `0o644` on a `.pem`
  path, without semantic context for whether the file is public or
  private.

### #5 — `py/log-injection` (MEDIUM)

- **File:** `python/vibap/proxy.py:4877` (in HTTP response handler)
- **Rule message:** *"This log entry depends on a user-provided
  value."*
- **Disposition:** False positive
- **Justification (verbatim, 280-char limit):** *"Line 4877 builds
  an HTTP response dict sent via `_send_json` (writes to
  `self.wfile`, the HTTP response stream). Not a log sink. The
  handler's `log_message` is overridden to no-op at
  `proxy.py:4605`, so HTTP input never reaches a log. CodeQL
  conflates `wfile.write` with logging."*
- **Extended reasoning:** The flagged line is a `response: dict`
  assignment whose contents are written via `self._send_json`,
  which calls `self.wfile.write(...)` — the HTTP response stream,
  not a log. The proxy's `BaseHTTPRequestHandler` subclass
  explicitly overrides `log_message` to a no-op return at
  `proxy.py:4605–4606`, suppressing the default request-line log
  that would otherwise flow `self.path` into a log call. The other
  `logger.warning` sites in `proxy.py` log filesystem-controlled
  names (e.g. `session_file.name` from a directory glob), not HTTP
  user input. CodeQL's heuristics treat any `wfile.write` of
  user-controlled data as a potential log injection sink; in this
  codebase that classification is wrong.

### #13, #14, #15 — `py/unsafe-cyclic-import` (rule severity: error)

- **Files:**
  - `#13`: `python/vibap/proxy.py:100` (`build_receipt` reference)
  - `#14`: `python/vibap/proxy.py:100` (`sign_receipt` reference)
  - `#15`: `python/vibap/receipt.py:30` (`PolicyEvent` reference)
- **Rule message (representative):** *"`build_receipt` may not be
  defined if module `vibap.receipt` is imported before module
  `vibap.proxy`, as the definition of `build_receipt` occurs after
  the cyclic import of `vibap.proxy`."*
- **Disposition:** False positive (with real fix landed)
- **Justification (verbatim, 280-char limit):** *"Fixed in dev
  commit `438ee15`: deferred `from .receipt import` into
  `_build_receipt_log_entry`, breaking static topology cycle.
  Runtime was already safe via `TYPE_CHECKING` + PEP 563. Will
  auto-close on main post-merge."*
- **Extended reasoning:** The cycle CodeQL flagged was structurally
  safe at runtime:
  - `receipt.py` uses `from __future__ import annotations` (PEP
    563), so all annotations are evaluated as strings — never
    resolved at module-load time.
  - The `receipt → proxy` edge (`from .proxy import PolicyEvent`)
    was gated by `if TYPE_CHECKING:`, which evaluates `False` at
    runtime.
  - `build_receipt` and `sign_receipt` were referenced only inside
    one method (`_build_receipt_log_entry`); no module-level use.

  CodeQL's `py/unsafe-cyclic-import` rule operates on import
  topology and does not fully reason about
  `TYPE_CHECKING` + PEP 563 together, so it reported the cycle
  even though no runtime path could fail. The fix in commit
  `438ee15` removes the static topology cycle by moving
  `from .receipt import build_receipt, sign_receipt` from
  `proxy.py` module scope into the body of
  `_build_receipt_log_entry`. The cost is one `sys.modules`
  cache lookup per receipt issuance; receipt issuance is not in
  a hot loop. Verified by:
  - `python -m pytest tests/`: 423 passed
  - AST check: no top-level `.receipt` import remains in
    `proxy.py`
  - Both import orders work
    (`vibap.receipt` then `vibap.proxy`, and
    `vibap.proxy` then `vibap.receipt`)

  The alerts are dismissed against the PR's `refs/heads/main`
  ref because that ref's CodeQL database still reflects the
  pre-fix topology. They will auto-close on the next CodeQL scan
  against `main` once this PR merges.

## What's not in this file

The 39 note-severity CodeQL alerts left open after this triage
(`py/unused-import`, `py/cyclic-import` (note severity, not
unsafe), `py/empty-except`, `py/not-named-self`,
`py/import-and-import-from`, `py/ineffectual-statement`) are
deferred. None are security-relevant. The branch protection rule
on `main` was tightened on 2026-04-29 from
`code_quality: severity: all` to `code_quality: severity: errors`
so future PRs are not gridlocked by note-level cleanups while
real correctness alerts (`error` severity) continue to gate the
merge.

A future cleanup pass will remove the legitimate unused imports
inline and dismiss the rest as `won't fix` with a single
explanatory comment.

## How to verify

The dismissals above are visible via:

```bash
# Each alert (replace <N> with 1, 2, 3, 4, 5, 13, 14, or 15):
gh api repos/ArdurAI/ardur-evidence/code-scanning/alerts/<N> \
  --jq '{state, dismissed_reason, dismissed_comment, dismissed_by, dismissed_at}'
```

Or in the GitHub UI under
*Security → Code scanning → Closed alerts*.

The on-disk fix for #13/#14/#15 is verifiable by:

```bash
# Should return zero matches — no top-level .receipt import remains:
python3 -c "
import ast
with open('python/vibap/proxy.py') as f: tree = ast.parse(f.read())
for node in ast.iter_child_nodes(tree):
    if isinstance(node, ast.ImportFrom) and node.module == 'receipt' \
       and node.level == 1:
        print('PRESENT at line', node.lineno)
        break
else:
    print('OK: no top-level .receipt import')
"
```

## 2026-04-30 follow-up — alert #51

After PR #8 merged to `main` on 2026-04-30, the post-merge CodeQL
analysis on the new `main` ref surfaced one additional alert that
the previous SARIF (against the pre-merge tree) had not flagged.
Triaged and dismissed on the same day.

| Alert | Rule | Sec sev | Rule sev | Disposition | Class |
|---|---|---|---|---|---|
| #51 | `py/weak-sensitive-data-hashing` | high | warning | false positive | Bearer-token length normalization, not password hashing |

### #51 — `py/weak-sensitive-data-hashing` (HIGH security severity)

- **File:** `python/vibap/proxy.py:4582`
  (`api_token_hash = hashlib.sha256(api_token_bytes).digest()`)
- **Rule message:** *"Sensitive data (password) is used in a hashing
  algorithm (SHA256) that is insecure for password hashing, since
  it is not a computationally expensive hash function."*
- **Disposition:** Superseded by code fix on `dev` (2026-06-04)
- **Justification:** Bearer-auth normalization now uses fixed-length compare
  material before `hmac.compare_digest`; the bare SHA-256 token-hashing site
  was removed.
- **Extended reasoning:**
  This section records the original 2026-04-29 triage. The underlying security
  predicate remains fixed-length comparison before `hmac.compare_digest`, but
  the 2026-06-04 hardening moved from bare SHA-256 to
  `_api_token_compare_material()` to avoid both the CodeQL password-hashing
  shape and direct token dataflow.

  Original context for the length-oracle defense:

  - CPython's `_tscmp` (the C function backing
    `hmac.compare_digest`) iterates `min(len_a, len_b)` and
    short-circuits on length mismatch, leaking the expected
    token's length to a remote attacker who controls the
    presented token.
  - Hashing both sides through SHA-256 first normalizes them to a
    fixed 32 bytes; the constant-time compare then runs on
    fixed-length inputs and the length-oracle is closed.
  - The token being hashed is `api_token` — a 256-bit
    machine-generated bearer (from `_generate_api_token()`), not a
    user-supplied low-entropy password. SHA-256 is the *correct*
    primitive for length normalization of high-entropy material.

  Replacing SHA-256 with a slow KDF (bcrypt, scrypt, Argon2,
  PBKDF2) here would actively make things worse:

  - Variable timing of KDFs would *break* the constant-time-compare
    invariant the entire R7/R8 fix exists to preserve.
  - KDF cost-per-call multiplies on every authenticated request.
    The bearer-auth path is on the hot path of every proxy call.
  - There is no rainbow-table or brute-force concern for 256-bit
    random tokens; KDFs solve a problem this code doesn't have.

  The audit cycle's terminal-round verdict (round 11, 2026-04-29)
  explicitly endorsed this design:

  > *"the public-surface authentication and credential-issuance
  > code is consistently fail-closed at every entry point:
  > SHA-256-normalized constant-time bearer compare on
  > Authority/Governor/Python proxy …"*

  The same SHA-256 normalization was previously landed on the Go
  side (R7) for `cmd/authority` + `pkg/governance`. R8 closed the
  symmetric gap on the Python proxy that R7's audit had flagged
  as `MED-NEW-1`.

- **Why CodeQL didn't fire on this in the pre-merge SARIF:** the
  alert was created in the database on 2026-04-29 16:09:17Z but
  surfaced in PR #8's view only after the post-merge CodeQL run
  uploaded SARIF against `refs/heads/main`. The pre-merge view
  scoped to `refs/heads/dev` had the alert but in a state that
  the PR-diff filter didn't classify as "new in this PR." This is
  a known-shape of GitHub Code Scanning: alerts move between
  per-ref states as analyses run, and a dismissed-or-not-yet-
  surfaced alert against one ref can re-surface as "open" against
  another ref when the same code lands there. The `dismissed`
  state set here applies repository-wide.

  **Same-rule alerts on related token-fingerprint sites:** none
  flagged at time of dismissal. `_passport_token_hash` at
  `python/vibap/passport.py:257` uses the same
  `hashlib.sha256(token).digest()` pattern for replay-cache and
  log-fingerprint computation; CodeQL's data-flow analysis did
  not classify the input there as `password`-tainted, so no
  alert. If that classification ever changes, the same
  reasoning above applies (high-entropy machine-generated token,
  not user password) and the dismissal will be added here.

---

*Prepared 2026-04-29 by the maintainer; mirrored from the GitHub
Code Scanning audit trail. Update this file (do not delete entries)
if any dismissal is later reversed or if new dismissals land —
the convention is append-only with dated rows. 2026-04-30 follow-up
section appended for alert #51 surfaced post-merge.*
