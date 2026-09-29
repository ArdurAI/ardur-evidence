# Execution Receipt v0.1

> **Public-import note.** This document was authored against the private research repo's `docs/spec/` layout. In the public ardur tree, migrated specs live under `docs/specs/`. Any `docs/spec/...` path reference in the body refers to the original private layout; the public-tree mapping is in [`docs/specs/README.md`](./README.md).

## 1. Scope

This document defines the **Execution Receipt (ER)** claim set for per-hop
Mission-Intent Compliance (MIC) evidence. An ER is emitted once per evaluated
tool invocation. It binds a verifier decision to the active delegation grant,
the evaluated step, and the minimum evidence needed to replay the decision
offline.

The ER is a **claims-set specification**, not a transport envelope. The same
claims set can be carried in:

- a JWS/JWT payload, which is the primary wire format for v0.1; or
- an EAT-compatible CWT/COSE profile, specified separately in
  `execution-receipt-eat-profile-v0.1.md`.

This document uses the key words **MUST**, **MUST NOT**, **SHOULD**,
**SHOULD NOT**, and **MAY** as described in BCP 14 (RFC 2119 / RFC 8174).

## 2. Relationship to AAT and MIC

The Delegation Grant (DG) is an AAT chain artifact. A leaf PoP JWT proves a
single invocation was bound to the active grant, but MIC requires **per-hop**
evidence over the full execution trace. The ER is that per-hop evidence record.

For every governed step:

1. the active DG contributes `grant_id`, which MUST equal the governing AAT
   `jti`;
2. the verifier evaluates the normalized invocation;
3. the verifier emits an ER with a `verdict`; and
4. the next ER in the lineage references this ER via `parent_receipt_id`.

## 3. Core Semantics

### 3.1 Required Claims

The following claims are REQUIRED in every ER:

| Claim | Type | Meaning |
|---|---|---|
| `receipt_id` | string | Stable identifier for this receipt as an evidence object. |
| `grant_id` | string | Identifier of the governing delegation grant. This MUST equal the AAT `jti` used for the step. |
| `parent_receipt_id` | string or `null` | Previous ER in the same lineage. The lineage root MUST set this to `null`. |
| `parent_receipt_hash` | hex string or `null` | SHA-256 digest of the previous signed ER JWT. The lineage root MUST set this to `null`. |
| `actor` | string | Identity of the agent, sub-agent, or runtime principal that performed the step. |
| `verifier_id` | string | Identity of the verifier instance that emitted the receipt. |
| `trace_id` | string | Stable identifier for the mission run or trace segment. Receivers use this with `run_nonce` and `jti` for replay detection. |
| `run_nonce` | string | Per-run freshness value generated before the first governed step. |
| `step_id` | string | Stable identifier for the evaluated step within the local execution trace. |
| `invocation_digest` | object | Digest of the normalized invocation envelope evaluated by the verifier. |
| `tool` | string | Tool, API, or capability invoked by the actor. |
| `action_class` | enum | High-level action family: `search`, `read`, `write`, `query`, `delegate`, `send`, `summarize`, or `observe`. |
| `target` | string | Normalized target of the invocation after projection. |
| `resource_family` | string | Coarse resource category used by MIC policy. |
| `side_effect_class` | enum | Side-effect family: `none`, `internal_write`, `external_send`, or `state_change`. |
| `verdict` | enum | One of `compliant`, `violation`, `insufficient_evidence`, or `unknown`. |
| `evidence_level` | enum | One of `self_signed`, `counter_signed`, or `transparency_logged`. |
| `reason` | string | Audit-facing verifier explanation. Public projections MAY redact it. |
| `policy_decisions` | array | Per-policy-engine decisions that contributed to the receipt verdict. |
| `arguments_hash` | hex string | SHA-256 digest of the normalized invocation arguments. |
| `budget_remaining` | object | Verifier-visible budget counters remaining after the decision. |
| `timestamp` | RFC 3339 date-time string | Time at which the evaluated step occurred or was observed. |
| `iss` | string | Token issuer. In v0.1 deployments this SHOULD equal `verifier_id`. |
| `iat` | NumericDate integer | Token issuance time. |
| `exp` | NumericDate integer | Token expiration time. |
| `jti` | string | Unique token identifier for replay detection. |

### 3.2 Optional MIC-Evidence Claims

The following claims are OPTIONAL in the base schema and REQUIRED by higher
level **MIC-Evidence** deployments:

| Claim | Type | Meaning |
|---|---|---|
| `content_class` | string | Content category touched by the step, for example `source_code`, `raw_records`, or `credentials`. |
| `content_provenance` | object | Provenance summary for the content used in the decision. |
| `sensitivity` | enum | Sensitivity tier: `public`, `internal`, `confidential`, `restricted`, `regulated`, or `unknown`. |
| `instruction_bearing` | boolean | Whether the observed content contained actionable instructions that materially affected the step. |
| `budget_delta` | object | Per-hop change to a lineage budget bucket. |
| `result_hash` | object | Digest of the result material or normalized verifier input. |
| `evidence_proof_ref` | string or object | Optional reference to a countersignature, transparency inclusion proof, mission-binding proof, or detached evidence bundle. |

### 3.3 Optional EAT-Binding Extension

The `measurements` claim is OPTIONAL. It exists to support the EAT/CWT profile
and holds verifier-side measurement records that can be projected into EAT
`submods`.

The `measurements` claim is **not** part of the MIC-Evidence minimum set.

`public_denial_reason` and `internal_denial_code` are OPTIONAL at the schema
level for compliant receipts, but both become REQUIRED whenever `verdict` is
`violation` or `insufficient_evidence`. `internal_denial_code` MUST be treated
as audit-channel data.

## 4. Verdict Model

`verdict` is load-bearing and MUST NOT be collapsed to a binary allow/deny
result.

- `compliant`: the verifier had sufficient evidence and found the step within
  policy.
- `violation`: the verifier had sufficient evidence and found a policy or
  integrity violation.
- `insufficient_evidence`: the verifier could not honestly determine compliance
  because required evidence was missing, hidden, revoked, or inconsistent.

An implementation MUST treat `insufficient_evidence` as distinct from
`compliant`. It is an honesty result, not a soft permit.

## 5. Evidence Level

`evidence_level` communicates the assurance level of the emitted ER:

- `self_signed`: the ER is signed only by the emitting verifier.
- `counter_signed`: the ER is signed by the verifier and independently
  countersigned or vouched for out of band.
- `transparency_logged`: the ER or its digest is anchored in an append-only
  transparency system.

The enum is ordered by increasing assurance, but the schema does not carry the
counter-signature or transparency proof itself. Those bindings are deployment
artifacts outside this claims set.

## 6. Privacy-Preserving Denial Reasons

If `verdict` is `violation` or `insufficient_evidence`, the ER MUST carry a
user-facing `public_denial_reason` drawn from the fixed vocabulary below. If
`verdict` is `compliant`, `public_denial_reason` and `internal_denial_code`
MUST be absent from the public ER payload.

Permitted values:

- `policy_denied`
- `budget_exhausted`
- `insufficient_evidence`
- `revoked`
- `chain_invalid`

Free-form denial text, stack traces, policy fragments, and sensitive causal
detail MUST NOT appear in the user-facing ER payload. Detailed explanations
belong in the audit channel only. Implementations MAY emit
`internal_denial_code` in an audit-only projection using deployment-local
values such as `telemetry_missing`, `manifest_drift`, or
`envelope_tampered`. This requirement exists to reduce denial-feedback
leakage.

## 7. Claim-Level Requirements

### 7.1 Identifiers

- `receipt_id`, `trace_id`, `run_nonce`, `grant_id`, `parent_receipt_id`, and
  `jti` MUST be collision resistant.
- `receipt_id` SHOULD be stable across re-encodings of the same receipt.
- `parent_receipt_id` MUST reference the immediately preceding ER in the same
  lineage, not an arbitrary ancestor.
- `trace_id` MUST be stable for the governed run or trace segment.
- `run_nonce` MUST be fresh for each governed run and MUST NOT be reused across
  independent mission executions.

### 7.2 Time

- `timestamp` records step time, while `iat` records token issuance time.
- `iat` MUST be greater than or equal to `timestamp`, modulo bounded clock skew.
- `exp` MUST be strictly greater than `iat`.
- Implementations SHOULD use short ER lifetimes because receipts are
  replay-sensitive evidence.

### 7.3 Budget Accounting

If `budget_delta` is present:

- legacy projections use `bucket`, `unit`, `delta`, and optional
  `remaining_after`/`ceiling`; and
- lineage-budget projections use `operation`, `resource`, `amount`, `unit`,
  optional `remaining_for_parent`, `remaining_after`, `used_total`,
  `reserved_total`, and `delegation_request_id`.

Lineage-wide budget conservation is a verifier/application-state property.
`budget_delta` records the per-hop receipt evidence; it does not by itself
prove that sibling reservations were conserved.

### 7.4 Measurements

If `measurements` is present, each entry describes one measured subsystem or
integrity check relevant to the verifier's decision, for example manifest
binding, envelope binding, memory integrity, or telemetry completeness.

## 8. Canonicalization and Hashing

Hashes over nested JSON objects MUST be computed over **RFC 8785 JSON
Canonicalization Scheme (JCS)** output, not over implementation-dependent
serializer output.

This applies in particular to:

- `invocation_digest`
- `result_hash`
- nested values inside `content_provenance`
- nested values inside `budget_delta`
- nested measurement objects if they are hashed or detached

Producers MUST enforce the RFC 8785 input constraints before hashing, including:

- no duplicate object names;
- Unicode-preserving string handling;
- IEEE 754-compatible JSON numbers; and
- recursive lexicographic sorting of object properties.

## 9. JWT Profile (Primary)

The primary ER wire format is a JWS-signed JWT carrying the ER claims set.

### 9.1 Header Requirements

- The protected header MUST set `alg` to `ES256`.
- The protected header SHOULD set `typ` to
  `application/ardur.er+jwt`.
- The protected header SHOULD include a `kid`.

#### 9.1.1 `kid` Derivation

This clause makes the `kid` above checkable. It was previously left entirely to
the producer, which meant a receiver had no way to tell a correct `kid` from an
arbitrary label.

- When a producer emits `kid`, it SHOULD be **content-addressed**: the
  lowercase hex SHA-256 digest of the signing key's DER-encoded
  SubjectPublicKeyInfo (SPKI), prefixed with `sha256:` — that is,
  `sha256:<64 hex chars>`.
- A content-addressed `kid` is derivable by any holder of the public key, so a
  receiver verifies it by recomputation and never needs a registry lookup, a
  network fetch, or issuer-supplied metadata. This is what keeps the check
  available to a fully offline verifier.
- Producers that must interoperate with an external key-management system MAY
  emit a deployment-specific `kid` instead. Such a `kid` is an opaque label: it
  is not recomputable, and a receiver applying the recomputation rule in §9.3
  will reject it. Deployments choosing this path MUST publish the resolution
  mechanism their receivers are expected to use.
- The digest is taken over SPKI rather than over a raw public point so that the
  identifier commits to the algorithm and curve, not only to the coordinates.
  Producers MUST use the DER encoding with a `namedCurve` algorithm parameter;
  an SPKI carrying explicit curve parameters encodes the same key to different
  bytes and therefore yields a different, non-interoperable `kid`.

Ardur's reference implementation (`vibap.receipt.sign_receipt`) always emits
this content-addressed form, and derives it through the same helper that
produces the `spki_fingerprint` values in offline verification reports, so the
two are comparable by eye.

### 9.2 Payload Requirements

- The JWT payload MUST validate against
  `execution-receipt-v0.1.schema.json`.
- `iss`, `iat`, `exp`, and `jti` MUST follow JWT semantics from RFC 7519.
- Deployments SHOULD set `iss == verifier_id` unless a distinct issuer front-end
  is used for the verifier fleet.
- If `iss != verifier_id`, deployments MUST publish a trust-anchor or registry
  binding that authorizes the issuer to sign for the named verifier.

### 9.3 Signature Requirements

- The JWT MUST be integrity protected before it is relied upon.
- Receivers MUST verify the signature before trusting `verdict`,
  `evidence_level`, or any privacy-sensitive optional claims.

#### 9.3.1 `kid` and the Verifying Key

- A receiver MUST NOT treat an **absent** `kid` as a failure. `kid` is a
  SHOULD in §9.1, so its absence is silence, not a contradicted claim, and ERs
  issued before a producer adopted `kid` remain valid.
- A receiver MUST NOT use `kid` to *select* trust. `kid` names a key; it does
  not authorize one. The verifying key comes from the receiver's own trust
  configuration, exactly as it does when `kid` is absent.
- When `kid` is **present**, a receiver that has recomputed the content-addressed
  value for its verifying key MUST reject the ER if the two differ. A header
  asserting a different key than the one that verified the signature is a
  contradiction the receiver cannot resolve, and per the fail-closed rule it
  denies rather than warns.
- This is defence in depth, not the primary integrity control. The protected
  header is inside the JWS signing input, so an attacker who rewrites `kid`
  invalidates the signature and is rejected before this check is reached. The
  check covers what the signature cannot: a producer that signs with one key
  while naming another.

The `kid` binding says nothing about key *validity*. Revocation and trust-root
freshness remain out of scope for the ER itself.

### 9.4 Replay and Accountability Requirements

Receivers MUST reject replayed or stale ERs. At minimum, a receiver MUST:

1. verify the signature and issuer/verifier binding;
2. verify `exp`, `iat`, and bounded clock skew;
3. enforce `jti` uniqueness within the configured replay window;
4. bind `trace_id`, `run_nonce`, `grant_id`, `step_id`, and
   `invocation_digest` to the evaluated step;
5. verify that `parent_receipt_id`, when non-null, names the immediately
   preceding ER in the same lineage; and
6. reject receipts whose normalized invocation digest does not match the
   invocation envelope being replayed.

### 9.5 Receipt Data Handling

ERs can reveal sensitive operational metadata even when payloads are redacted.
Deployments MUST define retention, access-control, encryption, and
minimization policies for receipt storage.

At minimum:

1. ERs MUST be encrypted in transit and SHOULD be encrypted at rest;
2. detailed audit projections containing `internal_denial_code`,
   `content_provenance`, detached measurement details, or result material MUST
   be access controlled separately from public ER projections;
3. public ERs SHOULD carry digests and coarse classifications rather than raw
   content whenever replay does not require raw content;
4. retention periods SHOULD be bounded by mission sensitivity and regulatory
   requirements; and
5. deletion or redaction MUST preserve enough digest evidence to audit whether
   an ER was emitted for a governed step, unless local law requires full
   erasure.

## 10. JSON Schema and Examples

The companion JSON Schema is `execution-receipt-v0.1.schema.json`.

Examples:

- `examples/er-compliant.json`
- `examples/er-violation.json`
- `examples/er-insufficient-evidence.json`

The examples are claim-set examples, not serialized JWTs or CWTs.