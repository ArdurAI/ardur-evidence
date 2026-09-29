# Known Limitations

This page distinguishes documented product boundaries from implementation bugs.

## Research and foundation surfaces not yet broad runtime claims

- semantic judging and behavioral fingerprinting are library-only prototypes:
  neither is wired into `python/vibap/proxy.py`, so their outputs are not
  authoritative governance verdicts
- the semantic judge returns `UNSURE` on exceptions; behavioral fingerprinting
  defaults to `policy="fail_open"`, where a definite `FAIL` rejects but
  `UNSURE` proceeds. A custom enforcement integration must deliberately choose
  `policy="fail_closed"` and accept its provider-availability trade-off
- behavioral templates are the intended deterministic direction, but broad
  marketing claims still require template coverage and L5 evidence
- streaming reconciliation and active revocation primitives exist, but broader
  framework-live proof remains a follow-on for some surfaces
- manual reconciliation is implemented at an API-first foundation layer; richer
  operator UX is follow-on work
- TEE support is not yet a general hardware-rooted production claim until real
  vendor quote verification and proof-of-possession artifacts exist
- nested attestation primitives exist, but framework-level end-to-end evidence
  still needs expansion
- fast HMAC is intentionally not a cross-organization non-repudiation tier

## Evidence limits

If a delegated tool or gateway can hide all relevant side effects and emits no
evidence, Ardur must classify the result as `insufficient_evidence` (resulting
in an `unknown` verdict at the session/verifier level) rather than safe. See
[`coverage-map.md`](coverage-map.md) for the receipt-level evidence taxonomy.

Ardur's current first-run proof is a configured tool-boundary proof. It can
verify the issuer signature and hash linkage on receipts for calls observed by
the adapter or proxy. It does not prove that every host or provider action was
observed. Optional transparency anchors can add independently keyed inclusion
evidence, and the Receiver Attestation v0.1 MCP shim can add a separately keyed
called-service signature for an exact receipt and request/response digests.
Both remain opt-in configured-path evidence: neither proves action-set
completeness, detects a fully suppressed call, proves receiver correctness, or
turns an uninstrumented provider path into an observed one.

The Offline Verification Bundle v0.1 verifies the evidence it is given; it
cannot prove that a presenter supplied every action or an honest receiver. The
hash-linked chain exposes receipts removed from its start or middle; receipts
removed from its end are exposed only when the verifier is also given the
session seal (`--seal`), the signed session attestation whose
`receipt_chain_head` names the final receipt. The seal is signed by the same
issuer as the receipts, so it proves the journal is the whole sealed chain, not
that the issuer recorded every action. Trust roots are external inputs and their
SPKI fingerprints must be checked against an independent inventory or channel.
Raw JSONL verification is an explicit lower-assurance `--chain-only` mode.
Offline verification reports `revocation_checked: false`, so a receipt revoked
after bundle assembly may still verify cryptographically. Static JSON/HTML
reports are derived views, not new signed evidence; retain the source bundle,
trust-root fingerprints, and verifier command for reproduction.

## DRP draft-profile proof boundary

Ardur implements the `ardur.drp.v0.1` Authorization Object emitter and
full-transitive-chain verifier pinned to DRP draft-10. The draft is an
individual Internet-Draft with no formal IETF standing.

The verifier consumes `DRPVerifiedLogEvidence` only after a separately trusted
backend has validated raw inclusion/TSA proof. Ardur does not yet ship a raw
RFC 3161 token parser/verifier for this profile. Supplying that object from
receipt claims without external proof validation violates the contract.
Existing action-receipt transparency anchors are not automatically DRP
pre-action delegation-log evidence.

Likewise, `receiptChainAnchor.state = "present"` is accepted only with a
matching `DRPVerifiedReceiptChainEvidence` value produced by a separately
trusted action-chain verifier. The profile does not turn a signed reference
into proof of the referenced action chain. Concrete verification requests must
also carry trusted operation/resource arguments, side-effect classification,
and cwd context; model-supplied labels are not a sufficient enforcement input.

The public root/child/grandchild fixture contains synthetic preverified context
facts so the runtime API can be reproduced offline. It is not raw RFC 3161
proof, independent implementation interoperability, IETF conformance, or
current revocation evidence. Those evidence obligations remain issue #180.

The AuditBench evaluation protocol can create a local content-integrity seal
over captures, blind bundles, annotations, splits, and results, but no real
annotation study has been run. Annotator and adjudicator IDs are self-asserted
identity strings: the pipeline does not authenticate annotators and does not
demonstrate evaluator independence. It also cannot verify an external
registration service or replace the gated privacy and consent review for
real-agent traces. Current in-repo benchmark scenarios remain deterministic
harness fixtures.

Governance telemetry export is a detached, verified projection of the receipt
journal. It does not prove the journal is complete, re-check revocation by
default, guarantee end-to-end delivery, authenticate or operate a collector,
configure retention/access control, or make a telemetry backend part of the
signed evidence chain. OTLP retry is deliberately left to operator-controlled
collection; reruns can duplicate records, so sinks should deduplicate on
`ardur.receipt.id`. Vendor-specific SIEM, LLM-observability, and EDR
connectors remain separate work.

The projected `actor` and `verifier_id` values are signed receipt claims. The
detached exporter does not validate an SVID or bind the receipt signing key to
a SPIFFE workload identity, even when either string begins with `spiffe://`.
Machine-readable JSONL and OTLP fields report this assurance boundary.

## Product limits

Ardur is not:

- a sandbox by itself
- a universal discovery layer for calls that bypass its configured adapter
- a universal semantic-safety engine
- a replacement for identity, workload isolation, or network controls

Those controls still matter around Ardur.

## Verifier-contract conformance (reference proxy, 2026-05-19)

The reference Python proxy in `python/vibap/` implements all three
conformance profiles of `verifier-contract-v0.1`: **Delegation-Core**,
**MIC-State**, and **MIC-Evidence**. The four design-only gaps identified
in the 2026-04-28 hostile audit are closed by task t_dcbf560b:

- `observed_manifest_digest == MD.tool_manifest_digest` (Section 6.3 #6)
  — enforced after mission policy resolution
- per-grant `last_seen_receipts` tracking (Section 5.7) — replayed from
  durable receipt log across proxy restarts
- MIC-Evidence visible-receipt-linkage / hidden-hop detection
  (Section 6.3 #7) — child receipts carry `parent_receipt_id` linking to
  the parent grant's latest receipt
- explicit invocation-envelope signature (Section 6.3 #5) — verified via
  `envelope_signature_valid` telemetry field

All 29 MIC conformance tests in `python/tests/test_mic_conformance.py`
pass, validating all three profiles. See
`docs/specs/verifier-contract-v0.1.md` Section 13 for the full conformance
map.

## Mission Declaration schema enforcement (2026-04-28 hardening)

After the round-3 hostile re-audit, the MD loader unconditionally
enforces FIVE of the seven audit-flagged v0.1 spec members
(`receipt_policy`, `conformance_profile`, `tool_manifest_digest`,
`revocation_ref`, `governed_memory_stores`). The two omitted members
are intentional, not oversights:

- **`approval_policy`** — absence is treated by the proxy as "no
  approval gate", which is a visible operator choice. Including it in
  the always-required list would force every tool call in deployments
  that don't use approvals to carry an `operator_id`.
- **`probing_rate_limit`** — round-2 audit flagged validate-but-don't-
  enforce theater. The runtime currently has no rate-limiter consuming
  the value, so requiring it without downstream effect is accuracy debt.
  It returns to the always-required list once a per-mission rate-limiter
  actually consumes it.

Both members ARE required under `strict_schema=True`. Full v0.1 schema
validation (including `additionalProperties: false` at the root) is
opt-in via `strict_schema=True` on `load_mission_declaration` /
`fetch_mission_declaration`. Existing producers that mix legacy fields
(`allowed_tools` etc.) with v0.1 MDs will fail strict validation; clean
v0.1 producers should set the flag.

The canonical schema doc at `docs/specs/mission-declaration-v0.1.schema.json`
is mirrored to `python/vibap/_specs/mission_declaration_v01.schema.json`
so the runtime can validate without depending on the docs tree on disk.
The two files are kept byte-identical by the
`spec-schema-sync` job in `.github/workflows/validate-formats.yml`,
which fails the build on drift (FIX-R3-B from round-3 re-audit).

## Bounded JWT iat skew at every verifier (2026-04-28 round-3 + round-4 + round-5)

Round-2 hostile re-audit flagged that FIX-6's bounded-iat-skew gate
only protected receipts; AAT, Mission Declaration, status-list, and
passport JWT loaders all still accepted `iat=year_3000`. Round-3 lifted
the gate into a shared `vibap.passport.assert_iat_in_window` helper
applied at every JWT decode call site. Round-4 and round-5 extended the
gate to the parallel-format and Go verifiers the round-3 prompt missed.

The full set of bounded-iat surfaces is now:

**Python JWT verifiers (assert_iat_in_window helper):**
- `vibap.passport._decode_passport`
- `vibap.aat_adapter.decode_aat_claims`
- `vibap.mission.load_mission_declaration`
- `vibap.mission.mission_is_revoked` (status list)
- `vibap.receipt.verify_receipt`
- `vibap.attestation.verify_attestation` (round-4 FIX-R4-3)
- `vibap.spiffe_identity.verify_jwt_svid` (round-4 FIX-R4-4)
- `vibap.memory.GovernedMemoryStore.read` (round-5 FIX-R5-M3)
- `vibap.tool_response_provenance.verify_envelope` (round-5 FIX-R5-M4; uses tighter ±60s future window for short-lived tokens)

**Python parallel-format / non-JWT verifiers:**
- `vibap.biscuit_passport.verify_biscuit_passport` (round-4 FIX-R4-1; round-5 FIX-R5-H5 walks every block, not just leaf)
- `vibap.training_attestation.verify_bundle` (round-5 FIX-R5-H6; future-skew now unconditional, was gated on `max_age_s`)

**Go verifiers (mirrored fail-closed pattern):**
- `go/pkg/credential/verify.go::Verify` (SD-JWT-VC; round-3 FIX-R4-2)
- `go/pkg/credential/delegation.go::VerifyPassport` (round-5 FIX-R5-H3)
- `go/pkg/credential/status.go::ParseStatusListToken` (round-5 FIX-R5-H4)

Default Python window is ±300s future / 30 days past. Each call site
disables PyJWT's stock `verify_iat` (which uses zero leeway and clashes
with cross-node clock drift) in favor of the explicit window. Archival
re-verification can pass `future_skew_s=None`/`past_skew_s=None` per
call. Go uses a tighter 30s default consistent with the SD-JWT-VC
profile's clock-drift tolerance.

## Biscuit JWT-SVID holder binding is server-pinned but still bearer evidence

The Python proxy accepts a Biscuit peer JWT-SVID only when its verifier has a
server-owned Biscuit issuer key, trust bundle, and expected audience. Request
payloads cannot supply or override the JWKS, trust domain, or audience, and a
per-call issuer key cannot replace the configured issuer. Configured binding is
fail-closed: omitting the SVID, presenting a matching SPIFFE ID under an
untrusted key, using a different trust domain, or relying on a bundle key not
eligible for JWT-SVID verification rejects the session. Workload API JWT JWKS
keys commonly omit the optional `use` member and are eligible; federation keys
must use `use=jwt-svid`, while explicit `x509-svid` and other labels are
excluded. `svid_bound=true` is recorded only after all checks pass.

This closes presenter-owned-root forgery; it does not turn JWT-SVID into proof
of a live channel or one-time possession. JWT-SVID is a bearer credential and
can be replayed during its validity window if both the Biscuit and SVID are
stolen. Deployments needing channel-bound workload identity should prefer the
X.509-SVID mTLS pattern in ADR-022.

Configured `ardur start` and `ardur hub` processes can now fetch and retain
their own X.509-SVID before serving, and the shipped proxy can load the
server-owned inputs above from flags or environment variables. These S0–S2
paths do not resolve identity at issuance, bind the receipt signer to the
fetched SVID, or upgrade caller-provided credential `spiffe_id` values beyond
self-asserted attribution.

The local Compose demo joins the proxy and Hub to the SPIRE agent PID namespace
so the Unix workload attestor can inspect callers. This reduces process
isolation among those local containers and is not a production deployment
recommendation.

## BPF policy-map teardown is serialized, but mid-run failover is not automatic

The Linux daemon publishes the complete BPF policy-map handle set and the
`bpf_lsm` tier under one lifecycle mutex. Health reads and every map operation
participate in that same boundary. On guard exit, the daemon waits for in-flight
map users, withdraws the tier and all shared map references, and only then
closes the underlying BPF handles. Startup fallback selection is serialized as
well, so a BPF load completing after the readiness timeout cannot replace an
already selected seccomp tier.

If a live BPF-LSM guard exits mid-run, the daemon records degradation and
reports enforcement tier `none`. It does not automatically start or migrate
the workload to seccomp user-notify after that failure; seccomp supervision is
currently selected only during startup. Operators must treat the degradation
event as an availability incident rather than assuming transparent failover.

## Operator + webhook /metrics endpoints (deployment hardening required)

The `cmd/operator` and `cmd/webhook` binaries expose Prometheus metrics
on `:8080/metrics` via controller-runtime's default `metricsserver`,
without an `AuthorizeFunc` or `FilterProvider`. This is a deliberate
controller-runtime convention: production operators are expected to
gate metrics at the deploy layer with one of:

- a `kube-rbac-proxy` sidecar that requires a Kubernetes `ServiceAccount`
  bearer token with the `metrics.k8s.io` API group,
- a `NetworkPolicy` that limits the metrics port to the cluster's
  Prometheus operator pod, or
- a service-mesh `AuthorizationPolicy` (Istio/Linkerd).

The reference `deploy/k8s/spire/` manifests do NOT ship a metrics-auth
sidecar today. Production deployments MUST configure one. This is
documented here as a known limitation rather than a code-level fix
because the right answer is deployment-environment-specific.

## Python proxy bearer authentication is a shared-secret boundary

The public tree does not ship the Go Authority or Governor HTTP services
described by earlier audit-round documentation. The shipped HTTP control plane
is `vibap.proxy.serve_proxy`. It requires authentication by default on every
endpoint except `/health`, `/healthz`, and `/.well-known/jwks.json`.

`VIBAP_API_TOKEN` takes precedence over the `--api-token` argument. When neither
is supplied, the proxy generates a random 32-byte token. Expected and presented
tokens are stripped at their entry points, the bearer scheme is accepted
case-insensitively, and `vibap.proxy._api_token_compare_material` converts both
values to equal-length material before `hmac.compare_digest` compares them. An
explicit `--no-require-auth` remains available only for trusted local
development.

This is one process-wide bearer secret, not per-client identity or delegated
authorization. The proxy does not assign client-specific scopes or expiry, and
rotation requires restarting it with a new token. Any party holding the token
can call every protected endpoint. Protect it in storage and in transit: bearer
possession alone grants access, as defined by
[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html#section-1.2), and the RFC
requires transport confidentiality. Ardur enables TLS by default; do not use
`--no-tls` across an untrusted network. Python also documents that different
input lengths can expose length information even when using
[`hmac.compare_digest`](https://docs.python.org/3/library/hmac.html#hmac.compare_digest),
which is why Ardur compares fixed-width material.

## `_pinned_urlopen` semantics (2026-04-28 round-3)

The pinned-IP fetch path used by the SSRF-resistant Mission Declaration
and status-list fetchers (`vibap.mission._pinned_urlopen`) explicitly
**rejects HTTP redirects** (any 3xx → `URLError`) instead of following.
Following would re-resolve DNS at each hop and bypass the pinned-IP
guard. Producers that need redirects must reconfigure their server to
serve the final URL directly. Non-2xx response status codes (4xx/5xx)
also raise `HTTPError`, matching the contract `urllib.request.urlopen`
provides — without this, a 500 body would be passed to the JWT decoder
downstream and fail with a noisy parse error rather than a clean fetch
error.

## AAT proof-of-possession default (2026-04-28 hardening)

`vibap.aat_adapter.material_from_aat_grant` and
`vibap.proxy.GovernanceProxy.start_session_from_aat`
default to `require_pop=True`. A `cnf`-bearing AAT presented without
`holder_public_key` + `kb_jwt` fails closed. AATs without `cnf` are also
rejected by default; temporary bearer compatibility requires constructing the
proxy with `allow_aat_without_cnf=True`. For a present `cnf`, callers that need
to bypass PoP verification must still opt out explicitly with
`require_pop=False` so the security choice is visible at the call site.

The HTTP `/sessions` endpoint plumbs `require_pop`,
`holder_public_key_pem`, and `kb_jwt` through the request body, with
the same fail-closed default.

## Revocation fail-closed (2026-04-28 hardening, FIX-1)

`go/pkg/credential.Verify` no longer fail-opens when a credential
carries a status claim and no `StatusClient` is configured. Callers
must either provide a `StatusClient` or set `opts.SkipStatusCheck=true`
explicitly. The Python loader has always fetched the status list when
present; this fix brings the Go path to the same posture.
