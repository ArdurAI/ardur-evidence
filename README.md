# Ardur Evidence

> **Renamed on 2026-09-29.** This repository was `ArdurAI/ardur`. It is being
> refocused as **Ardur Evidence**: the signed execution-receipt format and the
> offline verifier (`ardur-verify`). The name *Ardur* now refers to the
> [Ardur app](https://github.com/ArdurAI/ardur-bot). Parts of this repository
> that are not about evidence are being archived. See the
> [Naming Note](#naming-note).

Ardur governs AI-agent tool calls that pass through a configured adapter or
proxy. It checks mission, resource, budget, and delegation constraints before
that integration dispatches the call, then emits an issuer-signed,
hash-linked receipt for the decision.

For issuer-selected dangerous tools, an optional signed `risk_budget` claim
binds authenticated tool schemas to typed per-action impact caps and atomic
session, agent, and lineage ceilings. The executor must explicitly close every
permitted reservation as committed once execution may have started, or as
released only when execution never started. This does not infer semantic risk
or hidden side effects; see the
[typed risk-budget reference](docs/reference/risk-budgets.md).

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-blue)](STATUS.md)
[![Discussions](https://img.shields.io/badge/GitHub-Discussions-181717?logo=github)](https://github.com/ArdurAI/ardur-evidence/discussions)

This public repo contains the product intent, research-informed positioning,
public specs, the Python governance runtime, Go packages for eBPF kernel
capture and Kubernetes control-plane components, mission examples, runnable
framework adapters (LangChain, LangGraph, AutoGen), the Ardur Personal Hub
service, the Claude Code plugin and hook, and the public Hugo evidence site.
The current public proof is strongest at those configured tool boundaries. It
does not establish universal agent capture, third-party witnessing unless an
optional transparency anchor verifies under an independently trusted log key
or an optional receiver envelope verifies under a separately trusted tool key,
provider-hidden behavior, or cross-platform kernel enforcement. Re-runnable
proof media, full packaging, and production deployment material are still
being tightened before they are presented as release-ready.

Ardur can also verify a receipt journal and correlate it offline with
operator-supplied normalized, Tetragon, or Falco JSONL evidence. That path
produces a detached redacted report with explicit match confidence, source
assurance, and coverage limits. It does not deploy or authenticate a sensor,
and a high-confidence association to imported JSON is corroboration rather
than independent proof.

The separate Kubernetes operator telemetry endpoint is disabled unless an
operator configures explicit `source=spiffe://...` bindings. When enabled, it
requires TLS 1.3 mutual authentication with rotating SPIFFE X.509-SVIDs and
rejects an authenticated producer that claims another configured source. See
the [operator telemetry identity guide](docs/guides/operator-telemetry-identity.md)
for the deployment contract and remaining collector trust boundary.

For `ardur run` on Linux, when the launch bridge successfully registers the
governed cgroup with `ardur-kernelcaptured`, each proxy receipt is reported to
the daemon before the evaluated action is released. The signed session
attestation then carries an `observability_gap` summary over the daemon's
captured process exec/exit sample: captured, correlated, and uncorrelated
effects plus the observed-effect gap ratio. An empty sample is `not_measured`;
ringbuf loss or producer-counter uncertainty makes it `degraded`. This is not a
universal file/network/host-effect percentage, and receipt source assurance is
the authenticated session owner rather than daemon-side JWT verification.

The Linux daemon also has an opt-in `--agent-recognition` preview. It adds
separate exact, in-kernel Linux `comm` and successful-exec basename prefilters
for the release-bound `claude`, `codex`, `gemini`, and `kimi` command names and
logs matching execs as low-confidence, observe-only launch candidates. The
default cgroup-scoped capture path is unchanged. The producer derives only a
bounded basename and never emits the parent path. Operators may additionally
provide a daemon-owned `--agent-recognition-fingerprint-registry` on Linux to
compare recognized native executables and script-backed launchers through a
fixed asynchronous pidfd worker pool. Native candidates use the live
`/proc/<pid>/exe` object. Script candidates require an optional non-enforcing
BPF-LSM observer to bind the original exec object; bounded cmdline fields are
only locators and must reopen beneath the observed process root with matching
device, inode, and mount ID before hashing. Unsupported kernels fail the script
lane low without disabling native fingerprinting or ordinary lifecycle
capture. A configured match is only a medium-confidence heuristic content
signal; computed digests, full paths, argv, environment, and file contents are
never emitted. It does not attest, adopt, authorize, or enforce the observed
process, and neither an exact name nor an ordinary SHA-256 match proves agent
identity or provenance. A [maintained sanitized corpus and deterministic
gate](docs/reference/agent-recognition-evaluation.md) publishes exact corpus and
registry digests, sample-counted precision/recall, Wilson intervals, and stable
false-positive/false-negative IDs. Its v0.2 report keeps 28 exact-name samples
separate from eight synthetic native/launcher content transitions, requires
zero mismatch confidence promotions, grades launcher fixtures against an
independent observed-interpreter input, and never blends content matches into
name-only accuracy. The gate is regression evidence for the maintained
corpus—not population accuracy, provenance, or identity assurance. Attestation,
adoption, governance, and non-Linux launch sources remain separate follow-up
work.

For performance engineering, the
[Linux governance overhead harness](docs/benchmarks/linux-governance-overhead.md)
produces schema-validated JSON and Markdown reports that keep governance-only
latency, imported-evidence processing, sustained resource use, and optional
paired sensor overhead separate. Pull requests run a small shape-only smoke;
host-specific stress results are manual evidence, not a universal overhead
claim.

The separate
[agent-recognition overhead harness](docs/benchmarks/agent-recognition-overhead.md)
runs a real-Linux exact-exec corpus with recognition disabled for the candidate
baseline, enabled for the exact target-branch reference daemon, and enabled for
the candidate daemon on the same VM; arm order rotates through all six
permutations. Its machine report keeps
lifecycle delivery/loss, classifier rejection, fingerprint terminal outcomes,
daemon CPU, peak RSS, and workload wall time separate. It is host-specific
observer-effect evidence, not identity, accuracy, attestation, or governance
proof.

The [AuditBench evaluation protocol](docs/specs/auditbench-evaluation-protocol-v0.1.md)
adds strict raw-capture replay, blind two-view annotations, a local
content-integrity seal, and held-out four-state scoring (`compliant`, `violation`, `insufficient_evidence`, `unknown`). The pipeline is
implemented, but it does not authenticate annotators or demonstrate evaluator
independence. No real annotation study, headline corpus, or comparative result
is claimed.

[Research](RESEARCH.md) · [Status](STATUS.md) · [Coverage Map](docs/coverage-map.md) · [Roadmap](ROADMAP.md) · [Media](MEDIA.md) · [Articles](docs/articles/README.md) · [Docs](docs/README.md) · [Reference](docs/reference/README.md) · [Phase 1 Demo Packet](docs/guides/phase1-demo-packet.md) · [Read the Phase 1 Evidence Bundle](docs/guides/read-phase1-evidence-bundle.md) · [Evidence Site Source](site/README.md)

## Verification Snapshot

At the reviewed `dev` tree on 2026-07-11, the current gates were:

| Gate | Verified result |
|---|---|
| Python local matrix (Python 3.13) | 1,665 passed, 33 skipped; CI separately enforces its coverage threshold |
| Python CI | Python 3.10 and 3.13 passed; lint and wheel smoke passed |
| Go CI | Tests, vet, lint, and vulnerability scan passed |
| Linux enforcement CI | BPF generation plus Go build/vet/race tests, policy-map startup/teardown lifetime races, live BPF-LSM kernel smoke, strict BPF `ardur run --enforce` with a kernel-stopped, exact-artifact bootstrap and denied child exec, seccomp smoke, and full seccomp E2E with an authenticated governance call followed by a denied unrelated loopback connect passed |
| Security and release hygiene | CodeQL for Python and Go, secret scanning, formats, links, Hugo, package build, and OCI smoke passed |

These gates verify the checked-in runtime and its configured integration
paths: policy evaluation, fail-closed error handling, signed/hash-linked
receipts, delegation, package contracts, and the explicitly gated Linux
enforcement harnesses. They do **not** prove that Ardur observes calls that
bypass an adapter, provider-hidden actions, every effect below a tool call, or
production readiness on every platform.

The numeric Python result is a dated snapshot, not a permanent badge; the
workflow files under [`.github/workflows/`](.github/workflows/) are the current
source of truth. Historical model/adversarial aggregates remain at
`python/tests/comprehensive_test_report.json`, but they are not presented here
as evidence for the current tree.

## First-Run Paths

Start with one of these source-checkout paths. All three avoid a provider API
key; the local demo additionally avoids manual bearer-token and Docker setup.

### Local governance loop

```bash
git clone https://github.com/ArdurAI/ardur-evidence.git && cd ardur
./scripts/setup-dev.sh --skip-go
source python/.venv/bin/activate
python scripts/run-no-key-mvp-demo.py
```

This temporary loopback-only demo reaches a `PERMIT`, a `DENY`, and a locally
verified signed attestation. It disables TLS and bearer auth only for the child
process; do not use it as a production launch command. See the
[no-key MVP guide](docs/guides/no-key-mvp-demo.md) for the boundary and timing.

`setup-dev.sh` defaults to `python3.13` and creates `python/.venv`. For a manual
install instead, use Python 3.10 or newer (`python/pyproject.toml` enforces this),
run `python -m pip install --upgrade pip` first, then
`python -m pip install -e python/`; macOS system Python 3.9 and its bundled pip
are too old for the PEP 660 editable install.

### Fresh-user evidence bundle

```bash
python3 scripts/run-rwt-phase1-fresh-user.py \
  --expected-origin-dev "$(git rev-parse --short=12 origin/dev)" \
  --output-dir /tmp/ardur-rwt-phase1
```

This runs the repeatable no-key install, profile, hook allow/deny, receipt-chain,
and redaction checks. Read the [Claude Code MVP quickstart](docs/guides/claude-code-mvp-quickstart.md)
for the expected bundle result and the optional live-Claude path.

### Authenticated Docker evaluator

`make demo` plus [`scripts/verify-mvp.sh`](scripts/verify-mvp.sh) is the
authenticated Docker path. Configure `ARDUR_API_TOKEN` before starting it; the
[MVP evaluator guide](docs/mvp-evaluator-guide.md) contains the tested,
copy-paste authenticated lifecycle. CI starts this full stack from fresh named
volumes and requires the health, `PERMIT`, `DENY`, and signed-attestation
lifecycle to pass before the aggregate test gate succeeds.

## Fastest MVP Path: Claude Code

Start with the source-checkout walkthrough in
[`docs/guides/claude-code-mvp-quickstart.md`](docs/guides/claude-code-mvp-quickstart.md).
It gives three bounded paths:

- a **personal action-firewall proof** using `ardur personal-firewall demo`;
  it shows one local `ASK` outcome (Claude Code's normal permission flow stays
  in charge), three pre-dispatch denials for outside-workspace, secret-like,
  and network requests, and four verified signed receipt summaries without an
  API key or retained demo state. Absolute local scope paths are canonicalized
  before a permit so a symlinked path cannot redirect outside the workspace;
  this hook-only check does not prove hard-link identity or prevent a path from
  changing between the decision and the tool's later filesystem operation;
- a **60-second deliberate deny proof** using
  `python3 scripts/run-claude-deny-demo.py`; it exercises the real local hook
  adapter, verifies a signed violation receipt, checks an unchanged canary, and
  removes all temporary state without contacting an LLM provider;
- a **no-key confidence check** that runs the fresh-user evidence harness,
  simulated Claude Code hook allow/deny receipts, and redacted bundle checks
  without contacting an LLM provider; and
- a **live Claude Code demo** for users who already have the `claude` binary
  installed and authenticated.

That guide also separates **Works now**, **Not claimed**, and **Coming soon**
to clearly mark the boundary between shipped, deferred, and in-progress
capabilities — package-manager release status, provider-hidden behavior,
and subprocess/kernel/network side-effect gaps.

The personal mode enforces a signed governed-tool-call budget. It does not
claim a dollar-denominated cost cap unless an adapter supplies trusted signed
cost telemetry.

After a run, use the
[`Phase 1 Demo Packet`](docs/guides/phase1-demo-packet.md) to assemble a bounded
handoff: tested commit, `bundle.redacted.json`, optional live-Claude report, and
the exact claims the artifacts do and do not support.

> **Capture boundary today (v0.1):** Ardur signs the Claude Code tool-call
> events delivered to its installed hooks. Hook-only runs do not automatically
> capture subprocess trees, kernel events, or network connections below that
> boundary. A successfully daemon-linked Linux `ardur run` additionally
> captures cgroup-scoped process exec/exit events and measures their
> receipt-correlation gap, but still does not claim universal file, network, or
> provider-hidden effect coverage. An explicit Linux `--agent-recognition`
> preview can surface a bounded set of exact-name exec candidates outside a
> governed cgroup, but it is heuristic, observe-only, and not identity,
> attestation, or governance. The offline runtime-evidence correlator can
> inspect supplied sensor events, but does not create or authenticate them.
> macOS Endpoint Security and broader native effect coverage remain roadmap
> work. See [`docs/coverage-map.md`](docs/coverage-map.md) for the precise
> per-tool audit.

## Why Ardur

Many agent stacks can log what happened. A configured Ardur adapter can stop an
out-of-scope tool request before that adapter dispatches it. Its receipts let a
reviewer verify the issuer signature and hash linkage later, including what the
runtime allowed, denied, or left unknown.

Ardur is being built to do all three:

- bind agents to a declared mission
- enforce runtime boundaries over tools, resources, budgets, and delegation
- emit evidence that can be checked instead of argued about

Concretely — these are the design principles the repo is being built to meet, not guarantees that every checked-in surface is already production-ready:

- **Public-by-default as a working principle.** The aim is that every public claim ties to a verifier path, an artifact, a re-runnable test, or an explicit limitation note. The code-bearing runtime is landing in phases per the [public import plan](docs/public-import-plan.md); claims that depend on not-yet-verified runtime behavior still need explicit caveats.
- **Composable with what already exists.** Designed around SPIFFE for workload identity, Biscuit for first-party-attenuation credentials, Cedar for policy, the individual AAT Internet-Draft for delegation-token semantics, and EAT (RFC 9711) for attestation-token semantics. The configured Python proxy and Hub can fetch and retain their own X.509-SVID at startup, and the proxy can verify a peer JWT-SVID for Biscuit holder binding when operator trust inputs are configured. This does not make issuance SPIRE-bound; see the [S0–S2 workload-identity reference](docs/reference/spiffe-workload-identity.md).
- **Cryptographically bound by design.** Mission credentials are designed to be signed by an issuer key and produce signed receipts chain-hashed to the previous one. The Python Biscuit path reports SPIFFE holder binding only when the proxy has a server-owned Biscuit issuer key, JWT-SVID trust bundle, and audience and the presented credentials verify against them; request payloads cannot choose those verifier inputs. JWT-SVID itself remains a replayable bearer credential, so this is bounded holder evidence rather than universal replay prevention. The design is documented in the [ADRs](docs/decisions/README.md); the public code that implements it is being curated in phases.
- **Delegation that narrows, never widens.** Child sessions get strictly narrower authority than their parent — fewer tools, smaller resource scope, smaller budget. The narrowing discipline is formalised in [ADR-017](docs/decisions/ADR-017-biscuit-attenuation-narrowing-semantics.md).
- **Impact caps before dangerous actions.** Opted-in Mission Passports bind trusted tool contracts to typed action caps and atomically conserved session/agent/lineage ceilings. Crash reservations quarantine instead of silently refunding authority; the design is recorded in [ADR-026](docs/decisions/ADR-026-typed-dangerous-action-risk-budgets.md).
- **Pre-action spend authority.** Library adapters can reserve signed token and currency-micro ceilings across session, agent, and delegation-lineage scopes before a metered call, then settle trusted usage or quarantine uncertainty without silently refunding it. [Reference](docs/reference/spend-budgets.md).
- **No authority by omission.** An absent or empty `resource_scope` grants no resource authority. Operators who intentionally permit every resource must sign the sole explicit wildcard `resource_scope: ["**"]`; issuance and governed-run surfaces warn when they do. The decision and format-specific attenuation rules are documented in [ADR-023](docs/decisions/ADR-023-explicit-resource-scope-authority.md).
- **Explicit about what it doesn't do.** Scope-level governance can't catch semantic misuse — if an allowed tool is used on an allowed resource for the wrong reason, that's a different layer's job.
- **MIT licensed.** The research foundation (the Silence Theorem, the protocol formalism, the benchmark methodology) will be linked from this repo when the paper's public identifier is assigned. Articles in this repo paraphrase the research in original prose; they do not reproduce paper content.

## What Is Public Today

This repo currently includes:

- the product thesis and launch direction
- a short research-informed positioning summary
- current status and what is still being resolved
- public v0.1 specs for mission declarations, execution receipts, verifier contracts, conformance profiles, and related protocol surfaces, plus a draft-10-pinned DRP mapping and executable profile with RFC 8785/P-256 emit, external-trust full-chain and critical-bound verification, and a portable seven-scenario implementation self-test bundle/report (not an IETF or independent interoperability claim), the v0.2 Execution Receipt hardening profile with versioned RFC 8785 payloads and legacy verification, a transparency-anchor sidecar profile with offline-verifiable Rekor v1 and separately keyed self-hosted proofs, a receiver-attestation profile with a two-key offline verifier and MCP shim fixture, a full offline-verification bundle/profile with redacted CLI/JSON/static HTML explorer reports, and a verified-receipt governance telemetry profile with redacted JSONL plus OTLP/HTTP trace/log export
- Python governance runtime under `python/`, including the framework-neutral [governed subagent adapter](docs/reference/governed-subagent-adapter.md) with opaque parent-bound handles, durable retry/recovery, pre-action child gates, and credential-free session evidence; Go eBPF/K8s packages and version-dispatched JWT AAT credential attenuation under `go/`: the existing draft-00 DG v0.1 contract plus the explicit `ardur.dg.aat-draft-01.v0.2` profile with chain-position roles, audience-bound PoP, fresh per-hop holder keys, approval gates, and a deterministic self-test fixture (CWT and independent interoperability are not claimed)
- optional Python typed dangerous-action risk budgets with authenticated schema/extractor digests, signed attenuation, fsync-backed multi-scope reservations, explicit executor outcomes, and privacy-bounded signed receipts; the existing DRP profile does not project this extension
- a Linux governance-overhead harness with a closed report schema, PR smoke workflow, manual stress profile, owner-only artifacts, and an opt-in shell-free paired-sensor mode
- the Ardur Personal Hub service and CLI under `python/vibap/` (`ardur hub`, `ardur setup`, `ardur status`, `ardur protect claude-code`, `ardur profile init`, `ardur doctor-claude-code`, full offline evidence verification, verified redacted receipt telemetry export, receiver-envelope verification, detached normalized/Tetragon/Falco runtime-evidence correlation, static non-executing MCP/tool-server preflight, and no-key DRP/receiver/offline-verification fixtures), plus deterministic `ardur-drp-fixtures` and `ardur-policy-conformance` runners
- the Claude Code plugin under `plugins/claude-code/` with `PreToolUse`, `PostToolUse`, `SubagentStart`, and `SubagentStop` hooks emitting signed receipts
- runnable framework adapters under `examples/`: LangChain, LangGraph, AutoGen, browser extension, desktop-observe, native-host, static tool-server preflight fixtures, and offline/no-key OpenAI Agents SDK and Google ADK fixtures. JSON mission examples remain in `examples/missions/`
- dedicated Python (3.10 + 3.13) and Go CI under `.github/workflows/tests.yml`, including the offline examples-smoke regression in `python/tests/test_examples_smoke.py` and a required fresh-volume Compose demo lifecycle, plus CodeQL, link-check, secret-scan, format validation, and the Hugo build
- the Hugo public evidence site source under `site/`, with each public claim linkable to its backing source file
- bootstrap and verification scripts under `scripts/` (`conductor-bootstrap.sh`, `setup-dev.sh`, `check-local.sh`)
- agent-specific public guides under [`docs/agent-instructions/`](docs/agent-instructions/) (Conductor, Codex, Claude)
- new technical reference pages under [`docs/reference/`](docs/reference/) — CLI, Personal Hub HTTP API, the `ARDUR.md` profile format, and the governed subagent adapter
- selected archival terminal recordings, plus a separate re-runnable no-key
  Phase 1 evidence harness for the Claude Code MVP path — see
  [MEDIA.md](MEDIA.md) and the
  [evidence-bundle guide](docs/guides/read-phase1-evidence-bundle.md)
- a journey-log [article series](docs/articles/README.md) — Article 06 (Public Import Discipline) and Article 05 (Proof Media That Actually Means Something) are the first-wave shippers
- a public audit trail at [`docs/audit/`](docs/audit/) mirroring the GitHub Code Scanning dismissal record so triage decisions are auditable from the repo tree without GitHub credentials

## What Is Coming Next

The next repo drops will add:

- live-provider OpenAI Agents SDK and Google ADK wrapper evidence as a separate, opt-in path beyond the current no-key fixture examples
- Codex hooks and Claude Desktop MCP packaging as separate next-cycle integrations
- re-runnable proof media — recordings made against the public runtime with stable verifier commands and artifact paths, replacing the current archival walkthrough casts
- a tagged release with a regenerated Homebrew formula carrying Python resource stanzas, so non-technical users can install Ardur Personal without a source checkout
- broader deployment material (cluster, identity, receipt storage) past the current SPIRE design surface

## Integrations

Ardur sits between an AI agent and the tools it calls — so the integration story is which agent frameworks, model providers, policy engines, and identity systems Ardur plugs into.

| Layer                | In repo now | Still pending public validation |
|----------------------|-------------|---------------------------------|
| **Agent framework**  | JSON mission examples; Claude Code plugin; runnable LangChain, LangGraph, AutoGen, browser, desktop-observe, native-host, and offline/no-key OpenAI Agents SDK and Google ADK fixture examples | live-provider wrappers and more runnable framework adapters |
| **Model provider**   | provider-agnostic tool boundary in the runtime design | local Ollama quickstarts and live-provider examples |
| **Policy engine**    | native checks, forbid-rules, Cedar bridge, draft-00 DG v0.1 plus the versioned draft-01 DG v0.2 JWT AAT profile | independent AAT interoperability, OPA, and broader Biscuit datalog examples |
| **Identity**         | configured Python proxy/Hub X.509-SVID startup acquisition and optional inbound JWT-SVID verification; X.509-SVID mTLS and source authorization for Go operator-ingress telemetry; detached receipt export labels actor/verifier strings as signed claims, not SPIFFE-verified workloads; production deployment ADR | SPIRE-bound Python credential issuance, full cluster deployment walkthrough, and live multi-producer proof |
| **Receipts sink**    | local JSON / stdout receipts; verified redacted governance JSONL; OTLP/HTTP JSON traces and logs; idempotent pending anchor sidecars; optional Rekor v1 or separately keyed self-hosted signed-log proofs; optional receiver-attested MCP envelopes | production collector deployment/auth/retention examples, checkpoint witnessing/consistency monitoring, vendor-specific sinks, broader durable storage examples, and integrated multi-artifact chain verification |

In the Go credential identity layer, SPIRE authenticates the workload
`spiffe_id`; the configured deployer `owner_id` is signed attribution, not an
authenticated owner binding. New credentials state
`owner_id_assurance: "self_asserted"`, and verifiers reject missing or stronger
unimplemented assurance values. [ADR-024](docs/decisions/ADR-024-self-asserted-owner-identity-assurance.md)
records the boundary and the proof required before a verified owner state can
exist.

The Python S0–S2 startup path is a separate boundary: it does not resolve
credential identity at issuance. A `spiffe_id` supplied to Python issuance
remains caller-provided and self-asserted even when the service has fetched its
own SVID.

If you'd use an integration that isn't listed, file an [integration request](https://github.com/ArdurAI/ardur-evidence/issues/new?template=integration_request.yml) — it's the strongest signal we have for prioritisation.

## Naming Note

`Ardur Evidence` is this project's public name. It was called `Ardur`, and the
repository was `ArdurAI/ardur`, until 2026-09-29; `Ardur` now names the Ardur
app. Protocol identifiers keep their existing `ardur.*` names, for example the
`ardur.execution_receipt.v0.2` schema and the `application/ardur.er+jwt` token
type, so receipts issued before the rename stay valid. The Go module path is
unchanged for now.

Some implementation and protocol surfaces still use `VIBAP`, `MCEP`, and
related protocol names. Those names are part of the technical lineage and are
kept where they describe actual artifacts, specifications, or protocol roots.

## Scope and Status

This repo is published progressively — each surface lands when it is
backed by runnable code, verifiable artifacts, or documented limitations.
See `STATUS.md` for what is public today and `ROADMAP.md` for what is
coming next.
