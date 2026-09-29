# Reproducing AuditBench Harness Fixtures

This document describes how to reproduce the deterministic AuditBench harness
fixtures on a clean clone of this repository. These runs exercise engineering
contracts; they are not a completed independent evaluation or real annotation
study.

## What runs now (Workstream B1)

The evaluation harness (`go/cmd/benchcheck`) runs **four evaluation arms** over
the **four AuditBench scenarios** that ship in-repo under `go/benchmark/testdata/`:

| Scenario | Ground truth | Description |
|----------|-------------|-------------|
| AB-01 | compliant | Read-only session, all events authorized, full visibility |
| AB-02 | violation | Unauthorized write — tool not in allowed list |
| AB-03 | violation | Authorized tool with hidden visibility |
| AB-04 | violation | Tool-call budget exceeded on third call |

The four **evaluation arms** are:

| Arm | What it checks |
|-----|---------------|
| `cedar_strict` | Declared `AllowedActions` + `AllowedTools` — stateless |
| `cedar_state` | Same as cedar_strict + cumulative `tool_calls` budget enforcement |
| `visibility` | All events must have `visibility: "full"` |
| `mcep_reconciliation` | Per-event `expected_label` oracle — **100% accuracy by construction; not a detection metric** (see warning below) |

> **Oracle circularity — mcep_reconciliation**
>
> `mcep_reconciliation` reads back the `expected_label` field from the event trace file. That field *is* the ground truth: the arm agrees with it 100% of the time by definition, regardless of what the harness does. Its accuracy figure does not reflect detection capability. It exists only as a sanity-check — confirming that the label schema round-trips correctly and that the harness sees the same events used to generate the expected output. Do not cite the `mcep_reconciliation` accuracy as evidence of Ardur's detection performance; use `cedar_strict`, `cedar_state`, and `visibility` for that.

These scenarios are deliberately small and exercise orthogonal policy dimensions
so that the arms return **different verdicts** (see the table produced by
`make bench`), confirming the harness is actually doing discriminative evaluation
rather than trivially agreeing.

## Reproducing the results

**Prerequisites**: Go ≥ 1.26.6, `make`.

```sh
# 1. Clone (or pull) the repository
git clone https://github.com/ArdurAI/ardur-evidence.git
cd ardur

# 2. Run the benchmark
make bench
# Equivalent: cd go && go run ./cmd/benchcheck -- ./benchmark/testdata

# 3. Results are written to bench-results/
cat bench-results/results.json   # structured JSON
cat bench-results/summary.csv    # CSV row per scenario
```

The run is **deterministic and byte-reproducible**:
- Input files are read from `go/benchmark/testdata/` (version-controlled).
- Scenarios are processed in sorted order by file path and then by `scenario_id`.
- No randomness, no network calls, no timestamps in output fields.
- `results.json` round-trips identically from any commit that touches only
  non-testdata files.

### Content-addressing inputs

To verify the scenario+events files haven't changed:

```sh
find go/benchmark/testdata -type f | sort | xargs shasum -a 256
```

This sha256 tree fingerprint is stable between runs on the same commit.

### Running the Go tests only (no output files)

```sh
cd go && go test -count=1 ./benchmark/live/...
```

Seven tests cover: each of the four scenarios end-to-end, the pack walker,
and error paths for missing files.

## What is NOT yet runnable (Workstream B2)

The planned Ardur headline corpus (**externally human-labeled scenarios drawn
from real agentic-AI traces**) is **not bundled in this repository**. This is
intentional: the corpus carries privacy-sensitive information and requires an
externally governed collection and labeling process to avoid ground-truth
leakage into the evaluators.

The versioned engineering pipeline for that future corpus is implemented under
`go/benchmark/independent` with three commands:

- `auditbench-oracle` strictly normalizes a raw capture into full-oracle and
  projected-evidence views;
- `auditbench-label` creates one-view blind bundles and enforces declared role
  separation over submitted identity strings;
- `auditbench-score` creates a local content-integrity seal and verifies
  held-out tri-state scoring against that exact artifact graph.

Run its hostile pipeline tests with:

```sh
cd go && go test -race -count=1 ./benchmark/independent ./cmd/auditbench-oracle ./cmd/auditbench-label ./cmd/auditbench-score
```

See
[`docs/specs/auditbench-evaluation-protocol-v0.1.md`](docs/specs/auditbench-evaluation-protocol-v0.1.md)
for the artifact contract and proof boundary. Passing these tests proves the
pipeline and local content integrity, not annotator identity, evaluator
independence, external registration, or a headline corpus.

The following items remain gated on the separately-labeled corpus:

- Scaled evaluation over the full headline corpus (50+ scenarios per label class)
- Recall/precision curves per arm across the full distribution
- Statistical significance analysis (bootstrap CIs on arm-accuracy differences)
- The `cedar_strict` arm using a real compiled Cedar policy (not just the
  declared `allowed_actions` / `allowed_tools` lists)

To contribute corpus scenarios, follow the `Scenario` and `Event` JSON schemas
defined in `go/benchmark/types.go` and place files under a pack directory that
can be passed as the first argument to `benchcheck`:

```sh
cd go && go run ./cmd/benchcheck -- /path/to/your-corpus-pack
```

The harness will evaluate and report on whatever `.scenario.json` /
`.events.jsonl` pairs it finds, without modification to the harness itself.

## Command reference

```
Usage: benchcheck [flags] [pack-dir]

  pack-dir   directory containing *.scenario.json + *.events.jsonl pairs
             (default: go/benchmark/testdata relative to the repo root)

Flags:
  -out string   output directory (default: bench-results)
  -quiet        suppress result table on stdout

Exit codes:
  0  success
  1  error (missing files, invalid JSON, …)
```
