# Comparisons and engineering responses

A reader doing due diligence on Ardur ends up with the same set of questions every time. This directory is where those questions get serious technical answers — not marketing comparisons, but engineering documents that describe trade-offs directly.

## In this directory

- **[OAuth and managed-agent auth](./oauth-and-managed-agent-auth.md)** — where Ardur sits relative to OAuth, AAT, and the managed-agent-auth direction Cloudflare and others are pursuing. Short version: complementary, not competing.
- **[Hook evaluation model](./hook-evaluation-model.md)** — how the verifier decides on a tool call when the call's arguments aren't fully resolved at pre-action time. Three responses (deterministic pre-action, abstain on uncertainty, post-action attestation) covering the cases LLM-driven agents actually produce.
- **[Protocol overhead](./protocol-overhead.md)** — what we'll measure and publish (payload size, latency, audit volume), and why we're not publishing the internal numbers until they've been re-run under the renamed runtime.

## What's not here

- A comparison against every adjacent governance product. We do that on request, not preemptively. If you're evaluating Ardur next to a specific tool and want a structured comparison, [open a Discussion](https://github.com/ArdurAI/ardur-evidence/discussions) and name the tool — we'll write it up.
- A "why Ardur is better than X" page. The comparison docs in this directory all converge on "different problems, often complementary." If we ever post a "why Ardur is better than X" page, take that as a sign we've drifted from the protocol-research framing this project came from.

## Reading order if you're new to the docs

1. Start with the [OAuth comparison](./oauth-and-managed-agent-auth.md) — it sets up the boundary between Ardur and the layer below it.
2. Then [hook evaluation](./hook-evaluation-model.md) — that's the most common engineering question after the boundary is clear.
3. [Protocol overhead](./protocol-overhead.md) is for when you're weighing deployment cost.

For the underlying spec, [`docs/specs/`](../specs/) is the authoritative source. Comparisons here cite specs but don't replace them.
