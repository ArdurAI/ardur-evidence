---
title: "Get Started"
description: "Run the current source-checkout governance proof without a provider API key."
weight: 5
maturity: ["public-now"]
claim_types: ["orientation"]
surfaces: ["python", "go", "examples"]
frameworks: ["framework-agnostic", "claude-code", "ollama"]
evidence_levels: ["code-and-doc"]
---

## Pick your path

The source-checkout governance loop works anywhere Python 3.10+ runs. Choose
the setup that matches your host.

---

### Mac (Apple Silicon or Intel)

```bash
# 1. Clone the repo
git clone https://github.com/ArdurAI/ardur-evidence.git
cd ardur

# 2. Create the dev virtualenv and install the package
./scripts/setup-dev.sh --skip-go
source python/.venv/bin/activate

# 3. Verify it works
PYTHONPATH=python python -c "from vibap.passport import generate_keypair; generate_keypair()"
```

**Done.** You can now issue mission passports and run the governance proxy.

For a manual install instead, use Python 3.10 or newer (`python/pyproject.toml`
enforces this), run `python -m pip install --upgrade pip`, then
`pip install -e python/`. macOS system Python 3.9 and its bundled pip are too
old for the PEP 660 editable install.

---

### Linux (Ubuntu / Debian / Fedora)

```bash
# 1. Clone and set up Python
git clone https://github.com/ArdurAI/ardur-evidence.git
cd ardur
./scripts/setup-dev.sh --skip-go
source python/.venv/bin/activate

# 2. Optional: build the Go AAT engine
cd go && go build ./...
```

---

### VM / Sandbox / Remote Server

Same as Linux above. `ardur start` binds to `127.0.0.1` by default. For a VM or
remote sandbox, keep Ardur on loopback and use an SSH tunnel for development
access unless you have separately reviewed the host, proxy, and network boundary.
The local TLS flags are loopback proxy configuration, not a hosted-service or
client-certificate deployment claim; see the [CLI reference]({{< relref "/source/docs/reference/cli/" >}})
for the current `ardur start --host` and TLS boundary.

---

### Docker

The authenticated evaluator stack is available from a source checkout through
`make demo`. Published release images remain gated; see the
[MVP evaluator guide]({{< relref "/source/docs/mvp-evaluator-guide/" >}}).

---

## Connect your AI agent

### With Ollama (local models)

The proxy evaluates tool requests routed to it, not model outputs. Ollama can
be used by a configured harness; this is not automatic discovery of every
model action.

```bash
# Start Ollama with a local model
ollama pull <your-model>
ollama serve

# Run the governance proxy
PYTHONPATH=python python -m vibap.cli hub
```

### With Ollama (cloud models)

For larger models via Ollama's cloud API:

```bash
export OLLAMA_API_KEY="your-api-key"

# Run the full governance test
PYTHONPATH=python python python/tests/run_cloud_model_test.py "$MODEL_NAME"
```

This optional harness routes its configured tool requests through Ardur's
governance check. Its historical aggregate report is not the first-run proof.

### With Claude Code

Ardur ships a native Claude Code plugin:

```bash
# Initialize a mission profile
PYTHONPATH=python python -m vibap.cli profile init

# Protect your Claude Code session
PYTHONPATH=python python -m vibap.cli protect claude-code --profile ARDUR.md
```

See the [Claude Code plugin README]({{< relref "/source/plugins/claude-code/README.md" >}}) for the full setup.

### With LangChain / LangGraph / AutoGen

Runnable quickstarts live in the examples directory:

- [LangChain quickstart]({{< relref "/source/examples/langchain-quickstart/readme/" >}})
- [LangGraph quickstart]({{< relref "/source/examples/langgraph-quickstart/readme/" >}})
- [AutoGen quickstart]({{< relref "/source/examples/autogen-quickstart/readme/" >}})

---

## Run your first governed session

The shortest current end-to-end path is provider-free and cleans up its own
temporary state:

```bash
git clone https://github.com/ArdurAI/ardur-evidence.git
cd ardur
./scripts/setup-dev.sh --skip-go
source python/.venv/bin/activate
python scripts/run-no-key-mvp-demo.py
```

The demo reaches a `PERMIT`, a `DENY`, and a locally verified signed
attestation. It disables TLS and bearer auth only for its loopback child
process; it is not a production launch command.

---

## Next steps

- [Review current evidence]({{< relref "/evidence" >}})
- [Read the CLI reference]({{< relref "/source/docs/reference/cli/" >}})
- [Understand the security model]({{< relref "/source/docs/security-model/" >}})
- [Browse the examples]({{< relref "/examples" >}})
