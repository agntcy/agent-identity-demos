#!/bin/sh
# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
#
# Generates /workspace/opencode.json from env, then starts OpenCode headless.
#
#   OPENCODE_MODEL    "provider/model", e.g. "ollama/qwen2.5-coder:7b"
#                     or "anthropic/claude-sonnet-4-5"
#   OLLAMA_BASE_URL   OpenAI-compatible base URL of the host's Ollama
#                     (default http://host.docker.internal:11434/v1)
#   ANTHROPIC_API_KEY picked up automatically by the built-in anthropic
#                     provider when set — no config entry needed
#
# The model id is a JSON *key* under provider.models, so the config cannot
# use env substitution — it is rendered here at container start instead.
set -eu

OPENCODE_MODEL="${OPENCODE_MODEL:-ollama/qwen2.5-coder:7b}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://host.docker.internal:11434/v1}"

PROVIDER="${OPENCODE_MODEL%%/*}"
MODEL_ID="${OPENCODE_MODEL#*/}"

if [ "$PROVIDER" = "ollama" ]; then
  cat > /workspace/opencode.json <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "model": "ollama/${MODEL_ID}",
  "small_model": "ollama/${MODEL_ID}",
  "provider": {
    "ollama": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Ollama (host)",
      "options": { "baseURL": "${OLLAMA_BASE_URL}" },
      "models": { "${MODEL_ID}": { "name": "${MODEL_ID}" } }
    }
  },
  "permission": { "edit": "deny", "bash": "deny" }
}
EOF
else
  # Built-in provider (e.g. anthropic) — credentials come from env
  # (ANTHROPIC_API_KEY); only pin the model and deny mutations.
  cat > /workspace/opencode.json <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "model": "${PROVIDER}/${MODEL_ID}",
  "small_model": "${PROVIDER}/${MODEL_ID}",
  "permission": { "edit": "deny", "bash": "deny" }
}
EOF
fi

# Seed a minimal project so the coding agent has context for its plan work.
if [ ! -f /workspace/README.md ]; then
  cat > /workspace/README.md <<'EOF'
# Org A remediation workspace

This workspace belongs to OpenCode, Org A's AI coding agent, acting on
behalf of Sarah (sarah@org-a.example). Tasks arriving here concern CVE
remediation in repositories owned by Org B, accessed cross-domain through
AGNTCY identity delegation (ID-JAG + VC badges). Produce concise, concrete
remediation plans.
EOF
fi

if [ ! -d /workspace/.git ]; then
  git init -q /workspace 2>/dev/null || true
fi

echo "opencode-server: model=${PROVIDER}/${MODEL_ID} config=/workspace/opencode.json"
exec opencode serve --hostname 0.0.0.0 --port 4096
