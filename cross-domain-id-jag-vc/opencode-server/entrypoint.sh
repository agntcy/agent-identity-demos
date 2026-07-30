#!/bin/sh
# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0
#
# Generates /workspace/opencode.json from env, then starts OpenCode headless.
#
#   OPENCODE_MODEL    "provider/model". The provider half is free-form for
#                     self-hosted endpoints — e.g. "ollama/qwen2.5-coder:7b",
#                     "onprem/gemma-3-27b-it" — or one of OpenCode's built-in
#                     cloud providers, e.g. "anthropic/claude-sonnet-4-5".
#   LLM_BASE_URL      OpenAI-compatible base URL of the model server: local
#                     Ollama, or an on-prem vLLM / TGI / SGLang deployment
#                     (default: OLLAMA_BASE_URL, i.e. the host's Ollama)
#   LLM_API_KEY       optional bearer token for that endpoint (omit if open
#                     on the network); Ollama ignores it
#   ANTHROPIC_API_KEY picked up automatically by the built-in anthropic
#                     provider when set — no config entry needed
#
# Any provider that is NOT a known built-in cloud provider is configured via
# @ai-sdk/openai-compatible against LLM_BASE_URL — that covers Ollama and
# every standard on-prem serving stack identically.
#
# The model id is a JSON *key* under provider.models, so the config cannot
# use env substitution — it is rendered here at container start instead.
set -eu

OPENCODE_MODEL="${OPENCODE_MODEL:-ollama/qwen2.5-coder:7b}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-http://host.docker.internal:11434/v1}"
LLM_BASE_URL="${LLM_BASE_URL:-$OLLAMA_BASE_URL}"
LLM_API_KEY="${LLM_API_KEY:-}"

PROVIDER="${OPENCODE_MODEL%%/*}"
MODEL_ID="${OPENCODE_MODEL#*/}"

case "$PROVIDER" in
  anthropic|openai|azure|google|vertex|bedrock|openrouter|groq|mistral|deepseek|xai)
    IS_BUILTIN=1 ;;
  *)
    IS_BUILTIN=0 ;;
esac

if [ "$IS_BUILTIN" = "0" ]; then
  # Self-hosted / OpenAI-compatible endpoint (Ollama, vLLM, TGI, SGLang…).
  API_KEY_FRAGMENT=""
  if [ -n "$LLM_API_KEY" ]; then
    API_KEY_FRAGMENT=", \"apiKey\": \"${LLM_API_KEY}\""
  fi
  cat > /workspace/opencode.json <<EOF
{
  "\$schema": "https://opencode.ai/config.json",
  "model": "${PROVIDER}/${MODEL_ID}",
  "small_model": "${PROVIDER}/${MODEL_ID}",
  "provider": {
    "${PROVIDER}": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "${PROVIDER} (OpenAI-compatible endpoint)",
      "options": { "baseURL": "${LLM_BASE_URL}"${API_KEY_FRAGMENT} },
      "models": { "${MODEL_ID}": { "name": "${MODEL_ID}" } }
    }
  },
  "permission": { "edit": "deny", "bash": "deny", "external_directory": "deny" }
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
  "permission": { "edit": "deny", "bash": "deny", "external_directory": "deny" }
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

if [ "$IS_BUILTIN" = "0" ]; then
  echo "opencode-server: model=${PROVIDER}/${MODEL_ID} endpoint=${LLM_BASE_URL} config=/workspace/opencode.json"
else
  echo "opencode-server: model=${PROVIDER}/${MODEL_ID} (built-in provider) config=/workspace/opencode.json"
fi
exec opencode serve --hostname 0.0.0.0 --port 4096
