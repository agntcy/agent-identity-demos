# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

# Real OpenCode (opencode.ai) running headless — Org A's AI coding agent.
# Pinned npm release; the identity orchestrator (opencode-agent service)
# drives it over the HTTP API on :4096.
FROM node:22-bookworm-slim

# git: OpenCode expects a project/VCS context; curl: container healthcheck.
RUN apt-get update && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN npm install -g opencode-ai@1.18.7 && npm cache clean --force

RUN useradd --create-home --shell /bin/bash opencode \
    && mkdir -p /workspace && chown opencode:opencode /workspace
USER opencode
ENV HOME=/home/opencode
WORKDIR /workspace

COPY --chown=opencode:opencode entrypoint.sh /entrypoint.sh

EXPOSE 4096
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
