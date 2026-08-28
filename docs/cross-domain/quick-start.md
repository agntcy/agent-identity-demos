# Quick start

The demo README is the operational source of truth. This page is the shortest path to a running stack.

```bash
cd cross-domain-id-jag-vc
cp .env.example .env
# SARAH_PASSWORD / OPENCODE_CLIENT_SECRET / TRIAGE_CLIENT_SECRET /
# SUB_AGENT_CLIENT_SECRET must stay as the .env.example defaults (or be
# changed to match keycloak-a/org-a-realm.json + keycloak-b/org-b-realm.json)
# — everything else can be freely changed.

docker compose up -d --build
```

First boot takes ~3–5 minutes (Keycloak + identity-node + Directory cold start). Wait until these one-shot containers exit 0: `kc-a-init`, `kc-b-init`, `gitea-init`, `identity-node-init`, `agent-dir-init`.

```bash
docker compose logs -f
```

Then open the webapp at [http://localhost:8090](http://localhost:8090) and run the sequence.

## Model backend (optional)

The real OpenCode agent uses the **host's** Ollama as its free, local model provider (no API key). On your machine — not inside Docker:

```bash
ollama pull qwen2.5-coder:7b   # one-time (~4.7 GB)
ollama serve                    # or keep the Ollama desktop app running
```

**Without any model server, every run still succeeds** — the `opencode-plan` step reports `status=skipped` and the identity chain completes normally.

Custom OpenAI-compatible endpoints, Anthropic passthrough, reverse-proxy recipes, traces, and reviewer verification are in the [demo README](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/README.md#quick-start).

## Troubleshooting

- **`dir-zot` / `dir-apiserver` stay "starting"** — distroless images; `depends_on` is `service_started` by design.
- **`gitea-init` fails with "not supposed to be run as root"** — `user: git` must be set on `gitea-init` (already in compose).
- **CIMD steps return `ERROR_REASON_INVALID_PROOF`** — usually a Vault restart in dev mode destroyed the transit key while identity-node registrations survived. Re-bootstrap as documented in the [demo README troubleshooting](https://github.com/agntcy/agent-identity-demos/blob/main/cross-domain-id-jag-vc/README.md#troubleshooting).
- **Port already in use** — override the `*_PORT` variables in `.env`.
