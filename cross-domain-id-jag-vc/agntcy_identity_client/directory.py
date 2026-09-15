# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

"""AGNTCY Directory Node client — OASF record push + search over gRPC.

The generated protobuf modules (agntcy.dir.*) are compiled at image build
time from the shared proto/ tree (see the consumers' Dockerfiles); imports
happen lazily so this module can be imported in environments without them.

gRPC calls are synchronous — async callers should wrap them in an executor,
e.g. `await asyncio.get_event_loop().run_in_executor(None, fn)`.
Extracted from webapp/app.py.
"""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any
from urllib.parse import quote

OASF_SCHEMA_VERSION = "1.1.0"
AGENT_RECORD_TYPE = "agent"
AUDIT_RECORD_TYPE = "audit"

# This is the one canonical agent-description catalog used by both the
# Directory bootstrap and Agent Badge issuance. Runtime turn records must not
# be used as credentials or as the source of an agent's standing description.
_AGENT_CATALOG: dict[str, dict[str, Any]] = {
    "security-autonomous-agent": {
        "name": "security-autonomous-agent",
        "version": "0.2.0",
        "description": "Security Autonomous Agent - scans code with its internal OpenCode engine and coordinates least-privilege remediation across organizations",
        "authors": ["cross-domain-demo"],
        "skills": [
            {"name": "cybersecurity/vulnerability_management/dependency_security", "id": 100304},
            {"name": "software_engineering/code_quality/code_review", "id": 60701},
        ],
        "domains": [
            {"name": "technology/security", "id": 107},
            {"name": "technology/software_engineering", "id": 102},
        ],
        "locators": [{"type": "url", "urls": [
            "http://security-autonomous-agent:8100",
            "http://security-autonomous-agent:8100/.well-known/agent-card.json",
        ]}],
        "annotations": {
            "org": "org-a",
            "cross_domain": "true",
            "autonomous": "true",
            "client_id": "security-autonomous-agent",
            "principal": "service-account-security-autonomous-agent",
            "role": "security-remediation-orchestrator",
            "planning_engine": "OpenCode (internal tool, not an agent identity)",
        },
    },
    "triage-agent": {
        "name": "triage-agent",
        "version": "0.2.0",
        "description": "Org B AI remediation agent - creates tickets, plans fixes, spawns sub-agents",
        "authors": ["cross-domain-demo"],
        "skills": [
            {"name": "research_knowledge_productivity/project_task_management/issue_tracking", "id": 130801},
            {"name": "software_engineering/code_quality/code_review", "id": 60701},
        ],
        "domains": [{"name": "technology/security", "id": 107}],
        "locators": [{"type": "url", "urls": [
            "http://triage-agent:8200",
            "http://triage-agent:8200/.well-known/agent-card.json",
        ]}],
        "annotations": {"org": "org-b", "cross_domain": "true", "client_id": "triage-agent"},
    },
    "sub-agent": {
        "name": "sub-agent",
        "version": "0.2.0",
        "description": "Org B sub-agent - bounded privilege, creates PRs in Gitea (gitea:write gitea:pr only)",
        "authors": ["cross-domain-demo"],
        "skills": [
            {"name": "software_engineering/version_control/pull_request_management", "id": 61003},
            {"name": "software_engineering/version_control/commit_authoring", "id": 61002},
        ],
        "domains": [{"name": "technology/security", "id": 107}],
        "locators": [{"type": "url", "urls": [
            "http://sub-agent:8300",
            "http://sub-agent:8300/.well-known/agent-card.json",
        ]}],
        "annotations": {"org": "org-b", "cross_domain": "true", "client_id": "sub-agent", "bounded_privilege": "true"},
    },
}


def _normalize_json(value: Any) -> Any:
    """Normalize protobuf Struct numbers before producing canonical JSON."""
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, dict):
        return {key: _normalize_json(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_json(item) for item in value]
    return value


def canonical_oasf(record: dict[str, Any]) -> bytes:
    """Canonical bytes used to bind a badge to the Directory record."""
    return json.dumps(_normalize_json(record), sort_keys=True, separators=(",", ":")).encode()


def oasf_digest(record: dict[str, Any]) -> str:
    """Return a stable SHA-256 digest for an OASF agent definition."""
    return "f" + hashlib.sha256(canonical_oasf(record)).hexdigest()


def build_agent_record(
    client_id: str,
    identity_node_url: str,
    *,
    identity_id: str | None = None,
) -> dict[str, Any]:
    """Build the canonical searchable OASF record for one known agent.

    ``identity_id`` and ``badge_url`` are discovery metadata. The
    ``credentialSubject.badge`` field carries this complete record so a
    verifier can compare the signed description with what Directory search
    returned, while the Directory remains a non-authoritative catalog.
    """
    try:
        record = copy.deepcopy(_AGENT_CATALOG[client_id])
    except KeyError as exc:
        raise ValueError(f"no canonical OASF definition for {client_id}") from exc

    resolved_identity_id = identity_id or f"AGNTCY-{client_id}"
    record.update({
        "schema_version": OASF_SCHEMA_VERSION,
        # Keep the canonical description stable across bootstrap and runtime
        # badge issuance. Turn records carry their own event timestamp.
        "created_at": "2026-01-01T00:00:00Z",
    })
    record["annotations"].update({
        "record_type": AGENT_RECORD_TYPE,
        "identity_id": resolved_identity_id,
        "badge_url": (
            f"{identity_node_url.rstrip('/')}/v1alpha1/vc/"
            f"{quote(resolved_identity_id, safe='')}/.well-known/vcs.json"
        ),
    })
    return record


def canonical_agent_records(identity_node_url: str) -> list[dict[str, Any]]:
    """Return the records bootstrapped into the Directory."""
    return [build_agent_record(client_id, identity_node_url) for client_id in _AGENT_CATALOG]


def push_record(dir_apiserver_url: str, record_dict: dict) -> str:
    """Push one OASF record to the Directory. Returns its CID."""
    import grpc
    from agntcy.dir.core.v1 import record_pb2
    from agntcy.dir.store.v1 import store_service_pb2_grpc
    from google.protobuf import struct_pb2

    record_data = struct_pb2.Struct()
    record_data.update(record_dict)
    record = record_pb2.Record(data=record_data)

    channel = grpc.insecure_channel(dir_apiserver_url)
    try:
        stub = store_service_pb2_grpc.StoreServiceStub(channel)
        refs = list(stub.Push(iter([record])))
    finally:
        channel.close()
    return refs[0].cid if refs else ""


def search_by_name(dir_apiserver_url: str, agent_name: str, limit: int = 5) -> list[dict]:
    """Search Directory records by agent name. Returns raw record dicts."""
    import grpc
    from agntcy.dir.search.v1 import search_service_pb2, search_service_pb2_grpc
    from google.protobuf.json_format import MessageToDict

    req = search_service_pb2.SearchRecordsRequest(
        queries=[search_service_pb2.RecordQuery(
            type=search_service_pb2.RECORD_QUERY_TYPE_NAME,
            value=agent_name,
        )],
        limit=limit,
    )

    channel = grpc.insecure_channel(dir_apiserver_url)
    try:
        stub = search_service_pb2_grpc.SearchServiceStub(channel)
        results = list(stub.SearchRecords(req))
    finally:
        channel.close()
    return [MessageToDict(res.record.data) for res in results]


def search_agents_by_name(dir_apiserver_url: str, agent_name: str, limit: int = 1000) -> list[dict]:
    """Search only canonical agent records, excluding runtime audit records.

    Agent and audit records intentionally share the agent name.  Ask for a
    broad result window before filtering so a growing audit history cannot
    crowd the canonical discovery record out of a small top-N response.
    """
    return [
        record for record in search_by_name(dir_apiserver_url, agent_name, limit)
        if (record.get("annotations") or {}).get("record_type") == AGENT_RECORD_TYPE
    ]
