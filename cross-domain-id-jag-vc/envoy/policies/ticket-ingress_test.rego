# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

package envoy.authz

import rego.v1

valid_access := {
	"iss": "http://keycloak-b:8080/realms/org-b",
	"sub": "org-b-user-id",
	"azp": "triage-agent",
	"scope": "openid triage:create",
	"preferred_username": "sarah",
}

valid_actor := {
	"iss": "http://keycloak-a:8080/realms/org-a",
	"sub": "sarah@org-a.example",
	"aud": "http://keycloak-b:8080/keycloak-b/realms/org-b",
	"azp": "triage-agent",
	"client_id": "triage-agent",
	"scope": "triage:create",
	"intent": ["create-pr-fix"],
	"act": {
		"sub": "opencode-agent",
		"act_chain": ["opencode-agent"],
	},
}

valid_headers := {
	"x-verified-access-token-payload": base64url.encode(json.marshal(valid_access)),
	"x-verified-actor-token-payload": base64url.encode(json.marshal(valid_actor)),
}

valid_body := {
	"repo": "demo-admin/payments-service",
	"cve": "CVE-2026-1234",
	"severity": "HIGH",
	"delegating_agent": "opencode-agent",
	"act_chain": ["opencode-agent"],
	"intent": "create-pr-fix",
}

ticket_input(headers, body) := {
	"attributes": {"request": {"http": {
		"method": "POST",
		"path": "/api/ticket",
		"headers": headers,
	}}},
	"body": body,
}

valid_input := ticket_input(valid_headers, valid_body)

test_health_allowed if {
	result := allow with input as {"attributes": {"request": {"http": {
		"method": "GET",
		"path": "/health",
		"headers": {},
	}}}}
	result.allowed
	result.headers["x-agntcy-policy-rule"] == "org-b-health"
}

test_valid_delegation_allowed if {
	result := allow with input as valid_input
	result.allowed
	result.headers["x-agntcy-delegation-depth"] == "1"
}

test_missing_actor_token_denied if {
	headers := object.remove(valid_headers, {"x-verified-actor-token-payload"})
	result := allow with input as ticket_input(headers, valid_body)
	not result.allowed
	result.http_status == 403
}

test_unsigned_intent_change_denied if {
	body := object.union(valid_body, {"intent": "delete-repository"})
	result := allow with input as ticket_input(valid_headers, body)
	not result.allowed
}

test_signed_but_unsupported_intent_denied if {
	actor := object.union(valid_actor, {"intent": ["delete-repository"]})
	headers := object.union(valid_headers, {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))})
	body := object.union(valid_body, {"intent": "delete-repository"})
	result := allow with input as ticket_input(headers, body)
	not result.allowed
}

test_insufficient_actor_scope_denied if {
	actor := object.union(valid_actor, {"scope": "triage:read"})
	headers := object.union(valid_headers, {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))})
	result := allow with input as ticket_input(headers, valid_body)
	not result.allowed
}

test_access_actor_subject_mismatch_denied if {
	access := object.union(valid_access, {"preferred_username": "mallory"})
	headers := object.union(valid_headers, {"x-verified-access-token-payload": base64url.encode(json.marshal(access))})
	result := allow with input as ticket_input(headers, valid_body)
	not result.allowed
}

test_act_chain_mismatch_denied if {
	body := object.union(valid_body, {"act_chain": ["different-agent"]})
	result := allow with input as ticket_input(valid_headers, body)
	not result.allowed
}

test_resource_outside_demo_admin_denied if {
	body := object.union(valid_body, {"repo": "other-owner/payments-service"})
	result := allow with input as ticket_input(valid_headers, body)
	not result.allowed
}

# ── Sub-badge scope PDP tests ────────────────────────────────────────────────

valid_subbadge_request_headers := {
	"x-agntcy-requested-scope": "openid gitea:write gitea:pr",
	"x-agntcy-requested-repo": "demo-admin/payments-service",
	"x-agntcy-requested-intent": "create-pr-fix",
}

subbadge_input(access, extra_headers) := {"attributes": {"request": {"http": {
	"method": "POST",
	"path": "/api/subbadge-scope-check",
	"headers": object.union(
		{"x-verified-access-token-payload": base64url.encode(json.marshal(access))},
		extra_headers,
	),
}}}}

test_subbadge_scope_allowed_with_scoped_headers if {
	result := allow with input as subbadge_input(valid_access, valid_subbadge_request_headers)
	result.allowed
	result.headers["x-agntcy-policy-rule"] == "org-b-subbadge-scope"
	result.headers["x-agntcy-scoped-scope"] == "openid gitea:write gitea:pr"
	result.headers["x-agntcy-scoped-resource"] == "demo-admin/payments-service"
}

test_subbadge_scope_escalation_denied if {
	headers := object.union(valid_subbadge_request_headers, {
		"x-agntcy-requested-scope": "openid triage:create gitea:write",
	})
	result := allow with input as subbadge_input(valid_access, headers)
	not result.allowed
	result.http_status == 403
}

test_subbadge_wrong_client_denied if {
	access := object.union(valid_access, {"azp": "rogue-agent"})
	result := allow with input as subbadge_input(access, valid_subbadge_request_headers)
	not result.allowed
}

test_subbadge_protected_repo_denied if {
	headers := object.union(valid_subbadge_request_headers, {
		"x-agntcy-requested-repo": "demo-admin/demo-protected",
	})
	result := allow with input as subbadge_input(valid_access, headers)
	not result.allowed
}

test_subbadge_unsupported_intent_denied if {
	headers := object.union(valid_subbadge_request_headers, {
		"x-agntcy-requested-intent": "delete-repository",
	})
	result := allow with input as subbadge_input(valid_access, headers)
	not result.allowed
}

test_subbadge_missing_request_headers_denied if {
	result := allow with input as subbadge_input(valid_access, {})
	not result.allowed
}
