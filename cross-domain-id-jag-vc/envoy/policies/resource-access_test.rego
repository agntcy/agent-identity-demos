# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

package envoy.authz

import rego.v1

valid_resource_access := {
	"iss": "http://keycloak-b:8080/realms/org-b",
	"sub": "org-b-user-id",
	"azp": "sub-agent",
	"scope": "profile email gitea:write gitea:pr",
	"preferred_username": "sarah",
}

valid_sub_badge := {
	"iss": "http://idjag-issuer:9000",
	"sub": "sarah@org-a.example",
	"aud": "http://keycloak-b:8080/realms/org-b",
	"azp": "sub-agent",
	"client_id": "sub-agent",
	"scope": "openid gitea:write gitea:pr",
	"intent": ["create-pr-fix"],
	"resource": ["demo-admin/payments-service"],
	"act": {
		"sub": "triage-agent",
		"act_chain": ["opencode-agent", "triage-agent"],
	},
}

valid_resource_headers := {
	"x-verified-access-token-payload": base64url.encode(json.marshal(valid_resource_access)),
	"x-verified-actor-token-payload": base64url.encode(json.marshal(valid_sub_badge)),
}

valid_context := {
	"intent": "create-pr-fix",
	"act_chain": ["opencode-agent", "triage-agent", "sub-agent"],
	"ticket_id": "TRIAGE-2024-12345",
}

valid_pr_body := object.union(valid_context, {
	"head": "agent/feature-a1b2c3",
	"base": "main",
	"title": "fix: remediate create-pr-fix [ticket=TRIAGE-2024-12345]",
})

resource_input(operation, repo, body, headers) := {
	"attributes": {"request": {"http": {
		"method": "POST",
		"path": sprintf("/api/gitea/%s/demo-admin/%s", [operation, repo]),
		"headers": headers,
	}}},
	"body": body,
}

test_resource_health_allowed if {
	result := allow with input as {
		"attributes": {"request": {"http": {
			"method": "GET",
			"path": "/healthz",
			"headers": {},
		}}},
	}
	result.allowed
	result.headers["x-agntcy-policy-rule"] == "org-b-resource-health"
}

test_valid_push_allowed if {
	result := allow with input as resource_input("push", "payments-service", valid_context, valid_resource_headers)
	result.allowed
	result.headers["x-agntcy-policy-action"] == "push-file"
	result.headers["x-agntcy-policy-repository"] == "demo-admin/payments-service"
	result.headers["x-agntcy-delegation-depth"] == "2"
}

test_valid_pr_allowed if {
	result := allow with input as resource_input("pulls", "payments-service", valid_pr_body, valid_resource_headers)
	result.allowed
	result.headers["x-agntcy-policy-action"] == "open-pr"
}

test_missing_sub_badge_denied if {
	headers := object.remove(valid_resource_headers, {"x-verified-actor-token-payload"})
	result := allow with input as resource_input("push", "payments-service", valid_context, headers)
	not result.allowed
}

test_access_actor_subject_mismatch_denied if {
	access := object.union(valid_resource_access, {"preferred_username": "mallory"})
	headers := object.union(valid_resource_headers, {"x-verified-access-token-payload": base64url.encode(json.marshal(access))})
	result := allow with input as resource_input("push", "payments-service", valid_context, headers)
	not result.allowed
}

test_missing_operation_scope_denied if {
	access := object.union(valid_resource_access, {"scope": "profile email gitea:pr"})
	headers := object.union(valid_resource_headers, {"x-verified-access-token-payload": base64url.encode(json.marshal(access))})
	result := allow with input as resource_input("push", "payments-service", valid_context, headers)
	not result.allowed
}

test_parent_triage_scope_is_not_inherited if {
	actor := object.union(valid_sub_badge, {"scope": "openid triage:create gitea:write gitea:pr"})
	headers := object.union(valid_resource_headers, {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))})
	result := allow with input as resource_input("push", "payments-service", valid_context, headers)
	not result.allowed
}

test_delegation_chain_mismatch_denied if {
	body := object.union(valid_context, {"act_chain": ["opencode-agent", "triage-agent", "different-agent"]})
	result := allow with input as resource_input("push", "payments-service", body, valid_resource_headers)
	not result.allowed
}

test_unsigned_intent_change_denied if {
	body := object.union(valid_context, {"intent": "delete-repository"})
	result := allow with input as resource_input("push", "payments-service", body, valid_resource_headers)
	not result.allowed
}

test_repository_outside_signed_badge_denied if {
	result := allow with input as resource_input("push", "other-service", valid_context, valid_resource_headers)
	not result.allowed
}

test_protected_repository_denied if {
	actor := object.union(valid_sub_badge, {"resource": ["demo-admin/demo-protected"]})
	headers := object.union(valid_resource_headers, {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))})
	result := allow with input as resource_input("pulls", "demo-protected", valid_pr_body, headers)
	not result.allowed
}

test_repository_creation_endpoint_denied if {
	result := allow with input as resource_input("repos", "payments-service", valid_context, valid_resource_headers)
	not result.allowed
}

test_non_main_pr_base_denied if {
	body := object.union(valid_pr_body, {"base": "release"})
	result := allow with input as resource_input("pulls", "payments-service", body, valid_resource_headers)
	not result.allowed
}

# ── Source read (Org A's agent, one hop, read-scoped) ────────────────────────

valid_read_access := {
	"iss": "http://keycloak-b:8080/realms/org-b",
	"sub": "org-b-opencode-id",
	"azp": "opencode-agent",
	"scope": "profile email gitea:read",
	"preferred_username": "sarah",
}

valid_read_assertion := {
	"iss": "http://keycloak-a:8080/realms/org-a",
	"sub": "sarah@org-a.example",
	"aud": "http://keycloak-b:8080/keycloak-b/realms/org-b",
	"azp": "opencode-agent",
	"client_id": "opencode-agent",
	"scope": "openid gitea:read",
	"intent": ["scan-source"],
	"resource": ["demo-admin/payments-service"],
	"act": {"sub": "opencode-agent", "act_chain": ["opencode-agent"]},
}

read_headers(access, actor) := {
	"x-verified-access-token-payload": base64url.encode(json.marshal(access)),
	"x-verified-actor-token-payload": base64url.encode(json.marshal(actor)),
}

read_request(access, actor) := {"attributes": {"request": {"http": {
	"method": "GET",
	"path": "/api/gitea/source/demo-admin/payments-service/src/main/java/com/example/payments/PaymentLookupRepository.java",
	"headers": read_headers(access, actor),
}}}}

test_source_read_allowed if {
	result := allow with input as read_request(valid_read_access, valid_read_assertion)
	result.allowed
	result.headers["x-agntcy-policy-rule"] == "org-b-source-read"
	result.headers["x-agntcy-policy-action"] == "read-source"
	result.headers["x-agntcy-policy-repository"] == "demo-admin/payments-service"
	result.headers["x-agntcy-delegation-depth"] == "1"
}

# A read-scoped credential must not be usable to write.
test_read_token_cannot_push if {
	result := allow with input as {"attributes": {"request": {"http": {
		"method": "POST",
		"path": "/api/gitea/push/demo-admin/payments-service",
		"headers": read_headers(valid_read_access, valid_read_assertion),
	}}}}
	not result.allowed
}

# Escalation: a read assertion that also carries write authority is refused.
test_read_with_write_scope_denied if {
	wide := json.patch(valid_read_assertion, [{
		"op": "replace", "path": "/scope", "value": "openid gitea:read gitea:write",
	}])
	result := allow with input as read_request(valid_read_access, wide)
	not result.allowed
}

test_read_with_triage_scope_denied if {
	wide := json.patch(valid_read_assertion, [{
		"op": "replace", "path": "/scope", "value": "openid gitea:read triage:create",
	}])
	result := allow with input as read_request(valid_read_access, wide)
	not result.allowed
}

# The read is bound to the repository signed into the assertion.
test_read_outside_signed_resource_denied if {
	other := json.patch(valid_read_assertion, [{
		"op": "replace", "path": "/resource", "value": ["demo-admin/other-service"],
	}])
	result := allow with input as read_request(valid_read_access, other)
	not result.allowed
}

# Deny-listed repos are unreadable, not merely unwritable.
test_read_protected_repository_denied if {
	protected := json.patch(valid_read_assertion, [{
		"op": "replace", "path": "/resource", "value": ["demo-admin/demo-protected"],
	}])
	result := allow with input as {"attributes": {"request": {"http": {
		"method": "GET",
		"path": "/api/gitea/source/demo-admin/demo-protected/src/Main.java",
		"headers": read_headers(valid_read_access, protected),
	}}}}
	not result.allowed
}

# A deeper chain must not reach the read route — this is Org A's own hop.
test_read_with_delegated_chain_denied if {
	deeper := json.patch(valid_read_assertion, [{
		"op": "replace", "path": "/act", "value": {
			"sub": "triage-agent", "act_chain": ["opencode-agent", "triage-agent"],
		},
	}])
	result := allow with input as read_request(valid_read_access, deeper)
	not result.allowed
}

# The sub-agent's write credential must not be reusable to read source.
test_subagent_token_cannot_read_source if {
	result := allow with input as read_request(valid_resource_access, valid_sub_badge)
	not result.allowed
}
