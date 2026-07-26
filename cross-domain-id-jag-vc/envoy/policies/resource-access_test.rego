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
