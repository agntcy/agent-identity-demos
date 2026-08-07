# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

package envoy.authz

import rego.v1

valid_actor := {
	"iss": "http://idjag-issuer:9000",
	"sub": "sarah@org-a.example",
	"aud": "http://keycloak-b:8080/realms/org-b",
	"azp": "triage-agent",
	"client_id": "triage-agent",
	"scope": "openid triage:create",
	"intent": ["create-pr-fix"],
	"act": {
		"sub": "opencode-agent",
		"act_chain": ["opencode-agent"],
	},
}

valid_headers := {
	"x-verified-actor-token-payload": base64url.encode(json.marshal(valid_actor)),
}

egress_input(headers) := {"attributes": {"request": {"http": {
	"method": "POST",
	"path": "/api/egress-check",
	"headers": headers,
}}}}

valid_input := egress_input(valid_headers)

test_health_allowed if {
	result := allow with input as {"attributes": {"request": {"http": {
		"method": "GET",
		"path": "/health",
		"headers": {},
	}}}}
	result.allowed
	result.headers["x-agntcy-policy-rule"] == "org-a-egress-health"
}

test_valid_delegation_allowed if {
	result := allow with input as valid_input
	result.allowed
	result.headers["x-agntcy-delegation-depth"] == "1"
}

test_missing_actor_token_denied if {
	result := allow with input as egress_input({})
	not result.allowed
	result.http_status == 403
}

test_wrong_subject_denied if {
	actor := object.union(valid_actor, {"sub": "mallory@org-a.example"})
	headers := {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))}
	result := allow with input as egress_input(headers)
	not result.allowed
}

test_insufficient_scope_denied if {
	actor := object.union(valid_actor, {"scope": "openid"})
	headers := {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))}
	result := allow with input as egress_input(headers)
	not result.allowed
}

test_unsupported_intent_denied if {
	actor := object.union(valid_actor, {"intent": ["delete-repository"]})
	headers := {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))}
	result := allow with input as egress_input(headers)
	not result.allowed
}

test_wrong_azp_denied if {
	actor := object.union(valid_actor, {"azp": "sub-agent", "client_id": "sub-agent"})
	headers := {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))}
	result := allow with input as egress_input(headers)
	not result.allowed
}

test_act_chain_too_deep_denied if {
	actor := object.union(valid_actor, {"act": {
		"sub": "sub-agent",
		"act_chain": ["opencode-agent", "triage-agent", "sub-agent"],
	}})
	headers := {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))}
	result := allow with input as egress_input(headers)
	not result.allowed
}

test_empty_act_chain_denied if {
	actor := object.union(valid_actor, {"act": {"sub": "opencode-agent", "act_chain": []}})
	headers := {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))}
	result := allow with input as egress_input(headers)
	not result.allowed
}

test_act_chain_origin_mismatch_denied if {
	actor := object.union(valid_actor, {"act": {
		"sub": "other-agent",
		"act_chain": ["other-agent"],
	}})
	headers := {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))}
	result := allow with input as egress_input(headers)
	not result.allowed
}

# ── Badge-scope PDP tests ────────────────────────────────────────────────────

valid_user := {
	"iss": "http://keycloak-a:8080/realms/org-a",
	"sub": "8f7a2c1e-demo-user-id",
	"azp": "opencode-agent",
	"scope": "openid profile email",
	"email": "sarah@org-a.example",
	"preferred_username": "sarah",
}

badge_scope_input(user, extra_headers) := {"attributes": {"request": {"http": {
	"method": "POST",
	"path": "/api/badge-scope-check",
	"headers": object.union(
		{"x-verified-user-token-payload": base64url.encode(json.marshal(user))},
		extra_headers,
	),
}}}}

valid_badge_request_headers := {
	"x-agntcy-requested-action": "scan-remediate",
	"x-agntcy-requested-repo": "demo-admin/payments-service",
}

test_badge_scope_allowed_with_scoped_intent if {
	result := allow with input as badge_scope_input(valid_user, valid_badge_request_headers)
	result.allowed
	result.headers["x-agntcy-policy-rule"] == "org-a-badge-scope"
	result.headers["x-agntcy-scoped-intent"] == "scan-remediate:demo-admin/payments-service"
	result.headers["x-agntcy-scoped-resource"] == "demo-admin/payments-service"
}

test_badge_scope_wrong_client_denied if {
	user := object.union(valid_user, {"azp": "rogue-agent"})
	result := allow with input as badge_scope_input(user, valid_badge_request_headers)
	not result.allowed
	result.http_status == 403
}

test_badge_scope_wrong_user_denied if {
	user := object.union(valid_user, {"email": "mallory@org-a.example"})
	result := allow with input as badge_scope_input(user, valid_badge_request_headers)
	not result.allowed
}

test_badge_scope_repo_outside_allowlist_denied if {
	headers := object.union(valid_badge_request_headers, {
		"x-agntcy-requested-repo": "demo-admin/other-service",
	})
	result := allow with input as badge_scope_input(valid_user, headers)
	not result.allowed
}

test_badge_scope_unsupported_action_denied if {
	headers := object.union(valid_badge_request_headers, {
		"x-agntcy-requested-action": "delete-repository",
	})
	result := allow with input as badge_scope_input(valid_user, headers)
	not result.allowed
}

test_badge_scope_missing_task_headers_denied if {
	result := allow with input as badge_scope_input(valid_user, {})
	not result.allowed
}

# ── Egress: the READ assertion (source scanning) ─────────────────────────────

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

read_egress_request(actor) := {"attributes": {"request": {"http": {
	"method": "POST",
	"path": "/api/egress-check",
	"headers": {"x-verified-actor-token-payload": base64url.encode(json.marshal(actor))},
}}}}

test_source_read_egress_allowed if {
	result := allow with input as read_egress_request(valid_read_assertion)
	result.allowed
	result.headers["x-agntcy-policy-rule"] == "org-a-egress-source-read"
	result.headers["x-agntcy-delegation-depth"] == "1"
}

test_read_assertion_carrying_write_denied if {
	wide := json.patch(valid_read_assertion, [{
		"op": "replace", "path": "/scope", "value": "openid gitea:read gitea:write",
	}])
	result := allow with input as read_egress_request(wide)
	not result.allowed
}

test_read_assertion_carrying_triage_denied if {
	wide := json.patch(valid_read_assertion, [{
		"op": "replace", "path": "/scope", "value": "openid gitea:read triage:create",
	}])
	result := allow with input as read_egress_request(wide)
	not result.allowed
}

test_read_of_unlisted_repository_denied if {
	other := json.patch(valid_read_assertion, [{
		"op": "replace", "path": "/resource", "value": ["demo-admin/some-other-repo"],
	}])
	result := allow with input as read_egress_request(other)
	not result.allowed
}

test_read_with_delegated_chain_denied if {
	deeper := json.patch(valid_read_assertion, [{
		"op": "replace", "path": "/act", "value": {
			"sub": "triage-agent", "act_chain": ["opencode-agent", "triage-agent"],
		},
	}])
	result := allow with input as read_egress_request(deeper)
	not result.allowed
}

test_read_without_scan_intent_denied if {
	wrong := json.patch(valid_read_assertion, [{
		"op": "replace", "path": "/intent", "value": ["create-pr-fix"],
	}])
	result := allow with input as read_egress_request(wrong)
	not result.allowed
}
