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
