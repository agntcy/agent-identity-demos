# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

package envoy.authz

import rego.v1

# Envoy verifies both JWTs before this policy runs. The Keycloak access token
# proves the local capability; the original signed sub-badge proves who
# delegated, the intended action, and the exact repository.

default allow := {
	"allowed": false,
	"http_status": 403,
	"body": "{\"error\":\"policy_denied\",\"reason\":\"resource delegation constraints not satisfied\"}",
	"headers": {
		"content-type": "application/json",
		"x-agntcy-policy-decision": "DENY",
		"x-agntcy-policy-enforcer": "built-on-envoy-opa",
	},
}

allow := {
	"allowed": true,
	"headers": {
		"x-agntcy-policy-decision": "ALLOW",
		"x-agntcy-policy-rule": "org-b-resource-health",
		"x-agntcy-policy-enforcer": "built-on-envoy-opa",
	},
} if {
	input.attributes.request.http.method == "GET"
	input.attributes.request.http.path == "/healthz"
}

allow := {
	"allowed": true,
	"headers": {
		"x-agntcy-policy-decision": "ALLOW",
		"x-agntcy-policy-rule": "org-b-resource-delegation",
		"x-agntcy-policy-enforcer": "built-on-envoy-opa",
		"x-agntcy-policy-action": action,
		"x-agntcy-policy-repository": repository,
		"x-agntcy-delegation-depth": sprintf("%d", [count(actor.act.act_chain)]),
	},
} if {
	input.attributes.request.http.method == "POST"
	segments := request_path_segments
	action := resource_action
	repository := requested_repository
	required := required_scope(action)

	access := verified_payload("x-verified-access-token-payload")
	actor := verified_payload("x-verified-actor-token-payload")

	access.azp == "sub-agent"
	actor.azp == "sub-agent"
	actor.client_id == "sub-agent"
	sprintf("%s@org-a.example", [access.preferred_username]) == actor.sub
	actor.sub == "sarah@org-a.example"

	scope_contains(access.scope, required)
	scope_contains(actor.scope, required)
	not scope_contains(access.scope, "triage:create")
	not scope_contains(actor.scope, "triage:create")

	actor.act.sub == "triage-agent"
	actor.act.act_chain == ["opencode-agent", "triage-agent"]
	input.body.act_chain == array.concat(actor.act.act_chain, [actor.azp])
	count(actor.act.act_chain) == 2

	input.body.intent == "create-pr-fix"
	input.body.intent in actor.intent
	startswith(input.body.ticket_id, "TRIAGE-")

	repository in actor.resource
	segments[3] == "demo-admin"
	segments[4] != "demo-protected"
	valid_action_body(action)
}

request_path_segments := split(trim(input.attributes.request.http.path, "/"), "/")

resource_action := "push-file" if {
	segments := request_path_segments
	count(segments) == 5
	segments[0] == "api"
	segments[1] == "gitea"
	segments[2] == "push"
}

resource_action := "open-pr" if {
	segments := request_path_segments
	count(segments) == 5
	segments[0] == "api"
	segments[1] == "gitea"
	segments[2] == "pulls"
}

requested_repository := sprintf("%s/%s", [
	request_path_segments[3],
	request_path_segments[4],
])

required_scope("push-file") := "gitea:write"
required_scope("open-pr") := "gitea:pr"

valid_action_body("push-file") if {
	object.keys(input.body) == {"act_chain", "intent", "ticket_id"}
}

valid_action_body("open-pr") if {
	input.body.base == "main"
	startswith(input.body.head, "agent/feature-")
	startswith(input.body.title, "fix: remediate create-pr-fix")
}

verified_payload(header_name) := payload if {
	headers := input.attributes.request.http.headers
	encoded := headers[header_name]
	decoded := base64url.decode(encoded)
	payload := json.unmarshal(decoded)
}

scope_contains(scopes, required) if {
	required in split(scopes, " ")
}
