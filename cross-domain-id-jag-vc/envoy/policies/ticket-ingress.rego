# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

package envoy.authz

import rego.v1

# Envoy's jwt_authn filter verifies both signatures before this policy runs and
# forwards only the verified JWT payloads in internal headers. The policy binds
# those credentials to the requested delegation, intent, and resource.

default allow := {
	"allowed": false,
	"http_status": 403,
	"body": "{\"error\":\"policy_denied\",\"reason\":\"delegation constraints not satisfied\"}",
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
		"x-agntcy-policy-rule": "org-b-health",
		"x-agntcy-policy-enforcer": "built-on-envoy-opa",
	},
} if {
	input.attributes.request.http.method == "GET"
	input.attributes.request.http.path == "/health"
}

allow := {
	"allowed": true,
	"headers": {
		"x-agntcy-policy-decision": "ALLOW",
		"x-agntcy-policy-rule": "org-b-ticket-delegation",
		"x-agntcy-policy-enforcer": "built-on-envoy-opa",
		"x-agntcy-delegation-depth": sprintf("%d", [count(actor.act.act_chain)]),
	},
} if {
	input.attributes.request.http.method == "POST"
	input.attributes.request.http.path == "/api/ticket"

	access := verified_payload("x-verified-access-token-payload")
	actor := verified_payload("x-verified-actor-token-payload")

	scope_contains(access.scope, "triage:create")
	scope_contains(actor.scope, "triage:create")
	access.azp == "triage-agent"
	actor.azp == "triage-agent"
	actor.client_id == "triage-agent"
	sprintf("%s@org-a.example", [access.preferred_username]) == actor.sub
	actor.sub == "sarah@org-a.example"

	input.body.delegating_agent == actor.act.sub
	input.body.act_chain == actor.act.act_chain
	count(actor.act.act_chain) > 0
	count(actor.act.act_chain) <= 2
	input.body.intent == "create-pr-fix"
	input.body.intent in actor.intent

	startswith(input.body.repo, "demo-admin/")
	startswith(input.body.cve, "CVE-")
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
