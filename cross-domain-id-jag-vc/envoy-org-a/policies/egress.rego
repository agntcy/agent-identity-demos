# Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

package envoy.authz

import rego.v1

# Envoy's jwt_authn filter verifies the ID-JAG's signature, issuer, and
# audience before this policy runs, forwarding only the verified payload in
# an internal header. This policy answers the egress question: may Sarah's
# delegation actually leave Org A with the scope/intent it claims?

default allow := {
	"allowed": false,
	"http_status": 403,
	"body": "{\"error\":\"policy_denied\",\"reason\":\"egress delegation constraints not satisfied\"}",
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
		"x-agntcy-policy-rule": "org-a-egress-health",
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
		"x-agntcy-policy-rule": "org-a-egress-delegation",
		"x-agntcy-policy-enforcer": "built-on-envoy-opa",
		"x-agntcy-delegation-depth": sprintf("%d", [count(actor.act.act_chain)]),
	},
} if {
	input.attributes.request.http.method == "POST"
	input.attributes.request.http.path == "/api/egress-check"

	actor := verified_payload("x-verified-actor-token-payload")

	actor.sub == "sarah@org-a.example"
	actor.azp == "triage-agent"
	actor.client_id == "triage-agent"

	scope_contains(actor.scope, "triage:create")
	"create-pr-fix" in actor.intent

	count(actor.act.act_chain) > 0
	count(actor.act.act_chain) <= 2
	actor.act.act_chain[0] == "opencode-agent"
	actor.act.sub == "opencode-agent"
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
