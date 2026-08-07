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

# ── Egress: the READ assertion ───────────────────────────────────────────────
# Scanning Org B's source is a cross-domain read, so it leaves Org A under its
# own assertion — narrower than the remediation one above and checked
# separately rather than by loosening that rule. May Sarah delegate a *read*
# of this repository to Org B? Answered here, before the assertion leaves.
allow := {
	"allowed": true,
	"headers": {
		"x-agntcy-policy-decision": "ALLOW",
		"x-agntcy-policy-rule": "org-a-egress-source-read",
		"x-agntcy-policy-enforcer": "built-on-envoy-opa",
		"x-agntcy-delegation-depth": sprintf("%d", [count(actor.act.act_chain)]),
	},
} if {
	input.attributes.request.http.method == "POST"
	input.attributes.request.http.path == "/api/egress-check"

	actor := verified_payload("x-verified-actor-token-payload")

	actor.sub == "sarah@org-a.example"
	actor.azp == "opencode-agent"
	actor.client_id == "opencode-agent"

	# Read and nothing else: this assertion must not double as write authority.
	scope_contains(actor.scope, "gitea:read")
	not scope_contains(actor.scope, "gitea:write")
	not scope_contains(actor.scope, "gitea:pr")
	not scope_contains(actor.scope, "triage:create")

	"scan-source" in actor.intent

	# One hop — Org A's own agent, delegating onward to nobody.
	actor.act.act_chain == ["opencode-agent"]
	actor.act.sub == "opencode-agent"

	# Bound to a repository Org A permits delegated work on.
	count(actor.resource) == 1
	actor.resource[0] in badge_repo_allowlist
}

# ── Badge-scope PDP ──────────────────────────────────────────────────────────
# Before any task work runs, the agent presents Sarah's verified Keycloak A
# access token (jwt_authn, kc_a_access_token provider) plus the task it wants
# a badge for. This policy decides whether Sarah may delegate that task to
# the agent at all — and answers with the narrowed, task-scoped intent the
# VC badge must be minted with (least privilege, decided by policy, not by
# the agent).

# Repositories org-a policy permits delegated remediation work on.
badge_repo_allowlist := {"demo-admin/payments-service"}

# Task actions a badge may be requested for.
badge_action_allowlist := {"scan-remediate"}

allow := {
	"allowed": true,
	"headers": {
		"x-agntcy-policy-decision": "ALLOW",
		"x-agntcy-policy-rule": "org-a-badge-scope",
		"x-agntcy-policy-enforcer": "built-on-envoy-opa",
		"x-agntcy-scoped-intent": scoped_intent,
		"x-agntcy-scoped-resource": requested_repo,
	},
} if {
	input.attributes.request.http.method == "POST"
	input.attributes.request.http.path == "/api/badge-scope-check"

	user := verified_payload("x-verified-user-token-payload")

	user.email == "sarah@org-a.example"
	user.azp == "opencode-agent"
	scope_contains(user.scope, "openid")

	requested_action := input.attributes.request.http.headers["x-agntcy-requested-action"]
	requested_repo := input.attributes.request.http.headers["x-agntcy-requested-repo"]

	requested_action in badge_action_allowlist
	requested_repo in badge_repo_allowlist

	scoped_intent := sprintf("%s:%s", [requested_action, requested_repo])
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
