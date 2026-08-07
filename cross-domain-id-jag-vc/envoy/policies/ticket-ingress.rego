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
	well_formed_finding_id(input.body.cve)
}

# The ticket's finding identifier. Since the scan became a real source
# analysis, findings are reported as CWE classes — a weakness found by reading
# code has no CVE, which identifies a vulnerability in a *released product*.
# CVE- is still accepted for dependency-level findings.
well_formed_finding_id(id) if startswith(id, "CVE-")

well_formed_finding_id(id) if startswith(id, "CWE-")

# ── Sub-badge scope PDP ──────────────────────────────────────────────────────
# Before Triage mints the narrowed sub-badge at Keycloak B, it must ask this
# policy whether — and how narrowly — the delegation may be re-narrowed. It
# presents the inbound Sarah-federated access token (verified by jwt_authn)
# plus the narrowing it requests; the answer carries the policy-approved
# scope/resource the sub-badge must be minted with. Least privilege decided
# by policy, not by the agent.

# Scopes Org B policy permits on a narrowed sub-badge.
subbadge_scope_allowlist := {"openid", "gitea:write", "gitea:pr"}

# Intents a sub-badge may be requested for.
subbadge_intent_allowlist := {"create-pr-fix"}

allow := {
	"allowed": true,
	"headers": {
		"x-agntcy-policy-decision": "ALLOW",
		"x-agntcy-policy-rule": "org-b-subbadge-scope",
		"x-agntcy-policy-enforcer": "built-on-envoy-opa",
		"x-agntcy-scoped-scope": requested_scope,
		"x-agntcy-scoped-resource": requested_repo,
	},
} if {
	input.attributes.request.http.method == "POST"
	input.attributes.request.http.path == "/api/subbadge-scope-check"

	access := verified_payload("x-verified-access-token-payload")

	access.azp == "triage-agent"
	scope_contains(access.scope, "triage:create")
	sprintf("%s@org-a.example", [access.preferred_username]) == "sarah@org-a.example"

	requested_scope := input.attributes.request.http.headers["x-agntcy-requested-scope"]
	requested_repo := input.attributes.request.http.headers["x-agntcy-requested-repo"]
	requested_intent := input.attributes.request.http.headers["x-agntcy-requested-intent"]

	# Every requested scope must be within the narrowing allowlist — asking
	# for triage:create (or anything broader) is escalation, denied.
	every s in split(requested_scope, " ") {
		s in subbadge_scope_allowlist
	}
	requested_intent in subbadge_intent_allowlist

	startswith(requested_repo, "demo-admin/")
	requested_repo != "demo-admin/demo-protected"
	not endswith(requested_repo, "/demo-protected")
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
