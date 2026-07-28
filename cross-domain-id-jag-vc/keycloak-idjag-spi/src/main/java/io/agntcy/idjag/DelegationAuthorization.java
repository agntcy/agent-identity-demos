// Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0
package io.agntcy.idjag;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

import org.keycloak.models.ClientModel;

/**
 * Decides whether a calling client may assert delegation for the
 * authenticated subject to a given audience, at a given scope.
 *
 * This is the part that does not port over mechanically from idjag-issuer's
 * Python — Keycloak has no built-in concept of "this client may vouch for
 * that subject to a different realm." The check here is deliberately
 * narrow: it only covers the OpenCode -> Org B initial ID-JAG mint (the gap
 * the Slack discussion / Discussion #18 was actually about — Sarah's
 * delegation crossing from Org A to Org B for the first time).
 *
 * Triage-agent's narrowed sub-badge minting (Org B re-delegating a further,
 * narrower scope to Sub-Agent) is a different trust shape: triage-agent
 * never holds Sarah's original Keycloak A access token (it's an Org B
 * service, it only ever sees the already-issued ID-JAG assertion and its
 * own Keycloak B access token), so it cannot authenticate a live
 * subject_token the way this provider requires. Migrating that path would
 * need triage-agent registered as its own client in the org-a realm and a
 * "re-narrow an existing assertion" exchange mode — deliberately left on
 * idjag-issuer for now rather than solved here.
 *
 * Authorization is driven by two client attributes on the calling client in
 * Keycloak's own admin console / realm-import JSON, rather than hardcoded
 * client IDs in Java:
 *   - idjag.allowed.scopes    space-delimited, e.g. "openid triage:create"
 *   - idjag.allowed.audiences space-delimited list of acceptable "aud" values
 * Both must be satisfied for the request to proceed.
 */
final class DelegationAuthorization {

    static final String ATTR_ALLOWED_SCOPES = "idjag.allowed.scopes";
    static final String ATTR_ALLOWED_AUDIENCES = "idjag.allowed.audiences";

    private DelegationAuthorization() {
    }

    /**
     * @throws IdJagAuthorizationException if the client is not permitted to
     *         make this request; the message is safe to surface to the caller.
     */
    static void check(ClientModel client, String requestedScope, String requestedAudience) {
        Set<String> allowedScopes = spaceDelimited(client.getAttribute(ATTR_ALLOWED_SCOPES));
        Set<String> requestedScopes = spaceDelimited(requestedScope);
        if (requestedScopes.isEmpty() || !allowedScopes.containsAll(requestedScopes)) {
            throw new IdJagAuthorizationException(
                    "client '" + client.getClientId() + "' is not permitted to request scope(s): " + requestedScope);
        }

        Set<String> allowedAudiences = spaceDelimited(client.getAttribute(ATTR_ALLOWED_AUDIENCES));
        if (requestedAudience == null || requestedAudience.isBlank() || !allowedAudiences.contains(requestedAudience)) {
            throw new IdJagAuthorizationException(
                    "client '" + client.getClientId() + "' is not permitted to assert delegation to audience: " + requestedAudience);
        }
    }

    private static Set<String> spaceDelimited(String value) {
        if (value == null || value.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(value.trim().split("\\s+")).collect(Collectors.toSet());
    }

    /** Thrown by {@link #check} — message is safe to surface as error_description. */
    static final class IdJagAuthorizationException extends RuntimeException {
        IdJagAuthorizationException(String message) {
            super(message);
        }
    }
}
