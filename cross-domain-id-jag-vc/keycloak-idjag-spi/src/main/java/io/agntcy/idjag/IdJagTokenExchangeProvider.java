// Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0
package io.agntcy.idjag;

import java.security.PrivateKey;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jws.JWSBuilder;
import org.keycloak.models.ClientModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.representations.AccessToken;
import org.keycloak.services.Urls;

/**
 * Mints an ID-JAG (Identity Assertion JWT Authorization Grant, per
 * draft-ietf-oauth-identity-assertion-authz-grant) as a real
 * grant_type=urn:ietf:params:oauth:grant-type:token-exchange call, signed
 * with this realm's own active key, instead of relying on a separate mock
 * issuer service (idjag-issuer) with its own throwaway keypair.
 *
 * Scope of this provider (see DelegationAuthorization's javadoc for why):
 * only the initial Org A -> Org B mint (subject_token = a real, live
 * Keycloak A access token). Triage-agent's narrowed sub-badge minting is a
 * different trust shape and is intentionally left on idjag-issuer.
 */
public class IdJagTokenExchangeProvider implements TokenExchangeProvider {

    /** Exact URN the IETF draft specifies for requested_token_type. */
    static final String ID_JAG_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:id-jag";

    /** JWT "typ" header — matches idjag-issuer's existing assertions (draft's typ value). */
    private static final String ID_JAG_TYP = "oauth-id-jag+jwt";

    private static final int ASSERTION_TTL_SECONDS = 300;

    @Override
    public boolean supports(TokenExchangeContext context) {
        return ID_JAG_TOKEN_TYPE.equals(context.getParams().getRequestedTokenType());
    }

    @Override
    public Response exchange(TokenExchangeContext context) {
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();
        ClientModel client = context.getClient();
        TokenExchangeContext.Params params = context.getParams();

        String subjectTokenString = params.getSubjectToken();
        if (subjectTokenString == null || subjectTokenString.isBlank()) {
            return oauthError(Response.Status.BAD_REQUEST, "invalid_request", "subject_token is required");
        }

        // Full signature + realm verification against this realm's own keys —
        // NOT just decoding the claims unverified. Returns null if the
        // signature doesn't check out.
        AccessToken subjectToken = session.tokens().decode(subjectTokenString, AccessToken.class);
        if (subjectToken == null) {
            return oauthError(Response.Status.BAD_REQUEST, "invalid_grant", "subject_token failed signature verification");
        }
        if (!subjectToken.isActive()) {
            return oauthError(Response.Status.BAD_REQUEST, "invalid_grant", "subject_token is expired");
        }

        String sub = subjectToken.getEmail() != null ? subjectToken.getEmail() : subjectToken.getSubject();

        String scope = params.getScope();
        List<String> audienceParams = params.getAudience();
        String audience = (audienceParams == null || audienceParams.isEmpty()) ? null : audienceParams.get(0);

        try {
            DelegationAuthorization.check(client, scope, audience);
        } catch (DelegationAuthorization.IdJagAuthorizationException e) {
            return oauthError(Response.Status.FORBIDDEN, "invalid_scope", e.getMessage());
        }

        // Verify the VC delegation badge presented as actor_token, and require
        // that it attests delegation by this very subject. Without this the
        // badge is only ever checked by the agent it constrains, and the
        // issuer signs whatever capabilities the caller declares.
        try {
            BadgeAttestation.verify(client, context.getFormParams().getFirst("actor_token"), sub);
        } catch (BadgeAttestation.BadgeException e) {
            return oauthError(Response.Status.FORBIDDEN, "invalid_grant", e.getMessage());
        }

        // act_chain is trusted as supplied by the (already-authorized, per
        // DelegationAuthorization above) caller as-is — it is not built up
        // automatically here, matching idjag-issuer's original model where
        // the caller declares the full chain itself.
        List<String> actChain = commaDelimited(context.getFormParams().getFirst("act_chain"));
        List<String> intent = commaDelimited(context.getFormParams().getFirst("intent"));
        List<String> resource = commaDelimited(context.getFormParams().getFirst("resource"));
        // client_id/azp on an ID-JAG identify the *target* client the
        // assertion is for (e.g. "triage-agent"), not the caller minting it
        // (e.g. "opencode-agent") — matching idjag-issuer's original
        // client_id request field. Falls back to the calling client's own
        // ID if the caller doesn't specify one.
        String targetClientId = context.getFormParams().getFirst("target_client_id");
        if (targetClientId == null || targetClientId.isBlank()) {
            targetClientId = client.getClientId();
        }

        String issuer = Urls.realmIssuer(session.getContext().getUri().getBaseUri(), realm.getName());
        long now = Instant.now().getEpochSecond();

        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", issuer);
        claims.put("sub", sub);
        claims.put("aud", audience);
        claims.put("iat", now);
        claims.put("exp", now + ASSERTION_TTL_SECONDS);
        claims.put("jti", UUID.randomUUID().toString());
        claims.put("client_id", targetClientId);
        claims.put("azp", targetClientId);
        if (scope != null && !scope.isBlank()) {
            claims.put("scope", scope);
        }
        Map<String, Object> act = new LinkedHashMap<>();
        act.put("sub", actChain.get(actChain.size() - 1));
        act.put("act_chain", actChain);
        claims.put("act", act);
        if (!intent.isEmpty()) {
            claims.put("intent", intent);
        }
        if (!resource.isEmpty()) {
            claims.put("resource", resource);
        }

        KeyWrapper signingKey = session.keys().getActiveKey(realm, KeyUse.SIG, "RS256");
        if (signingKey == null) {
            return oauthError(Response.Status.INTERNAL_SERVER_ERROR, "server_error", "no active RS256 signing key for this realm");
        }

        String assertion = new JWSBuilder()
                .type(ID_JAG_TYP)
                .kid(signingKey.getKid())
                .jsonContent(claims)
                .rsa256((PrivateKey) signingKey.getPrivateKey());

        // RFC 8693 §2.2.1: the issued token always goes in "access_token"
        // regardless of its actual type; "issued_token_type" carries the
        // real type, and "token_type" is "N_A" since this isn't a bearer
        // access token usable against a resource server directly.
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("access_token", assertion);
        response.put("issued_token_type", ID_JAG_TOKEN_TYPE);
        response.put("token_type", "N_A");
        response.put("expires_in", ASSERTION_TTL_SECONDS);

        return Response.ok(response, MediaType.APPLICATION_JSON_TYPE).build();
    }

    @Override
    public void close() {
        // nothing to release
    }

    private static List<String> commaDelimited(String value) {
        List<String> result = new ArrayList<>();
        if (value != null && !value.isBlank()) {
            for (String part : value.split(",")) {
                if (!part.isBlank()) {
                    result.add(part.trim());
                }
            }
        }
        return result;
    }

    private static Response oauthError(Response.Status status, String error, String description) {
        Map<String, String> body = Map.of("error", error, "error_description", description);
        return Response.status(status).type(MediaType.APPLICATION_JSON_TYPE).entity(body).build();
    }
}
