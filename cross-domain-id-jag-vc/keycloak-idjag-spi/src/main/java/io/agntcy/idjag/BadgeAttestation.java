// Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0
package io.agntcy.idjag;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.keycloak.models.ClientModel;

/**
 * Verifies the VC delegation badge presented as {@code actor_token}, and binds
 * it to the authenticated subject.
 *
 * Why this exists: without it, the badge is decorative at the issuance
 * boundary. OpenCode verifies its own badge against vc-issuer and then tells
 * Keycloak what authority to mint — meaning the only party checking the
 * attestation is the party it is supposed to constrain. Keycloak would sign
 * whatever was asked for, and the badge's scoping would be advisory.
 *
 * What is checked here (deliberately a narrow subset — see the README's
 * "known limitations"):
 *   1. the badge is a real, unexpired {@code vc+jwt} signed by vc-issuer,
 *      verified against vc-issuer's published JWKS; and
 *   2. its {@code delegating_user} is the same principal as the verified
 *      {@code subject_token}'s subject.
 *
 * Deliberately NOT checked yet (would be the natural next increment):
 * containment of requested scope/resource/intent within the badge's
 * capabilities, and constructing {@code act_chain} rather than accepting the
 * caller's. Those are a larger design change and are tracked separately.
 *
 * Note on (1): the signature check is what gives (2) its meaning. Comparing
 * {@code delegating_user} against an unverified badge would be trivially
 * defeated by forging one, so the two are implemented together or not at all.
 *
 * Enabled per calling client via the {@code idjag.badge.jwks.url} attribute;
 * when that attribute is absent the check is skipped, so realms that have not
 * opted in keep their existing behaviour.
 */
final class BadgeAttestation {

    static final String ATTR_BADGE_JWKS_URL = "idjag.badge.jwks.url";

    /** JWT "typ" header vc-issuer stamps on a badge. */
    private static final String BADGE_TYP = "vc+jwt";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Base64.Decoder B64URL = Base64.getUrlDecoder();

    /**
     * vc-issuer generates a fresh keypair (and kid) on every boot, so the JWKS
     * is cached only briefly and re-fetched whenever a kid is unknown — pinning
     * would break the demo across a vc-issuer restart.
     */
    private static final Duration JWKS_TTL = Duration.ofSeconds(300);

    private static final HttpClient HTTP = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(5))
            .build();

    private static volatile Map<String, PublicKey> cachedKeys = Map.of();
    private static volatile String cachedUrl = "";
    private static volatile Instant cachedAt = Instant.EPOCH;

    private BadgeAttestation() {
    }

    static final class BadgeException extends Exception {
        BadgeException(String message) {
            super(message);
        }
    }

    /**
     * @param client        the calling client (carries the JWKS URL attribute)
     * @param actorToken    the raw actor_token form parameter, may be null
     * @param subjectId     subject of the already-verified subject_token
     * @throws BadgeException if a badge is required and does not verify, or
     *                        does not attest delegation by {@code subjectId}
     */
    static void verify(ClientModel client, String actorToken, String subjectId) throws BadgeException {
        String jwksUrl = client.getAttribute(ATTR_BADGE_JWKS_URL);
        if (jwksUrl == null || jwksUrl.isBlank()) {
            return; // client has not opted in — preserve previous behaviour
        }
        if (actorToken == null || actorToken.isBlank()) {
            throw new BadgeException(
                    "actor_token (VC delegation badge) is required by this client but was not supplied");
        }

        String[] parts = actorToken.split("\\.");
        if (parts.length != 3) {
            throw new BadgeException("actor_token is not a well-formed JWS");
        }

        JsonNode header = decodeJson(parts[0], "header");
        String typ = header.path("typ").asText("");
        if (!BADGE_TYP.equals(typ)) {
            throw new BadgeException("actor_token is not a VC badge (typ=" + typ + ")");
        }
        String kid = header.path("kid").asText("");
        if (kid.isBlank()) {
            throw new BadgeException("actor_token has no kid");
        }

        PublicKey key = resolveKey(jwksUrl, kid);
        if (!signatureValid(actorToken, parts, key)) {
            throw new BadgeException("actor_token signature does not verify against vc-issuer's JWKS");
        }

        JsonNode claims = decodeJson(parts[1], "payload");

        long exp = claims.path("exp").asLong(0);
        if (exp > 0 && Instant.now().getEpochSecond() >= exp) {
            throw new BadgeException("actor_token (VC badge) has expired");
        }

        String delegatingUser = claims.path("delegating_user").asText("");
        if (delegatingUser.isBlank()) {
            throw new BadgeException("actor_token carries no delegating_user claim");
        }
        // The binding that makes the badge meaningful: the attestation must be
        // about the same human whose token is being exchanged. Otherwise a
        // valid badge issued for one principal could accompany another's token.
        if (!delegatingUser.equals(subjectId)) {
            throw new BadgeException("actor_token attests delegation by '" + delegatingUser
                    + "', which is not the subject_token's subject '" + subjectId + "'");
        }
    }

    private static boolean signatureValid(String token, String[] parts, PublicKey key) throws BadgeException {
        try {
            Signature rsa = Signature.getInstance("SHA256withRSA");
            rsa.initVerify(key);
            rsa.update(token.substring(0, token.lastIndexOf('.')).getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return rsa.verify(B64URL.decode(parts[2]));
        } catch (Exception e) {
            throw new BadgeException("could not verify actor_token signature: " + e.getMessage());
        }
    }

    private static JsonNode decodeJson(String segment, String what) throws BadgeException {
        try {
            return MAPPER.readTree(B64URL.decode(segment));
        } catch (IOException | IllegalArgumentException e) {
            throw new BadgeException("actor_token " + what + " is not valid base64url JSON");
        }
    }

    private static PublicKey resolveKey(String jwksUrl, String kid) throws BadgeException {
        Map<String, PublicKey> keys = cachedKeys;
        boolean fresh = jwksUrl.equals(cachedUrl)
                && Instant.now().isBefore(cachedAt.plus(JWKS_TTL));
        if (!fresh || !keys.containsKey(kid)) {
            keys = fetchJwks(jwksUrl); // unknown kid: vc-issuer may have restarted
            cachedKeys = keys;
            cachedUrl = jwksUrl;
            cachedAt = Instant.now();
        }
        PublicKey key = keys.get(kid);
        if (key == null) {
            throw new BadgeException("vc-issuer's JWKS has no key for kid '" + kid + "'");
        }
        return key;
    }

    private static Map<String, PublicKey> fetchJwks(String jwksUrl) throws BadgeException {
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(jwksUrl))
                    .timeout(Duration.ofSeconds(5))
                    .GET()
                    .build();
            HttpResponse<InputStream> response = HTTP.send(request, HttpResponse.BodyHandlers.ofInputStream());
            if (response.statusCode() != 200) {
                throw new BadgeException("vc-issuer JWKS returned HTTP " + response.statusCode());
            }
            JsonNode keys = MAPPER.readTree(response.body()).path("keys");
            Map<String, PublicKey> parsed = new java.util.LinkedHashMap<>();
            for (JsonNode jwk : keys) {
                if (!"RSA".equals(jwk.path("kty").asText())) {
                    continue;
                }
                String kid = jwk.path("kid").asText("");
                if (kid.isBlank()) {
                    continue;
                }
                BigInteger n = new BigInteger(1, B64URL.decode(jwk.path("n").asText()));
                BigInteger e = new BigInteger(1, B64URL.decode(jwk.path("e").asText()));
                parsed.put(kid, KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e)));
            }
            if (parsed.isEmpty()) {
                throw new BadgeException("vc-issuer JWKS contained no usable RSA keys");
            }
            return Map.copyOf(parsed);
        } catch (BadgeException e) {
            throw e;
        } catch (Exception e) {
            throw new BadgeException("could not fetch vc-issuer JWKS: " + e.getMessage());
        }
    }
}
