// Copyright 2026 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0
package io.agntcy.idjag;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;

/**
 * Registers {@link IdJagTokenExchangeProvider} with Keycloak's token-exchange
 * dispatch (see org.keycloak.protocol.oidc.grants.TokenExchangeGrantType,
 * which sorts all registered TokenExchangeProviderFactory instances by
 * order() descending and picks the first whose supports() returns true).
 *
 * order() = 100, higher than the built-in "standard" provider's 10, so this
 * is checked first — but supports() only returns true for our own
 * requested_token_type, so every other token-exchange request falls through
 * to Keycloak's existing providers unaffected.
 */
public class IdJagTokenExchangeProviderFactory implements TokenExchangeProviderFactory {

    public static final String PROVIDER_ID = "idjag";

    @Override
    public TokenExchangeProvider create(KeycloakSession session) {
        return new IdJagTokenExchangeProvider();
    }

    @Override
    public void init(Config.Scope config) {
        // no configuration needed
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        // no cross-provider wiring needed
    }

    @Override
    public void close() {
        // nothing to release
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public int order() {
        return 100;
    }
}
