package org.azidp4j.client;

import java.util.Set;

public class TokenEndpointAuthMethodExtractor {

    public static TokenEndpointAuthMethod extract(
            String requestedEndpointAuthMethod,
            Set<TokenEndpointAuthMethod> endpointAuthMethodsSupported) {
        // the server doesn't support xxxAuthMethod
        if (endpointAuthMethodsSupported == null) {
            return null;
        }

        var tokenEndpointAuthMethod = TokenEndpointAuthMethod.client_secret_basic;
        if (requestedEndpointAuthMethod != null) {
            tokenEndpointAuthMethod = TokenEndpointAuthMethod.of(requestedEndpointAuthMethod);
        }
        return tokenEndpointAuthMethod;
    }
}
