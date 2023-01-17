package org.azidp4j.client;

import java.util.Set;

public class TokenEndpointAuthSigningAlgExtractor {

    public static SigningAlgorithm extract(
            String requestedEndpointAuthSigningAlg,
            TokenEndpointAuthMethod tokenEndpointAuthMethod,
            Set<SigningAlgorithm> endpointAuthSigningAlgValuesSupported) {
        if (endpointAuthSigningAlgValuesSupported == null) {
            return null;
        }

        SigningAlgorithm tokenEndpointAuthSigningAlg = null;
        if (requestedEndpointAuthSigningAlg != null) {
            tokenEndpointAuthSigningAlg = SigningAlgorithm.of(requestedEndpointAuthSigningAlg);
        }

        // set default when token_endpoint_auth_method requires signing algorithm
        if (tokenEndpointAuthMethod.usingTokenAuthMethodSigningAlg
                && tokenEndpointAuthSigningAlg == null) {
            tokenEndpointAuthSigningAlg = SigningAlgorithm.RS256;
        }

        return tokenEndpointAuthSigningAlg;
    }
}
