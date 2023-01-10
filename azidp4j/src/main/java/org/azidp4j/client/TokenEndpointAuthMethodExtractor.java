package org.azidp4j.client;

import java.util.Set;

public class TokenEndpointAuthMethodExtractor {

    /**
     * @param clientXxxEndpointAuthMethod
     * @param xxxEndpointAuthMethodsSupported
     * @return
     * @throws IllegalArgumentException
     */
    public static TokenEndpointAuthMethod extractXxxEndpointAuthMethod(
            String clientXxxEndpointAuthMethod,
            Set<TokenEndpointAuthMethod> xxxEndpointAuthMethodsSupported) {
        if (xxxEndpointAuthMethodsSupported == null) {
            return null;
        }
        // TODO 常にデフォルトでいいのか？とか
        // TODO introspection とかサポートしてない場合どうする？とか
        var tokenEndpointAuthMethod = TokenEndpointAuthMethod.client_secret_basic;
        if (clientXxxEndpointAuthMethod != null) {
            tokenEndpointAuthMethod = TokenEndpointAuthMethod.of(clientXxxEndpointAuthMethod);
        }
        if (!xxxEndpointAuthMethodsSupported.contains(tokenEndpointAuthMethod)) {
            throw new IllegalArgumentException();
        }
        return tokenEndpointAuthMethod;
    }

    /**
     * @param clientTokenEndpointAuthSigningAlg
     * @param tokenEndpointAuthMethod
     * @return
     * @throws IllegalArgumentException
     */
    public static SigningAlgorithm extractTokenEndpointAuthSigningAlg(
            String clientTokenEndpointAuthSigningAlg,
            TokenEndpointAuthMethod tokenEndpointAuthMethod) {
        var tokenEndpointAuthSigningAlg = SigningAlgorithm.of(clientTokenEndpointAuthSigningAlg);

        if ((tokenEndpointAuthMethod == TokenEndpointAuthMethod.private_key_jwt
                        || tokenEndpointAuthMethod == TokenEndpointAuthMethod.client_secret_jwt)
                && tokenEndpointAuthSigningAlg == null) {
            tokenEndpointAuthSigningAlg = SigningAlgorithm.RS256;
        }

        // TODO check supported
        return tokenEndpointAuthSigningAlg;
    }
}
