package org.azidp4j.client;

import java.util.Set;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.token.TokenEndpointAuthMethod;

public class Client {

    public final String clientId;
    public final String clientSecret;
    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final Set<String> redirectUris;
    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final Set<ResponseType> responseTypes;
    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final Set<GrantType> grantTypes;

    public final String scope;
    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final TokenEndpointAuthMethod tokenEndpointAuthMethod;
    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final Set<SigningAlgorithm> idTokenSignedResponseAlg;

    public Client(
            String clientId,
            String clientSecret,
            Set<String> redirectUris,
            Set<GrantType> grantTypes,
            Set<ResponseType> responseTypes,
            String scope,
            TokenEndpointAuthMethod tokenEndpointAuthMethod,
            Set<SigningAlgorithm> idTokenSignedResponseAlg) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.responseTypes = responseTypes;
        this.scope = scope;
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
    }

    public SigningAlgorithm primarySigningAlgorithm() {
        if (idTokenSignedResponseAlg.contains(SigningAlgorithm.ES256)) {
            return SigningAlgorithm.ES256;
        } else if (idTokenSignedResponseAlg.contains(SigningAlgorithm.RS256)) {
            return SigningAlgorithm.RS256;
        }
        return SigningAlgorithm.none;
    }
}
