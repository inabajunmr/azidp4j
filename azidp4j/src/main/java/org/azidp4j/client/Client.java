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

    public Client(
            String clientId,
            String clientSecret,
            Set<String> redirectUris,
            Set<GrantType> grantTypes,
            Set<ResponseType> responseTypes,
            String scope,
            TokenEndpointAuthMethod tokenEndpointAuthMethod) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.responseTypes = responseTypes;
        this.scope = scope;
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }
}