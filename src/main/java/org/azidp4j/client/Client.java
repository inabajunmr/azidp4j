package org.azidp4j.client;

import java.util.Set;
import org.azidp4j.authorize.ResponseType;

public class Client {

    public final String clientId;
    public final String clientSecret;
    public final Set<String> redirectUris;
    public final Set<GrantType> grantTypes;
    public final Set<ResponseType> responseTypes;
    public final String scope;

    public Client(
            String clientId,
            String clientSecret,
            Set<String> redirectUris,
            Set<GrantType> grantTypes,
            Set<ResponseType> responseTypes,
            String scope) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.responseTypes = responseTypes;
        this.scope = scope;
    }
}
