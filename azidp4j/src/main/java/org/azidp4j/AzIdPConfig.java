package org.azidp4j;

import java.util.Set;

public class AzIdPConfig {

    public final String issuer;
    public final String authorizationEndpoint;
    public final String tokenEndpoint;
    public final String jwksEndpoint;
    public final String clientRegistrationEndpoint;
    /** ex. http://localhost:8080/client/{CLIENT_ID} */
    public final String clientConfigurationEndpointPattern;

    public final String userInfoEndpoint;
    public final Set<String> scopesSupported;
    public final String accessTokenKid;
    public final int authorizationCodeExpirationSec;
    public final int accessTokenExpirationSec;
    public final int idTokenExpirationSec;
    public final int refreshTokenExpirationSec;

    public AzIdPConfig(
            String issuer,
            String authorizationEndpoint,
            String tokenEndpoint,
            String jwksEndpoint,
            String clientRegistrationEndpoint,
            String clientConfigurationEndpointPattern,
            String userInfoEndpoint,
            Set<String> scopesSupported,
            String accessTokenKid,
            int accessTokenExpirationSec,
            int authorizationCodeExpirationSec,
            int refreshTokenExpirationSec,
            int idTokenExpirationSec) {
        this.issuer = issuer;
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.jwksEndpoint = jwksEndpoint;
        this.clientRegistrationEndpoint = clientRegistrationEndpoint;
        this.clientConfigurationEndpointPattern = clientConfigurationEndpointPattern;
        this.userInfoEndpoint = userInfoEndpoint;
        this.scopesSupported = scopesSupported;
        this.accessTokenKid = accessTokenKid;
        this.accessTokenExpirationSec = accessTokenExpirationSec;
        this.authorizationCodeExpirationSec = authorizationCodeExpirationSec;
        this.refreshTokenExpirationSec = refreshTokenExpirationSec;
        this.idTokenExpirationSec = idTokenExpirationSec;
    }
}
