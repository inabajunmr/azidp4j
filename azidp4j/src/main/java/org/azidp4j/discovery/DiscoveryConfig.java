package org.azidp4j.discovery;

public class DiscoveryConfig {
    public final String authorizationEndpoint;
    public final String tokenEndpoint;
    public final String jwksEndpoint;
    public final String clientRegistrationEndpoint;
    /** ex. http://localhost:8080/client/{CLIENT_ID} */
    public final String clientConfigurationEndpointPattern;

    public final String userInfoEndpoint;

    public DiscoveryConfig(
            String authorizationEndpoint,
            String tokenEndpoint,
            String jwksEndpoint,
            String clientRegistrationEndpoint,
            String clientConfigurationEndpointPattern,
            String userInfoEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.jwksEndpoint = jwksEndpoint;
        this.clientRegistrationEndpoint = clientRegistrationEndpoint;
        this.clientConfigurationEndpointPattern = clientConfigurationEndpointPattern;
        this.userInfoEndpoint = userInfoEndpoint;
    }

    public static DiscoveryConfigBuilder builder() {
        return new DiscoveryConfigBuilder();
    }
}
