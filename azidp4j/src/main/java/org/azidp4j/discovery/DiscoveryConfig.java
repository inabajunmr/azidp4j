package org.azidp4j.discovery;

public class DiscoveryConfig {
    public final String authorizationEndpoint;
    public final String tokenEndpoint;
    public final String jwksEndpoint;
    public final String clientRegistrationEndpoint;
    public final String userInfoEndpoint;

    public DiscoveryConfig(
            String authorizationEndpoint,
            String tokenEndpoint,
            String jwksEndpoint,
            String clientRegistrationEndpoint,
            String userInfoEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.jwksEndpoint = jwksEndpoint;
        this.clientRegistrationEndpoint = clientRegistrationEndpoint;
        this.userInfoEndpoint = userInfoEndpoint;
    }

    public static DiscoveryConfigBuilder builder() {
        return new DiscoveryConfigBuilder();
    }
}
