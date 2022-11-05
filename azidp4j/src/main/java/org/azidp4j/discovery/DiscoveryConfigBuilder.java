package org.azidp4j.discovery;

public class DiscoveryConfigBuilder {

    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String jwksEndpoint;
    private String clientRegistrationEndpoint;
    private String clientConfigurationEndpointPattern;

    private String userInfoEndpoint;

    public DiscoveryConfigBuilder authorizationEndpoint(String authorizationEndpoint) {
        this.authorizationEndpoint = authorizationEndpoint;
        return this;
    }

    public DiscoveryConfigBuilder tokenEndpoint(String tokenEndpoint) {
        this.tokenEndpoint = tokenEndpoint;
        return this;
    }

    public DiscoveryConfigBuilder jwksEndpoint(String jwksEndpoint) {
        this.jwksEndpoint = jwksEndpoint;
        return this;
    }

    public DiscoveryConfigBuilder clientRegistrationEndpoint(String clientRegistrationEndpoint) {
        this.clientRegistrationEndpoint = clientRegistrationEndpoint;
        return this;
    }

    /** ex. http://localhost:8080/client/{CLIENT_ID} */
    public DiscoveryConfigBuilder clientConfigurationEndpointPattern(
            String clientConfigurationEndpointPattern) {
        this.clientConfigurationEndpointPattern = clientConfigurationEndpointPattern;
        return this;
    }

    public DiscoveryConfigBuilder userInfoEndpoint(String userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
        return this;
    }

    public DiscoveryConfig build() {
        return new DiscoveryConfig(
                this.authorizationEndpoint,
                this.tokenEndpoint,
                this.jwksEndpoint,
                this.clientRegistrationEndpoint,
                this.clientConfigurationEndpointPattern,
                this.userInfoEndpoint);
    }
}
