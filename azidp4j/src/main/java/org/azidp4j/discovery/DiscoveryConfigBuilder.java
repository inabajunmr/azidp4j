package org.azidp4j.discovery;

import java.util.Set;
import org.azidp4j.authorize.request.Display;

public class DiscoveryConfigBuilder {

    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String jwksEndpoint;
    private String clientRegistrationEndpoint;
    private String userInfoEndpoint;
    private Set<Display> displayValueSupported = Set.of(Display.page);

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

    public DiscoveryConfigBuilder userInfoEndpoint(String userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
        return this;
    }

    public DiscoveryConfigBuilder displayValueSupported(Set<Display> displayValueSupported) {
        this.displayValueSupported = displayValueSupported;
        return this;
    }

    public DiscoveryConfig build() {
        return new DiscoveryConfig(
                this.authorizationEndpoint,
                this.tokenEndpoint,
                this.jwksEndpoint,
                this.clientRegistrationEndpoint,
                this.userInfoEndpoint,
                displayValueSupported);
    }
}
