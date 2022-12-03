package org.azidp4j.discovery;

import java.util.Set;
import org.azidp4j.authorize.request.Display;

public class DiscoveryConfig {
    public final String authorizationEndpoint;
    public final String tokenEndpoint;
    public final String jwksEndpoint;
    public final String clientRegistrationEndpoint;
    public final String userInfoEndpoint;
    public Set<Display> displayValueSupported;

    public DiscoveryConfig(
            String authorizationEndpoint,
            String tokenEndpoint,
            String jwksEndpoint,
            String clientRegistrationEndpoint,
            String userInfoEndpoint,
            Set<Display> displayValueSupported) {
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.jwksEndpoint = jwksEndpoint;
        this.clientRegistrationEndpoint = clientRegistrationEndpoint;
        this.userInfoEndpoint = userInfoEndpoint;
        this.displayValueSupported = displayValueSupported;
    }

    public static DiscoveryConfigBuilder builder() {
        return new DiscoveryConfigBuilder();
    }
}
