package org.azidp4j.discovery;

import java.util.List;
import java.util.Set;
import org.azidp4j.authorize.request.Display;

public class DiscoveryConfig {
    public final String authorizationEndpoint;
    public final String tokenEndpoint;
    public final String jwksEndpoint;
    public final String clientRegistrationEndpoint;
    public final String userInfoEndpoint;
    public Set<Display> displayValueSupported;
    public Set<String> userinfoSigningAlgValuesSupported;
    public Set<String> userinfoEncryptionAlgValuesSupported;
    public Set<String> userinfoEncryptionEncValuesSupported;
    public String serviceDocumentation;
    public List<String> uiLocalesSupported;
    public String opPolicyUri;
    public String opTosUri;

    public DiscoveryConfig(
            String authorizationEndpoint,
            String tokenEndpoint,
            String jwksEndpoint,
            String clientRegistrationEndpoint,
            String userInfoEndpoint,
            Set<Display> displayValueSupported,
            Set<String> userinfoSigningAlgValuesSupported,
            Set<String> userinfoEncryptionAlgValuesSupported,
            Set<String> userinfoEncryptionEncValuesSupported,
            String serviceDocumentation,
            List<String> uiLocalesSupported,
            String opPolicyUri,
            String opTosUri) {
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.jwksEndpoint = jwksEndpoint;
        this.clientRegistrationEndpoint = clientRegistrationEndpoint;
        this.userInfoEndpoint = userInfoEndpoint;
        this.displayValueSupported = displayValueSupported;
        this.userinfoSigningAlgValuesSupported = userinfoSigningAlgValuesSupported;
        this.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
        this.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
        this.serviceDocumentation = serviceDocumentation;
        this.uiLocalesSupported = uiLocalesSupported;
        this.opPolicyUri = opPolicyUri;
        this.opTosUri = opTosUri;
    }

    public static DiscoveryConfigBuilder builder() {
        return new DiscoveryConfigBuilder();
    }
}
