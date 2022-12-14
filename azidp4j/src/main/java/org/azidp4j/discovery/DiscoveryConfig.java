package org.azidp4j.discovery;

import java.util.List;
import java.util.Set;
import org.azidp4j.authorize.request.Display;

public class DiscoveryConfig {
    public final String authorizationEndpoint;
    public final String tokenEndpoint;
    public final String jwksEndpoint;
    public final String clientRegistrationEndpoint;
    public final String revocationEndpoint;
    public final String introspectionEndpoint;
    public final String userInfoEndpoint;
    public Set<Display> displayValueSupported;
    public Set<String> claimsSupported;
    public Set<String> userinfoSigningAlgValuesSupported;
    public Set<String> userinfoEncryptionAlgValuesSupported;
    public Set<String> userinfoEncryptionEncValuesSupported;
    public String serviceDocumentation;
    public List<String> uiLocalesSupported;
    public boolean claimsParameterSupported;
    public String opPolicyUri;
    public String opTosUri;

    public DiscoveryConfig(
            String authorizationEndpoint,
            String tokenEndpoint,
            String jwksEndpoint,
            String clientRegistrationEndpoint,
            String revocationEndpoint,
            String introspectionEndpoint,
            String userInfoEndpoint,
            Set<Display> displayValueSupported,
            Set<String> claimsSupported,
            Set<String> userinfoSigningAlgValuesSupported,
            Set<String> userinfoEncryptionAlgValuesSupported,
            Set<String> userinfoEncryptionEncValuesSupported,
            String serviceDocumentation,
            List<String> uiLocalesSupported,
            boolean claimsParameterSupported,
            String opPolicyUri,
            String opTosUri) {
        this.authorizationEndpoint = authorizationEndpoint;
        this.tokenEndpoint = tokenEndpoint;
        this.jwksEndpoint = jwksEndpoint;
        this.revocationEndpoint = revocationEndpoint;
        this.introspectionEndpoint = introspectionEndpoint;
        this.clientRegistrationEndpoint = clientRegistrationEndpoint;
        this.userInfoEndpoint = userInfoEndpoint;
        this.displayValueSupported = displayValueSupported;
        this.claimsSupported = claimsSupported;
        this.userinfoSigningAlgValuesSupported = userinfoSigningAlgValuesSupported;
        this.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
        this.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
        this.serviceDocumentation = serviceDocumentation;
        this.uiLocalesSupported = uiLocalesSupported;
        this.claimsParameterSupported = claimsParameterSupported;
        this.opPolicyUri = opPolicyUri;
        this.opTosUri = opTosUri;
    }

    public static DiscoveryConfigBuilder builder() {
        return new DiscoveryConfigBuilder();
    }
}
