package org.azidp4j.discovery;

import java.util.List;
import java.util.Set;
import org.azidp4j.authorize.request.Display;

public class DiscoveryConfigBuilder {

    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String jwksEndpoint;
    private String clientRegistrationEndpoint;
    private String userInfoEndpoint;
    private String introspectionEndpoint;
    private String revocationEndpoint;
    private Set<Display> displayValueSupported = Set.of(Display.page);
    public Set<String> claimsSupported =
            Set.of(
                    "iss",
                    "sub",
                    "aud",
                    "acr",
                    "exp",
                    "iat",
                    "jti",
                    "auth_time",
                    "nonce",
                    "azp",
                    "at_hash",
                    "c_hash");
    private Set<String> userinfoSigningAlgValuesSupported;
    private Set<String> userinfoEncryptionAlgValuesSupported;
    private Set<String> userinfoEncryptionEncValuesSupported;
    private String serviceDocumentation;
    private List<String> uiLocalesSupported;
    boolean claimsParameterSupported = false;
    private String opPolicyUri;
    private String opTosUri;

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

    public DiscoveryConfigBuilder displayValueSupported(Set<Display> displayValueSupported) {
        this.displayValueSupported = displayValueSupported;
        return this;
    }

    public DiscoveryConfigBuilder claimsSupported(Set<String> claimsSupported) {
        this.claimsSupported = claimsSupported;
        return this;
    }

    public DiscoveryConfigBuilder userInfoEndpoint(String userInfoEndpoint) {
        this.userInfoEndpoint = userInfoEndpoint;
        return this;
    }

    public DiscoveryConfigBuilder revocationEndpoint(String revocationEndpoint) {
        this.revocationEndpoint = revocationEndpoint;
        return this;
    }

    public DiscoveryConfigBuilder introspectionEndpoint(String introspectionEndpoint) {
        this.introspectionEndpoint = introspectionEndpoint;
        return this;
    }

    public DiscoveryConfigBuilder userinfoSigningAlgValuesSupported(
            Set<String> userinfoSigningAlgValuesSupported) {
        this.userinfoSigningAlgValuesSupported = userinfoSigningAlgValuesSupported;
        return this;
    }

    public DiscoveryConfigBuilder userinfoEncryptionAlgValuesSupported(
            Set<String> userinfoEncryptionAlgValuesSupported) {
        this.userinfoEncryptionAlgValuesSupported = userinfoEncryptionAlgValuesSupported;
        return this;
    }

    public DiscoveryConfigBuilder userinfoEncryptionEncValuesSupported(
            Set<String> userinfoEncryptionEncValuesSupported) {
        this.userinfoEncryptionEncValuesSupported = userinfoEncryptionEncValuesSupported;
        return this;
    }

    public DiscoveryConfigBuilder serviceDocumentation(String serviceDocumentation) {
        this.serviceDocumentation = serviceDocumentation;
        return this;
    }

    public DiscoveryConfigBuilder uiLocalesSupported(List<String> uiLocalesSupported) {
        this.uiLocalesSupported = uiLocalesSupported;
        return this;
    }

    public DiscoveryConfigBuilder claimsParameterSupported(boolean claimsParameterSupported) {
        this.claimsParameterSupported = claimsParameterSupported;
        return this;
    }

    public DiscoveryConfigBuilder opPolicyUri(String opPolicyUri) {
        this.opPolicyUri = opPolicyUri;
        return this;
    }

    public DiscoveryConfigBuilder opTosUri(String opTosUri) {
        this.opTosUri = opTosUri;
        return this;
    }

    public DiscoveryConfig build() {
        return new DiscoveryConfig(
                this.authorizationEndpoint,
                this.tokenEndpoint,
                this.jwksEndpoint,
                this.clientRegistrationEndpoint,
                this.revocationEndpoint,
                this.introspectionEndpoint,
                this.userInfoEndpoint,
                this.displayValueSupported,
                this.claimsSupported,
                this.userinfoSigningAlgValuesSupported,
                this.userinfoEncryptionAlgValuesSupported,
                this.userinfoEncryptionEncValuesSupported,
                this.serviceDocumentation,
                this.uiLocalesSupported,
                this.claimsParameterSupported,
                this.opPolicyUri,
                this.opTosUri);
    }
}
