package org.azidp4j.client.request;

import java.util.List;
import java.util.Set;
import org.azidp4j.util.HumanReadable;

public class ClientRegistrationRequest {

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol OpenID Connect Dynamic Client Registration 1.0
     */
    public final Set<String> redirectUris;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol OpenID Connect Dynamic Client Registration 1.0
     */
    public final Set<String> grantTypes;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol OpenID Connect Dynamic Client Registration 1.0
     */
    public final Set<String> responseTypes;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final HumanReadable<String> clientName;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String clientUri;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String logoUri;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String scope;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final List<String> contacts;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final HumanReadable<String> tosUri;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final HumanReadable<String> policyUri;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String jwksUri;

    // TODO The "jwks_uri" and "jwks" parameters MUST NOT both
    //      be present in the same request or response.

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String jwks;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String softwareId;

    /** OAuth 2.0 Dynamic Client Registration Protocol */
    public final String softwareVersion;

    /**
     * OAuth 2.0 Dynamic Client Registration Protocol OpenID Connect Dynamic Client Registration 1.0
     */
    public final String tokenEndpointAuthMethod;

    /** OpenID Connect Dynamic Client Registration 1.0 */
    public final String idTokenSignedResponseAlg;

    public static Builder builder() {
        return new Builder();
    }

    private ClientRegistrationRequest(
            Set<String> redirectUris,
            Set<String> grantTypes,
            Set<String> responseTypes,
            HumanReadable<String> clientName,
            String clientUri,
            String logoUri,
            String scope,
            List<String> contacts,
            HumanReadable<String> tosUri,
            HumanReadable<String> policyUri,
            String jwksUri,
            String jwks,
            String softwareId,
            String softwareVersion,
            String tokenEndpointAuthMethod,
            String idTokenSignedResponseAlg) {
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.responseTypes = responseTypes;
        this.clientName = clientName;
        this.clientUri = clientUri;
        this.logoUri = logoUri;
        this.scope = scope;
        this.contacts = contacts;
        this.tosUri = tosUri;
        this.policyUri = policyUri;
        this.jwksUri = jwksUri;
        this.jwks = jwks;
        this.softwareId = softwareId;
        this.softwareVersion = softwareVersion;
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
    }

    public static class Builder {
        private Set<String> redirectUris;
        private Set<String> grantTypes;
        private Set<String> responseTypes;
        private HumanReadable<String> clientName;
        private String clientUri;
        private String logoUri;
        private String scope;
        private List<String> contacts;
        private HumanReadable<String> tosUri;
        private HumanReadable<String> policyUri;
        private String jwksUri;
        private String jwks;
        private String softwareId;
        private String softwareVersion;
        private String tokenEndpointAuthMethod;
        private String idTokenSignedResponseAlg;

        public Builder redirectUris(Set<String> redirectUris) {
            this.redirectUris = redirectUris;
            return this;
        }

        public Builder grantTypes(Set<String> grantTypes) {
            this.grantTypes = grantTypes;
            return this;
        }

        public Builder responseTypes(Set<String> responseTypes) {
            this.responseTypes = responseTypes;
            return this;
        }

        public Builder clientName(HumanReadable<String> clientName) {
            this.clientName = clientName;
            return this;
        }

        public Builder clientUri(String clientUri) {
            this.clientUri = clientUri;
            return this;
        }

        public Builder logoUri(String logoUri) {
            this.logoUri = logoUri;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder contacts(List<String> contacts) {
            this.contacts = contacts;
            return this;
        }

        public Builder tosUri(HumanReadable<String> tosUri) {
            this.tosUri = tosUri;
            return this;
        }

        public Builder policyUri(HumanReadable<String> policyUri) {
            this.policyUri = policyUri;
            return this;
        }

        public Builder jwksUri(String jwksUri) {
            this.jwksUri = jwksUri;
            return this;
        }

        public Builder jwks(String jwks) {
            this.jwks = jwks;
            return this;
        }

        public Builder softwareId(String softwareId) {
            this.softwareId = softwareId;
            return this;
        }

        public Builder softwareVersion(String softwareVersion) {
            this.softwareVersion = softwareVersion;
            return this;
        }

        public Builder tokenEndpointAuthMethod(String tokenEndpointAuthMethod) {
            this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
            return this;
        }

        public Builder idTokenSignedResponseAlg(String idTokenSignedResponseAlg) {
            this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
            return this;
        }

        public ClientRegistrationRequest build() {
            return new ClientRegistrationRequest(
                    redirectUris,
                    grantTypes,
                    responseTypes,
                    clientName,
                    clientUri,
                    logoUri,
                    scope,
                    contacts,
                    tosUri,
                    policyUri,
                    jwksUri,
                    jwks,
                    softwareId,
                    softwareVersion,
                    tokenEndpointAuthMethod,
                    idTokenSignedResponseAlg);
        }
    }
}
