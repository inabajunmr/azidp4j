package org.azidp4j.client.request;

import java.util.Set;

public class ClientConfigurationRequest {

    // TODO add field or merge with registration

    public final String clientId;
    public final Set<String> redirectUris;
    public final Set<String> grantTypes;
    public final Set<String> responseTypes;
    public final String scope;
    public final String tokenEndpointAuthMethod;
    public final String idTokenSignedResponseAlg;

    public static Builder builder() {
        return new Builder();
    }

    private ClientConfigurationRequest(
            String clientId,
            Set<String> redirectUris,
            Set<String> grantTypes,
            Set<String> responseTypes,
            String scope,
            String tokenEndpointAuthMethod,
            String idTokenSignedResponseAlg) {
        this.clientId = clientId;
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.responseTypes = responseTypes;
        this.scope = scope;
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
        this.idTokenSignedResponseAlg = idTokenSignedResponseAlg;
    }

    public static class Builder {
        private String clientId;
        private Set<String> redirectUris;
        private Set<String> grantTypes;
        private Set<String> responseTypes;
        private String scope;
        private String tokenEndpointAuthMethod;
        private String idTokenSignedResponseAlg;

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

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

        public Builder scope(String scope) {
            this.scope = scope;
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

        public ClientConfigurationRequest build() {
            return new ClientConfigurationRequest(
                    clientId,
                    redirectUris,
                    grantTypes,
                    responseTypes,
                    scope,
                    tokenEndpointAuthMethod,
                    idTokenSignedResponseAlg);
        }
    }
}
