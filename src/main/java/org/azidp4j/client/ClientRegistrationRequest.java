package org.azidp4j.client;

import java.util.Set;

public class ClientRegistrationRequest {

    final Set<String> redirectUris;
    final Set<String> grantTypes;
    final Set<String> responseTypes;
    final String scope;
    final String tokenEndpointAuthMethod;

    public static Builder builder() {
        return new Builder();
    }

    private ClientRegistrationRequest(
            Set<String> redirectUris,
            Set<String> grantTypes,
            Set<String> responseTypes,
            String scope,
            String tokenEndpointAuthMethod) {
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.responseTypes = responseTypes;
        this.scope = scope;
        this.tokenEndpointAuthMethod = tokenEndpointAuthMethod;
    }

    public static class Builder {
        private Set<String> redirectUris;
        private Set<String> grantTypes;
        private Set<String> responseTypes;
        private String scope;
        private String tokenEndpointAuthMethod;

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

        public ClientRegistrationRequest build() {
            return new ClientRegistrationRequest(
                    redirectUris, grantTypes, responseTypes, scope, tokenEndpointAuthMethod);
        }
    }
}
