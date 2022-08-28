package org.azidp4j.client;

import org.azidp4j.authorize.ResponseType;

import java.util.Set;

public class ClientRegistrationRequest {

    final Set<String> redirectUris;
    final Set<GrantType> grantTypes;
    final Set<ResponseType> responseTypes;
    final String scope;

    public static Builder builder() {
        return new Builder();
    }

    private ClientRegistrationRequest(Set<String> redirectUris, Set<GrantType> grantTypes, Set<ResponseType> responseTypes, String scope) {
        this.redirectUris = redirectUris;
        this.grantTypes = grantTypes;
        this.responseTypes = responseTypes;
        this.scope = scope;
    }

    public static class Builder {
        private Set<String> redirectUris;
        private Set<GrantType> grantTypes;
        private Set<ResponseType> responseTypes;
        private String scope;

        public Builder redirectUris(Set<String> redirectUris) {
            this.redirectUris = redirectUris;
            return this;
        }

        public Builder grantTypes(Set<GrantType> grantTypes) {
            this.grantTypes = grantTypes;
            return this;
        }

        public Builder responseTypes(Set<ResponseType> responseTypes) {
            this.responseTypes = responseTypes;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public ClientRegistrationRequest build() {
            return new ClientRegistrationRequest(redirectUris, grantTypes, responseTypes, scope);
        }
    }
}
