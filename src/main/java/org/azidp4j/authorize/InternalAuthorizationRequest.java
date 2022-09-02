package org.azidp4j.authorize;

import java.util.Set;

public class InternalAuthorizationRequest {

    /** user identifier * */
    final String sub;

    final String responseType;
    final String clientId;
    final String redirectUri;
    final String scope;
    final String state;
    final Set<String> audiences;

    public static Builder builder() {
        return new Builder();
    }

    private InternalAuthorizationRequest(
            String sub,
            String responseType,
            String clientId,
            String redirectUri,
            String scope,
            String state,
            Set<String> audiences) {
        this.sub = sub;
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.state = state;
        this.audiences = audiences;
    }

    public static class Builder {

        private String sub;
        private String responseType;
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;
        private Set<String> audiences;

        private Builder() {}

        private Builder(String responseType) {
            this.responseType = responseType;
        }

        public Builder sub(String sub) {
            this.sub = sub;
            return this;
        }

        public Builder responseType(String responseType) {
            this.responseType = responseType;
            return this;
        }
        ;

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder state(String state) {
            this.state = state;
            return this;
        }

        public Builder audiences(Set<String> audiences) {
            this.audiences = audiences;
            return this;
        }

        public InternalAuthorizationRequest build() {
            return new InternalAuthorizationRequest(
                    sub, responseType, clientId, redirectUri, scope, state, audiences);
        }
    }
}
