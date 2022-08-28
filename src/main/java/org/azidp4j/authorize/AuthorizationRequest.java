package org.azidp4j.authorize;

public class AuthorizationRequest {

    /** user identifier **/
    final String sub;
    final String responseType;
    final String clientId;
    final String redirectUri;
    final String scope;
    final String state;

    public static Builder builder() {
        return new Builder();
    }

    private AuthorizationRequest(String sub, String responseType, String clientId, String redirectUri, String scope, String state) {
        this.sub = sub;
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.state = state;
    }

    public static class Builder {

        private String sub;
        private String responseType;
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;

        private Builder() {
            this.responseType = responseType;
        }

        public Builder sub(String sub) {
            this.sub = sub;
            return this;
        }
        public Builder responseType(String responseType) {
            this.responseType = responseType;
            return this;
        };
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

        public AuthorizationRequest build() {
            return new AuthorizationRequest(sub, responseType, clientId, redirectUri, scope, state);
        }
    }
}
