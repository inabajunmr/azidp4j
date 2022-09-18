package org.azidp4j.authorize;

import java.util.Set;

public class InternalAuthorizationRequest {

    /** user identifier * */
    final String authenticatedUserId;

    final Set<String> consentedScope;

    final String responseType;
    // TODO final String responseMode;
    final String nonce;
    final String maxAge;

    //    final String display;
    final String prompt;

    final String clientId;
    final String redirectUri;
    final String scope;
    final String state;
    final Set<String> audiences;

    public static Builder builder() {
        return new Builder();
    }

    private InternalAuthorizationRequest(
            String authenticatedUserId,
            Set<String> consentedScope,
            String responseType,
            String clientId,
            String redirectUri,
            String scope,
            String state,
            String nonce,
            String maxAge,
            String prompt,
            Set<String> audiences) {
        this.authenticatedUserId = authenticatedUserId;
        this.consentedScope = consentedScope;
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.state = state;
        this.nonce = nonce;
        this.maxAge = maxAge;
        this.prompt = prompt;
        this.audiences = audiences;
    }

    public static class Builder {

        private String authenticatedUserId;
        private Set<String> consentedScope;
        private String responseType;
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;
        private String nonce;
        private String maxAge;
        private String prompt;
        private Set<String> audiences;

        private Builder() {}

        private Builder(String responseType) {
            this.responseType = responseType;
        }

        public Builder authenticatedUserId(String authenticatedUserId) {
            this.authenticatedUserId = authenticatedUserId;
            return this;
        }

        public Builder consentedScope(Set<String> consentedScope) {
            this.consentedScope = consentedScope;
            return this;
        }

        public Builder responseType(String responseType) {
            this.responseType = responseType;
            return this;
        }

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

        public Builder nonce(String nonce) {
            this.nonce = nonce;
            return this;
        }

        public Builder maxAge(String maxAge) {
            this.maxAge = maxAge;
            return this;
        }

        public Builder prompt(String prompt) {
            this.prompt = prompt;
            return this;
        }

        public Builder audiences(Set<String> audiences) {
            this.audiences = audiences;
            return this;
        }

        public InternalAuthorizationRequest build() {
            return new InternalAuthorizationRequest(
                    authenticatedUserId,
                    consentedScope,
                    responseType,
                    clientId,
                    redirectUri,
                    scope,
                    state,
                    nonce,
                    maxAge,
                    prompt,
                    audiences);
        }
    }
}
