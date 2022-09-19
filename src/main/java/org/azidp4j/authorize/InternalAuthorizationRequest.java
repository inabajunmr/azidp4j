package org.azidp4j.authorize;

import java.util.Set;

public class InternalAuthorizationRequest {

    /** Authenticated user identifier (not authorization request parameter) */
    final String authenticatedUserId;

    /** User consented scope (not authorization request parameter) */
    final Set<String> consentedScope;

    /** Time when the End-User authentication occurred (not authorization request parameter) */
    final Long authTime;

    /** rfc6749 "authorization code grant", "implicit grant" */
    final String responseType;

    // TODO final String responseMode;
    final String nonce;

    final String maxAge;
    //    final String display;

    final String prompt;

    /** rfc6749 "authorization code grant", "implicit grant" */
    final String clientId;

    /** rfc6749 "authorization code grant", "implicit grant" */
    final String redirectUri;

    /** rfc6749 "authorization code grant", "implicit grant" */
    final String scope;

    /** rfc6749 "authorization code grant", "implicit grant" */
    final String state;

    public static Builder builder() {
        return new Builder();
    }

    private InternalAuthorizationRequest(
            String authenticatedUserId,
            Set<String> consentedScope,
            Long authTime,
            String responseType,
            String clientId,
            String redirectUri,
            String scope,
            String state,
            String nonce,
            String maxAge,
            String prompt) {
        this.authenticatedUserId = authenticatedUserId;
        this.consentedScope = consentedScope;
        this.authTime = authTime;
        this.responseType = responseType;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
        this.scope = scope;
        this.state = state;
        this.nonce = nonce;
        this.maxAge = maxAge;
        this.prompt = prompt;
    }

    public static class Builder {

        private String authenticatedUserId;
        private Set<String> consentedScope;
        private Long authTime;
        private String responseType;
        private String clientId;
        private String redirectUri;
        private String scope;
        private String state;
        private String nonce;
        private String maxAge;
        private String prompt;

        private Builder() {}

        public Builder authenticatedUserId(String authenticatedUserId) {
            this.authenticatedUserId = authenticatedUserId;
            return this;
        }

        public Builder consentedScope(Set<String> consentedScope) {
            this.consentedScope = consentedScope;
            return this;
        }

        public Builder authTime(Long authTime) {
            this.authTime = authTime;
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

        public InternalAuthorizationRequest build() {
            return new InternalAuthorizationRequest(
                    authenticatedUserId,
                    consentedScope,
                    authTime,
                    responseType,
                    clientId,
                    redirectUri,
                    scope,
                    state,
                    nonce,
                    maxAge,
                    prompt);
        }
    }
}
