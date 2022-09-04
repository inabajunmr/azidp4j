package org.azidp4j.token;

import java.util.Set;

public class InternalTokenRequest {

    /** for authorization code */
    final String code;

    final String grantType;

    /** for authorization code */
    final String redirectUri;

    /** for authorization code */
    final String clientId; // TODO split clientId and authenticatedClientId?

    /** for client credentials */
    final String scope;

    /** for resource owner password */
    final String username;
    /** for resource owner password */
    final String password;
    /** for token refresh */
    final String refreshToken;

    final Set<String> audiences;

    private InternalTokenRequest(
            String code,
            String grantType,
            String redirectUri,
            String clientId,
            String scope,
            String username,
            String password,
            String refreshToken,
            Set<String> audiences) {
        this.code = code;
        this.grantType = grantType;
        this.redirectUri = redirectUri;
        this.clientId = clientId;
        this.scope = scope;
        this.username = username;
        this.password = password;
        this.refreshToken = refreshToken;
        this.audiences = audiences;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private String code;
        private String grantType;
        private String redirectUri;
        private String clientId;
        private String scope;
        private String username;
        private String password;
        private String refreshToken;
        private Set<String> audiences;

        public Builder code(String code) {
            this.code = code;
            return this;
        }
        ;

        public Builder grantType(String grantType) {
            this.grantType = grantType;
            return this;
        }
        ;

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        }

        public Builder username(String username) {
            this.username = username;
            return this;
        }

        public Builder password(String password) {
            this.password = password;
            return this;
        }

        public Builder refreshToken(String refreshToken) {
            this.refreshToken = refreshToken;
            return this;
        }

        public Builder audiences(Set<String> audiences) {
            this.audiences = audiences;
            return this;
        }

        public InternalTokenRequest build() {
            return new InternalTokenRequest(
                    code,
                    grantType,
                    redirectUri,
                    clientId,
                    scope,
                    username,
                    password,
                    refreshToken,
                    audiences);
        }
    }
}
