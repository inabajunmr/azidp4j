package org.azidp4j.token;

import java.util.Set;

public class TokenRequest {

    /** for authorization code */
    final String code;

    final String grantType;

    /** for authorization code */
    final String redirectUri;

    /** for authorization code */
    final String clientId;

    /** for client credentials */
    final String scope;

    final Set<String> audiences;

    private TokenRequest(
            String code,
            String grantType,
            String redirectUri,
            String clientId,
            String scope,
            Set<String> audiences) {
        this.code = code;
        this.grantType = grantType;
        this.redirectUri = redirectUri;
        this.clientId = clientId;
        this.scope = scope;
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

        public Builder audiences(Set<String> audiences) {
            this.audiences = audiences;
            return this;
        }

        public TokenRequest build() {
            return new TokenRequest(code, grantType, redirectUri, clientId, scope, audiences);
        }
    }
}
