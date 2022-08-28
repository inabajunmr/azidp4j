package org.azidp4j.token;

public class TokenRequest {

    final String code;
    final String grantType;
    final String redirectUri;
    final String clientId;

    final String scope;

    private TokenRequest(String code, String grantType, String redirectUri, String clientId, String scope) {
        this.code = code;
        this.grantType = grantType;
        this.redirectUri = redirectUri;
        this.clientId = clientId;
        this.scope = scope;
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

        public Builder code(String code) {
            this.code = code;
            return this;
        };
        public Builder grantType(String grantType) {
            this.grantType = grantType;
            return this;
        };
        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        };
        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        };
        public Builder scope(String scope) {
            this.scope = scope;
            return this;
        };
        public TokenRequest build() {
            return new TokenRequest(code, grantType, redirectUri, clientId, scope);
        }
    }
}
