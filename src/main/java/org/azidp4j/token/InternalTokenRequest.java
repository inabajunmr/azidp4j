package org.azidp4j.token;

public class InternalTokenRequest {

    /** for authorization code */
    final String code;

    final String grantType;

    /** for authorization code */
    final String redirectUri;

    /**
     * authenticated(ex. via basic authentication) client id.
     *
     * <p>for authorization code
     */
    final String authenticatedClientId;

    /**
     * client id via request body.
     *
     * <p>for authorization code
     */
    final String clientId;

    /** for client credentials */
    final String scope;

    /** for resource owner password */
    final String username;
    /** for resource owner password */
    final String password;
    /** for token refresh */
    final String refreshToken;
    /** the time to authenticate by user **/
    final Long authTime;

    private InternalTokenRequest(
            String code,
            String grantType,
            String redirectUri,
            String clientId,
            String authenticatedClientId,
            String scope,
            String username,
            String password,
            String refreshToken,
            Long authTime) {
        this.code = code;
        this.grantType = grantType;
        this.redirectUri = redirectUri;
        this.clientId = clientId;
        this.authenticatedClientId = authenticatedClientId;
        this.scope = scope;
        this.username = username;
        this.password = password;
        this.refreshToken = refreshToken;
        this.authTime = authTime;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder {

        private String code;
        private String grantType;
        private String redirectUri;
        private String clientId;
        private String authenticatedClientId;
        private String scope;
        private String username;
        private String password;
        private String refreshToken;
        private Long authTime;

        public Builder code(String code) {
            this.code = code;
            return this;
        }

        public Builder grantType(String grantType) {
            this.grantType = grantType;
            return this;
        }

        public Builder redirectUri(String redirectUri) {
            this.redirectUri = redirectUri;
            return this;
        }

        public Builder clientId(String clientId) {
            this.clientId = clientId;
            return this;
        }

        public Builder authenticatedClientId(String authenticatedClientId) {
            this.authenticatedClientId = authenticatedClientId;
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

        public Builder authTime(Long authTime) {
            this.authTime = authTime;
            return this;
        }

        public InternalTokenRequest build() {
            return new InternalTokenRequest(
                    code,
                    grantType,
                    redirectUri,
                    clientId,
                    authenticatedClientId,
                    scope,
                    username,
                    password,
                    refreshToken,
                    authTime);
        }
    }
}
