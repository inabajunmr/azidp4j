package org.azidp4j.revocation.request;

public class InternalRevocationRequest {

    /**
     * authenticated(ex. via basic authentication) client id.
     *
     * <p>for authorization code
     */
    public final String authenticatedClientId;

    public final String token;
    public final String tokenTypeHint;

    private InternalRevocationRequest(
            String authenticatedClientId, String token, String tokenTypeHint) {
        this.authenticatedClientId = authenticatedClientId;
        this.token = token;
        this.tokenTypeHint = tokenTypeHint;
    }

    public static InternalRevocationRequest.Builder builder() {
        return new InternalRevocationRequest.Builder();
    }

    public static class Builder {
        private String authenticatedClientId;
        private String token;
        private String tokenTypeHint;

        public Builder authenticatedClientId(String authenticatedClientId) {
            this.authenticatedClientId = authenticatedClientId;
            return this;
        }

        public Builder token(String token) {
            this.token = token;
            return this;
        }

        public Builder tokenTypeHint(String tokenTypeHint) {
            this.tokenTypeHint = tokenTypeHint;
            return this;
        }

        public InternalRevocationRequest build() {
            return new InternalRevocationRequest(
                    this.authenticatedClientId, this.token, this.tokenTypeHint);
        }
    }
}
