package org.azidp4j.introspection.request;

public class InternalIntrospectionRequest {

    public final String token;
    public final String tokenTypeHint;

    private InternalIntrospectionRequest(String token, String tokenTypeHint) {
        this.token = token;
        this.tokenTypeHint = tokenTypeHint;
    }

    public static InternalIntrospectionRequest.Builder builder() {
        return new InternalIntrospectionRequest.Builder();
    }

    public static class Builder {
        private String token;
        private String tokenTypeHint;

        public Builder token(String token) {
            this.token = token;
            return this;
        }

        public Builder tokenTypeHint(String tokenTypeHint) {
            this.tokenTypeHint = tokenTypeHint;
            return this;
        }

        public InternalIntrospectionRequest build() {
            return new InternalIntrospectionRequest(this.token, this.tokenTypeHint);
        }
    }
}
