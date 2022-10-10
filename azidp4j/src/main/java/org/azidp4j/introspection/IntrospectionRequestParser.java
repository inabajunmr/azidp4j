package org.azidp4j.introspection;

public class IntrospectionRequestParser {

    public InternalIntrospectionRequest parse(IntrospectionRequest request) {
        var token = request.bodyParameters.get("token");
        var tokenTypeHint = request.bodyParameters.get("token_type_hint");
        return InternalIntrospectionRequest.builder()
                .token(token)
                .tokenTypeHint(tokenTypeHint)
                .build();
    }
}
