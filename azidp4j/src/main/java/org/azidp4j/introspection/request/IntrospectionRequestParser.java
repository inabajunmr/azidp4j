package org.azidp4j.introspection.request;

import org.azidp4j.RequestParserUtil;

public class IntrospectionRequestParser {

    public InternalIntrospectionRequest parse(IntrospectionRequest request) {
        var token = RequestParserUtil.valueToString("token", request.bodyParameters);
        var tokenTypeHint =
                RequestParserUtil.valueToString("token_type_hint", request.bodyParameters);
        return InternalIntrospectionRequest.builder()
                .token(token)
                .tokenTypeHint(tokenTypeHint)
                .build();
    }
}
