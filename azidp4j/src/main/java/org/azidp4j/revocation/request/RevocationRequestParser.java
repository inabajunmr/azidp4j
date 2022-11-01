package org.azidp4j.revocation.request;

import org.azidp4j.RequestParserUtil;

public class RevocationRequestParser {

    public InternalRevocationRequest parse(RevocationRequest request) {

        var token = RequestParserUtil.valueToString("token", request.bodyParameters);
        var tokenTypeHint =
                RequestParserUtil.valueToString("token_type_hint", request.bodyParameters);
        return InternalRevocationRequest.builder()
                .authenticatedClientId(request.authenticatedClientId)
                .token(token)
                .tokenTypeHint(tokenTypeHint)
                .build();
    }
}
