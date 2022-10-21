package org.azidp4j.revocation.request;

public class RevocationRequestParser {

    public InternalRevocationRequest parse(RevocationRequest request) {
        var token = request.bodyParameters.get("token");
        var tokenTypeHint = request.bodyParameters.get("token_type_hint");
        return InternalRevocationRequest.builder()
                .authenticatedClientId(request.authenticatedClientId)
                .token(token)
                .tokenTypeHint(tokenTypeHint)
                .build();
    }
}
