package org.azidp4j.authorize;

public class AuthorizationRequestParser {

    public InternalAuthorizationRequest parse(AuthorizationRequest req) {
        String responseType = req.queryParameters.get("response_type");
        String clientId = req.queryParameters.get("client_id");
        String redirectUri = req.queryParameters.get("redirect_uri");
        String scope = req.queryParameters.get("scope");
        String state = req.queryParameters.get("state");

        var authorizationRequest =
                InternalAuthorizationRequest.builder()
                        .sub(req.userId)
                        .responseType(responseType)
                        .clientId(clientId)
                        .redirectUri(redirectUri)
                        .scope(scope)
                        .state(state)
                        .audiences(req.audiences)
                        .build();
        return authorizationRequest;
    }
}
