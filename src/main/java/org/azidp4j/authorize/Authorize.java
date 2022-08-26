package org.azidp4j.authorize;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class Authorize {

    AuthorizationCodeStore authorizationCodeStore = new InMemoryAuthorizationCodeStore();

    public AuthorizationResponse authorize(AuthorizationRequest authorizationRequest) {
        var responseType = ResponseType.of(authorizationRequest.responseType);
        if(responseType == ResponseType.code) {

            // TODO validate client
            // TODO validate? scope
            var code = UUID.randomUUID().toString();
            var state = authorizationRequest.state;
            authorizationCodeStore.save(
                    new AuthorizationCode(code, authorizationRequest.scope, authorizationRequest.clientId));
            return new AuthorizationResponse(Map.of("code", code, "state", state), Map.of());
        }

        throw new RuntimeException();
    }
}
