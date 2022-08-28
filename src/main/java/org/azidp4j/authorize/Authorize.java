package org.azidp4j.authorize;

import java.util.Map;
import java.util.UUID;

public class Authorize {

    AuthorizationCodeStore authorizationCodeStore;
    ;

    public Authorize(AuthorizationCodeStore authorizationCodeStore) {
        this.authorizationCodeStore = authorizationCodeStore;
    }

    public AuthorizationResponse authorize(AuthorizationRequest authorizationRequest) {
        var responseType = ResponseType.of(authorizationRequest.responseType);
        if (responseType == ResponseType.code) {

            // TODO validate client
            // TODO validate? scope
            var code = UUID.randomUUID().toString();
            var state = authorizationRequest.state;
            authorizationCodeStore.save(
                    new AuthorizationCode(
                            authorizationRequest.sub,
                            code,
                            authorizationRequest.scope,
                            authorizationRequest.clientId,
                            authorizationRequest.state));
            return new AuthorizationResponse(Map.of("code", code, "state", state), Map.of());
        }

        throw new RuntimeException();
    }
}
