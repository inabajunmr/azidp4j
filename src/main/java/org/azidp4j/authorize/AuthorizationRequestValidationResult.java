package org.azidp4j.authorize;

import java.util.Set;

public class AuthorizationRequestValidationResult {
    public final boolean hasError;
    public final AuthorizationResponse authorizationResponse;
    public final Set<Prompt> prompt;

    public AuthorizationRequestValidationResult(
            boolean hasError, AuthorizationResponse authorizationResponse, Set<Prompt> prompt) {
        this.hasError = hasError;
        this.authorizationResponse = authorizationResponse;
        this.prompt = prompt;
    }
}
