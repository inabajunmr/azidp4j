package org.azidp4j.authorize;

public class AuthorizationRequestValidationResult {
    public final boolean hasError;
    public final AuthorizationResponse authorizationResponse;
    public final Prompt prompt;

    public AuthorizationRequestValidationResult(
            boolean hasError, AuthorizationResponse authorizationResponse, Prompt prompt) {
        this.hasError = hasError;
        this.authorizationResponse = authorizationResponse;
        this.prompt = prompt;
    }
}
