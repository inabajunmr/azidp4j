package org.azidp4j.authorize;

import org.azidp4j.authorize.response.AuthorizationResponse;

public class ParseResult<T> {

    private final T value;

    private final AuthorizationResponse errorResponse;

    public ParseResult(T value, AuthorizationResponse errorResponse) {
        this.value = value;
        this.errorResponse = errorResponse;
    }

    public T getValue() {
        return value;
    }

    public AuthorizationResponse getErrorResponse() {
        return errorResponse;
    }

    public boolean isError() {
        return getErrorResponse() != null;
    }
}
