package org.azidp4j.authorize;

import org.azidp4j.authorize.response.AuthorizationResponse;

/**
 * Authorization Request Parse result
 *
 * @param <T>
 */
public class ParseResult<T> {

    /** Parsed value. */
    private final T value;

    /**
     * When parse failed, errorResponse is specified so caller should return the value as response.
     */
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
