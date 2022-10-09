package org.azidp4j.authorize.response;

public class ErrorPage {

    public final AuthorizationErrorTypeWithoutRedirect errorType;

    public ErrorPage(AuthorizationErrorTypeWithoutRedirect errorType) {
        this.errorType = errorType;
    }
}
