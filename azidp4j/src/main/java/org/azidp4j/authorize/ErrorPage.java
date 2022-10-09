package org.azidp4j.authorize;

public class ErrorPage {

    public final AuthorizationErrorTypeWithoutRedirect errorType;

    public ErrorPage(AuthorizationErrorTypeWithoutRedirect errorType) {
        this.errorType = errorType;
    }
}
