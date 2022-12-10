package org.azidp4j.authorize.response;

import java.util.List;

public class ErrorPage {

    public final AuthorizationErrorTypeWithoutRedirect errorType;
    public List<String> uiLocales;

    public ErrorPage(AuthorizationErrorTypeWithoutRedirect errorType, List<String> uiLocales) {
        this.errorType = errorType;
        this.uiLocales = uiLocales;
    }
}
