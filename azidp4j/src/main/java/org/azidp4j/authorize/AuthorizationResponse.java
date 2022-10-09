package org.azidp4j.authorize;

import java.net.URI;
import java.util.Map;

public class AuthorizationResponse {

    public final NextAction next;
    public final AdditionalPage additionalPage;
    public final ErrorPage errorPage;
    public final Redirect redirect;

    private AuthorizationResponse(
            NextAction next,
            Redirect redirect,
            AdditionalPage additionalPage,
            ErrorPage errorPage) {
        this.next = next;
        this.additionalPage = additionalPage;
        this.errorPage = errorPage;
        this.redirect = redirect;
    }

    public static AuthorizationResponse additionalPage(Prompt prompt, Display display) {
        var page = new AdditionalPage(prompt, display);
        return new AuthorizationResponse(NextAction.additionalPage, null, page, null);
    }

    public static AuthorizationResponse errorPage(AuthorizationErrorTypeWithoutRedirect error) {
        return new AuthorizationResponse(NextAction.errorPage, null, null, new ErrorPage(error));
    }

    public static AuthorizationResponse redirect(
            URI redirectUri, Map<String, String> params, ResponseMode responseMode) {
        var redirect = new Redirect(redirectUri, params, responseMode);
        return new AuthorizationResponse(NextAction.redirect, redirect, null, null);
    }
}
