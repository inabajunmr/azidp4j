package org.azidp4j.authorize.response;

import java.net.URI;
import java.util.Map;
import org.azidp4j.authorize.request.Display;
import org.azidp4j.authorize.request.Prompt;
import org.azidp4j.authorize.request.ResponseMode;

public class AuthorizationResponse {

    /** authorization server what should do next */
    public final NextAction next;

    /** when next is additioanlPage, the parameter is specified. */
    public final AdditionalPage additionalPage;

    /** when next is errorPage, the parameter is specified. */
    public final ErrorPage errorPage;

    /** when next is redirect, the parameter is specified. */
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

    public static AuthorizationResponse additionalPage(
            Prompt prompt, Display display, String clientId, String scope) {
        var page = new AdditionalPage(prompt, display, clientId, scope);
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
