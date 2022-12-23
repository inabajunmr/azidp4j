package org.azidp4j.authorize.response;

import java.net.URI;
import java.util.List;
import java.util.Map;
import org.azidp4j.authorize.request.Display;
import org.azidp4j.authorize.request.Prompt;
import org.azidp4j.authorize.request.ResponseMode;

public class AuthorizationResponse {

    /** authorization server what should do next */
    public final NextAction next;

    /** when next is additionalPage, the parameter is specified. */
    public final AdditionalPage additionalPage;

    /** when next is errorPage, the parameter is specified. */
    public final ErrorPage errorPage;

    /** when next is redirect, the parameter is specified. */
    public final Redirect redirect;

    /** error description for developer * */
    public final String errorDescription;

    private AuthorizationResponse(
            NextAction next,
            Redirect redirect,
            AdditionalPage additionalPage,
            ErrorPage errorPage,
            String errorDescription) {
        this.next = next;
        this.additionalPage = additionalPage;
        this.errorPage = errorPage;
        this.redirect = redirect;
        this.errorDescription = errorDescription;
    }

    public static AuthorizationResponse additionalPage(
            Prompt prompt,
            Display display,
            String clientId,
            String scope,
            List<String> uiLocales,
            String expectedUserSubject,
            String loginHint,
            String errorDescription) {
        var page =
                new AdditionalPage(
                        prompt,
                        display,
                        clientId,
                        scope,
                        uiLocales,
                        expectedUserSubject,
                        loginHint);
        return new AuthorizationResponse(
                NextAction.additionalPage, null, page, null, errorDescription);
    }

    public static AuthorizationResponse errorPage(
            AuthorizationErrorTypeWithoutRedirect error,
            List<String> uiLocales,
            String errorDescription) {
        return new AuthorizationResponse(
                NextAction.errorPage,
                null,
                null,
                new ErrorPage(error, uiLocales),
                errorDescription);
    }

    public static AuthorizationResponse redirect(
            URI redirectUri,
            Map<String, String> params,
            ResponseMode responseMode,
            String errorDescription) {
        var redirect = new Redirect(redirectUri, params, responseMode);
        return new AuthorizationResponse(
                NextAction.redirect, redirect, null, null, errorDescription);
    }
}
