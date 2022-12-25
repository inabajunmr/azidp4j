package org.azidp4j.authorize.response;

import java.net.URI;
import java.util.List;
import java.util.Map;
import org.azidp4j.authorize.request.*;

public class AuthorizationResponse {

    /** authorization server what should do next */
    public final NextAction next;

    /** when next is additionalPage, the parameter is specified. */
    private final AdditionalPage additionalPage;

    /** when next is errorPage, the parameter is specified. */
    private final ErrorPage errorPage;

    private final Redirect redirect;

    /** error description for developer * */
    public final String errorDescription;

    private final InternalAuthorizationRequest authorizationRequest;

    private AuthorizationResponse(
            NextAction next,
            Redirect redirect,
            AdditionalPage additionalPage,
            ErrorPage errorPage,
            String errorDescription,
            InternalAuthorizationRequest authorizationRequest) {
        this.next = next;
        this.additionalPage = additionalPage;
        this.errorPage = errorPage;
        this.redirect = redirect;
        this.errorDescription = errorDescription;
        this.authorizationRequest = authorizationRequest;
    }

    public static AuthorizationResponse additionalPage(
            Prompt prompt,
            Display display,
            String clientId,
            String scope,
            List<String> uiLocales,
            String expectedUserSubject,
            String loginHint,
            String errorDescription,
            InternalAuthorizationRequest authorizationRequest) {
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
                NextAction.additionalPage,
                null,
                page,
                null,
                errorDescription,
                authorizationRequest);
    }

    public static AuthorizationResponse errorPage(
            AuthorizationErrorTypeWithoutRedirect error,
            List<String> uiLocales,
            String errorDescription,
            InternalAuthorizationRequest authorizationRequest) {
        return new AuthorizationResponse(
                NextAction.errorPage,
                null,
                null,
                new ErrorPage(error, uiLocales),
                errorDescription,
                authorizationRequest);
    }

    public static AuthorizationResponse redirect(
            URI redirectUri,
            Map<String, String> params,
            ResponseMode responseMode,
            boolean isSuccessResponse,
            String errorDescription,
            InternalAuthorizationRequest authorizationRequest) {
        return new AuthorizationResponse(
                NextAction.redirect,
                new Redirect(
                        () -> new RedirectTo(redirectUri, params, responseMode), isSuccessResponse),
                null,
                null,
                errorDescription,
                authorizationRequest);
    }

    public static AuthorizationResponse redirect(
            RedirectToSupplier redirectToSupplier,
            boolean isSuccessResponse,
            String errorDescription,
            InternalAuthorizationRequest authorizationRequest) {
        return new AuthorizationResponse(
                NextAction.redirect,
                new Redirect(redirectToSupplier, isSuccessResponse),
                null,
                null,
                errorDescription,
                authorizationRequest);
    }

    public AdditionalPage additionalPage() {
        return additionalPage;
    }

    public ErrorPage errorPage() {
        return errorPage;
    }

    public Redirect redirect() {
        return redirect;
    }

    public InternalAuthorizationRequest authorizationRequest() {
        return authorizationRequest;
    }
}
