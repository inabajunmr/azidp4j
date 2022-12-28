package org.azidp4j.authorize.parser;

import java.net.URI;
import java.util.List;
import org.azidp4j.authorize.request.InternalAuthorizationRequest;
import org.azidp4j.authorize.response.AuthorizationErrorTypeWithoutRedirect;
import org.azidp4j.authorize.response.AuthorizationResponse;
import org.azidp4j.client.Client;

public class RedirectURIParser {

    public static ParseResult<URI> parse(
            String redirectUri,
            Client client,
            List<String> locales,
            InternalAuthorizationRequest authorizationRequest) {

        // validate redirect urls
        if (redirectUri == null) {
            return ParseResult.error(
                    AuthorizationResponse.errorPage(
                            AuthorizationErrorTypeWithoutRedirect.invalid_redirect_uri,
                            locales,
                            "redirect_uri required",
                            authorizationRequest));
        }
        if (!client.redirectUris.contains(redirectUri)) {
            return ParseResult.error(
                    AuthorizationResponse.errorPage(
                            AuthorizationErrorTypeWithoutRedirect.redirect_uri_not_allowed,
                            locales,
                            "client doesn't allow redirect_uri",
                            authorizationRequest));
        }
        try {
            return ParseResult.of(URI.create(authorizationRequest.redirectUri));
        } catch (IllegalArgumentException e) {
            throw new AssertionError("Client has illegal redirect_uris.", e);
        }
    }
}
