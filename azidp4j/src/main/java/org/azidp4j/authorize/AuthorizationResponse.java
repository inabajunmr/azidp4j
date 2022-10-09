package org.azidp4j.authorize;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.stream.Collectors;

public class AuthorizationResponse {

    public final NextAction next;

    public final int status;
    private final Map<String, String> query;
    private final Map<String, String> fragment;
    private final URI redirectUri;
    public final AdditionalPage additionalPage;
    public final AuthorizationErrorTypeWithoutRedirect error;

    private AuthorizationResponse(
            NextAction next,
            int status,
            Map<String, String> query,
            Map<String, String> fragment,
            URI redirectUri,
            AdditionalPage additionalPage,
            AuthorizationErrorTypeWithoutRedirect error) {
        this.next = next;
        this.status = status;
        this.query = query;
        this.fragment = fragment;
        this.redirectUri = redirectUri;
        this.additionalPage = additionalPage;
        this.error = error;
    }

    public static AuthorizationResponse additionalPage(Prompt prompt, Display display) {
        var page = new AdditionalPage(prompt, display);
        return new AuthorizationResponse(
                NextAction.additionalPage, 0, null, null, null, page, null);
    }

    public AuthorizationResponse(AuthorizationErrorTypeWithoutRedirect error) {
        this.next = NextAction.errorPage;
        this.status = 0;
        this.query = null;
        this.fragment = null;
        this.redirectUri = null;
        this.additionalPage = null;
        this.error = error;
    }

    public AuthorizationResponse(
            int status,
            URI redirectUri,
            Map<String, String> parameters,
            ResponseMode responseMode) {
        if (responseMode == null) {
            throw new AssertionError();
        }
        this.next = NextAction.redirect;
        this.additionalPage = null;
        this.status = status;
        switch (responseMode) {
            case query -> {
                this.query =
                        parameters.entrySet().stream()
                                .filter(q -> q.getValue() != null)
                                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
                this.fragment = Map.of();
                break;
            }
            case fragment -> {
                this.query = Map.of();
                this.fragment =
                        parameters.entrySet().stream()
                                .filter(f -> f.getValue() != null)
                                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
            }
            default -> throw new AssertionError();
        }
        this.redirectUri = redirectUri;
        this.error = null;
    }

    public AuthorizationResponse(AdditionalPage additionalPage) {
        this.next = NextAction.additionalPage;
        this.status = 0;
        this.query = null;
        this.fragment = null;
        this.additionalPage = additionalPage;
        this.redirectUri = null;
        this.error = null;
    }

    public Map<String, String> headers() {
        // TODO test
        if (this.status != 302) {
            return Map.of();
        }
        var uri = new StringBuilder(redirectUri.toString());
        if (!query.entrySet().isEmpty()) {
            var queryResponse =
                    query.entrySet().stream()
                            .map(
                                    kv ->
                                            kv.getKey()
                                                    + '='
                                                    + URLEncoder.encode(
                                                            kv.getValue(), StandardCharsets.UTF_8))
                            .collect(Collectors.joining("&"));
            uri.append("?").append(queryResponse);
        }

        if (!fragment.entrySet().isEmpty()) {
            var fragmentResponse =
                    fragment.entrySet().stream()
                            .map(
                                    kv ->
                                            kv.getKey()
                                                    + '='
                                                    + URLEncoder.encode(
                                                            kv.getValue(), StandardCharsets.UTF_8))
                            .collect(Collectors.joining("&"));
            uri.append("#").append(fragmentResponse);
        }
        return Map.of("Location", uri.toString());
    }
}
