package org.azidp4j.sample.handler;

import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.AuthorizationRequest;
import org.azidp4j.sample.web.CookieParser;

public class AuthorizationEndpointHandler extends AzIdpHttpHandler {

    private final AzIdP azIdp;

    public AuthorizationEndpointHandler(AzIdP azIdp) {
        this.azIdp = azIdp;
    }

    @Override
    public void process(HttpExchange httpExchange) throws IOException {
        var query = httpExchange.getRequestURI().getQuery();
        var queryMap =
                Arrays.stream(query.split("&"))
                        .map(kv -> kv.split("="))
                        .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));
        var result = azIdp.validateAuthorizationRequest(new AuthorizationRequest(queryMap));
        if (result.hasError) {
            result.authorizationResponse
                    .headers("https://example.com")
                    .entrySet()
                    .forEach(
                            h -> {
                                httpExchange.getResponseHeaders().set(h.getKey(), h.getValue());
                            });
            httpExchange.sendResponseHeaders(302, 0);
            httpExchange.close();
            return;
        }
        if (result.prompt == null) {
            // default prompt
            // check session
            var cookies = CookieParser.parse(httpExchange);
            if (!cookies.containsKey("Login")) {
                // to login page
                redirectToLoginPage(httpExchange, queryMap);
                return;
            }

            // check consent
            if (!cookies.containsKey("Consent")) {
                // to consent page
                redirectToConsentPage(httpExchange, queryMap);
                return;
            }

            var authorizationRequest = new AuthorizationRequest(cookies.get("Login"), queryMap);
            authorize(httpExchange, authorizationRequest);
            return;
        }

        switch (result.prompt.stream().findFirst().get()) { // TODO need to handle multiple prompt
            case none:
                {
                    // check session
                    var cookies = CookieParser.parse(httpExchange);
                    var authorizationRequest = new AuthorizationRequest(queryMap);
                    if (cookies.containsKey("Login")) {
                        // TODO not good interface
                        authorizationRequest =
                                new AuthorizationRequest(cookies.get("Login"), queryMap);
                    }
                    authorize(httpExchange, authorizationRequest);
                    return;
                }
            case login:
                {
                    redirectToLoginPage(httpExchange, queryMap);
                    return;
                }
            case consent:
                {
                    var cookies = CookieParser.parse(httpExchange);
                    if (!cookies.containsKey("Login")) {
                        redirectToLoginPage(httpExchange, queryMap);
                        return;
                    }

                    redirectToConsentPage(httpExchange, queryMap);
                    return;
                }
            default:
                {
                    // TODO error
                }
        }
    }

    private void authorize(HttpExchange httpExchange, AuthorizationRequest authorizationRequest)
            throws IOException {
        var authorizationResponse = azIdp.authorize(authorizationRequest);
        authorizationResponse
                .headers("https://example.com")
                .forEach((key, value) -> httpExchange.getResponseHeaders().set(key, value));
        httpExchange.sendResponseHeaders(authorizationResponse.status, 0);
        httpExchange.close();
    }

    private void redirectToLoginPage(HttpExchange httpExchange, Map<String, String> queryMap)
            throws IOException {
        redirectWithRedirectTo(httpExchange, "/login", "login", queryMap, null);
    }

    private void redirectToConsentPage(HttpExchange httpExchange, Map<String, String> queryMap)
            throws IOException {
        redirectWithRedirectTo(
                httpExchange,
                "/consent",
                "consent",
                queryMap,
                Map.of("client_id", queryMap.get("client_id"), "scope", queryMap.get("scope")));
    }

    private void redirectWithRedirectTo(
            HttpExchange httpExchange,
            String targetPage,
            String removePrompt,
            Map<String, String> authorizationRequestQueryMap,
            Map<String, String> targetPageQueryMap)
            throws IOException {
        var url = "http://" + httpExchange.getRequestHeaders().getFirst("Host");
        var redirectTo =
                url
                        + "/authorize?"
                        + URLEncoder.encode(
                                new AuthorizationRequest(authorizationRequestQueryMap)
                                                .removePrompt(removePrompt)
                                                .queryParameters()
                                                .entrySet()
                                                .stream()
                                                .map(e -> e.getKey() + "=" + e.getValue())
                                                .collect(Collectors.joining("&")),
                                StandardCharsets.UTF_8);

        var targetUrl = new StringBuilder();
        targetUrl.append(
                url
                        + targetPage
                        + "?redirect_to="
                        + URLEncoder.encode(redirectTo, StandardCharsets.UTF_8));
        if (targetPageQueryMap != null) {
            targetPageQueryMap
                    .entrySet()
                    .forEach(
                            kv -> {
                                targetUrl.append("&" + kv.getKey() + "=" + kv.getValue());
                            });
        }
        httpExchange.getResponseHeaders().put("Location", List.of(targetUrl.toString()));
        httpExchange.sendResponseHeaders(302, 0);
        httpExchange.close();
    }
}
