package httpserversample.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.request.AuthorizationRequest;
import httpserversample.web.CookieParser;

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

        var cookies = CookieParser.parse(httpExchange);
        Set<String> consentedScope = Set.of();
        if (cookies.containsKey("Consent")) {
            var consent = new ObjectMapper().readTree(cookies.get("Consent"));
            if (consent.has(queryMap.get("client_id"))) {
                consentedScope =
                        Arrays.stream(consent.get(queryMap.get("client_id")).textValue().split(" "))
                                .collect(Collectors.toSet());
            }
        }
        var authorizationRequest =
                new AuthorizationRequest(
                        cookies.get("Login"),
                        Long.parseLong(cookies.get("AuthTime")),
                        consentedScope,
                        queryMap);
        authorize(httpExchange, authorizationRequest, queryMap);
    }

    private void authorize(
            HttpExchange httpExchange,
            AuthorizationRequest authorizationRequest,
            Map<String, String> queryMap)
            throws IOException {
        var authorizationResponse = azIdp.authorize(authorizationRequest);
        switch (authorizationResponse.next) {
            case additionalPage -> {
                switch (authorizationResponse.additionalPage.prompt) {
                    case login:
                    {
                        redirectToLoginPage(httpExchange, authorizationRequest);
                    }
                    case consent:
                    {
                        redirectToConsentPage(httpExchange, authorizationRequest, queryMap);
                    }
                }
                return;
            }
            case redirect -> {
                httpExchange.getResponseHeaders().put("Location", List.of(authorizationResponse.redirect.redirectTo));
                httpExchange.sendResponseHeaders(302, 0);
                httpExchange.close();
            }
            default -> {
                httpExchange.sendResponseHeaders(400, 0);
                httpExchange.close();
            }
        }

    }

    private void redirectToLoginPage(
            HttpExchange httpExchange, AuthorizationRequest authorizationRequest)
            throws IOException {
        redirectWithRedirectTo(httpExchange, "/login", "login", authorizationRequest, null);
    }

    private void redirectToConsentPage(
            HttpExchange httpExchange,
            AuthorizationRequest authorizationRequest,
            Map<String, String> queryMap)
            throws IOException {
        redirectWithRedirectTo(
                httpExchange,
                "/consent",
                "consent",
                authorizationRequest,
                Map.of("client_id", queryMap.get("client_id"), "scope", queryMap.get("scope")));
    }

    private void redirectWithRedirectTo(
            HttpExchange httpExchange,
            String targetPage,
            String removePrompt,
            AuthorizationRequest authorizationRequest,
            Map<String, String> targetPageQueryMap)
            throws IOException {
        var url = "http://" + httpExchange.getRequestHeaders().getFirst("Host");
        var redirectTo =
                url
                        + "/authorize?"
                        + URLEncoder.encode(
                                authorizationRequest
                                        .removePrompt(removePrompt)
                                        .queryParameters()
                                        .entrySet()
                                        .stream()
                                        .map(e -> e.getKey() + "=" + e.getValue())
                                        .collect(Collectors.joining("&")),
                                StandardCharsets.UTF_8);

        var targetUrl = new StringBuilder();
        targetUrl
                .append(url)
                .append(targetPage)
                .append("?redirect_to=")
                .append(URLEncoder.encode(redirectTo, StandardCharsets.UTF_8));
        if (targetPageQueryMap != null) {
            for (Map.Entry<String, String> entry : targetPageQueryMap.entrySet()) {
                String key = entry.getKey();
                String value = entry.getValue();
                targetUrl.append("&").append(key).append("=").append(value);
            }
        }
        httpExchange.getResponseHeaders().put("Location", List.of(targetUrl.toString()));
        httpExchange.sendResponseHeaders(302, 0);
        httpExchange.close();
    }
}
