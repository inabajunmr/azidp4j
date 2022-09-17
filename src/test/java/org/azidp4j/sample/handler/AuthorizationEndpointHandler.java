package org.azidp4j.sample.handler;

import static org.azidp4j.authorize.Prompt.none;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.AuthorizationRequest;
import org.azidp4j.sample.web.CookieParser;

public class AuthorizationEndpointHandler implements HttpHandler {

    private final AzIdP azIdp;

    public AuthorizationEndpointHandler(AzIdP azIdp) {
        this.azIdp = azIdp;
    }

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {

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

        switch (result.prompt) {
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

                    var authorizationResponse = azIdp.authorize(authorizationRequest);
                    authorizationResponse
                            .headers("https://example.com")
                            .entrySet()
                            .forEach(
                                    h ->
                                            httpExchange
                                                    .getResponseHeaders()
                                                    .set(h.getKey(), h.getValue()));
                    httpExchange.sendResponseHeaders(authorizationResponse.status, 0);
                    httpExchange.close();
                }
            case login:
                {
                    var redirectTo =
                            "/authorize?"
                                    + new AuthorizationRequest(queryMap)
                                            .noPrompt().queryParameters().entrySet().stream()
                                                    .map(e -> e.getKey() + "=" + e.getValue())
                                                    .collect(Collectors.joining("&"));
                    var url = httpExchange.getRequestURI().toString().replaceAll("/.*", "");
                    httpExchange
                            .getResponseHeaders()
                            .put(
                                    "Location",
                                    List.of(
                                            url
                                                    + "/login?redirect_to="
                                                    + Base64.getEncoder()
                                                            .encodeToString(
                                                                    redirectTo.getBytes(
                                                                            StandardCharsets
                                                                                    .UTF_8))));
                    httpExchange.sendResponseHeaders(200, 0);
                    httpExchange.close();
                }
            default:
                {
                    // TODO
                    // has session
                    // return authz respones
                    // not has session
                    // login page with redirect_to
                }
        }
    }
}
