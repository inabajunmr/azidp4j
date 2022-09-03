package org.azidp4j.sample.handler;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.AuthorizationRequest;

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
        var authorizationRequest =
                new AuthorizationRequest(httpExchange.getPrincipal().getUsername(), queryMap);
        var authorizationResponse = azIdp.authorize(authorizationRequest);
        authorizationResponse
                .headers("https://example.com")
                .entrySet()
                .forEach(
                        h -> {
                            httpExchange.getResponseHeaders().set(h.getKey(), h.getValue());
                        });
        httpExchange.sendResponseHeaders(302, 0);
        httpExchange.close();
    }
}
