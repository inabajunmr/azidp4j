package org.azidp4j.sample.handler;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.AuthorizationRequest;

import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;

public class AuthorizationEndpointHandler implements HttpHandler {

    private final AzIdP azIdp;

    public AuthorizationEndpointHandler(AzIdP azIdp) {
        this.azIdp = azIdp;
    }

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        var query = httpExchange.getRequestURI().getQuery();
        var queryMap = Arrays.stream(query.split("&"))
                .map(kv -> kv.split("="))
                .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));

        String responseType = queryMap.get("response_type");
        String clientId = queryMap.get("client_id");
        String redirectUri = queryMap.get("redirect_uri");
        String scope = queryMap.get("scope");
        String state = queryMap.get("state");

        var authorizationRequest = AuthorizationRequest.builder()
                .sub("username")
                .responseType(responseType)
                .clientId(clientId)
                .redirectUri(redirectUri)
                .scope(scope)
                .state(state).build();

        var authorizationResponse = azIdp.authorize(authorizationRequest);
        var queryResponse = authorizationResponse.query.entrySet().stream()
                .map(kv -> kv.getKey() + '=' + kv.getValue())
                .collect(Collectors.joining("&"));
        var fragmentResponse = authorizationResponse.fragment.entrySet().stream()
                .map(kv -> kv.getKey() + '=' + kv.getValue())
                .collect(Collectors.joining("&"));

        httpExchange.getResponseHeaders().set("Location", "example.com?" + queryResponse + "#" + fragmentResponse);
        httpExchange.sendResponseHeaders(302, 0);
        httpExchange.close();
    }
}