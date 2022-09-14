package org.azidp4j.sample.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.token.TokenRequest;

public class TokenEndpointHandler implements HttpHandler {

    private final AzIdP azIdp;

    public TokenEndpointHandler(AzIdP azIdp) {
        this.azIdp = azIdp;
    }

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        var clientId = httpExchange.getPrincipal().getUsername();
        var body = new String(httpExchange.getRequestBody().readAllBytes());
        var bodyMap =
                Arrays.stream(body.split("&"))
                        .map(kv -> kv.split("="))
                        .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));
        var tokenRequest = new TokenRequest(clientId, Instant.now().getEpochSecond(), bodyMap);
        var tokenResponse = azIdp.issueToken(tokenRequest);
        var mapper = new ObjectMapper();
        var responseJSON = mapper.writeValueAsString(tokenResponse.body);
        httpExchange.getResponseHeaders().set("Content-Type", "application/json;charset=UTF-8");
        httpExchange.sendResponseHeaders(200, 0);
        var output = httpExchange.getResponseBody();
        output.write(responseJSON.getBytes(StandardCharsets.UTF_8));
        httpExchange.close();
    }
}
