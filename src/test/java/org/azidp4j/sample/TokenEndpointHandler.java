package org.azidp4j.sample;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.azidp4j.AzIdP;
import org.azidp4j.token.TokenRequest;

import javax.management.ObjectName;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.stream.Collectors;

public class TokenEndpointHandler implements HttpHandler {

    private final AzIdP azIdp;

    public TokenEndpointHandler(AzIdP azIdp) {
        this.azIdp = azIdp;
    }

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        System.out.println("TOKEN");
        var body = new String(httpExchange.getRequestBody().readAllBytes());
        var bodyMap = Arrays.stream(body.split("&"))
                .map(kv -> kv.split("="))
                .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));
        var code = bodyMap.get("code");
        var grantType = bodyMap.get("grant_type");
        var redirectUri = bodyMap.get("redirect_uri");
        var clientId = bodyMap.get("client_id");
        var tokenRequest = TokenRequest.builder()
                .code(code)
                .grantType(grantType)
                .redirectUri(redirectUri)
                .clientId(clientId).build();
        var tokenResponse = azIdp.issueToken(tokenRequest);
        var mapper = new ObjectMapper();
        var responseJSON = mapper.writeValueAsString(tokenResponse.body);
        httpExchange.getResponseHeaders().set("Content-Type", "application/json;charset=UTF-8");
        httpExchange.sendResponseHeaders(200, 0);
        var output = httpExchange.getResponseBody();
        output.write(responseJSON.getBytes(StandardCharsets.UTF_8));
        httpExchange.close();
        // TODO

    }
}
