package org.azidp4j.sample.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.Authenticator;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.stream.Collectors;
import org.azidp4j.AzIdP;
import org.azidp4j.client.ClientStore;
import org.azidp4j.sample.authenticator.ClientBasicAuthenticator;
import org.azidp4j.token.TokenRequest;

public class TokenEndpointHandler extends AzIdpHttpHandler {

    private final AzIdP azIdp;

    private final ClientBasicAuthenticator clientBasicAuthenticator;

    public TokenEndpointHandler(AzIdP azIdp, ClientStore clientStore) {
        this.azIdp = azIdp;
        this.clientBasicAuthenticator = new ClientBasicAuthenticator(clientStore);
    }

    @Override
    public void process(HttpExchange httpExchange) throws IOException {
        var result = clientBasicAuthenticator.authenticate(httpExchange);
        String authenticatedClientId = null;
        if (result instanceof Authenticator.Success) {
            authenticatedClientId = ((Authenticator.Success) result).getPrincipal().getUsername();
        }
        var body = new String(httpExchange.getRequestBody().readAllBytes());
        var bodyMap =
                Arrays.stream(body.split("&"))
                        .map(kv -> kv.split("="))
                        .collect(Collectors.toMap(kv -> kv[0], kv -> kv[1]));
        var tokenRequest =
                new TokenRequest(authenticatedClientId, Instant.now().getEpochSecond(), bodyMap);
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
