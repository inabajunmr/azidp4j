package org.azidp4j.sample.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.azidp4j.AzIdP;
import org.azidp4j.authorize.ResponseType;
import org.azidp4j.client.ClientRegistrationRequest;
import org.azidp4j.client.GrantType;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;

public class DynamicClientRegistrationHandler implements HttpHandler {

    private final AzIdP azIdp;

    public DynamicClientRegistrationHandler(AzIdP azIdp) {
        this.azIdp = azIdp;
    }

    @Override
    public void handle(HttpExchange httpExchange) throws IOException {
        var body = new ObjectMapper().readTree(httpExchange.getRequestBody());
        var responseTypes = new HashSet<ResponseType>();
        body.get("response_types").spliterator().forEachRemaining(v -> responseTypes.add(ResponseType.of(v.asText())));
        var grantTypes = new HashSet<GrantType>();
        body.get("grant_types").spliterator().forEachRemaining(v -> grantTypes.add(GrantType.of(v.asText())));
        var redirectUris = new HashSet<String>();
        body.get("grant_types").spliterator().forEachRemaining(v -> redirectUris.add(v.asText()));
        var request = ClientRegistrationRequest.builder()
                .scope(body.get("scope").asText())
                .responseTypes(responseTypes)
                .grantTypes(grantTypes)
                .redirectUris(redirectUris)
                .build();
        var response = azIdp.registerClient(request);
        var os = httpExchange.getResponseBody();
        var responseBody = new ObjectMapper()
                .writeValueAsString(response.body).getBytes(StandardCharsets.UTF_8);
        httpExchange.sendResponseHeaders(200, responseBody.length);
        os.write(responseBody);
        os.close();
        httpExchange.close();
    }
}
