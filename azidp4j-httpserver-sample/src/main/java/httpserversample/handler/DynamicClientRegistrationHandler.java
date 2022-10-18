package httpserversample.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import org.azidp4j.AzIdP;
import org.azidp4j.client.request.ClientRegistrationRequest;

public class DynamicClientRegistrationHandler extends AzIdpHttpHandler {

    private final AzIdP azIdp;

    public DynamicClientRegistrationHandler(AzIdP azIdp) {
        this.azIdp = azIdp;
    }

    @Override
    public void process(HttpExchange httpExchange) throws IOException {
        var body = new ObjectMapper().readTree(httpExchange.getRequestBody());
        var responseTypes = new HashSet<String>();
        body.get("response_types")
                .spliterator()
                .forEachRemaining(v -> responseTypes.add(v.asText()));
        var grantTypes = new HashSet<String>();
        body.get("grant_types").spliterator().forEachRemaining(v -> grantTypes.add(v.asText()));
        var redirectUris = new HashSet<String>();
        body.get("redirect_uris").spliterator().forEachRemaining(v -> redirectUris.add(v.asText()));
        String tokenEndpointAuthMethod = null;
        if (body.has("token_endpoint_auth_method")) {
            tokenEndpointAuthMethod = body.get("token_endpoint_auth_method").asText();
        }

        var request =
                ClientRegistrationRequest.builder()
                        .scope(body.get("scope").asText())
                        .responseTypes(responseTypes)
                        .grantTypes(grantTypes)
                        .redirectUris(redirectUris)
                        .tokenEndpointAuthMethod(tokenEndpointAuthMethod)
                        .build();
        var response = azIdp.registerClient(request);
        var os = httpExchange.getResponseBody();
        var responseBody =
                new ObjectMapper()
                        .writeValueAsString(response.body)
                        .getBytes(StandardCharsets.UTF_8);
        httpExchange.sendResponseHeaders(response.status, responseBody.length);
        os.write(responseBody);
        os.close();
        httpExchange.close();
    }
}
