package httpserversample.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.azidp4j.AzIdP;

public class DynamicClientRegistrationHandler extends AzIdpHttpHandler {

    private final AzIdP azIdp;

    public DynamicClientRegistrationHandler(AzIdP azIdp) {
        this.azIdp = azIdp;
    }

    @Override
    public void process(HttpExchange httpExchange) throws IOException {
        var response = azIdp.registerClient(azIdp.parseClientRegistrationRequest(new ObjectMapper().readValue(httpExchange.getRequestBody(), Map.class)));
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
