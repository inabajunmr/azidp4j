package httpserversample.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import org.azidp4j.AzIdP;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class DiscoveryHandler implements HttpHandler {

    private final AzIdP azIdp;

    private final ObjectMapper MAPPER = new ObjectMapper();

    public DiscoveryHandler(AzIdP azIdp) {
        this.azIdp = azIdp;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        var discoveryJSON = MAPPER.writeValueAsString(azIdp.discovery());
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, discoveryJSON.getBytes(StandardCharsets.UTF_8).length);
        var os = exchange.getResponseBody();
        os.write(discoveryJSON.getBytes(StandardCharsets.UTF_8));
        os.close();
        exchange.close();
    }
}
