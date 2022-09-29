package httpserversample.handler;

import com.nimbusds.jose.jwk.JWKSet;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class JWKsEndpointHandler extends AzIdpHttpHandler {

    private final JWKSet jwkSet;

    public JWKsEndpointHandler(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @Override
    public void process(HttpExchange httpExchange) throws IOException {
        var jwksJSON = jwkSet.toPublicJWKSet().toString(true);
        httpExchange.getResponseHeaders().set("Content-Type", "application/json");
        httpExchange.sendResponseHeaders(200, jwksJSON.getBytes(StandardCharsets.UTF_8).length);
        var os = httpExchange.getResponseBody();
        os.write(jwksJSON.getBytes(StandardCharsets.UTF_8));
        os.close();
        httpExchange.close();
    }
}
